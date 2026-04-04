//! 環境変数インジェクション検知モジュール
//!
//! `/proc/*/environ` を定期スキャンし、プロセス単位の不審な環境変数設定を検知する。
//!
//! 検知対象:
//! - `LD_PRELOAD`, `LD_AUDIT`, `GCONV_PATH` など動的リンカ関連の危険変数（→ Critical）
//! - `LD_LIBRARY_PATH` に不審パスが含まれる場合（→ Critical）
//! - `PYTHONPATH`, `RUBYLIB` 等のランタイムパスに不審パスが含まれる場合（→ Warning）
//! - `PATH` に不審パスが含まれる場合（→ Warning）
//! - `HTTP_PROXY` / `HTTPS_PROXY` の存在（→ Warning、設定で無効化可能）
//! - ユーザー定義の追加危険変数（→ Warning）

use crate::config::EnvInjectionMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::BTreeMap;
use tokio_util::sync::CancellationToken;

/// Critical レベルの危険環境変数（存在自体が危険）
const CRITICAL_ENV_VARS: &[(&str, &str)] = &[
    ("LD_PRELOAD", "env_injection_ld_preload"),
    ("LD_AUDIT", "env_injection_ld_audit"),
    ("GCONV_PATH", "env_injection_gconv_path"),
];

/// Warning レベルの危険環境変数（存在自体が不審）
const WARNING_PRESENCE_VARS: &[(&str, &str)] = &[
    ("LD_DEBUG", "env_injection_ld_debug"),
    ("RESOLV_HOST_CONF", "env_injection_resolv_conf"),
];

/// パスの内容を検査する環境変数（Critical）
const CRITICAL_PATH_VARS: &[(&str, &str)] = &[("LD_LIBRARY_PATH", "env_injection_ld_library_path")];

/// パスの内容を検査するランタイム変数（Warning）
const RUNTIME_PATH_VARS: &[(&str, &str)] = &[
    ("PYTHONPATH", "env_injection_runtime_path"),
    ("RUBYLIB", "env_injection_runtime_path"),
    ("NODE_PATH", "env_injection_runtime_path"),
    ("PERL5LIB", "env_injection_runtime_path"),
    ("CLASSPATH", "env_injection_runtime_path"),
];

/// Proxy 変数（Warning）
const PROXY_VARS: &[(&str, &str)] = &[
    ("HTTP_PROXY", "env_injection_proxy"),
    ("HTTPS_PROXY", "env_injection_proxy"),
    ("http_proxy", "env_injection_proxy"),
    ("https_proxy", "env_injection_proxy"),
];

/// 検出された環境変数の異常
struct EnvAnomaly {
    /// プロセス ID
    pid: u32,
    /// プロセス名
    process_name: String,
    /// 環境変数名
    var_name: String,
    /// 環境変数の値
    var_value: String,
    /// 重大度
    severity: Severity,
    /// イベントタイプ
    event_type: String,
    /// 説明
    description: String,
}

/// 環境変数インジェクション検知モジュール
///
/// `/proc/*/environ` を定期スキャンし、プロセス単位の不審な環境変数設定を検知する。
pub struct EnvInjectionMonitorModule {
    config: EnvInjectionMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl EnvInjectionMonitorModule {
    /// 新しい環境変数インジェクション検知モジュールを作成する
    pub fn new(config: EnvInjectionMonitorConfig, event_bus: Option<EventBus>) -> Self {
        Self {
            config,
            cancel_token: CancellationToken::new(),
            event_bus,
        }
    }

    /// キャンセルトークンのクローンを返す
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    /// 全プロセスの `/proc/{pid}/environ` をスキャンし、異常を検出する
    ///
    /// 戻り値は (スキャンしたプロセス数, 検出された異常リスト)
    fn scan_all_processes(config: &EnvInjectionMonitorConfig) -> (usize, Vec<EnvAnomaly>) {
        let mut scanned = 0;
        let mut anomalies = Vec::new();

        let entries = match std::fs::read_dir("/proc") {
            Ok(entries) => entries,
            Err(e) => {
                tracing::debug!(error = %e, "/proc の読み取りに失敗しました");
                return (0, anomalies);
            }
        };

        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // 数値ディレクトリ（PID）のみ対象
            let pid: u32 = match name_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            let env_vars = match Self::read_process_environ(pid) {
                Some(vars) => vars,
                None => continue,
            };

            scanned += 1;
            let process_name = Self::get_process_name(pid);
            let mut found = Self::check_env_vars(pid, &process_name, &env_vars, config);
            anomalies.append(&mut found);
        }

        (scanned, anomalies)
    }

    /// `/proc/{pid}/environ` をバイナリ読み込みし、NUL 区切りでパースする
    ///
    /// 読み取り不可（権限不足等）なら `None` を返す（エラーログ不要）。
    fn read_process_environ(pid: u32) -> Option<Vec<(String, String)>> {
        let path = format!("/proc/{}/environ", pid);
        let data = std::fs::read(path).ok()?;
        Some(Self::parse_environ_bytes(&data))
    }

    /// NUL 区切りバイト列を環境変数のキー・バリューペアにパースする
    fn parse_environ_bytes(data: &[u8]) -> Vec<(String, String)> {
        let mut result = Vec::new();
        for chunk in data.split(|&b| b == 0) {
            if chunk.is_empty() {
                continue;
            }
            let s = String::from_utf8_lossy(chunk);
            if let Some((key, value)) = s.split_once('=') {
                result.push((key.to_string(), value.to_string()));
            }
        }
        result
    }

    /// `/proc/{pid}/comm` からプロセス名を取得する
    ///
    /// 取得不可なら `"unknown"` を返す。
    fn get_process_name(pid: u32) -> String {
        let path = format!("/proc/{}/comm", pid);
        std::fs::read_to_string(path)
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    }

    /// 各ルールを適用して環境変数の異常を検出する
    fn check_env_vars(
        pid: u32,
        process_name: &str,
        env_vars: &[(String, String)],
        config: &EnvInjectionMonitorConfig,
    ) -> Vec<EnvAnomaly> {
        let mut anomalies = Vec::new();
        let is_excluded = config.exclude_processes.contains(&process_name.to_string());

        for (key, value) in env_vars {
            // 1. CRITICAL_ENV_VARS: 存在自体が Critical（除外プロセスでも検知）
            for &(var_name, event_type) in CRITICAL_ENV_VARS {
                if key == var_name {
                    anomalies.push(EnvAnomaly {
                        pid,
                        process_name: process_name.to_string(),
                        var_name: key.clone(),
                        var_value: value.clone(),
                        severity: Severity::Critical,
                        event_type: event_type.to_string(),
                        description: format!(
                            "危険な環境変数 {} がプロセス {}(PID:{}) に設定されています: {}",
                            key, process_name, pid, value
                        ),
                    });
                }
            }

            // 2. WARNING_PRESENCE_VARS: 存在すれば Warning
            if !is_excluded {
                for &(var_name, event_type) in WARNING_PRESENCE_VARS {
                    if key == var_name {
                        anomalies.push(EnvAnomaly {
                            pid,
                            process_name: process_name.to_string(),
                            var_name: key.clone(),
                            var_value: value.clone(),
                            severity: Severity::Warning,
                            event_type: event_type.to_string(),
                            description: format!(
                                "不審な環境変数 {} がプロセス {}(PID:{}) に設定されています: {}",
                                key, process_name, pid, value
                            ),
                        });
                    }
                }
            }

            // 3. CRITICAL_PATH_VARS: パス内容を検査（Critical）
            for &(var_name, event_type) in CRITICAL_PATH_VARS {
                if key == var_name {
                    for component in value.split(&[':', ';'][..]) {
                        if Self::is_suspicious_path(component, &config.suspicious_paths) {
                            anomalies.push(EnvAnomaly {
                                pid,
                                process_name: process_name.to_string(),
                                var_name: key.clone(),
                                var_value: value.clone(),
                                severity: Severity::Critical,
                                event_type: event_type.to_string(),
                                description: format!(
                                    "{} に不審なパス '{}' が含まれています (プロセス: {}(PID:{}))",
                                    key, component, process_name, pid
                                ),
                            });
                            break;
                        }
                    }
                }
            }

            // 4. RUNTIME_PATH_VARS: 除外プロセスはスキップ（Warning）
            if !is_excluded {
                for &(var_name, event_type) in RUNTIME_PATH_VARS {
                    if key == var_name {
                        for component in value.split(&[':', ';'][..]) {
                            if Self::is_suspicious_path(component, &config.suspicious_paths) {
                                anomalies.push(EnvAnomaly {
                                    pid,
                                    process_name: process_name.to_string(),
                                    var_name: key.clone(),
                                    var_value: value.clone(),
                                    severity: Severity::Warning,
                                    event_type: event_type.to_string(),
                                    description: format!(
                                        "{} に不審なパス '{}' が含まれています (プロセス: {}(PID:{}))",
                                        key, component, process_name, pid
                                    ),
                                });
                                break;
                            }
                        }
                    }
                }
            }

            // 5. PATH: 不審パスを含む場合 Warning
            if key == "PATH" {
                for component in value.split(':') {
                    if Self::is_suspicious_path(component, &config.suspicious_paths) {
                        anomalies.push(EnvAnomaly {
                            pid,
                            process_name: process_name.to_string(),
                            var_name: key.clone(),
                            var_value: value.clone(),
                            severity: Severity::Warning,
                            event_type: "env_injection_suspicious_path".to_string(),
                            description: format!(
                                "PATH に不審なパス '{}' が含まれています (プロセス: {}(PID:{}))",
                                component, process_name, pid
                            ),
                        });
                        break;
                    }
                }
            }

            // 6. PROXY_VARS: check_proxy_vars が true の場合のみ（Warning）
            if config.check_proxy_vars {
                for &(var_name, event_type) in PROXY_VARS {
                    if key == var_name {
                        anomalies.push(EnvAnomaly {
                            pid,
                            process_name: process_name.to_string(),
                            var_name: key.clone(),
                            var_value: value.clone(),
                            severity: Severity::Warning,
                            event_type: event_type.to_string(),
                            description: format!(
                                "Proxy 変数 {} がプロセス {}(PID:{}) に設定されています: {}",
                                key, process_name, pid, value
                            ),
                        });
                    }
                }
            }

            // 7. extra_dangerous_vars: ユーザー定義の追加危険変数（Warning）
            if config.extra_dangerous_vars.contains(key) {
                anomalies.push(EnvAnomaly {
                    pid,
                    process_name: process_name.to_string(),
                    var_name: key.clone(),
                    var_value: value.clone(),
                    severity: Severity::Warning,
                    event_type: "env_injection_extra_dangerous".to_string(),
                    description: format!(
                        "追加危険変数 {} がプロセス {}(PID:{}) に設定されています: {}",
                        key, process_name, pid, value
                    ),
                });
            }
        }

        anomalies
    }

    /// パスコンポーネントが不審パスリストに含まれるか判定する
    ///
    /// 前方一致または完全一致で判定する。
    fn is_suspicious_path(component: &str, suspicious_paths: &[String]) -> bool {
        let trimmed = component.trim();
        if trimmed.is_empty() {
            return false;
        }
        for suspicious in suspicious_paths {
            if trimmed == suspicious.as_str() || trimmed.starts_with(&format!("{}/", suspicious)) {
                return true;
            }
        }
        false
    }

    /// 検出された異常をイベントバスに発行する
    fn publish_anomalies(anomalies: &[EnvAnomaly], event_bus: &Option<EventBus>) {
        let Some(bus) = event_bus else {
            return;
        };
        for anomaly in anomalies {
            match anomaly.severity {
                Severity::Critical => {
                    tracing::error!(
                        pid = anomaly.pid,
                        process = %anomaly.process_name,
                        variable = %anomaly.var_name,
                        "{}",
                        anomaly.description
                    );
                }
                _ => {
                    tracing::warn!(
                        pid = anomaly.pid,
                        process = %anomaly.process_name,
                        variable = %anomaly.var_name,
                        "{}",
                        anomaly.description
                    );
                }
            }
            bus.publish(
                SecurityEvent::new(
                    &anomaly.event_type,
                    anomaly.severity.clone(),
                    "env_injection_monitor",
                    anomaly.description.clone(),
                )
                .with_details(format!(
                    "PID:{} Process:{} {}={}",
                    anomaly.pid, anomaly.process_name, anomaly.var_name, anomaly.var_value
                )),
            );
        }
    }
}

impl Module for EnvInjectionMonitorModule {
    fn name(&self) -> &str {
        "env_injection_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            exclude_processes = ?self.config.exclude_processes,
            suspicious_paths = ?self.config.suspicious_paths,
            check_proxy_vars = self.config.check_proxy_vars,
            "環境変数インジェクション検知モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<(), AppError> {
        // 初回スキャン
        let (scanned, anomalies) = Self::scan_all_processes(&self.config);
        tracing::info!(
            scanned_processes = scanned,
            anomalies_found = anomalies.len(),
            "初回プロセス環境変数スキャンが完了しました"
        );
        Self::publish_anomalies(&anomalies, &self.event_bus);

        let config = self.config.clone();
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(config.scan_interval_secs));
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("環境変数インジェクション検知モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let (scanned, anomalies) = EnvInjectionMonitorModule::scan_all_processes(&config);
                        tracing::debug!(
                            scanned_processes = scanned,
                            anomalies_found = anomalies.len(),
                            "プロセス環境変数の定期スキャンが完了しました"
                        );
                        EnvInjectionMonitorModule::publish_anomalies(&anomalies, &event_bus);
                    }
                }
            }
        });

        Ok(())
    }

    async fn stop(&mut self) -> Result<(), AppError> {
        self.cancel_token.cancel();
        Ok(())
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();

        let (scanned, anomalies) = Self::scan_all_processes(&self.config);
        let issues_found = anomalies.len();
        let snapshot: BTreeMap<String, String> = anomalies
            .iter()
            .map(|a| {
                (
                    format!("{}:{}:{}", a.pid, a.process_name, a.var_name),
                    a.description.clone(),
                )
            })
            .collect();

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned: scanned,
            issues_found,
            duration,
            summary: format!(
                "プロセス環境変数 {}件をスキャンしました（問題: {}件）",
                scanned, issues_found
            ),
            snapshot,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_test_config() -> EnvInjectionMonitorConfig {
        EnvInjectionMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            exclude_processes: vec![
                "java".to_string(),
                "gradle".to_string(),
                "mvn".to_string(),
                "node".to_string(),
                "npm".to_string(),
                "python3".to_string(),
                "ruby".to_string(),
                "perl".to_string(),
            ],
            suspicious_paths: vec![
                "/tmp".to_string(),
                "/dev/shm".to_string(),
                "/var/tmp".to_string(),
                ".".to_string(),
            ],
            extra_dangerous_vars: vec![],
            check_proxy_vars: true,
        }
    }

    #[test]
    fn test_read_process_environ_self() {
        // 自プロセスの /proc/self/environ を読めることを確認
        let data = std::fs::read("/proc/self/environ");
        assert!(data.is_ok());
        let vars = EnvInjectionMonitorModule::parse_environ_bytes(&data.unwrap());
        assert!(!vars.is_empty());
        // PATH は通常存在するはず
        assert!(vars.iter().any(|(k, _)| k == "PATH"));
    }

    #[test]
    fn test_read_process_environ_parse() {
        // NUL 区切りバイト列のパーステスト
        let data = b"KEY1=value1\0KEY2=value2\0EMPTY=\0";
        let vars = EnvInjectionMonitorModule::parse_environ_bytes(data);
        assert_eq!(vars.len(), 3);
        assert_eq!(vars[0], ("KEY1".to_string(), "value1".to_string()));
        assert_eq!(vars[1], ("KEY2".to_string(), "value2".to_string()));
        assert_eq!(vars[2], ("EMPTY".to_string(), String::new()));
    }

    #[test]
    fn test_get_process_name_self() {
        // 自プロセス名が取得できることを確認
        let pid = std::process::id();
        let name = EnvInjectionMonitorModule::get_process_name(pid);
        assert_ne!(name, "unknown");
        assert!(!name.is_empty());
    }

    #[test]
    fn test_check_env_vars_ld_preload_critical() {
        let config = default_test_config();
        let env_vars = vec![("LD_PRELOAD".to_string(), "/tmp/evil.so".to_string())];
        let anomalies =
            EnvInjectionMonitorModule::check_env_vars(1, "test_proc", &env_vars, &config);
        assert!(!anomalies.is_empty());
        let a = &anomalies[0];
        assert_eq!(a.severity, Severity::Critical);
        assert_eq!(a.event_type, "env_injection_ld_preload");
    }

    #[test]
    fn test_check_env_vars_ld_audit_critical() {
        let config = default_test_config();
        let env_vars = vec![("LD_AUDIT".to_string(), "/tmp/audit.so".to_string())];
        let anomalies =
            EnvInjectionMonitorModule::check_env_vars(1, "test_proc", &env_vars, &config);
        assert!(!anomalies.is_empty());
        let a = anomalies.iter().find(|a| a.var_name == "LD_AUDIT").unwrap();
        assert_eq!(a.severity, Severity::Critical);
        assert_eq!(a.event_type, "env_injection_ld_audit");
    }

    #[test]
    fn test_check_env_vars_gconv_path_critical() {
        let config = default_test_config();
        let env_vars = vec![("GCONV_PATH".to_string(), "/tmp/gconv".to_string())];
        let anomalies =
            EnvInjectionMonitorModule::check_env_vars(1, "test_proc", &env_vars, &config);
        assert!(!anomalies.is_empty());
        let a = anomalies
            .iter()
            .find(|a| a.var_name == "GCONV_PATH")
            .unwrap();
        assert_eq!(a.severity, Severity::Critical);
        assert_eq!(a.event_type, "env_injection_gconv_path");
    }

    #[test]
    fn test_check_env_vars_ld_library_path_suspicious() {
        let config = default_test_config();
        let env_vars = vec![(
            "LD_LIBRARY_PATH".to_string(),
            "/usr/lib:/tmp/evil".to_string(),
        )];
        let anomalies =
            EnvInjectionMonitorModule::check_env_vars(1, "test_proc", &env_vars, &config);
        let critical = anomalies
            .iter()
            .find(|a| a.event_type == "env_injection_ld_library_path");
        assert!(critical.is_some());
        assert_eq!(critical.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn test_check_env_vars_ld_library_path_safe() {
        let config = default_test_config();
        let env_vars = vec![(
            "LD_LIBRARY_PATH".to_string(),
            "/usr/lib:/usr/local/lib".to_string(),
        )];
        let anomalies =
            EnvInjectionMonitorModule::check_env_vars(1, "test_proc", &env_vars, &config);
        let critical = anomalies
            .iter()
            .find(|a| a.event_type == "env_injection_ld_library_path");
        assert!(critical.is_none());
    }

    #[test]
    fn test_check_env_vars_path_suspicious() {
        let config = default_test_config();
        let env_vars = vec![(
            "PATH".to_string(),
            "/usr/bin:/tmp:/usr/local/bin".to_string(),
        )];
        let anomalies =
            EnvInjectionMonitorModule::check_env_vars(1, "test_proc", &env_vars, &config);
        let path_anomaly = anomalies
            .iter()
            .find(|a| a.event_type == "env_injection_suspicious_path");
        assert!(path_anomaly.is_some());
        assert_eq!(path_anomaly.unwrap().severity, Severity::Warning);
    }

    #[test]
    fn test_check_env_vars_path_safe() {
        let config = default_test_config();
        let env_vars = vec![("PATH".to_string(), "/usr/bin:/usr/local/bin".to_string())];
        let anomalies =
            EnvInjectionMonitorModule::check_env_vars(1, "test_proc", &env_vars, &config);
        let path_anomaly = anomalies
            .iter()
            .find(|a| a.event_type == "env_injection_suspicious_path");
        assert!(path_anomaly.is_none());
    }

    #[test]
    fn test_check_env_vars_runtime_path_excluded_process() {
        let config = default_test_config();
        let env_vars = vec![("PYTHONPATH".to_string(), "/tmp/evil".to_string())];
        // "python3" は除外プロセス
        let anomalies = EnvInjectionMonitorModule::check_env_vars(1, "python3", &env_vars, &config);
        let runtime = anomalies
            .iter()
            .find(|a| a.event_type == "env_injection_runtime_path");
        assert!(runtime.is_none());
    }

    #[test]
    fn test_check_env_vars_runtime_path_suspicious() {
        let config = default_test_config();
        let env_vars = vec![("PYTHONPATH".to_string(), "/tmp/evil".to_string())];
        // "some_proc" は除外プロセスではない
        let anomalies =
            EnvInjectionMonitorModule::check_env_vars(1, "some_proc", &env_vars, &config);
        let runtime = anomalies
            .iter()
            .find(|a| a.event_type == "env_injection_runtime_path");
        assert!(runtime.is_some());
        assert_eq!(runtime.unwrap().severity, Severity::Warning);
    }

    #[test]
    fn test_check_env_vars_proxy_detected() {
        let config = default_test_config();
        let env_vars = vec![(
            "HTTP_PROXY".to_string(),
            "http://evil.proxy:8080".to_string(),
        )];
        let anomalies =
            EnvInjectionMonitorModule::check_env_vars(1, "test_proc", &env_vars, &config);
        let proxy = anomalies
            .iter()
            .find(|a| a.event_type == "env_injection_proxy");
        assert!(proxy.is_some());
        assert_eq!(proxy.unwrap().severity, Severity::Warning);
    }

    #[test]
    fn test_check_env_vars_proxy_disabled() {
        let mut config = default_test_config();
        config.check_proxy_vars = false;
        let env_vars = vec![(
            "HTTP_PROXY".to_string(),
            "http://evil.proxy:8080".to_string(),
        )];
        let anomalies =
            EnvInjectionMonitorModule::check_env_vars(1, "test_proc", &env_vars, &config);
        let proxy = anomalies
            .iter()
            .find(|a| a.event_type == "env_injection_proxy");
        assert!(proxy.is_none());
    }

    #[test]
    fn test_check_env_vars_extra_dangerous() {
        let mut config = default_test_config();
        config.extra_dangerous_vars = vec!["MY_EVIL_VAR".to_string()];
        let env_vars = vec![("MY_EVIL_VAR".to_string(), "evil_value".to_string())];
        let anomalies =
            EnvInjectionMonitorModule::check_env_vars(1, "test_proc", &env_vars, &config);
        let extra = anomalies
            .iter()
            .find(|a| a.event_type == "env_injection_extra_dangerous");
        assert!(extra.is_some());
        assert_eq!(extra.unwrap().severity, Severity::Warning);
    }

    #[test]
    fn test_is_suspicious_path() {
        let suspicious = vec![
            "/tmp".to_string(),
            "/dev/shm".to_string(),
            "/var/tmp".to_string(),
            ".".to_string(),
        ];

        // 完全一致
        assert!(EnvInjectionMonitorModule::is_suspicious_path(
            "/tmp",
            &suspicious
        ));
        assert!(EnvInjectionMonitorModule::is_suspicious_path(
            "/dev/shm",
            &suspicious
        ));
        assert!(EnvInjectionMonitorModule::is_suspicious_path(
            ".",
            &suspicious
        ));

        // 前方一致
        assert!(EnvInjectionMonitorModule::is_suspicious_path(
            "/tmp/evil",
            &suspicious
        ));
        assert!(EnvInjectionMonitorModule::is_suspicious_path(
            "/var/tmp/subdir",
            &suspicious
        ));

        // 安全なパス
        assert!(!EnvInjectionMonitorModule::is_suspicious_path(
            "/usr/lib",
            &suspicious
        ));
        assert!(!EnvInjectionMonitorModule::is_suspicious_path(
            "/usr/local/bin",
            &suspicious
        ));

        // 空文字列
        assert!(!EnvInjectionMonitorModule::is_suspicious_path(
            "",
            &suspicious
        ));
    }

    #[test]
    fn test_init_zero_interval() {
        let mut config = default_test_config();
        config.scan_interval_secs = 0;
        let mut module = EnvInjectionMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_init_valid() {
        let config = default_test_config();
        let mut module = EnvInjectionMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let mut config = default_test_config();
        config.scan_interval_secs = 3600;
        let mut module = EnvInjectionMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let config = default_test_config();
        let module = EnvInjectionMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        // 少なくとも自プロセスはスキャンされるはず
        assert!(result.items_scanned > 0);
        assert!(result.summary.contains("件"));
    }

    #[test]
    fn test_scan_all_processes() {
        let config = default_test_config();
        let (scanned, _anomalies) = EnvInjectionMonitorModule::scan_all_processes(&config);
        // 少なくとも 1 プロセスはスキャンできるはず
        assert!(scanned > 0);
    }
}
