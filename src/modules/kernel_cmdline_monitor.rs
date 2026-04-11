//! カーネルコマンドライン実行時監視モジュール
//!
//! `/proc/cmdline` を定期チェックし、カーネルパラメータの実行時変更を検知する。
//! kexec によるカーネル入れ替えや、セキュリティ機能の無効化パラメータを検出する。
//!
//! 検知対象:
//! - `/proc/cmdline` の内容がベースラインから変更 — Critical
//! - 不審パラメータの存在:
//!   - High: `selinux=0`, `apparmor=0`, `security=none`, `ima_appraise=off`, `module.sig_enforce=0`
//!   - Warning: `init=/bin/sh`, `init=/bin/bash`, `single`, `debug`, `earlyprintk`
//! - `/sys/kernel/kexec_loaded` が `1` — High

use crate::config::KernelCmdlineMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::BTreeMap;
use std::path::Path;
use tokio_util::sync::CancellationToken;

/// セキュリティ無効化に関わる高危険度パラメータ
const HIGH_SEVERITY_PARAMS: &[&str] = &[
    "selinux=0",
    "apparmor=0",
    "security=none",
    "ima_appraise=off",
    "module.sig_enforce=0",
];

/// デバッグ・リカバリ用途の警告レベルパラメータ
const WARNING_SEVERITY_PARAMS: &[&str] = &[
    "init=/bin/sh",
    "init=/bin/bash",
    "single",
    "debug",
    "earlyprintk",
];

/// `/proc/cmdline` からカーネルコマンドラインを読み取る
fn read_cmdline(path: &Path) -> Option<String> {
    match std::fs::read_to_string(path) {
        Ok(content) => Some(content.trim().to_string()),
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "カーネルコマンドラインの読み取りに失敗しました"
            );
            None
        }
    }
}

/// `/sys/kernel/kexec_loaded` の値を読み取る
fn read_kexec_loaded(path: &Path) -> Option<String> {
    match std::fs::read_to_string(path) {
        Ok(content) => Some(content.trim().to_string()),
        Err(e) => {
            tracing::debug!(
                path = %path.display(),
                error = %e,
                "kexec_loaded の読み取りに失敗しました（kexec 非対応の可能性あり）"
            );
            None
        }
    }
}

/// パラメータが不審リストに含まれるかチェックする
fn classify_param(param: &str, suspicious_params: &[String]) -> Option<Severity> {
    if !suspicious_params.iter().any(|s| s == param) {
        return None;
    }

    if HIGH_SEVERITY_PARAMS.contains(&param) {
        Some(Severity::Critical)
    } else if WARNING_SEVERITY_PARAMS.contains(&param) {
        Some(Severity::Warning)
    } else {
        // ユーザー定義の不審パラメータはデフォルト Warning
        Some(Severity::Warning)
    }
}

/// カーネルコマンドライン実行時監視モジュール
///
/// `/proc/cmdline` を定期的にスキャンし、カーネルパラメータの変更や
/// セキュリティ機能の無効化を検知する。
pub struct KernelCmdlineMonitorModule {
    config: KernelCmdlineMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl KernelCmdlineMonitorModule {
    /// 新しいカーネルコマンドライン実行時監視モジュールを作成する
    pub fn new(config: KernelCmdlineMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// カーネルコマンドラインの不審パラメータを検査する
    fn check_suspicious_params(
        cmdline: &str,
        suspicious_params: &[String],
        event_bus: &Option<EventBus>,
    ) -> usize {
        let mut issues = 0;
        let params: Vec<&str> = cmdline.split_whitespace().collect();

        for param in &params {
            if let Some(severity) = classify_param(param, suspicious_params) {
                issues += 1;
                let severity_label = match severity {
                    Severity::Critical => "CRITICAL",
                    Severity::Warning => "WARNING",
                    Severity::Info => "INFO",
                };
                tracing::warn!(
                    param = %param,
                    severity = %severity_label,
                    "不審なカーネルパラメータが検出されました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "kernel_cmdline_suspicious_param",
                            severity,
                            "kernel_cmdline_monitor",
                            "不審なカーネルパラメータが検出されました",
                        )
                        .with_details(format!("param={}", param)),
                    );
                }
            }
        }

        issues
    }

    /// kexec_loaded の状態を検査する
    fn check_kexec_loaded(kexec_path: &Path, event_bus: &Option<EventBus>) -> bool {
        if let Some(value) = read_kexec_loaded(kexec_path)
            && value == "1"
        {
            tracing::warn!(
                "kexec にカーネルがロードされています — カーネル入れ替えの可能性があります"
            );
            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        "kernel_kexec_loaded",
                        Severity::Critical,
                        "kernel_cmdline_monitor",
                        "kexec にカーネルがロードされています",
                    )
                    .with_details("kexec_loaded=1".to_string()),
                );
            }
            return true;
        }
        false
    }

    /// コマンドラインの変更を検知する
    fn detect_cmdline_change(baseline: &str, current: &str, event_bus: &Option<EventBus>) -> bool {
        if baseline != current {
            tracing::error!("CRITICAL: カーネルコマンドラインがベースラインから変更されました");
            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        "kernel_cmdline_changed",
                        Severity::Critical,
                        "kernel_cmdline_monitor",
                        "カーネルコマンドラインがベースラインから変更されました",
                    )
                    .with_details(format!("baseline={}, current={}", baseline, current)),
                );
            }
            return true;
        }
        false
    }
}

impl Module for KernelCmdlineMonitorModule {
    fn name(&self) -> &str {
        "kernel_cmdline_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        let cmdline_path = Path::new(&self.config.proc_cmdline_path);
        if cmdline_path.exists() {
            tracing::info!(
                path = %self.config.proc_cmdline_path,
                "カーネルコマンドラインファイルを確認しました"
            );
        } else {
            tracing::warn!(
                path = %self.config.proc_cmdline_path,
                "カーネルコマンドラインファイルが見つかりません"
            );
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            check_kexec_loaded = self.config.check_kexec_loaded,
            suspicious_params_count = self.config.suspicious_params.len(),
            "カーネルコマンドライン実行時監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        let config = self.config.clone();
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        // 初回ベースラインを取得
        let cmdline_path = Path::new(&config.proc_cmdline_path);
        let baseline = read_cmdline(cmdline_path).unwrap_or_default();

        if baseline.is_empty() {
            tracing::warn!(
                "初回のカーネルコマンドライン取得に失敗しました。監視を開始しますが検知は限定的です"
            );
        } else {
            tracing::info!(
                cmdline_length = baseline.len(),
                "カーネルコマンドラインのベースラインを取得しました"
            );
        }

        // 初回の不審パラメータチェック
        Self::check_suspicious_params(&baseline, &config.suspicious_params, &event_bus);

        // 初回の kexec チェック
        if config.check_kexec_loaded {
            Self::check_kexec_loaded(Path::new(&config.kexec_loaded_path), &event_bus);
        }

        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(config.scan_interval_secs));
            // 最初の tick は即座に発火するのでスキップ
            interval.tick().await;

            let mut current_baseline = baseline;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("カーネルコマンドライン実行時監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let cmdline_path = Path::new(&config.proc_cmdline_path);
                        if let Some(current) = read_cmdline(cmdline_path) {
                            // ベースラインからの変更を検知
                            if Self::detect_cmdline_change(&current_baseline, &current, &event_bus) {
                                current_baseline = current.clone();
                            }

                            // 不審パラメータチェック
                            Self::check_suspicious_params(
                                &current,
                                &config.suspicious_params,
                                &event_bus,
                            );
                        }

                        // kexec チェック
                        if config.check_kexec_loaded {
                            Self::check_kexec_loaded(
                                Path::new(&config.kexec_loaded_path),
                                &event_bus,
                            );
                        }

                        tracing::debug!("カーネルコマンドラインのスキャンを完了しました");
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();
        let mut items_scanned = 0;
        let mut issues_found = 0;
        let mut snapshot_map: BTreeMap<String, String> = BTreeMap::new();

        // コマンドライン読み取り
        let cmdline_path = Path::new(&self.config.proc_cmdline_path);
        if let Some(cmdline) = read_cmdline(cmdline_path) {
            items_scanned += 1;
            snapshot_map.insert("proc_cmdline".to_string(), cmdline.clone());

            // 不審パラメータチェック
            issues_found += Self::check_suspicious_params(
                &cmdline,
                &self.config.suspicious_params,
                &self.event_bus,
            );
        }

        // kexec_loaded チェック
        if self.config.check_kexec_loaded {
            let kexec_path = Path::new(&self.config.kexec_loaded_path);
            if let Some(value) = read_kexec_loaded(kexec_path) {
                items_scanned += 1;
                snapshot_map.insert("kexec_loaded".to_string(), value.clone());
                if Self::check_kexec_loaded(kexec_path, &self.event_bus) {
                    issues_found += 1;
                }
            }
        }

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "カーネルコマンドライン {}項目をスキャンし、{}件の問題を検出しました",
                items_scanned, issues_found
            ),
            snapshot: snapshot_map,
        })
    }

    async fn stop(&mut self) -> Result<(), AppError> {
        self.cancel_token.cancel();
        tracing::info!("カーネルコマンドライン実行時監視モジュールを停止しました");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn test_config(dir: &tempfile::TempDir) -> KernelCmdlineMonitorConfig {
        let cmdline_path = dir.path().join("cmdline");
        let kexec_path = dir.path().join("kexec_loaded");
        KernelCmdlineMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            check_kexec_loaded: true,
            suspicious_params: vec![
                "selinux=0".to_string(),
                "apparmor=0".to_string(),
                "security=none".to_string(),
                "ima_appraise=off".to_string(),
                "module.sig_enforce=0".to_string(),
                "init=/bin/sh".to_string(),
                "init=/bin/bash".to_string(),
                "single".to_string(),
                "debug".to_string(),
                "earlyprintk".to_string(),
            ],
            proc_cmdline_path: cmdline_path.display().to_string(),
            kexec_loaded_path: kexec_path.display().to_string(),
        }
    }

    #[test]
    fn test_module_name() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(&dir);
        let module = KernelCmdlineMonitorModule::new(config, None);
        assert_eq!(module.name(), "kernel_cmdline_monitor");
    }

    #[test]
    fn test_init_zero_interval() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = test_config(&dir);
        config.scan_interval_secs = 0;
        let mut module = KernelCmdlineMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(&dir);
        let mut module = KernelCmdlineMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[test]
    fn test_read_cmdline_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cmdline");
        std::fs::write(&path, "BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro quiet\n").unwrap();

        let result = read_cmdline(&path);
        assert_eq!(
            result,
            Some("BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro quiet".to_string())
        );
    }

    #[test]
    fn test_read_cmdline_nonexistent() {
        let result = read_cmdline(Path::new("/nonexistent/cmdline"));
        assert!(result.is_none());
    }

    #[test]
    fn test_read_kexec_loaded_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kexec_loaded");
        std::fs::write(&path, "0\n").unwrap();

        let result = read_kexec_loaded(&path);
        assert_eq!(result, Some("0".to_string()));
    }

    #[test]
    fn test_read_kexec_loaded_nonexistent() {
        let result = read_kexec_loaded(Path::new("/nonexistent/kexec_loaded"));
        assert!(result.is_none());
    }

    #[test]
    fn test_classify_param_high_severity() {
        let suspicious = vec![
            "selinux=0".to_string(),
            "apparmor=0".to_string(),
            "security=none".to_string(),
            "ima_appraise=off".to_string(),
            "module.sig_enforce=0".to_string(),
        ];

        assert_eq!(
            classify_param("selinux=0", &suspicious),
            Some(Severity::Critical)
        );
        assert_eq!(
            classify_param("apparmor=0", &suspicious),
            Some(Severity::Critical)
        );
        assert_eq!(
            classify_param("security=none", &suspicious),
            Some(Severity::Critical)
        );
        assert_eq!(
            classify_param("ima_appraise=off", &suspicious),
            Some(Severity::Critical)
        );
        assert_eq!(
            classify_param("module.sig_enforce=0", &suspicious),
            Some(Severity::Critical)
        );
    }

    #[test]
    fn test_classify_param_warning_severity() {
        let suspicious = vec![
            "init=/bin/sh".to_string(),
            "init=/bin/bash".to_string(),
            "single".to_string(),
            "debug".to_string(),
            "earlyprintk".to_string(),
        ];

        assert_eq!(
            classify_param("init=/bin/sh", &suspicious),
            Some(Severity::Warning)
        );
        assert_eq!(
            classify_param("init=/bin/bash", &suspicious),
            Some(Severity::Warning)
        );
        assert_eq!(
            classify_param("single", &suspicious),
            Some(Severity::Warning)
        );
        assert_eq!(
            classify_param("debug", &suspicious),
            Some(Severity::Warning)
        );
        assert_eq!(
            classify_param("earlyprintk", &suspicious),
            Some(Severity::Warning)
        );
    }

    #[test]
    fn test_classify_param_not_suspicious() {
        let suspicious = vec!["selinux=0".to_string()];
        assert_eq!(classify_param("root=/dev/sda1", &suspicious), None);
        assert_eq!(classify_param("quiet", &suspicious), None);
    }

    #[test]
    fn test_check_suspicious_params_none_found() {
        let cmdline = "BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro quiet";
        let suspicious = vec!["selinux=0".to_string(), "debug".to_string()];
        let issues =
            KernelCmdlineMonitorModule::check_suspicious_params(cmdline, &suspicious, &None);
        assert_eq!(issues, 0);
    }

    #[test]
    fn test_check_suspicious_params_found() {
        let cmdline = "BOOT_IMAGE=/vmlinuz root=/dev/sda1 selinux=0 debug";
        let suspicious = vec!["selinux=0".to_string(), "debug".to_string()];
        let issues =
            KernelCmdlineMonitorModule::check_suspicious_params(cmdline, &suspicious, &None);
        assert_eq!(issues, 2);
    }

    #[test]
    fn test_check_kexec_loaded_active() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kexec_loaded");
        std::fs::write(&path, "1\n").unwrap();

        assert!(KernelCmdlineMonitorModule::check_kexec_loaded(&path, &None));
    }

    #[test]
    fn test_check_kexec_loaded_inactive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kexec_loaded");
        std::fs::write(&path, "0\n").unwrap();

        assert!(!KernelCmdlineMonitorModule::check_kexec_loaded(
            &path, &None
        ));
    }

    #[test]
    fn test_check_kexec_loaded_nonexistent() {
        assert!(!KernelCmdlineMonitorModule::check_kexec_loaded(
            Path::new("/nonexistent/kexec_loaded"),
            &None
        ));
    }

    #[test]
    fn test_detect_cmdline_change_no_change() {
        let baseline = "BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro quiet";
        let current = "BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro quiet";
        assert!(!KernelCmdlineMonitorModule::detect_cmdline_change(
            baseline, current, &None
        ));
    }

    #[test]
    fn test_detect_cmdline_change_changed() {
        let baseline = "BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro quiet";
        let current = "BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro quiet selinux=0";
        assert!(KernelCmdlineMonitorModule::detect_cmdline_change(
            baseline, current, &None
        ));
    }

    #[tokio::test]
    async fn test_initial_scan_with_files() {
        let dir = tempfile::tempdir().unwrap();
        let cmdline_path = dir.path().join("cmdline");
        let kexec_path = dir.path().join("kexec_loaded");

        std::fs::write(
            &cmdline_path,
            "BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro quiet\n",
        )
        .unwrap();
        std::fs::write(&kexec_path, "0\n").unwrap();

        let config = KernelCmdlineMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            check_kexec_loaded: true,
            suspicious_params: vec!["selinux=0".to_string()],
            proc_cmdline_path: cmdline_path.display().to_string(),
            kexec_loaded_path: kexec_path.display().to_string(),
        };

        let module = KernelCmdlineMonitorModule::new(config, None);
        let result = module.initial_scan().await.unwrap();

        assert_eq!(result.items_scanned, 2);
        assert_eq!(result.issues_found, 0);
        assert!(result.snapshot.contains_key("proc_cmdline"));
        assert!(result.snapshot.contains_key("kexec_loaded"));
    }

    #[tokio::test]
    async fn test_initial_scan_with_suspicious_params() {
        let dir = tempfile::tempdir().unwrap();
        let cmdline_path = dir.path().join("cmdline");
        let kexec_path = dir.path().join("kexec_loaded");

        std::fs::write(&cmdline_path, "BOOT_IMAGE=/vmlinuz selinux=0 debug\n").unwrap();
        std::fs::write(&kexec_path, "1\n").unwrap();

        let config = KernelCmdlineMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            check_kexec_loaded: true,
            suspicious_params: vec!["selinux=0".to_string(), "debug".to_string()],
            proc_cmdline_path: cmdline_path.display().to_string(),
            kexec_loaded_path: kexec_path.display().to_string(),
        };

        let module = KernelCmdlineMonitorModule::new(config, None);
        let result = module.initial_scan().await.unwrap();

        assert_eq!(result.items_scanned, 2);
        // selinux=0 + debug + kexec_loaded=1
        assert_eq!(result.issues_found, 3);
    }

    #[tokio::test]
    async fn test_initial_scan_no_files() {
        let dir = tempfile::tempdir().unwrap();
        let config = KernelCmdlineMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            check_kexec_loaded: true,
            suspicious_params: vec![],
            proc_cmdline_path: dir.path().join("nonexistent").display().to_string(),
            kexec_loaded_path: dir.path().join("nonexistent2").display().to_string(),
        };

        let module = KernelCmdlineMonitorModule::new(config, None);
        let result = module.initial_scan().await.unwrap();

        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
    }

    #[tokio::test]
    async fn test_stop() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(&dir);
        let mut module = KernelCmdlineMonitorModule::new(config, None);
        let token = module.cancel_token();

        module.stop().await.unwrap();
        assert!(token.is_cancelled());
    }
}
