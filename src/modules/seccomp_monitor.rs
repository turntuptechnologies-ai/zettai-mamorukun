//! seccomp プロファイル監視モジュール
//!
//! `/proc/*/status` の Seccomp フィールドを定期スキャンし、
//! セキュリティクリティカルなプロセスの seccomp フィルタが無効化されていないかを検知する。
//!
//! 検知対象:
//! - 監視対象プロセスの seccomp が無効（モード 0）
//! - 監視対象プロセスの seccomp モードが変更された
//! - 起動時スキャンで seccomp 無効を検出

use crate::config::SeccompMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::BTreeMap;
use std::path::Path;
use tokio_util::sync::CancellationToken;

/// seccomp モードの文字列表現を返す
fn seccomp_mode_label(mode: u8) -> &'static str {
    match mode {
        0 => "DISABLED",
        1 => "STRICT",
        2 => "FILTER",
        _ => "UNKNOWN",
    }
}

/// `/proc/{pid}/status` からプロセス名と Seccomp モードをパースする
fn parse_proc_status(content: &str) -> Option<(String, u8)> {
    let mut name = None;
    let mut seccomp = None;

    for line in content.lines() {
        if let Some(val) = line.strip_prefix("Name:\t") {
            name = Some(val.trim().to_string());
        } else if let Some(val) = line.strip_prefix("Seccomp:\t") {
            seccomp = val.trim().parse::<u8>().ok();
        }
    }

    match (name, seccomp) {
        (Some(n), Some(s)) => Some((n, s)),
        _ => None,
    }
}

/// プロセスの seccomp 情報
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessSeccompInfo {
    /// プロセス ID
    pid: u32,
    /// プロセス名
    name: String,
    /// seccomp モード（0=無効, 1=厳格, 2=フィルタ）
    seccomp_mode: u8,
}

/// seccomp のスナップショット（プロセス名 → 各インスタンスの情報）
struct SeccompSnapshot {
    /// プロセス名ごとの情報リスト（同名プロセス複数対応）
    processes: BTreeMap<String, Vec<ProcessSeccompInfo>>,
}

/// seccomp プロファイル監視モジュール
///
/// `/proc/*/status` を定期スキャンし、監視対象プロセスの seccomp モードを監視する。
pub struct SeccompMonitorModule {
    config: SeccompMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl SeccompMonitorModule {
    /// 新しい seccomp 監視モジュールを作成する
    pub fn new(config: SeccompMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// /proc を走査して監視対象プロセスの seccomp スナップショットを取得する
    fn scan_proc(proc_path: &Path, watched_processes: &[String]) -> SeccompSnapshot {
        let mut processes: BTreeMap<String, Vec<ProcessSeccompInfo>> = BTreeMap::new();

        let entries = match std::fs::read_dir(proc_path) {
            Ok(entries) => entries,
            Err(err) => {
                tracing::debug!(error = %err, "proc ディレクトリの読み取りに失敗しました");
                return SeccompSnapshot { processes };
            }
        };

        for entry in entries.filter_map(|e| e.ok()) {
            let file_name = entry.file_name();
            let pid_str = file_name.to_string_lossy();

            // 数値ディレクトリ（PID）のみ処理
            let pid: u32 = match pid_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            let status_path = proc_path.join(pid_str.to_string()).join("status");
            let content = match std::fs::read_to_string(&status_path) {
                Ok(c) => c,
                Err(_) => continue, // プロセスが終了した可能性
            };

            let (name, seccomp_mode) = match parse_proc_status(&content) {
                Some(parsed) => parsed,
                None => continue,
            };

            // 監視対象プロセスのみ記録
            if watched_processes.iter().any(|w| w == &name) {
                processes
                    .entry(name.clone())
                    .or_default()
                    .push(ProcessSeccompInfo {
                        pid,
                        name,
                        seccomp_mode,
                    });
            }
        }

        SeccompSnapshot { processes }
    }

    /// ベースラインと現在のスナップショットを比較し、変更を検知してイベント発行する
    fn detect_and_report(
        baseline: &SeccompSnapshot,
        current: &SeccompSnapshot,
        event_bus: &Option<EventBus>,
    ) -> bool {
        let mut has_changes = false;

        for (proc_name, current_infos) in &current.processes {
            let baseline_infos = baseline.processes.get(proc_name);

            for info in current_infos {
                // ベースラインでの同名プロセスの代表的なモードを取得
                let baseline_mode =
                    baseline_infos.and_then(|infos| infos.first().map(|i| i.seccomp_mode));

                match baseline_mode {
                    Some(old_mode) if old_mode != info.seccomp_mode => {
                        // seccomp モードが変更された
                        let severity = if info.seccomp_mode == 0 {
                            Severity::Critical
                        } else {
                            Severity::Warning
                        };
                        let details = format!(
                            "PID={}, プロセス={}, 旧モード={}({}), 新モード={}({})",
                            info.pid,
                            info.name,
                            old_mode,
                            seccomp_mode_label(old_mode),
                            info.seccomp_mode,
                            seccomp_mode_label(info.seccomp_mode)
                        );
                        tracing::warn!(
                            pid = info.pid,
                            process = %info.name,
                            old_mode = old_mode,
                            new_mode = info.seccomp_mode,
                            "seccomp モードが変更されました"
                        );
                        if let Some(bus) = event_bus {
                            bus.publish(
                                SecurityEvent::new(
                                    "seccomp_mode_changed",
                                    severity,
                                    "seccomp_monitor",
                                    "seccomp モードが変更されました",
                                )
                                .with_details(details),
                            );
                        }
                        has_changes = true;
                    }
                    None => {
                        // 新たに出現した監視対象プロセス
                        if info.seccomp_mode == 0 {
                            let details = format!(
                                "PID={}, プロセス={}, モード=0(DISABLED)",
                                info.pid, info.name
                            );
                            tracing::warn!(
                                pid = info.pid,
                                process = %info.name,
                                "監視対象プロセスの seccomp が無効です"
                            );
                            if let Some(bus) = event_bus {
                                bus.publish(
                                    SecurityEvent::new(
                                        "seccomp_disabled",
                                        Severity::Critical,
                                        "seccomp_monitor",
                                        "監視対象プロセスの seccomp が無効です",
                                    )
                                    .with_details(details),
                                );
                            }
                            has_changes = true;
                        }
                    }
                    _ => {
                        // モード変更なし
                    }
                }
            }
        }

        has_changes
    }
}

impl Module for SeccompMonitorModule {
    fn name(&self) -> &str {
        "seccomp_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        if self.config.watched_processes.is_empty() {
            return Err(AppError::ModuleConfig {
                message: "watched_processes に少なくとも 1 つのプロセス名を指定してください"
                    .to_string(),
            });
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            watched_processes_count = self.config.watched_processes.len(),
            "seccomp 監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<(), AppError> {
        let baseline = Self::scan_proc(Path::new("/proc"), &self.config.watched_processes);
        tracing::info!(
            process_count = baseline.processes.values().map(|v| v.len()).sum::<usize>(),
            "seccomp ベースラインスキャンが完了しました"
        );

        let watched_processes = self.config.watched_processes.clone();
        let scan_interval_secs = self.config.scan_interval_secs;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            interval.tick().await;

            let mut baseline = baseline;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("seccomp 監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = SeccompMonitorModule::scan_proc(
                            Path::new("/proc"),
                            &watched_processes,
                        );
                        let changed = SeccompMonitorModule::detect_and_report(
                            &baseline, &current, &event_bus,
                        );

                        if changed {
                            baseline = current;
                        } else {
                            tracing::debug!("seccomp モードに変更はありません");
                        }
                    }
                }
            }
        });

        Ok(())
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();
        let snapshot = Self::scan_proc(Path::new("/proc"), &self.config.watched_processes);

        let items_scanned: usize = snapshot.processes.values().map(|v| v.len()).sum();
        let mut issues_found = 0;

        // seccomp が無効なプロセスを警告
        for infos in snapshot.processes.values() {
            for info in infos {
                if info.seccomp_mode == 0 {
                    tracing::warn!(
                        pid = info.pid,
                        process = %info.name,
                        seccomp_mode = info.seccomp_mode,
                        "起動時スキャン: 監視対象プロセスの seccomp が無効です"
                    );
                    if let Some(bus) = &self.event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "seccomp_startup_warning",
                                Severity::Warning,
                                "seccomp_monitor",
                                "起動時スキャン: 監視対象プロセスの seccomp が無効です",
                            )
                            .with_details(format!(
                                "PID={}, プロセス={}, モード=0(DISABLED)",
                                info.pid, info.name
                            )),
                        );
                    }
                    issues_found += 1;
                }
            }
        }

        let scan_snapshot: BTreeMap<String, String> = snapshot
            .processes
            .iter()
            .flat_map(|(_, infos)| {
                infos.iter().map(|info| {
                    (
                        format!("{}:{}", info.name, info.pid),
                        format!(
                            "seccomp_mode={}({})",
                            info.seccomp_mode,
                            seccomp_mode_label(info.seccomp_mode)
                        ),
                    )
                })
            })
            .collect();
        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "監視対象プロセス {}件をスキャン（うち{}件が seccomp 無効）",
                items_scanned, issues_found
            ),
            snapshot: scan_snapshot,
        })
    }

    async fn stop(&mut self) -> Result<(), AppError> {
        self.cancel_token.cancel();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seccomp_mode_label() {
        assert_eq!(seccomp_mode_label(0), "DISABLED");
        assert_eq!(seccomp_mode_label(1), "STRICT");
        assert_eq!(seccomp_mode_label(2), "FILTER");
        assert_eq!(seccomp_mode_label(3), "UNKNOWN");
        assert_eq!(seccomp_mode_label(255), "UNKNOWN");
    }

    #[test]
    fn test_parse_proc_status_valid() {
        let content = "Name:\tsshd\nUmask:\t0022\nState:\tS (sleeping)\n\
                        Tgid:\t1234\nPid:\t1234\nSeccomp:\t2\n\
                        CapEff:\t000001ffffffffff\n";
        let result = parse_proc_status(content);
        assert!(result.is_some());
        let (name, mode) = result.unwrap();
        assert_eq!(name, "sshd");
        assert_eq!(mode, 2);
    }

    #[test]
    fn test_parse_proc_status_disabled() {
        let content = "Name:\tnginx\nPid:\t5678\nSeccomp:\t0\n";
        let result = parse_proc_status(content);
        assert!(result.is_some());
        let (name, mode) = result.unwrap();
        assert_eq!(name, "nginx");
        assert_eq!(mode, 0);
    }

    #[test]
    fn test_parse_proc_status_missing_seccomp() {
        let content = "Name:\tsshd\nPid:\t1234\n";
        assert!(parse_proc_status(content).is_none());
    }

    #[test]
    fn test_parse_proc_status_empty() {
        assert!(parse_proc_status("").is_none());
    }

    #[test]
    fn test_parse_proc_status_strict_mode() {
        let content = "Name:\tsandbox\nSeccomp:\t1\n";
        let result = parse_proc_status(content);
        assert!(result.is_some());
        let (name, mode) = result.unwrap();
        assert_eq!(name, "sandbox");
        assert_eq!(mode, 1);
    }

    #[test]
    fn test_detect_no_changes() {
        let mut processes = BTreeMap::new();
        processes.insert(
            "sshd".to_string(),
            vec![ProcessSeccompInfo {
                pid: 100,
                name: "sshd".to_string(),
                seccomp_mode: 2,
            }],
        );
        let baseline = SeccompSnapshot {
            processes: processes.clone(),
        };
        let current = SeccompSnapshot { processes };

        assert!(!SeccompMonitorModule::detect_and_report(
            &baseline, &current, &None,
        ));
    }

    #[test]
    fn test_detect_mode_changed() {
        let mut baseline_procs = BTreeMap::new();
        baseline_procs.insert(
            "sshd".to_string(),
            vec![ProcessSeccompInfo {
                pid: 100,
                name: "sshd".to_string(),
                seccomp_mode: 2,
            }],
        );
        let baseline = SeccompSnapshot {
            processes: baseline_procs,
        };

        let mut current_procs = BTreeMap::new();
        current_procs.insert(
            "sshd".to_string(),
            vec![ProcessSeccompInfo {
                pid: 100,
                name: "sshd".to_string(),
                seccomp_mode: 0, // FILTER → DISABLED
            }],
        );
        let current = SeccompSnapshot {
            processes: current_procs,
        };

        assert!(SeccompMonitorModule::detect_and_report(
            &baseline, &current, &None,
        ));
    }

    #[test]
    fn test_detect_new_process_disabled() {
        let baseline = SeccompSnapshot {
            processes: BTreeMap::new(),
        };

        let mut current_procs = BTreeMap::new();
        current_procs.insert(
            "nginx".to_string(),
            vec![ProcessSeccompInfo {
                pid: 200,
                name: "nginx".to_string(),
                seccomp_mode: 0,
            }],
        );
        let current = SeccompSnapshot {
            processes: current_procs,
        };

        assert!(SeccompMonitorModule::detect_and_report(
            &baseline, &current, &None,
        ));
    }

    #[test]
    fn test_detect_new_process_enabled() {
        let baseline = SeccompSnapshot {
            processes: BTreeMap::new(),
        };

        let mut current_procs = BTreeMap::new();
        current_procs.insert(
            "nginx".to_string(),
            vec![ProcessSeccompInfo {
                pid: 200,
                name: "nginx".to_string(),
                seccomp_mode: 2, // 新規だが FILTER 有効なので問題なし
            }],
        );
        let current = SeccompSnapshot {
            processes: current_procs,
        };

        assert!(!SeccompMonitorModule::detect_and_report(
            &baseline, &current, &None,
        ));
    }

    #[test]
    fn test_scan_proc_nonexistent_dir() {
        let snapshot = SeccompMonitorModule::scan_proc(
            Path::new("/nonexistent_proc_dir"),
            &["sshd".to_string()],
        );
        assert!(snapshot.processes.is_empty());
    }

    #[test]
    fn test_scan_proc_empty_watched() {
        let snapshot = SeccompMonitorModule::scan_proc(Path::new("/proc"), &[]);
        assert!(snapshot.processes.is_empty());
    }

    #[test]
    fn test_init_zero_interval() {
        let config = SeccompMonitorConfig {
            enabled: true,
            scan_interval_secs: 0,
            watched_processes: vec!["sshd".to_string()],
        };
        let mut module = SeccompMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_empty_watched_processes() {
        let config = SeccompMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            watched_processes: vec![],
        };
        let mut module = SeccompMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let config = SeccompMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            watched_processes: vec!["sshd".to_string(), "nginx".to_string()],
        };
        let mut module = SeccompMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let config = SeccompMonitorConfig {
            enabled: true,
            scan_interval_secs: 3600,
            watched_processes: vec!["sshd".to_string()],
        };
        let mut module = SeccompMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let config = SeccompMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            watched_processes: vec!["nonexistent_process_xyz".to_string()],
        };
        let module = SeccompMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        // 存在しないプロセスなので 0 件
        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
        assert!(result.summary.contains("件"));
    }

    #[test]
    fn test_multiple_instances_same_process() {
        let mut baseline_procs = BTreeMap::new();
        baseline_procs.insert(
            "nginx".to_string(),
            vec![
                ProcessSeccompInfo {
                    pid: 100,
                    name: "nginx".to_string(),
                    seccomp_mode: 2,
                },
                ProcessSeccompInfo {
                    pid: 101,
                    name: "nginx".to_string(),
                    seccomp_mode: 2,
                },
            ],
        );
        let baseline = SeccompSnapshot {
            processes: baseline_procs,
        };

        let mut current_procs = BTreeMap::new();
        current_procs.insert(
            "nginx".to_string(),
            vec![
                ProcessSeccompInfo {
                    pid: 100,
                    name: "nginx".to_string(),
                    seccomp_mode: 2,
                },
                ProcessSeccompInfo {
                    pid: 101,
                    name: "nginx".to_string(),
                    seccomp_mode: 2,
                },
            ],
        );
        let current = SeccompSnapshot {
            processes: current_procs,
        };

        assert!(!SeccompMonitorModule::detect_and_report(
            &baseline, &current, &None,
        ));
    }
}
