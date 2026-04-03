//! プロセス異常検知モジュール
//!
//! `/proc` ファイルシステムを定期的にスキャンし、不審なプロセスを検知する。
//!
//! 検知対象:
//! - 削除済みバイナリからの実行（`/proc/<pid>/exe` が `(deleted)` を含む）
//! - 不審なパスからの実行（`/tmp`, `/dev/shm` など一時ディレクトリ）
//! - 隠しディレクトリからの実行（パスに `.` で始まるコンポーネントが含まれる）

use crate::config::ProcessMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;

/// プロセスの異常種別
#[derive(Debug, Clone, PartialEq, Eq)]
enum AnomalyKind {
    /// 削除済みバイナリから実行されている
    DeletedBinary,
    /// 不審なパスから実行されている
    SuspiciousPath,
    /// 隠しディレクトリから実行されている
    HiddenDirectory,
}

impl std::fmt::Display for AnomalyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnomalyKind::DeletedBinary => write!(f, "deleted_binary"),
            AnomalyKind::SuspiciousPath => write!(f, "suspicious_path"),
            AnomalyKind::HiddenDirectory => write!(f, "hidden_directory"),
        }
    }
}

/// 検知されたプロセスの異常情報
#[derive(Debug)]
struct ProcessAnomaly {
    pid: u32,
    exe_path: String,
    kind: AnomalyKind,
}

/// プロセス異常検知モジュール
///
/// `/proc` を定期スキャンし、不審なプロセスを検知してログに記録する。
pub struct ProcessMonitorModule {
    config: ProcessMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl ProcessMonitorModule {
    /// 新しいプロセス異常検知モジュールを作成する
    pub fn new(config: ProcessMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// `/proc` からプロセス一覧を取得し、各プロセスの実行パスを返す
    fn scan_processes() -> Vec<(u32, String)> {
        let mut processes = Vec::new();
        let proc_dir = match std::fs::read_dir("/proc") {
            Ok(dir) => dir,
            Err(e) => {
                tracing::warn!(error = %e, "/proc の読み取りに失敗しました");
                return processes;
            }
        };

        for entry in proc_dir {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // PID（数字のみ）のディレクトリをフィルタ
            let pid: u32 = match name_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            // /proc/<pid>/exe の readlink で実行パスを取得
            let exe_link = PathBuf::from(format!("/proc/{pid}/exe"));
            match std::fs::read_link(&exe_link) {
                Ok(exe_path) => {
                    processes.push((pid, exe_path.to_string_lossy().into_owned()));
                }
                Err(_) => {
                    // 権限不足やプロセス終了により読めない場合はスキップ
                    continue;
                }
            }
        }

        processes
    }

    /// プロセスの異常を検査する
    fn check_anomalies(
        processes: &[(u32, String)],
        suspicious_paths: &[PathBuf],
    ) -> Vec<ProcessAnomaly> {
        let mut anomalies = Vec::new();

        for (pid, exe_path) in processes {
            // 1. 削除済みバイナリの検知
            if exe_path.contains(" (deleted)") {
                anomalies.push(ProcessAnomaly {
                    pid: *pid,
                    exe_path: exe_path.clone(),
                    kind: AnomalyKind::DeletedBinary,
                });
                continue;
            }

            let path = Path::new(exe_path);

            // 2. 不審なパスからの実行検知
            if is_under_suspicious_path(path, suspicious_paths) {
                anomalies.push(ProcessAnomaly {
                    pid: *pid,
                    exe_path: exe_path.clone(),
                    kind: AnomalyKind::SuspiciousPath,
                });
                continue;
            }

            // 3. 隠しディレクトリからの実行検知
            if is_in_hidden_directory(path) {
                anomalies.push(ProcessAnomaly {
                    pid: *pid,
                    exe_path: exe_path.clone(),
                    kind: AnomalyKind::HiddenDirectory,
                });
            }
        }

        anomalies
    }
}

/// パスが不審なディレクトリ配下にあるかを判定する
fn is_under_suspicious_path(exe_path: &Path, suspicious_paths: &[PathBuf]) -> bool {
    suspicious_paths
        .iter()
        .any(|suspicious| exe_path.starts_with(suspicious))
}

/// パスに隠しディレクトリ（`.` で始まるコンポーネント）が含まれるかを判定する
fn is_in_hidden_directory(exe_path: &Path) -> bool {
    exe_path.components().any(|component| {
        if let std::path::Component::Normal(name) = component {
            name.to_string_lossy().starts_with('.')
        } else {
            false
        }
    })
}

impl Module for ProcessMonitorModule {
    fn name(&self) -> &str {
        "process_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            suspicious_paths = ?self.config.suspicious_paths,
            "プロセス異常検知モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<(), AppError> {
        // 初回スキャンで動作確認
        let processes = Self::scan_processes();
        tracing::info!(
            process_count = processes.len(),
            "初回プロセススキャンが完了しました"
        );

        let suspicious_paths = self.config.suspicious_paths.clone();
        let scan_interval_secs = self.config.scan_interval_secs;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        // 既知の PID を記録し、同じ PID の同じ異常を繰り返し警告しない
        let mut known_anomalies: HashSet<(u32, String)> = HashSet::new();

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            // 最初の tick は即座に発火するのでスキップ
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("プロセス異常検知モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let processes = ProcessMonitorModule::scan_processes();
                        let anomalies = ProcessMonitorModule::check_anomalies(&processes, &suspicious_paths);

                        // 現在の PID セットを構築（終了済みプロセスを known から除去）
                        let current_pids: HashSet<u32> = processes.iter().map(|(pid, _)| *pid).collect();
                        known_anomalies.retain(|(pid, _)| current_pids.contains(pid));

                        for anomaly in &anomalies {
                            let key = (anomaly.pid, anomaly.kind.to_string());
                            if known_anomalies.insert(key) {
                                tracing::warn!(
                                    pid = anomaly.pid,
                                    exe_path = %anomaly.exe_path,
                                    anomaly_kind = %anomaly.kind,
                                    "不審なプロセスを検知しました"
                                );
                                if let Some(ref bus) = event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            "process_anomaly",
                                            Severity::Warning,
                                            "process_monitor",
                                            format!(
                                                "不審なプロセスを検知しました: PID={}, パス={}, 種別={}",
                                                anomaly.pid, anomaly.exe_path, anomaly.kind
                                            ),
                                        )
                                        .with_details(format!(
                                            "pid={}, exe_path={}, anomaly_kind={}",
                                            anomaly.pid, anomaly.exe_path, anomaly.kind
                                        )),
                                    );
                                }
                            }
                        }

                        if anomalies.is_empty() {
                            tracing::debug!("不審なプロセスは検知されませんでした");
                        }
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

        let processes = Self::scan_processes();
        let items_scanned = processes.len();

        let anomalies = Self::check_anomalies(&processes, &self.config.suspicious_paths);
        let issues_found = anomalies.len();

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "プロセス {}件をスキャンしました（不審なプロセス: {}件）",
                items_scanned, issues_found
            ),
            snapshot: BTreeMap::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_under_suspicious_path() {
        let suspicious = vec![
            PathBuf::from("/tmp"),
            PathBuf::from("/dev/shm"),
            PathBuf::from("/var/tmp"),
        ];

        assert!(is_under_suspicious_path(
            Path::new("/tmp/malware"),
            &suspicious
        ));
        assert!(is_under_suspicious_path(
            Path::new("/dev/shm/payload"),
            &suspicious
        ));
        assert!(is_under_suspicious_path(
            Path::new("/var/tmp/backdoor"),
            &suspicious
        ));
        assert!(!is_under_suspicious_path(
            Path::new("/usr/bin/bash"),
            &suspicious
        ));
        assert!(!is_under_suspicious_path(
            Path::new("/home/user/app"),
            &suspicious
        ));
    }

    #[test]
    fn test_is_under_suspicious_path_empty() {
        let suspicious: Vec<PathBuf> = vec![];
        assert!(!is_under_suspicious_path(
            Path::new("/tmp/something"),
            &suspicious
        ));
    }

    #[test]
    fn test_is_in_hidden_directory() {
        assert!(is_in_hidden_directory(Path::new(
            "/home/user/.hidden/malware"
        )));
        assert!(is_in_hidden_directory(Path::new("/opt/.secret/bin/app")));
        assert!(is_in_hidden_directory(Path::new(
            "/tmp/.X11-unix/something"
        )));
        assert!(!is_in_hidden_directory(Path::new("/usr/bin/bash")));
        assert!(!is_in_hidden_directory(Path::new("/home/user/normal/app")));
    }

    #[test]
    fn test_is_in_hidden_directory_root() {
        assert!(!is_in_hidden_directory(Path::new("/usr/bin/ls")));
        assert!(!is_in_hidden_directory(Path::new("/")));
    }

    #[test]
    fn test_check_anomalies_deleted_binary() {
        let processes = vec![(1234, "/usr/bin/test (deleted)".to_string())];
        let suspicious = vec![PathBuf::from("/tmp")];

        let anomalies = ProcessMonitorModule::check_anomalies(&processes, &suspicious);
        assert_eq!(anomalies.len(), 1);
        assert_eq!(anomalies[0].pid, 1234);
        assert_eq!(anomalies[0].kind, AnomalyKind::DeletedBinary);
    }

    #[test]
    fn test_check_anomalies_suspicious_path() {
        let processes = vec![(5678, "/tmp/backdoor".to_string())];
        let suspicious = vec![PathBuf::from("/tmp")];

        let anomalies = ProcessMonitorModule::check_anomalies(&processes, &suspicious);
        assert_eq!(anomalies.len(), 1);
        assert_eq!(anomalies[0].pid, 5678);
        assert_eq!(anomalies[0].kind, AnomalyKind::SuspiciousPath);
    }

    #[test]
    fn test_check_anomalies_hidden_directory() {
        let processes = vec![(9012, "/home/user/.hidden/malware".to_string())];
        let suspicious: Vec<PathBuf> = vec![];

        let anomalies = ProcessMonitorModule::check_anomalies(&processes, &suspicious);
        assert_eq!(anomalies.len(), 1);
        assert_eq!(anomalies[0].pid, 9012);
        assert_eq!(anomalies[0].kind, AnomalyKind::HiddenDirectory);
    }

    #[test]
    fn test_check_anomalies_no_anomaly() {
        let processes = vec![
            (1, "/usr/bin/bash".to_string()),
            (2, "/usr/sbin/sshd".to_string()),
        ];
        let suspicious = vec![PathBuf::from("/tmp")];

        let anomalies = ProcessMonitorModule::check_anomalies(&processes, &suspicious);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn test_check_anomalies_priority_deleted_over_suspicious() {
        // 削除済みかつ不審パスの場合、削除済みが優先される（continue で次へ）
        let processes = vec![(1234, "/tmp/malware (deleted)".to_string())];
        let suspicious = vec![PathBuf::from("/tmp")];

        let anomalies = ProcessMonitorModule::check_anomalies(&processes, &suspicious);
        assert_eq!(anomalies.len(), 1);
        assert_eq!(anomalies[0].kind, AnomalyKind::DeletedBinary);
    }

    #[test]
    fn test_check_anomalies_multiple() {
        let processes = vec![
            (1, "/usr/bin/bash".to_string()),
            (2, "/tmp/miner".to_string()),
            (3, "/usr/bin/old (deleted)".to_string()),
            (4, "/home/user/.hidden/shell".to_string()),
        ];
        let suspicious = vec![PathBuf::from("/tmp"), PathBuf::from("/dev/shm")];

        let anomalies = ProcessMonitorModule::check_anomalies(&processes, &suspicious);
        assert_eq!(anomalies.len(), 3);
    }

    #[test]
    fn test_scan_processes_returns_results() {
        // 実環境でのテスト: /proc が存在する Linux 上で実行
        let processes = ProcessMonitorModule::scan_processes();
        // 少なくとも自プロセスは見えるはず
        assert!(!processes.is_empty());
    }

    #[test]
    fn test_init_zero_interval() {
        let config = ProcessMonitorConfig {
            enabled: true,
            scan_interval_secs: 0,
            suspicious_paths: vec![],
        };
        let mut module = ProcessMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_init_valid_config() {
        let config = ProcessMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            suspicious_paths: vec![PathBuf::from("/tmp")],
        };
        let mut module = ProcessMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let config = ProcessMonitorConfig {
            enabled: true,
            scan_interval_secs: 3600,
            suspicious_paths: vec![PathBuf::from("/tmp")],
        };
        let mut module = ProcessMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[test]
    fn test_anomaly_kind_display() {
        assert_eq!(AnomalyKind::DeletedBinary.to_string(), "deleted_binary");
        assert_eq!(AnomalyKind::SuspiciousPath.to_string(), "suspicious_path");
        assert_eq!(AnomalyKind::HiddenDirectory.to_string(), "hidden_directory");
    }

    #[test]
    fn test_init_with_event_bus_none() {
        let config = ProcessMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            suspicious_paths: vec![PathBuf::from("/tmp")],
        };
        let mut module = ProcessMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[test]
    fn test_init_with_event_bus_some() {
        let config = ProcessMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            suspicious_paths: vec![PathBuf::from("/tmp")],
        };
        let bus = EventBus::new(16);
        let mut module = ProcessMonitorModule::new(config, Some(bus));
        assert!(module.init().is_ok());
    }

    #[tokio::test]
    async fn test_initial_scan_returns_processes() {
        let config = ProcessMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            suspicious_paths: vec![PathBuf::from("/tmp"), PathBuf::from("/dev/shm")],
        };
        let module = ProcessMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert!(result.items_scanned > 0);
        assert!(result.summary.contains("プロセス"));
        assert!(result.summary.contains("不審なプロセス"));
    }
}
