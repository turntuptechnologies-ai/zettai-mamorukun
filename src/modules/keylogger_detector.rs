//! キーロガー検知モジュール
//!
//! `/dev/input/` デバイスファイルへの不審なアクセスを監視し、キーロガーの兆候を検知する。
//!
//! 検知ロジック:
//! - `/proc/[pid]/fd/` のシンボリックリンク先が `/dev/input/event*` であるプロセスを検出
//! - ホワイトリスト（正規プロセス）と照合し、不審なプロセスを報告

use crate::config::KeyloggerDetectorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::BTreeMap;
use tokio_util::sync::CancellationToken;

/// input デバイスにアクセスしている不審プロセスの情報
#[derive(Debug, Clone)]
struct SuspectProcess {
    /// プロセス ID
    pid: u32,
    /// プロセス名
    comm: String,
    /// アクセス先デバイスパス
    device_path: String,
}

/// `/proc/` を走査して `/dev/input/event*` にアクセスしているプロセスを検出する
fn scan_input_device_access(allowed_processes: &[String]) -> Vec<SuspectProcess> {
    let mut suspects = Vec::new();
    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return suspects,
    };

    for entry in proc_dir.flatten() {
        let pid_str = entry.file_name();
        let pid_str = pid_str.to_string_lossy();
        let pid: u32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let fd_dir = format!("/proc/{}/fd", pid);
        let fds = match std::fs::read_dir(&fd_dir) {
            Ok(d) => d,
            Err(_) => continue,
        };

        for fd_entry in fds.flatten() {
            let link_target = match std::fs::read_link(fd_entry.path()) {
                Ok(t) => t,
                Err(_) => continue,
            };

            let target_str = link_target.to_string_lossy().to_string();
            if !target_str.starts_with("/dev/input/event") {
                continue;
            }

            let comm_path = format!("/proc/{}/comm", pid);
            let comm = std::fs::read_to_string(&comm_path)
                .unwrap_or_default()
                .trim()
                .to_string();

            if comm.is_empty() {
                continue;
            }

            let is_allowed = allowed_processes.contains(&comm);

            if !is_allowed {
                suspects.push(SuspectProcess {
                    pid,
                    comm,
                    device_path: target_str,
                });
                break;
            }
        }
    }

    suspects
}

/// キーロガー検知モジュール
///
/// `/dev/input/` デバイスファイルへの不審なアクセスを定期的にスキャンし、
/// キーロガーの兆候を検知する。
pub struct KeyloggerDetectorModule {
    config: KeyloggerDetectorConfig,
    event_bus: Option<EventBus>,
    cancel_token: CancellationToken,
}

impl KeyloggerDetectorModule {
    /// 新しいキーロガー検知モジュールを作成する
    pub fn new(config: KeyloggerDetectorConfig, event_bus: Option<EventBus>) -> Self {
        Self {
            config,
            event_bus,
            cancel_token: CancellationToken::new(),
        }
    }

    /// キャンセルトークンのクローンを返す
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }
}

impl Module for KeyloggerDetectorModule {
    fn name(&self) -> &str {
        "keylogger_detector"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            allowed_count = self.config.allowed_processes.len(),
            "キーロガー検知モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<(), AppError> {
        let scan_interval_secs = self.config.scan_interval_secs;
        let allowed_processes = self.config.allowed_processes.clone();
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("キーロガー検知モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let suspects = scan_input_device_access(&allowed_processes);

                        if suspects.is_empty() {
                            tracing::debug!("キーロガーの兆候は検知されませんでした");
                        } else {
                            for suspect in &suspects {
                                tracing::warn!(
                                    pid = suspect.pid,
                                    comm = %suspect.comm,
                                    device = %suspect.device_path,
                                    "キーロガーの兆候を検知しました"
                                );
                                if let Some(ref bus) = event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            "keylogger_suspect_detected",
                                            Severity::Critical,
                                            "keylogger_detector",
                                            format!(
                                                "不審なプロセスが input デバイスにアクセスしています: {} (PID: {})",
                                                suspect.comm, suspect.pid
                                            ),
                                        )
                                        .with_details(format!(
                                            "pid={} comm={} device={}",
                                            suspect.pid, suspect.comm, suspect.device_path
                                        )),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        });

        Ok(())
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();

        let suspects = scan_input_device_access(&self.config.allowed_processes);

        let mut snapshot = BTreeMap::new();
        let proc_dir = std::fs::read_dir("/proc").ok();
        let mut total_procs = 0usize;

        if let Some(dir) = proc_dir {
            for entry in dir.flatten() {
                let name = entry.file_name();
                if name.to_string_lossy().parse::<u32>().is_ok() {
                    total_procs += 1;
                }
            }
        }

        for suspect in &suspects {
            snapshot.insert(
                format!("{}:{}", suspect.pid, suspect.comm),
                suspect.device_path.clone(),
            );
        }

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned: total_procs,
            issues_found: suspects.len(),
            duration,
            summary: format!(
                "{}個のプロセスをスキャンし、input デバイスへの不審なアクセス {}件を検知しました",
                total_procs,
                suspects.len()
            ),
            snapshot,
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

    fn default_config() -> KeyloggerDetectorConfig {
        KeyloggerDetectorConfig {
            enabled: true,
            scan_interval_secs: 30,
            allowed_processes: vec![
                "Xorg".to_string(),
                "gnome-shell".to_string(),
                "systemd-logind".to_string(),
            ],
        }
    }

    #[test]
    fn test_init_valid_config() {
        let config = default_config();
        let mut module = KeyloggerDetectorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[test]
    fn test_init_zero_interval() {
        let mut config = default_config();
        config.scan_interval_secs = 0;
        let mut module = KeyloggerDetectorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_module_name() {
        let config = default_config();
        let module = KeyloggerDetectorModule::new(config, None);
        assert_eq!(module.name(), "keylogger_detector");
    }

    #[test]
    fn test_cancel_token() {
        let config = default_config();
        let module = KeyloggerDetectorModule::new(config, None);
        let token = module.cancel_token();
        assert!(!token.is_cancelled());
    }

    #[test]
    fn test_scan_input_device_access_with_allowlist() {
        let allowed = vec!["Xorg".to_string(), "gnome-shell".to_string()];
        let suspects = scan_input_device_access(&allowed);
        // CI 環境では /dev/input/event* にアクセスするプロセスは通常いないため、
        // パニックしないことを確認
        assert!(suspects.len() < 1000);
    }

    #[test]
    fn test_scan_input_device_access_empty_allowlist() {
        let suspects = scan_input_device_access(&[]);
        assert!(suspects.len() < 1000);
    }

    #[test]
    fn test_suspect_process_fields() {
        let suspect = SuspectProcess {
            pid: 1234,
            comm: "evil_keylogger".to_string(),
            device_path: "/dev/input/event0".to_string(),
        };
        assert_eq!(suspect.pid, 1234);
        assert_eq!(suspect.comm, "evil_keylogger");
        assert_eq!(suspect.device_path, "/dev/input/event0");
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let config = default_config();
        let module = KeyloggerDetectorModule::new(config, None);
        let result = module.initial_scan().await;
        assert!(result.is_ok());
        let scan = result.unwrap();
        assert!(scan.items_scanned > 0 || scan.items_scanned == 0);
        assert!(!scan.summary.is_empty());
    }

    #[tokio::test]
    async fn test_stop() {
        let config = default_config();
        let mut module = KeyloggerDetectorModule::new(config, None);
        let token = module.cancel_token();
        assert!(!token.is_cancelled());
        module.stop().await.unwrap();
        assert!(token.is_cancelled());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let config = default_config();
        let mut module = KeyloggerDetectorModule::new(config, None);
        module.init().unwrap();
        module.start().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        module.stop().await.unwrap();
    }

    #[test]
    fn test_default_config() {
        let config = KeyloggerDetectorConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.scan_interval_secs, 30);
        assert!(!config.allowed_processes.is_empty());
    }
}
