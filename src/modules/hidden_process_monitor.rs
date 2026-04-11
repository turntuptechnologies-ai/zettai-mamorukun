//! プロセス隠蔽検知モジュール
//!
//! `/proc/` ディレクトリの readdir 列挙と PID ブルートフォーススキャンの差分を比較し、
//! ルートキットによるプロセス隠蔽を検知する。
//!
//! 検知手法:
//! 1. `/proc/` の readdir で数値 PID エントリを一覧取得
//! 2. PID 1 ～ pid_max を順にスキャンし `/proc/<pid>/stat` に直接アクセス
//! 3. ブルートフォーススキャンで見つかったが readdir に存在しない PID を隠蔽プロセスとして検出
//! 4. false positive 対策として検知時に複数回の再確認を実施

use crate::config::HiddenProcessMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::{BTreeMap, HashSet};
use tokio_util::sync::CancellationToken;

/// 隠蔽プロセスの検知結果
#[derive(Debug, Clone)]
struct HiddenProcess {
    /// 隠蔽されたプロセスの PID
    pid: u32,
    /// プロセスのコマンドライン（取得できた場合）
    cmdline: String,
    /// プロセスのステータス情報（取得できた場合）
    status_info: String,
}

/// プロセス隠蔽検知モジュール
///
/// `/proc/` の readdir 列挙と PID ブルートフォーススキャンの差分で
/// ルートキットによるプロセス隠蔽を検知する。
pub struct HiddenProcessMonitorModule {
    config: HiddenProcessMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl HiddenProcessMonitorModule {
    /// 新しいプロセス隠蔽検知モジュールを作成する
    pub fn new(config: HiddenProcessMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// `/proc/sys/kernel/pid_max` から最大 PID を取得する
    fn get_pid_max() -> u32 {
        std::fs::read_to_string("/proc/sys/kernel/pid_max")
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .unwrap_or(32768)
    }

    /// `/proc/` の readdir で PID 一覧を取得する
    fn list_pids_readdir() -> HashSet<u32> {
        let entries = match std::fs::read_dir("/proc") {
            Ok(entries) => entries,
            Err(_) => return HashSet::new(),
        };

        entries
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let name = entry.file_name();
                let name_str = name.to_str()?;
                name_str.parse::<u32>().ok()
            })
            .collect()
    }

    /// `/proc/<pid>/stat` に直接アクセスして PID が存在するか確認する
    fn pid_exists_direct(pid: u32) -> bool {
        let stat_path = format!("/proc/{pid}/stat");
        std::fs::metadata(&stat_path).is_ok()
    }

    /// `/proc/<pid>/cmdline` からコマンドラインを取得する
    fn get_cmdline(pid: u32) -> String {
        let path = format!("/proc/{pid}/cmdline");
        std::fs::read(&path)
            .ok()
            .map(|bytes| {
                bytes
                    .split(|&b| b == 0)
                    .filter_map(|s| std::str::from_utf8(s).ok())
                    .collect::<Vec<&str>>()
                    .join(" ")
            })
            .unwrap_or_default()
    }

    /// `/proc/<pid>/status` から Name と Uid を取得する
    fn get_status_info(pid: u32) -> String {
        let path = format!("/proc/{pid}/status");
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return String::new(),
        };

        let mut name = String::new();
        let mut uid = String::new();

        for line in content.lines() {
            if let Some(val) = line.strip_prefix("Name:") {
                name = val.trim().to_string();
            } else if let Some(val) = line.strip_prefix("Uid:") {
                uid = val.trim().to_string();
            }
            if !name.is_empty() && !uid.is_empty() {
                break;
            }
        }

        if name.is_empty() {
            String::new()
        } else {
            format!("name={name}, uid={uid}")
        }
    }

    /// PID ブルートフォーススキャンで隠蔽プロセスを検出する
    fn scan_hidden_processes(config: &HiddenProcessMonitorConfig) -> Vec<HiddenProcess> {
        let pid_max = config.scan_max_pid.unwrap_or_else(Self::get_pid_max);
        let readdir_pids = Self::list_pids_readdir();
        let skip_set: HashSet<u32> = config.skip_pids.iter().copied().collect();

        let mut candidates: Vec<u32> = Vec::new();

        // ブルートフォーススキャン: readdir に存在しないが直接アクセスで存在する PID を検出
        for pid in 1..=pid_max {
            if skip_set.contains(&pid) {
                continue;
            }

            if !readdir_pids.contains(&pid) && Self::pid_exists_direct(pid) {
                candidates.push(pid);
            }
        }

        // 再確認: false positive 対策（短命プロセスのフィルタリング）
        let mut hidden_processes = Vec::new();
        for pid in candidates {
            let mut confirmed = true;
            for _ in 0..config.recheck_count {
                let current_readdir = Self::list_pids_readdir();
                if current_readdir.contains(&pid) || !Self::pid_exists_direct(pid) {
                    // readdir に現れた（タイミング差だった）か、既に終了した
                    confirmed = false;
                    break;
                }
            }

            if confirmed {
                let cmdline = Self::get_cmdline(pid);
                let status_info = Self::get_status_info(pid);

                hidden_processes.push(HiddenProcess {
                    pid,
                    cmdline,
                    status_info,
                });
            }
        }

        hidden_processes
    }

    /// 検知結果をイベントバスに発行する
    fn publish_findings(findings: &[HiddenProcess], event_bus: &Option<EventBus>) {
        for finding in findings {
            let message = format!(
                "隠蔽されたプロセスを検知しました: PID {} (cmdline: {}, {})",
                finding.pid,
                if finding.cmdline.is_empty() {
                    "<取得不可>"
                } else {
                    &finding.cmdline
                },
                if finding.status_info.is_empty() {
                    "status: <取得不可>"
                } else {
                    &finding.status_info
                }
            );

            let details = format!(
                "pid={}, cmdline={}, status={}",
                finding.pid, finding.cmdline, finding.status_info
            );

            tracing::error!(
                pid = finding.pid,
                cmdline = %finding.cmdline,
                status = %finding.status_info,
                "{}",
                message
            );

            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        "hidden_process_detected",
                        Severity::Critical,
                        "hidden_process_monitor",
                        &message,
                    )
                    .with_details(details),
                );
            }
        }
    }
}

impl Module for HiddenProcessMonitorModule {
    fn name(&self) -> &str {
        "hidden_process_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        if self.config.scan_batch_size == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_batch_size は 0 より大きい値を指定してください".to_string(),
            });
        }

        let pid_max = self.config.scan_max_pid.unwrap_or_else(Self::get_pid_max);

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            pid_max = pid_max,
            scan_batch_size = self.config.scan_batch_size,
            recheck_count = self.config.recheck_count,
            skip_pids = ?self.config.skip_pids,
            "プロセス隠蔽検知モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        let config = self.config.clone();
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        // 初回スキャン
        let initial_findings = Self::scan_hidden_processes(&config);
        tracing::info!(
            hidden_count = initial_findings.len(),
            "初回プロセス隠蔽スキャンが完了しました"
        );
        Self::publish_findings(&initial_findings, &event_bus);

        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(config.scan_interval_secs));
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("プロセス隠蔽検知モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let findings =
                            HiddenProcessMonitorModule::scan_hidden_processes(&config);
                        if findings.is_empty() {
                            tracing::debug!("隠蔽プロセスは検出されませんでした");
                        } else {
                            HiddenProcessMonitorModule::publish_findings(
                                &findings,
                                &event_bus,
                            );
                        }

                        // スキャン完了イベント
                        if let Some(ref bus) = event_bus {
                            let pid_max = config
                                .scan_max_pid
                                .unwrap_or_else(HiddenProcessMonitorModule::get_pid_max);
                            let msg = format!(
                                        "プロセス隠蔽スキャン完了: PID 1-{} をスキャンし、{}件の隠蔽プロセスを検出",
                                        pid_max,
                                        findings.len()
                                    );
                            bus.publish(
                                SecurityEvent::new(
                                    "hidden_process_scan_completed",
                                    Severity::Info,
                                    "hidden_process_monitor",
                                    &msg,
                                )
                                .with_details(format!(
                                    "pid_max={}, hidden_count={}",
                                    pid_max,
                                    findings.len()
                                )),
                            );
                        }
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn stop(&mut self) -> Result<(), AppError> {
        self.cancel_token.cancel();
        Ok(())
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();

        let pid_max = self.config.scan_max_pid.unwrap_or_else(Self::get_pid_max);
        let findings = Self::scan_hidden_processes(&self.config);
        let issues_found = findings.len();

        let scan_snapshot: BTreeMap<String, String> = findings
            .iter()
            .map(|f| {
                (
                    format!("hidden_pid:{}", f.pid),
                    format!("cmdline={}, status={}", f.cmdline, f.status_info),
                )
            })
            .collect();

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned: pid_max as usize,
            issues_found,
            duration,
            summary: format!(
                "PID 1-{} をスキャンし、{}件の隠蔽プロセスを検出しました",
                pid_max, issues_found
            ),
            snapshot: scan_snapshot,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> HiddenProcessMonitorConfig {
        HiddenProcessMonitorConfig {
            enabled: true,
            scan_interval_secs: 300,
            scan_max_pid: None,
            skip_pids: Vec::new(),
            scan_batch_size: 1000,
            recheck_count: 3,
        }
    }

    // --- list_pids_readdir tests ---

    #[test]
    fn test_list_pids_readdir_returns_entries() {
        let pids = HiddenProcessMonitorModule::list_pids_readdir();
        // PID 1（init）が含まれるはず
        assert!(!pids.is_empty());
        assert!(pids.contains(&1));
    }

    // --- pid_exists_direct tests ---

    #[test]
    fn test_pid_exists_direct_current_process() {
        let pid = std::process::id();
        assert!(HiddenProcessMonitorModule::pid_exists_direct(pid));
    }

    #[test]
    fn test_pid_exists_direct_nonexistent() {
        // 最大値付近の PID は存在しないはず
        assert!(!HiddenProcessMonitorModule::pid_exists_direct(u32::MAX));
    }

    // --- get_cmdline tests ---

    #[test]
    fn test_get_cmdline_current_process() {
        let pid = std::process::id();
        let cmdline = HiddenProcessMonitorModule::get_cmdline(pid);
        // テストバイナリのコマンドラインが取得できるはず
        assert!(!cmdline.is_empty());
    }

    #[test]
    fn test_get_cmdline_nonexistent() {
        let cmdline = HiddenProcessMonitorModule::get_cmdline(u32::MAX);
        assert!(cmdline.is_empty());
    }

    // --- get_status_info tests ---

    #[test]
    fn test_get_status_info_current_process() {
        let pid = std::process::id();
        let info = HiddenProcessMonitorModule::get_status_info(pid);
        assert!(!info.is_empty());
        assert!(info.contains("name="));
    }

    #[test]
    fn test_get_status_info_nonexistent() {
        let info = HiddenProcessMonitorModule::get_status_info(u32::MAX);
        assert!(info.is_empty());
    }

    // --- get_pid_max tests ---

    #[test]
    fn test_get_pid_max() {
        let pid_max = HiddenProcessMonitorModule::get_pid_max();
        // pid_max は通常 32768 以上
        assert!(pid_max >= 32768);
    }

    // --- scan_hidden_processes tests ---

    #[test]
    fn test_scan_hidden_processes_does_not_panic() {
        let mut config = default_config();
        // テスト時は小さい範囲でスキャン
        config.scan_max_pid = Some(100);
        let _findings = HiddenProcessMonitorModule::scan_hidden_processes(&config);
    }

    #[test]
    fn test_scan_hidden_processes_with_skip_pids() {
        let mut config = default_config();
        config.scan_max_pid = Some(100);
        config.skip_pids = vec![1, 2, 3];
        let _findings = HiddenProcessMonitorModule::scan_hidden_processes(&config);
    }

    // --- Module trait tests ---

    #[test]
    fn test_module_name() {
        let config = default_config();
        let module = HiddenProcessMonitorModule::new(config, None);
        assert_eq!(module.name(), "hidden_process_monitor");
    }

    #[test]
    fn test_init_valid() {
        let config = default_config();
        let mut module = HiddenProcessMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[test]
    fn test_init_zero_interval() {
        let mut config = default_config();
        config.scan_interval_secs = 0;
        let mut module = HiddenProcessMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_zero_batch_size() {
        let mut config = default_config();
        config.scan_batch_size = 0;
        let mut module = HiddenProcessMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let mut config = default_config();
        config.scan_interval_secs = 3600;
        config.scan_max_pid = Some(100);
        let mut module = HiddenProcessMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();
        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let mut config = default_config();
        config.scan_max_pid = Some(100);
        let module = HiddenProcessMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 100);
    }

    // --- publish_findings tests ---

    #[test]
    fn test_publish_findings_no_bus() {
        let findings = vec![HiddenProcess {
            pid: 9999,
            cmdline: "/bin/malware".to_string(),
            status_info: "name=malware, uid=0".to_string(),
        }];
        // event_bus が None でもパニックしない
        HiddenProcessMonitorModule::publish_findings(&findings, &None);
    }

    #[test]
    fn test_publish_findings_empty() {
        let findings: Vec<HiddenProcess> = Vec::new();
        HiddenProcessMonitorModule::publish_findings(&findings, &None);
    }

    #[test]
    fn test_publish_findings_empty_info() {
        let findings = vec![HiddenProcess {
            pid: 9999,
            cmdline: String::new(),
            status_info: String::new(),
        }];
        HiddenProcessMonitorModule::publish_findings(&findings, &None);
    }
}
