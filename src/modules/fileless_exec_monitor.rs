//! メモリ内実行（fileless malware）検知モジュール
//!
//! `/proc/*/exe` のシンボリックリンクを監視し、メモリ内実行の兆候を検知する。
//!
//! 検知対象:
//! 1. memfd_create による実行 — exe が `/memfd:` で始まる
//! 2. 削除済みファイルからの実行 — exe が ` (deleted)` で終わる
//! 3. /dev/shm からの実行 — exe が `/dev/shm/` 配下を指す

use crate::config::FilelessExecMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::BTreeMap;
use tokio_util::sync::CancellationToken;

/// ファイルレス実行の検知カテゴリ
#[derive(Debug, Clone, PartialEq, Eq)]
enum DetectionCategory {
    /// memfd_create による実行
    Memfd,
    /// /dev/shm 配下からの実行
    DevShm,
    /// 削除済みファイルからの実行
    DeletedFile,
}

impl DetectionCategory {
    /// 検知カテゴリに対応する Severity を返す
    fn severity(&self) -> Severity {
        match self {
            Self::Memfd => Severity::Critical,
            Self::DevShm => Severity::Critical,
            Self::DeletedFile => Severity::Warning,
        }
    }

    /// 検知カテゴリのイベント種別名を返す
    fn event_type(&self) -> &'static str {
        match self {
            Self::Memfd => "memfd_exec_detected",
            Self::DevShm => "devshm_exec_detected",
            Self::DeletedFile => "deleted_file_exec_detected",
        }
    }

    /// 検知カテゴリの説明を返す
    fn description(&self) -> &'static str {
        match self {
            Self::Memfd => "memfd_create によるメモリ内実行",
            Self::DevShm => "/dev/shm からの実行",
            Self::DeletedFile => "削除済みファイルからの実行",
        }
    }
}

/// ファイルレス実行の検知結果
#[derive(Debug, Clone)]
struct FilelessExecFinding {
    /// プロセスの PID
    pid: u32,
    /// `/proc/<pid>/exe` のリンク先パス
    exe_path: String,
    /// プロセスのコマンドライン
    cmdline: String,
    /// プロセスの UID
    uid: String,
    /// 検知カテゴリ
    category: DetectionCategory,
}

/// メモリ内実行（fileless malware）検知モジュール
///
/// `/proc/*/exe` のシンボリックリンクを定期スキャンし、
/// memfd_create 実行・削除済みファイル実行・/dev/shm 実行を検知する。
pub struct FilelessExecMonitorModule {
    config: FilelessExecMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl FilelessExecMonitorModule {
    /// 新しいファイルレス実行検知モジュールを作成する
    pub fn new(config: FilelessExecMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// `/proc/` から数値 PID ディレクトリの一覧を取得する
    fn list_pids() -> Vec<u32> {
        let entries = match std::fs::read_dir("/proc") {
            Ok(entries) => entries,
            Err(_) => return Vec::new(),
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

    /// `/proc/<pid>/exe` のシンボリックリンク先を取得する
    fn read_exe_link(pid: u32) -> Option<String> {
        let path = format!("/proc/{pid}/exe");
        std::fs::read_link(&path)
            .ok()
            .and_then(|p| p.to_str().map(|s| s.to_string()))
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

    /// `/proc/<pid>/status` から UID を取得する
    fn get_uid(pid: u32) -> Option<u32> {
        let path = format!("/proc/{pid}/status");
        let content = std::fs::read_to_string(&path).ok()?;

        for line in content.lines() {
            if let Some(val) = line.strip_prefix("Uid:") {
                return val.split_whitespace().next().and_then(|s| s.parse().ok());
            }
        }
        None
    }

    /// exe パスの検知カテゴリを判定する
    fn classify_exe(exe_path: &str) -> Option<DetectionCategory> {
        if exe_path.starts_with("/memfd:") {
            Some(DetectionCategory::Memfd)
        } else if exe_path.starts_with("/dev/shm/") {
            Some(DetectionCategory::DevShm)
        } else if exe_path.ends_with(" (deleted)") {
            Some(DetectionCategory::DeletedFile)
        } else {
            None
        }
    }

    /// 除外対象かどうかを判定する
    fn is_excluded(exe_path: &str, uid: Option<u32>, config: &FilelessExecMonitorConfig) -> bool {
        if let Some(uid) = uid
            && config.exclude_uids.contains(&uid)
        {
            return true;
        }

        for exclude_path in &config.exclude_paths {
            if exe_path.starts_with(exclude_path.as_str()) {
                return true;
            }
        }

        false
    }

    /// 全プロセスをスキャンしてファイルレス実行を検知する
    fn scan(config: &FilelessExecMonitorConfig) -> Vec<FilelessExecFinding> {
        let pids = Self::list_pids();
        let mut findings = Vec::new();

        for pid in pids {
            let exe_path = match Self::read_exe_link(pid) {
                Some(p) => p,
                None => continue,
            };

            let category = match Self::classify_exe(&exe_path) {
                Some(c) => c,
                None => continue,
            };

            let uid = Self::get_uid(pid);

            if Self::is_excluded(&exe_path, uid, config) {
                continue;
            }

            let cmdline = Self::get_cmdline(pid);
            let uid_str = uid.map(|u| u.to_string()).unwrap_or_default();

            findings.push(FilelessExecFinding {
                pid,
                exe_path,
                cmdline,
                uid: uid_str,
                category,
            });
        }

        findings
    }

    /// 検知結果をイベントバスに発行する
    fn publish_findings(findings: &[FilelessExecFinding], event_bus: &Option<EventBus>) {
        for finding in findings {
            let message = format!(
                "{}を検知しました: PID {} (exe: {}, cmdline: {}, uid: {})",
                finding.category.description(),
                finding.pid,
                finding.exe_path,
                if finding.cmdline.is_empty() {
                    "<取得不可>"
                } else {
                    &finding.cmdline
                },
                if finding.uid.is_empty() {
                    "<取得不可>"
                } else {
                    &finding.uid
                },
            );

            let details = format!(
                "pid={}, exe={}, cmdline={}, uid={}",
                finding.pid, finding.exe_path, finding.cmdline, finding.uid
            );

            match finding.category.severity() {
                Severity::Critical => tracing::error!(
                    pid = finding.pid,
                    exe = %finding.exe_path,
                    cmdline = %finding.cmdline,
                    uid = %finding.uid,
                    "{}",
                    message
                ),
                _ => tracing::info!(
                    pid = finding.pid,
                    exe = %finding.exe_path,
                    cmdline = %finding.cmdline,
                    uid = %finding.uid,
                    "{}",
                    message
                ),
            }

            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        finding.category.event_type(),
                        finding.category.severity(),
                        "fileless_exec_monitor",
                        &message,
                    )
                    .with_details(details),
                );
            }
        }
    }
}

impl Module for FilelessExecMonitorModule {
    fn name(&self) -> &str {
        "fileless_exec_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            exclude_paths = ?self.config.exclude_paths,
            exclude_uids = ?self.config.exclude_uids,
            "ファイルレス実行検知モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<(), AppError> {
        let config = self.config.clone();
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        let initial_findings = Self::scan(&config);
        tracing::info!(
            findings_count = initial_findings.len(),
            "初回ファイルレス実行スキャンが完了しました"
        );
        Self::publish_findings(&initial_findings, &event_bus);

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(config.scan_interval_secs));
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("ファイルレス実行検知モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let findings = FilelessExecMonitorModule::scan(&config);
                        if findings.is_empty() {
                            tracing::debug!("ファイルレス実行は検出されませんでした");
                        } else {
                            FilelessExecMonitorModule::publish_findings(
                                &findings,
                                &event_bus,
                            );
                        }

                        if let Some(ref bus) = event_bus {
                            let msg = format!(
                                "ファイルレス実行スキャン完了: {}件の不審なプロセスを検出",
                                findings.len()
                            );
                            bus.publish(
                                SecurityEvent::new(
                                    "fileless_exec_scan_completed",
                                    Severity::Info,
                                    "fileless_exec_monitor",
                                    &msg,
                                )
                                .with_details(format!(
                                    "findings_count={}",
                                    findings.len()
                                )),
                            );
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

        let pids = Self::list_pids();
        let items_scanned = pids.len();
        let findings = Self::scan(&self.config);
        let issues_found = findings.len();

        let scan_snapshot: BTreeMap<String, String> = findings
            .iter()
            .map(|f| {
                (
                    format!("{}:{}", f.category.event_type(), f.pid),
                    format!("exe={}, cmdline={}, uid={}", f.exe_path, f.cmdline, f.uid),
                )
            })
            .collect();

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "{}件のプロセスをスキャンし、{}件のファイルレス実行を検出しました",
                items_scanned, issues_found
            ),
            snapshot: scan_snapshot,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> FilelessExecMonitorConfig {
        FilelessExecMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            exclude_paths: Vec::new(),
            exclude_uids: Vec::new(),
        }
    }

    // --- classify_exe tests ---

    #[test]
    fn test_classify_memfd() {
        let result = FilelessExecMonitorModule::classify_exe("/memfd:test (deleted)");
        assert_eq!(result, Some(DetectionCategory::Memfd));
    }

    #[test]
    fn test_classify_devshm() {
        let result = FilelessExecMonitorModule::classify_exe("/dev/shm/payload");
        assert_eq!(result, Some(DetectionCategory::DevShm));
    }

    #[test]
    fn test_classify_deleted() {
        let result = FilelessExecMonitorModule::classify_exe("/usr/bin/evil (deleted)");
        assert_eq!(result, Some(DetectionCategory::DeletedFile));
    }

    #[test]
    fn test_classify_normal() {
        let result = FilelessExecMonitorModule::classify_exe("/usr/bin/bash");
        assert_eq!(result, None);
    }

    #[test]
    fn test_classify_memfd_takes_priority_over_deleted() {
        let result = FilelessExecMonitorModule::classify_exe("/memfd:name (deleted)");
        assert_eq!(result, Some(DetectionCategory::Memfd));
    }

    // --- is_excluded tests ---

    #[test]
    fn test_is_excluded_by_uid() {
        let mut config = default_config();
        config.exclude_uids = vec![1000];
        assert!(FilelessExecMonitorModule::is_excluded(
            "/memfd:test",
            Some(1000),
            &config
        ));
    }

    #[test]
    fn test_is_excluded_by_path() {
        let mut config = default_config();
        config.exclude_paths = vec!["/dev/shm/expected".to_string()];
        assert!(FilelessExecMonitorModule::is_excluded(
            "/dev/shm/expected-app",
            None,
            &config
        ));
    }

    #[test]
    fn test_not_excluded() {
        let config = default_config();
        assert!(!FilelessExecMonitorModule::is_excluded(
            "/memfd:test",
            Some(1000),
            &config
        ));
    }

    // --- severity tests ---

    #[test]
    fn test_severity_memfd_is_critical() {
        assert_eq!(DetectionCategory::Memfd.severity(), Severity::Critical);
    }

    #[test]
    fn test_severity_devshm_is_high() {
        assert_eq!(DetectionCategory::DevShm.severity(), Severity::Critical);
    }

    #[test]
    fn test_severity_deleted_is_warning() {
        assert_eq!(DetectionCategory::DeletedFile.severity(), Severity::Warning);
    }

    // --- list_pids tests ---

    #[test]
    fn test_list_pids_returns_entries() {
        let pids = FilelessExecMonitorModule::list_pids();
        assert!(!pids.is_empty());
        assert!(pids.contains(&1));
    }

    // --- get_cmdline tests ---

    #[test]
    fn test_get_cmdline_current_process() {
        let pid = std::process::id();
        let cmdline = FilelessExecMonitorModule::get_cmdline(pid);
        assert!(!cmdline.is_empty());
    }

    #[test]
    fn test_get_cmdline_nonexistent() {
        let cmdline = FilelessExecMonitorModule::get_cmdline(u32::MAX);
        assert!(cmdline.is_empty());
    }

    // --- get_uid tests ---

    #[test]
    fn test_get_uid_current_process() {
        let pid = std::process::id();
        let uid = FilelessExecMonitorModule::get_uid(pid);
        assert!(uid.is_some());
    }

    #[test]
    fn test_get_uid_nonexistent() {
        let uid = FilelessExecMonitorModule::get_uid(u32::MAX);
        assert!(uid.is_none());
    }

    // --- read_exe_link tests ---

    #[test]
    fn test_read_exe_link_current_process() {
        let pid = std::process::id();
        let exe = FilelessExecMonitorModule::read_exe_link(pid);
        assert!(exe.is_some());
    }

    #[test]
    fn test_read_exe_link_nonexistent() {
        let exe = FilelessExecMonitorModule::read_exe_link(u32::MAX);
        assert!(exe.is_none());
    }

    // --- scan tests ---

    #[test]
    fn test_scan_does_not_panic() {
        let config = default_config();
        let _findings = FilelessExecMonitorModule::scan(&config);
    }

    #[test]
    fn test_scan_with_exclusions() {
        let mut config = default_config();
        config.exclude_uids = vec![0, 1000];
        config.exclude_paths = vec!["/usr/bin".to_string()];
        let _findings = FilelessExecMonitorModule::scan(&config);
    }

    // --- Module trait tests ---

    #[test]
    fn test_module_name() {
        let config = default_config();
        let module = FilelessExecMonitorModule::new(config, None);
        assert_eq!(module.name(), "fileless_exec_monitor");
    }

    #[test]
    fn test_init_valid() {
        let config = default_config();
        let mut module = FilelessExecMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[test]
    fn test_init_zero_interval() {
        let mut config = default_config();
        config.scan_interval_secs = 0;
        let mut module = FilelessExecMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let config = default_config();
        let mut module = FilelessExecMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();
        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let config = default_config();
        let module = FilelessExecMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert!(result.items_scanned > 0);
    }

    // --- publish_findings tests ---

    #[test]
    fn test_publish_findings_no_bus() {
        let findings = vec![FilelessExecFinding {
            pid: 9999,
            exe_path: "/memfd:malware (deleted)".to_string(),
            cmdline: "./payload".to_string(),
            uid: "0".to_string(),
            category: DetectionCategory::Memfd,
        }];
        FilelessExecMonitorModule::publish_findings(&findings, &None);
    }

    #[test]
    fn test_publish_findings_empty() {
        let findings: Vec<FilelessExecFinding> = Vec::new();
        FilelessExecMonitorModule::publish_findings(&findings, &None);
    }

    #[test]
    fn test_publish_findings_empty_info() {
        let findings = vec![FilelessExecFinding {
            pid: 9999,
            exe_path: "/dev/shm/test".to_string(),
            cmdline: String::new(),
            uid: String::new(),
            category: DetectionCategory::DevShm,
        }];
        FilelessExecMonitorModule::publish_findings(&findings, &None);
    }

    #[test]
    fn test_publish_findings_deleted_category() {
        let findings = vec![FilelessExecFinding {
            pid: 1234,
            exe_path: "/tmp/evil (deleted)".to_string(),
            cmdline: "evil".to_string(),
            uid: "1000".to_string(),
            category: DetectionCategory::DeletedFile,
        }];
        FilelessExecMonitorModule::publish_findings(&findings, &None);
    }

    // --- DetectionCategory tests ---

    #[test]
    fn test_event_type_names() {
        assert_eq!(DetectionCategory::Memfd.event_type(), "memfd_exec_detected");
        assert_eq!(
            DetectionCategory::DevShm.event_type(),
            "devshm_exec_detected"
        );
        assert_eq!(
            DetectionCategory::DeletedFile.event_type(),
            "deleted_file_exec_detected"
        );
    }

    #[test]
    fn test_description() {
        assert!(!DetectionCategory::Memfd.description().is_empty());
        assert!(!DetectionCategory::DevShm.description().is_empty());
        assert!(!DetectionCategory::DeletedFile.description().is_empty());
    }
}
