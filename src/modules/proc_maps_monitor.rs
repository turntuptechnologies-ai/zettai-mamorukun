//! プロセスメモリマップ監視モジュール
//!
//! `/proc/[pid]/maps` を定期的に解析し、不審な共有ライブラリの
//! インジェクションや異常なメモリマッピングを検知する。
//!
//! 検知対象:
//! - 不審なパスからのライブラリロード（`/tmp`, `/dev/shm`, `/var/tmp` 等）
//! - 削除済みファイルからのマッピング（`(deleted)` マーカー）
//! - RWX 権限を持つ匿名メモリ領域
//! - 隠しファイル（ドットファイル）からのライブラリロード

use crate::config::ProcMapsMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::BTreeMap;
use tokio_util::sync::CancellationToken;

/// `/proc/[pid]/maps` の 1 行をパースした結果
#[derive(Debug, Clone, PartialEq, Eq)]
struct MapEntry {
    /// パーミッション文字列（例: "r-xp"）
    perms: String,
    /// マッピングのパス名（空文字列 = 匿名マッピング）
    pathname: String,
    /// 削除済みファイルからのマッピングか
    is_deleted: bool,
}

impl MapEntry {
    /// `/proc/[pid]/maps` の 1 行をパースする
    ///
    /// フォーマット: `address perms offset dev inode pathname`
    /// 例: `7f1234000000-7f1234021000 r-xp 00000000 fd:01 123456 /usr/lib/libc.so.6`
    fn parse(line: &str) -> Option<Self> {
        // フォーマット: address perms offset dev inode pathname
        // フィールド間は1つ以上のスペースで区切られる
        let mut fields = line.split_whitespace();
        let _address = fields.next()?;
        let perms = fields.next()?.to_string();
        let _offset = fields.next()?;
        let _dev = fields.next()?;
        let _inode = fields.next()?;
        // 残りをパス名として結合（パス名にスペースが含まれる場合に対応）
        let pathname: String = fields.collect::<Vec<&str>>().join(" ");

        let is_deleted = pathname.ends_with(" (deleted)");
        let pathname_clean = if is_deleted {
            pathname
                .strip_suffix(" (deleted)")
                .unwrap_or(&pathname)
                .to_string()
        } else {
            pathname
        };

        Some(Self {
            perms,
            pathname: pathname_clean,
            is_deleted,
        })
    }

    /// RWX（読み書き実行）権限を持つ匿名マッピングかどうか
    fn is_rwx_anonymous(&self) -> bool {
        self.pathname.is_empty() && self.perms.len() >= 3 && self.perms.starts_with("rwx")
    }

    /// パス名に隠しファイル（ドットで始まるコンポーネント）を含むか
    fn has_hidden_component(&self) -> bool {
        if self.pathname.is_empty() || self.pathname.starts_with('[') {
            return false;
        }
        self.pathname
            .split('/')
            .any(|component| !component.is_empty() && component.starts_with('.'))
    }

    /// パス名が指定された不審パスのいずれかで始まるか
    fn matches_suspicious_path(&self, suspicious_paths: &[String]) -> bool {
        if self.pathname.is_empty() || self.pathname.starts_with('[') {
            return false;
        }
        suspicious_paths
            .iter()
            .any(|sp| self.pathname.starts_with(sp.as_str()))
    }

    /// パス名が指定された除外パスのいずれかで始まるか
    fn matches_exclude_path(&self, exclude_paths: &[String]) -> bool {
        if self.pathname.is_empty() {
            return false;
        }
        exclude_paths
            .iter()
            .any(|ep| self.pathname.starts_with(ep.as_str()))
    }
}

/// プロセスごとのスキャン結果
#[derive(Debug)]
struct ProcessScanResult {
    /// PID
    pid: u32,
    /// プロセス名
    name: String,
    /// 不審なマッピングのリスト
    findings: Vec<Finding>,
}

/// 検知結果
#[derive(Debug, Clone)]
struct Finding {
    /// イベント種別
    event_type: &'static str,
    /// 重要度
    severity: Severity,
    /// 説明メッセージ
    message: String,
    /// 詳細情報
    details: String,
}

/// プロセスメモリマップ監視モジュール
///
/// `/proc/[pid]/maps` を定期スキャンし、不審なメモリマッピングを検知する。
pub struct ProcMapsMonitorModule {
    config: ProcMapsMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl ProcMapsMonitorModule {
    /// 新しいプロセスメモリマップ監視モジュールを作成する
    pub fn new(config: ProcMapsMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// プロセス名を取得する
    fn get_process_name(pid: u32) -> String {
        let comm_path = format!("/proc/{pid}/comm");
        std::fs::read_to_string(&comm_path)
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    }

    /// 実行中のプロセス PID 一覧を取得する
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

    /// 指定された PID の `/proc/[pid]/maps` を読み取りパースする
    fn read_maps(pid: u32) -> Vec<MapEntry> {
        let maps_path = format!("/proc/{pid}/maps");
        let content = match std::fs::read_to_string(&maps_path) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        content.lines().filter_map(MapEntry::parse).collect()
    }

    /// 1 つのプロセスをスキャンし、検知結果を返す
    fn scan_process(pid: u32, process_name: &str, config: &ProcMapsMonitorConfig) -> Vec<Finding> {
        let entries = Self::read_maps(pid);
        let mut findings = Vec::new();

        for entry in &entries {
            // 除外パスに一致する場合はスキップ
            if entry.matches_exclude_path(&config.exclude_paths) {
                continue;
            }

            // 削除済みマッピングの検知
            if config.detect_deleted_mappings && entry.is_deleted {
                findings.push(Finding {
                    event_type: "proc_maps_deleted_mapping",
                    severity: Severity::Critical,
                    message: format!(
                        "PID {} ({}) で削除済みファイルからのマッピングを検出しました",
                        pid, process_name
                    ),
                    details: format!(
                        "pid={}, process={}, path={} (deleted)",
                        pid, process_name, entry.pathname
                    ),
                });
            }

            // RWX 匿名メモリの検知
            if config.detect_rwx_anonymous && entry.is_rwx_anonymous() {
                findings.push(Finding {
                    event_type: "proc_maps_rwx_anonymous",
                    severity: Severity::Warning,
                    message: format!(
                        "PID {} ({}) に RWX 権限の匿名メモリ領域を検出しました",
                        pid, process_name
                    ),
                    details: format!(
                        "pid={}, process={}, perms={}",
                        pid, process_name, entry.perms
                    ),
                });
            }

            // 不審パスからのライブラリロード検知
            if entry.matches_suspicious_path(&config.suspicious_paths) {
                findings.push(Finding {
                    event_type: "proc_maps_suspicious_path",
                    severity: Severity::Warning,
                    message: format!(
                        "PID {} ({}) で不審なパスからのライブラリロードを検出しました",
                        pid, process_name
                    ),
                    details: format!(
                        "pid={}, process={}, path={}",
                        pid, process_name, entry.pathname
                    ),
                });
            }

            // 隠しライブラリの検知
            if config.detect_hidden_libraries && entry.has_hidden_component() {
                findings.push(Finding {
                    event_type: "proc_maps_hidden_library",
                    severity: Severity::Warning,
                    message: format!(
                        "PID {} ({}) で隠しファイルからのライブラリロードを検出しました",
                        pid, process_name
                    ),
                    details: format!(
                        "pid={}, process={}, path={}",
                        pid, process_name, entry.pathname
                    ),
                });
            }
        }

        findings
    }

    /// 全プロセスをスキャンする
    fn scan_all(config: &ProcMapsMonitorConfig) -> Vec<ProcessScanResult> {
        let pids = Self::list_pids();
        let mut results = Vec::new();

        for pid in pids {
            let process_name = Self::get_process_name(pid);

            // プロセス名が空の場合（既に終了している等）はスキップ
            if process_name.is_empty() {
                continue;
            }

            // 除外プロセスに一致する場合はスキップ
            if config.exclude_processes.contains(&process_name) {
                continue;
            }

            let findings = Self::scan_process(pid, &process_name, config);
            if !findings.is_empty() {
                results.push(ProcessScanResult {
                    pid,
                    name: process_name,
                    findings,
                });
            }
        }

        results
    }

    /// スキャン結果をイベントバスに発行する
    fn publish_findings(results: &[ProcessScanResult], event_bus: &Option<EventBus>) {
        for result in results {
            for finding in &result.findings {
                match finding.severity {
                    Severity::Critical => {
                        tracing::error!(
                            pid = result.pid,
                            process = %result.name,
                            event_type = finding.event_type,
                            "{}",
                            finding.message
                        );
                    }
                    Severity::Warning => {
                        tracing::warn!(
                            pid = result.pid,
                            process = %result.name,
                            event_type = finding.event_type,
                            "{}",
                            finding.message
                        );
                    }
                    _ => {
                        tracing::info!(
                            pid = result.pid,
                            process = %result.name,
                            event_type = finding.event_type,
                            "{}",
                            finding.message
                        );
                    }
                }

                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            finding.event_type,
                            finding.severity.clone(),
                            "proc_maps_monitor",
                            &finding.message,
                        )
                        .with_details(finding.details.clone()),
                    );
                }
            }
        }
    }
}

impl Module for ProcMapsMonitorModule {
    fn name(&self) -> &str {
        "proc_maps_monitor"
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
            detect_deleted_mappings = self.config.detect_deleted_mappings,
            detect_rwx_anonymous = self.config.detect_rwx_anonymous,
            detect_hidden_libraries = self.config.detect_hidden_libraries,
            exclude_processes_count = self.config.exclude_processes.len(),
            "プロセスメモリマップ監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        let config = self.config.clone();
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        // 初回スキャン
        let initial_results = Self::scan_all(&config);
        let total_findings: usize = initial_results.iter().map(|r| r.findings.len()).sum();
        tracing::info!(
            processes_with_findings = initial_results.len(),
            total_findings = total_findings,
            "初回メモリマップスキャンが完了しました"
        );
        Self::publish_findings(&initial_results, &event_bus);

        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(config.scan_interval_secs));
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("プロセスメモリマップ監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let results = ProcMapsMonitorModule::scan_all(&config);
                        if results.is_empty() {
                            tracing::debug!("プロセスメモリマップに異常は検出されませんでした");
                        } else {
                            ProcMapsMonitorModule::publish_findings(&results, &event_bus);
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

        let results = Self::scan_all(&self.config);
        let pids = Self::list_pids();
        let items_scanned = pids.len();
        let issues_found: usize = results.iter().map(|r| r.findings.len()).sum();

        let scan_snapshot: BTreeMap<String, String> = results
            .iter()
            .flat_map(|r| {
                r.findings.iter().map(move |f| {
                    (
                        format!("{}:{}:{}", r.pid, r.name, f.event_type),
                        f.details.clone(),
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
                "{}件のプロセスをスキャンし、{}件の不審なメモリマッピングを検出しました",
                items_scanned, issues_found
            ),
            snapshot: scan_snapshot,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> ProcMapsMonitorConfig {
        ProcMapsMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            suspicious_paths: vec![
                "/tmp".to_string(),
                "/dev/shm".to_string(),
                "/var/tmp".to_string(),
            ],
            detect_deleted_mappings: true,
            detect_rwx_anonymous: true,
            detect_hidden_libraries: true,
            exclude_processes: Vec::new(),
            exclude_paths: Vec::new(),
        }
    }

    // --- MapEntry::parse tests ---

    #[test]
    fn test_parse_regular_mapping() {
        let line = "7f1234000000-7f1234021000 r-xp 00000000 fd:01 123456                     /usr/lib/libc.so.6";
        let entry = MapEntry::parse(line).unwrap();
        assert_eq!(entry.perms, "r-xp");
        assert_eq!(entry.pathname, "/usr/lib/libc.so.6");
        assert!(!entry.is_deleted);
    }

    #[test]
    fn test_parse_anonymous_mapping() {
        let line = "7f1234000000-7f1234021000 rwxp 00000000 00:00 0";
        let entry = MapEntry::parse(line).unwrap();
        assert_eq!(entry.perms, "rwxp");
        assert_eq!(entry.pathname, "");
        assert!(!entry.is_deleted);
    }

    #[test]
    fn test_parse_deleted_mapping() {
        let line = "7f1234000000-7f1234021000 r-xp 00000000 fd:01 123456                     /tmp/malware.so (deleted)";
        let entry = MapEntry::parse(line).unwrap();
        assert_eq!(entry.pathname, "/tmp/malware.so");
        assert!(entry.is_deleted);
    }

    #[test]
    fn test_parse_special_mapping() {
        let line =
            "7ffe12345000-7ffe12367000 rw-p 00000000 00:00 0                          [stack]";
        let entry = MapEntry::parse(line).unwrap();
        assert_eq!(entry.pathname, "[stack]");
        assert!(!entry.is_deleted);
    }

    #[test]
    fn test_parse_heap_mapping() {
        let line =
            "55a234000000-55a234021000 rw-p 00000000 00:00 0                          [heap]";
        let entry = MapEntry::parse(line).unwrap();
        assert_eq!(entry.pathname, "[heap]");
    }

    // --- MapEntry method tests ---

    #[test]
    fn test_is_rwx_anonymous() {
        let entry = MapEntry {
            perms: "rwxp".to_string(),
            pathname: String::new(),
            is_deleted: false,
        };
        assert!(entry.is_rwx_anonymous());
    }

    #[test]
    fn test_is_not_rwx_anonymous_with_path() {
        let entry = MapEntry {
            perms: "rwxp".to_string(),
            pathname: "/usr/lib/libtest.so".to_string(),
            is_deleted: false,
        };
        assert!(!entry.is_rwx_anonymous());
    }

    #[test]
    fn test_is_not_rwx_anonymous_readonly() {
        let entry = MapEntry {
            perms: "r--p".to_string(),
            pathname: String::new(),
            is_deleted: false,
        };
        assert!(!entry.is_rwx_anonymous());
    }

    #[test]
    fn test_has_hidden_component() {
        let entry = MapEntry {
            perms: "r-xp".to_string(),
            pathname: "/usr/lib/.hidden/libmalware.so".to_string(),
            is_deleted: false,
        };
        assert!(entry.has_hidden_component());
    }

    #[test]
    fn test_has_hidden_component_dotfile() {
        let entry = MapEntry {
            perms: "r-xp".to_string(),
            pathname: "/lib/.libhidden.so".to_string(),
            is_deleted: false,
        };
        assert!(entry.has_hidden_component());
    }

    #[test]
    fn test_no_hidden_component_normal() {
        let entry = MapEntry {
            perms: "r-xp".to_string(),
            pathname: "/usr/lib/libc.so.6".to_string(),
            is_deleted: false,
        };
        assert!(!entry.has_hidden_component());
    }

    #[test]
    fn test_no_hidden_component_special() {
        let entry = MapEntry {
            perms: "rw-p".to_string(),
            pathname: "[stack]".to_string(),
            is_deleted: false,
        };
        assert!(!entry.has_hidden_component());
    }

    #[test]
    fn test_no_hidden_component_anonymous() {
        let entry = MapEntry {
            perms: "rw-p".to_string(),
            pathname: String::new(),
            is_deleted: false,
        };
        assert!(!entry.has_hidden_component());
    }

    #[test]
    fn test_matches_suspicious_path() {
        let entry = MapEntry {
            perms: "r-xp".to_string(),
            pathname: "/tmp/evil.so".to_string(),
            is_deleted: false,
        };
        let suspicious = vec!["/tmp".to_string(), "/dev/shm".to_string()];
        assert!(entry.matches_suspicious_path(&suspicious));
    }

    #[test]
    fn test_no_match_suspicious_path() {
        let entry = MapEntry {
            perms: "r-xp".to_string(),
            pathname: "/usr/lib/libc.so.6".to_string(),
            is_deleted: false,
        };
        let suspicious = vec!["/tmp".to_string(), "/dev/shm".to_string()];
        assert!(!entry.matches_suspicious_path(&suspicious));
    }

    #[test]
    fn test_suspicious_path_special_ignored() {
        let entry = MapEntry {
            perms: "rw-p".to_string(),
            pathname: "[heap]".to_string(),
            is_deleted: false,
        };
        let suspicious = vec!["/tmp".to_string()];
        assert!(!entry.matches_suspicious_path(&suspicious));
    }

    #[test]
    fn test_matches_exclude_path() {
        let entry = MapEntry {
            perms: "r-xp".to_string(),
            pathname: "/usr/lib/libc.so.6".to_string(),
            is_deleted: false,
        };
        let exclude = vec!["/usr/lib".to_string()];
        assert!(entry.matches_exclude_path(&exclude));
    }

    #[test]
    fn test_no_match_exclude_path() {
        let entry = MapEntry {
            perms: "r-xp".to_string(),
            pathname: "/tmp/evil.so".to_string(),
            is_deleted: false,
        };
        let exclude = vec!["/usr/lib".to_string()];
        assert!(!entry.matches_exclude_path(&exclude));
    }

    // --- scan_process tests ---

    #[test]
    fn test_scan_process_detects_deleted() {
        let config = default_config();
        // Use PID 1 (init) which should exist on any Linux
        // This tests that scan_process doesn't panic
        let _findings = ProcMapsMonitorModule::scan_process(1, "init", &config);
        // We can't assert specific findings since it depends on system state
    }

    // --- Module trait tests ---

    #[test]
    fn test_init_zero_interval() {
        let mut config = default_config();
        config.scan_interval_secs = 0;
        let mut module = ProcMapsMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let config = default_config();
        let mut module = ProcMapsMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let mut config = default_config();
        config.scan_interval_secs = 3600;
        let mut module = ProcMapsMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();
        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let config = default_config();
        let module = ProcMapsMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        // At minimum, the current process should be scanned
        assert!(result.items_scanned > 0);
    }

    #[test]
    fn test_module_name() {
        let config = default_config();
        let module = ProcMapsMonitorModule::new(config, None);
        assert_eq!(module.name(), "proc_maps_monitor");
    }

    #[test]
    fn test_list_pids_returns_entries() {
        let pids = ProcMapsMonitorModule::list_pids();
        // At minimum PID 1 (init) should exist
        assert!(!pids.is_empty());
    }

    #[test]
    fn test_read_maps_current_process() {
        let pid = std::process::id();
        let entries = ProcMapsMonitorModule::read_maps(pid);
        // Current process should have memory mappings
        assert!(!entries.is_empty());
    }

    #[test]
    fn test_read_maps_nonexistent_pid() {
        let entries = ProcMapsMonitorModule::read_maps(u32::MAX);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_exclude_processes() {
        let mut config = default_config();
        config.exclude_processes = vec!["init".to_string(), "systemd".to_string()];
        // scan_all should skip excluded processes
        let _results = ProcMapsMonitorModule::scan_all(&config);
        // Can't assert specific results but shouldn't panic
    }

    #[test]
    fn test_exclude_paths() {
        let config = ProcMapsMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            suspicious_paths: vec!["/tmp".to_string()],
            detect_deleted_mappings: true,
            detect_rwx_anonymous: true,
            detect_hidden_libraries: true,
            exclude_processes: Vec::new(),
            exclude_paths: vec!["/tmp/allowed".to_string()],
        };

        // Entry matching suspicious path but also exclude path should be excluded
        let entry = MapEntry {
            perms: "r-xp".to_string(),
            pathname: "/tmp/allowed/lib.so".to_string(),
            is_deleted: false,
        };
        assert!(entry.matches_exclude_path(&config.exclude_paths));
        assert!(entry.matches_suspicious_path(&config.suspicious_paths));
    }
}
