//! プロセス cgroup 逸脱検知モジュール
//!
//! 各プロセスが所属する cgroup を定期的にスキャンし、ベースラインからの変更を検知する。
//!
//! 検知対象:
//! - プロセスの cgroup 変更（Critical: `process_cgroup_changed`）
//! - ルート cgroup への移動（Critical: `process_cgroup_root_escape`）
//! - ルート cgroup に所属する新規プロセス（Warning: `process_cgroup_root_new`）
//! - ホワイトリスト外の cgroup に所属する新規プロセス（Warning: `process_cgroup_unlisted`）

use crate::config::ProcessCgroupMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use regex::Regex;
use std::collections::BTreeMap;
use tokio_util::sync::CancellationToken;

/// プロセス cgroup スナップショット（PID → エントリ）
type ProcessCgroupSnapshot = BTreeMap<u32, ProcessCgroupEntry>;

/// プロセスの cgroup 情報
#[derive(Debug, Clone, PartialEq)]
struct ProcessCgroupEntry {
    /// プロセス名（comm）
    comm: String,
    /// cgroup パス
    cgroup_path: String,
}

/// `/proc/<pid>/cgroup` を読み、cgroup v2 パスを抽出する
///
/// cgroup v2 形式: `0::/path` → `/path` を返す。
/// v1 形式（`0::` プレフィックスなし）はスキップして `None` を返す。
fn read_process_cgroup(pid: u32) -> Option<String> {
    let path = format!("/proc/{}/cgroup", pid);
    let content = std::fs::read_to_string(path).ok()?;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // cgroup v2: "0::/path"
        if let Some(rest) = line.strip_prefix("0::") {
            return Some(rest.to_string());
        }
    }

    // v1 形式のみの場合は warning ログを出して None
    tracing::warn!(
        pid = pid,
        "cgroup v2 エントリが見つかりません（v1 形式のみ）"
    );
    None
}

/// `/proc/<pid>/comm` を読み、プロセス名を返す
fn read_process_comm(pid: u32) -> Option<String> {
    let path = format!("/proc/{}/comm", pid);
    let content = std::fs::read_to_string(path).ok()?;
    Some(content.trim().to_string())
}

/// /proc の数値ディレクトリを列挙してプロセス cgroup スナップショットを作成する
fn scan_process_cgroups(watch_process_names: &[String]) -> ProcessCgroupSnapshot {
    let mut snapshot = ProcessCgroupSnapshot::new();

    let entries = match std::fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(e) => {
            tracing::error!(error = %e, "/proc の読み取りに失敗しました");
            return snapshot;
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();

        // 数値ディレクトリ（PID）のみ処理
        let pid: u32 = match name.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let comm = match read_process_comm(pid) {
            Some(c) => c,
            None => continue,
        };

        // watch_process_names が指定されている場合、フィルタ
        if !watch_process_names.is_empty() && !watch_process_names.contains(&comm) {
            continue;
        }

        let cgroup_path = match read_process_cgroup(pid) {
            Some(p) => p,
            None => continue,
        };

        snapshot.insert(pid, ProcessCgroupEntry { comm, cgroup_path });
    }

    snapshot
}

/// ベースラインと現在のスナップショットを比較し、変更を検知する
///
/// 変更があった場合は `true` を返す。
fn detect_cgroup_changes(
    baseline: &ProcessCgroupSnapshot,
    current: &ProcessCgroupSnapshot,
    detect_root_escape: bool,
    whitelist_patterns: &[Regex],
    event_bus: &Option<EventBus>,
) -> bool {
    let mut has_changes = false;

    for (pid, current_entry) in current {
        if let Some(baseline_entry) = baseline.get(pid) {
            // PID 再利用チェック: comm が異なる場合は新規プロセスとして扱う
            if baseline_entry.comm != current_entry.comm {
                has_changes |= check_new_process(
                    *pid,
                    current_entry,
                    detect_root_escape,
                    whitelist_patterns,
                    event_bus,
                );
                continue;
            }

            // 同一 PID + 同一 comm: cgroup 変更を検知
            if baseline_entry.cgroup_path != current_entry.cgroup_path {
                // ルート cgroup への移動
                if current_entry.cgroup_path == "/" && detect_root_escape {
                    let details = format!(
                        "pid={}, comm={}, 旧cgroup={}, 新cgroup=/",
                        pid, current_entry.comm, baseline_entry.cgroup_path
                    );
                    tracing::warn!(
                        pid = pid,
                        comm = %current_entry.comm,
                        old_cgroup = %baseline_entry.cgroup_path,
                        new_cgroup = "/",
                        "プロセスがルート cgroup に移動しました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "process_cgroup_root_escape",
                                Severity::Critical,
                                "process_cgroup_monitor",
                                "プロセスがルート cgroup に移動しました",
                            )
                            .with_details(details),
                        );
                    }
                    has_changes = true;
                    continue;
                }

                // ホワイトリストチェック
                if whitelist_patterns
                    .iter()
                    .any(|re| re.is_match(&current_entry.cgroup_path))
                {
                    tracing::debug!(
                        pid = pid,
                        comm = %current_entry.comm,
                        cgroup = %current_entry.cgroup_path,
                        "cgroup 変更はホワイトリストにマッチしました"
                    );
                    continue;
                }

                let details = format!(
                    "pid={}, comm={}, 旧cgroup={}, 新cgroup={}",
                    pid, current_entry.comm, baseline_entry.cgroup_path, current_entry.cgroup_path
                );
                tracing::warn!(
                    pid = pid,
                    comm = %current_entry.comm,
                    old_cgroup = %baseline_entry.cgroup_path,
                    new_cgroup = %current_entry.cgroup_path,
                    "プロセスの cgroup が変更されました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "process_cgroup_changed",
                            Severity::Critical,
                            "process_cgroup_monitor",
                            "プロセスの cgroup が変更されました",
                        )
                        .with_details(details),
                    );
                }
                has_changes = true;
            }
        } else {
            // 新規プロセス
            has_changes |= check_new_process(
                *pid,
                current_entry,
                detect_root_escape,
                whitelist_patterns,
                event_bus,
            );
        }
    }

    has_changes
}

/// 新規プロセスに対するチェック
fn check_new_process(
    pid: u32,
    entry: &ProcessCgroupEntry,
    detect_root_escape: bool,
    whitelist_patterns: &[Regex],
    event_bus: &Option<EventBus>,
) -> bool {
    // ルート cgroup 所属 + detect_root_escape=true → Warning
    if entry.cgroup_path == "/" && detect_root_escape {
        let details = format!("pid={}, comm={}, cgroup=/", pid, entry.comm);
        tracing::warn!(
            pid = pid,
            comm = %entry.comm,
            "ルート cgroup に所属する新規プロセスを検知しました"
        );
        if let Some(bus) = event_bus {
            bus.publish(
                SecurityEvent::new(
                    "process_cgroup_root_new",
                    Severity::Warning,
                    "process_cgroup_monitor",
                    "ルート cgroup に所属する新規プロセスを検知しました",
                )
                .with_details(details),
            );
        }
        return true;
    }

    // ホワイトリスト設定あり + どのパターンにも非マッチ → Warning
    if !whitelist_patterns.is_empty()
        && !whitelist_patterns
            .iter()
            .any(|re| re.is_match(&entry.cgroup_path))
    {
        let details = format!(
            "pid={}, comm={}, cgroup={}",
            pid, entry.comm, entry.cgroup_path
        );
        tracing::warn!(
            pid = pid,
            comm = %entry.comm,
            cgroup = %entry.cgroup_path,
            "ホワイトリスト外の cgroup に所属する新規プロセスを検知しました"
        );
        if let Some(bus) = event_bus {
            bus.publish(
                SecurityEvent::new(
                    "process_cgroup_unlisted",
                    Severity::Warning,
                    "process_cgroup_monitor",
                    "ホワイトリスト外の cgroup に所属する新規プロセスを検知しました",
                )
                .with_details(details),
            );
        }
        return true;
    }

    false
}

/// プロセス cgroup 逸脱検知モジュール
///
/// プロセスが本来所属すべき cgroup から逸脱していないかを監視し、
/// コンテナブレイクアウトの兆候を検知する。
pub struct ProcessCgroupMonitorModule {
    config: ProcessCgroupMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl ProcessCgroupMonitorModule {
    /// 新しいプロセス cgroup 逸脱検知モジュールを作成する
    pub fn new(config: ProcessCgroupMonitorConfig, event_bus: Option<EventBus>) -> Self {
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
}

impl Module for ProcessCgroupMonitorModule {
    fn name(&self) -> &str {
        "process_cgroup_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        // ホワイトリストパターンの正規表現コンパイルテスト
        for pattern in &self.config.whitelist_patterns {
            Regex::new(pattern).map_err(|e| AppError::ModuleConfig {
                message: format!("不正な正規表現パターン '{}': {}", pattern, e),
            })?;
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            watch_process_names_count = self.config.watch_process_names.len(),
            whitelist_patterns_count = self.config.whitelist_patterns.len(),
            detect_root_cgroup_escape = self.config.detect_root_cgroup_escape,
            "プロセス cgroup 逸脱検知モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        let watch_process_names = self.config.watch_process_names.clone();
        let detect_root_escape = self.config.detect_root_cgroup_escape;
        let scan_interval_secs = self.config.scan_interval_secs;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        // ホワイトリストパターンをコンパイル
        let whitelist_patterns: Vec<Regex> = self
            .config
            .whitelist_patterns
            .iter()
            .filter_map(|p| Regex::new(p).ok())
            .collect();

        let baseline = scan_process_cgroups(&watch_process_names);
        tracing::info!(
            process_count = baseline.len(),
            "プロセス cgroup ベースラインスキャンが完了しました"
        );

        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            interval.tick().await;

            let mut baseline = baseline;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("プロセス cgroup 逸脱検知モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = scan_process_cgroups(&watch_process_names);
                        let changed = detect_cgroup_changes(
                            &baseline,
                            &current,
                            detect_root_escape,
                            &whitelist_patterns,
                            &event_bus,
                        );

                        if changed {
                            baseline = current;
                        } else {
                            tracing::debug!("プロセス cgroup に変更はありません");
                        }
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();
        let snapshot = scan_process_cgroups(&self.config.watch_process_names);

        let mut scan_snapshot: BTreeMap<String, String> = BTreeMap::new();
        for (pid, entry) in &snapshot {
            let key = format!("proc_cgroup:{}:{}", pid, entry.comm);
            scan_snapshot.insert(key, entry.cgroup_path.clone());
        }

        let items_scanned = snapshot.len();
        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found: 0,
            duration,
            summary: format!("プロセス cgroup {}件のプロセスをスキャン", items_scanned),
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
    fn test_init_valid() {
        let config = ProcessCgroupMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            watch_process_names: vec![],
            whitelist_patterns: vec![],
            detect_root_cgroup_escape: true,
        };
        let mut module = ProcessCgroupMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[test]
    fn test_init_zero_interval() {
        let config = ProcessCgroupMonitorConfig {
            enabled: true,
            scan_interval_secs: 0,
            watch_process_names: vec![],
            whitelist_patterns: vec![],
            detect_root_cgroup_escape: true,
        };
        let mut module = ProcessCgroupMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("scan_interval_secs"));
    }

    #[test]
    fn test_init_invalid_regex() {
        let config = ProcessCgroupMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            watch_process_names: vec![],
            whitelist_patterns: vec!["[invalid".to_string()],
            detect_root_cgroup_escape: true,
        };
        let mut module = ProcessCgroupMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("[invalid"));
    }

    #[test]
    fn test_parse_cgroup_v2() {
        // read_process_cgroup は /proc/<pid>/cgroup を読むので直接テストできない。
        // 代わりに内部ロジックと同等のパースをテストする。
        let content = "0::/system.slice/sshd.service\n";
        let mut result = None;
        for line in content.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("0::") {
                result = Some(rest.to_string());
                break;
            }
        }
        assert_eq!(result, Some("/system.slice/sshd.service".to_string()));
    }

    #[test]
    fn test_parse_cgroup_v2_root() {
        let content = "0::/\n";
        let mut result = None;
        for line in content.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("0::") {
                result = Some(rest.to_string());
                break;
            }
        }
        assert_eq!(result, Some("/".to_string()));
    }

    #[test]
    fn test_parse_cgroup_v1_only() {
        // v1 形式のみ: "0::/" プレフィックスがないので None
        let content = "12:memory:/docker/abc123\n11:cpu:/docker/abc123\n";
        let mut result = None;
        for line in content.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("0::") {
                result = Some(rest.to_string());
                break;
            }
        }
        assert_eq!(result, None);
    }

    #[test]
    fn test_detect_no_changes() {
        let mut baseline = ProcessCgroupSnapshot::new();
        baseline.insert(
            100,
            ProcessCgroupEntry {
                comm: "sshd".to_string(),
                cgroup_path: "/system.slice/sshd.service".to_string(),
            },
        );

        let current = baseline.clone();
        let result = detect_cgroup_changes(&baseline, &current, true, &[], &None);
        assert!(!result);
    }

    #[test]
    fn test_detect_cgroup_changed() {
        let mut baseline = ProcessCgroupSnapshot::new();
        baseline.insert(
            100,
            ProcessCgroupEntry {
                comm: "sshd".to_string(),
                cgroup_path: "/system.slice/sshd.service".to_string(),
            },
        );

        let mut current = ProcessCgroupSnapshot::new();
        current.insert(
            100,
            ProcessCgroupEntry {
                comm: "sshd".to_string(),
                cgroup_path: "/user.slice/user-1000.slice".to_string(),
            },
        );

        let result = detect_cgroup_changes(&baseline, &current, true, &[], &None);
        assert!(result);
    }

    #[test]
    fn test_detect_root_escape() {
        let mut baseline = ProcessCgroupSnapshot::new();
        baseline.insert(
            100,
            ProcessCgroupEntry {
                comm: "sshd".to_string(),
                cgroup_path: "/system.slice/sshd.service".to_string(),
            },
        );

        let mut current = ProcessCgroupSnapshot::new();
        current.insert(
            100,
            ProcessCgroupEntry {
                comm: "sshd".to_string(),
                cgroup_path: "/".to_string(),
            },
        );

        // detect_root_escape=true → Critical
        let result = detect_cgroup_changes(&baseline, &current, true, &[], &None);
        assert!(result);

        // detect_root_escape=false → still detected as cgroup_changed
        let result = detect_cgroup_changes(&baseline, &current, false, &[], &None);
        assert!(result);
    }

    #[test]
    fn test_detect_whitelist_skip() {
        let mut baseline = ProcessCgroupSnapshot::new();
        baseline.insert(
            100,
            ProcessCgroupEntry {
                comm: "sshd".to_string(),
                cgroup_path: "/system.slice/sshd.service".to_string(),
            },
        );

        let mut current = ProcessCgroupSnapshot::new();
        current.insert(
            100,
            ProcessCgroupEntry {
                comm: "sshd".to_string(),
                cgroup_path: "/user.slice/user-1000.slice".to_string(),
            },
        );

        let whitelist = vec![Regex::new(r"^/user\.slice/").unwrap()];
        let result = detect_cgroup_changes(&baseline, &current, true, &whitelist, &None);
        assert!(!result);
    }

    #[test]
    fn test_detect_pid_reuse() {
        let mut baseline = ProcessCgroupSnapshot::new();
        baseline.insert(
            100,
            ProcessCgroupEntry {
                comm: "sshd".to_string(),
                cgroup_path: "/system.slice/sshd.service".to_string(),
            },
        );

        // 同一 PID で異なる comm → 新規プロセスとして扱う
        let mut current = ProcessCgroupSnapshot::new();
        current.insert(
            100,
            ProcessCgroupEntry {
                comm: "nginx".to_string(),
                cgroup_path: "/system.slice/nginx.service".to_string(),
            },
        );

        // ホワイトリストなし、ルート cgroup でもない → 変更なし
        let result = detect_cgroup_changes(&baseline, &current, true, &[], &None);
        assert!(!result);
    }

    #[test]
    fn test_detect_new_process_root_cgroup() {
        let baseline = ProcessCgroupSnapshot::new();

        let mut current = ProcessCgroupSnapshot::new();
        current.insert(
            200,
            ProcessCgroupEntry {
                comm: "suspicious".to_string(),
                cgroup_path: "/".to_string(),
            },
        );

        let result = detect_cgroup_changes(&baseline, &current, true, &[], &None);
        assert!(result);

        // detect_root_escape=false → ルート cgroup の新規プロセスは検知しない
        let result = detect_cgroup_changes(&baseline, &current, false, &[], &None);
        assert!(!result);
    }

    #[test]
    fn test_detect_new_process_unlisted() {
        let baseline = ProcessCgroupSnapshot::new();

        let mut current = ProcessCgroupSnapshot::new();
        current.insert(
            200,
            ProcessCgroupEntry {
                comm: "app".to_string(),
                cgroup_path: "/unknown.slice".to_string(),
            },
        );

        let whitelist = vec![Regex::new(r"^/system\.slice/").unwrap()];
        let result = detect_cgroup_changes(&baseline, &current, true, &whitelist, &None);
        assert!(result);
    }

    #[test]
    fn test_detect_new_process_whitelisted() {
        let baseline = ProcessCgroupSnapshot::new();

        let mut current = ProcessCgroupSnapshot::new();
        current.insert(
            200,
            ProcessCgroupEntry {
                comm: "app".to_string(),
                cgroup_path: "/system.slice/app.service".to_string(),
            },
        );

        let whitelist = vec![Regex::new(r"^/system\.slice/").unwrap()];
        let result = detect_cgroup_changes(&baseline, &current, true, &whitelist, &None);
        assert!(!result);
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let config = ProcessCgroupMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            watch_process_names: vec![],
            whitelist_patterns: vec![],
            detect_root_cgroup_escape: true,
        };
        let mut module = ProcessCgroupMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let config = ProcessCgroupMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            watch_process_names: vec![],
            whitelist_patterns: vec![],
            detect_root_cgroup_escape: true,
        };
        let module = ProcessCgroupMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        // /proc にアクセスできるので少なくとも自プロセスがある
        assert!(result.items_scanned > 0);
        assert_eq!(result.issues_found, 0);
        assert!(result.summary.contains("プロセス cgroup"));

        // スナップショットキーが "proc_cgroup:<pid>:<comm>" 形式であること
        for key in result.snapshot.keys() {
            assert!(key.starts_with("proc_cgroup:"), "unexpected key: {}", key);
        }
    }
}
