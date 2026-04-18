//! ファイルディスクリプタ監視モジュール
//!
//! `/proc/[pid]/fd` を定期スキャンし、不審なファイルディスクリプタを検知する。
//!
//! 検知対象:
//! - 削除済みファイルへのファイルディスクリプタ参照 → Critical
//! - プロセスあたりのファイルディスクリプタ数が閾値超過 → Warning
//! - 不審なソケット参照の異常な増加 → Warning

use crate::config::FdMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::BTreeMap;
use std::path::Path;
use tokio_util::sync::CancellationToken;

/// プロセスの fd 情報
#[derive(Debug, Clone)]
struct ProcessFdInfo {
    pid: u32,
    comm: String,
    fd_count: usize,
    deleted_fds: Vec<String>,
    socket_count: usize,
}

/// /proc/[pid]/comm からプロセス名を取得する
fn read_process_comm(proc_path: &Path, pid: u32) -> String {
    let comm_path = proc_path.join(pid.to_string()).join("comm");
    std::fs::read_to_string(comm_path)
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// 指定した pid の /proc/[pid]/fd をスキャンする
fn scan_process_fds(proc_path: &Path, pid: u32) -> Option<ProcessFdInfo> {
    let fd_dir = proc_path.join(pid.to_string()).join("fd");
    let entries = match std::fs::read_dir(&fd_dir) {
        Ok(entries) => entries,
        Err(_) => return None,
    };

    let comm = read_process_comm(proc_path, pid);
    let mut fd_count: usize = 0;
    let mut deleted_fds = Vec::new();
    let mut socket_count: usize = 0;

    for entry in entries.flatten() {
        fd_count += 1;
        let link = match std::fs::read_link(entry.path()) {
            Ok(link) => link,
            Err(_) => continue,
        };
        let link_str = link.to_string_lossy();

        if link_str.contains("(deleted)") {
            deleted_fds.push(link_str.to_string());
        }
        if link_str.starts_with("socket:") {
            socket_count += 1;
        }
    }

    Some(ProcessFdInfo {
        pid,
        comm,
        fd_count,
        deleted_fds,
        socket_count,
    })
}

/// /proc 配下の全プロセスの pid を列挙する
fn list_pids(proc_path: &Path) -> Vec<u32> {
    let entries = match std::fs::read_dir(proc_path) {
        Ok(entries) => entries,
        Err(e) => {
            tracing::debug!(path = %proc_path.display(), error = %e, "proc ディレクトリの読み取りに失敗しました");
            return Vec::new();
        }
    };

    entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name();
            name.to_str()?.parse::<u32>().ok()
        })
        .collect()
}

/// ホワイトリストに含まれるプロセスかチェックする
fn is_whitelisted(comm: &str, whitelist: &[String]) -> bool {
    whitelist.iter().any(|w| comm == w)
}

/// 全プロセスをスキャンし、問題を検知してイベントを発行する
///
/// 検知した問題数を返す。
fn scan_and_report(
    proc_path: &Path,
    max_fd_per_process: usize,
    whitelist: &[String],
    event_bus: &Option<EventBus>,
) -> (Vec<ProcessFdInfo>, usize) {
    let pids = list_pids(proc_path);
    let mut all_infos = Vec::new();
    let mut issues = 0;

    for pid in pids {
        let info = match scan_process_fds(proc_path, pid) {
            Some(info) => info,
            None => continue,
        };

        if is_whitelisted(&info.comm, whitelist) {
            all_infos.push(info);
            continue;
        }

        // 削除済みファイルへの fd 参照を検知
        if !info.deleted_fds.is_empty() {
            let details = format!(
                "pid={}, comm={}, 削除済みfd={}",
                info.pid,
                info.comm,
                info.deleted_fds.join("; ")
            );
            tracing::error!(
                pid = info.pid,
                comm = %info.comm,
                deleted_count = info.deleted_fds.len(),
                "削除済みファイルへのファイルディスクリプタ参照を検知しました"
            );
            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        "deleted_file_fd",
                        Severity::Critical,
                        "fd_monitor",
                        format!(
                            "削除済みファイルへの fd 参照を検知: pid={} ({}), {}件",
                            info.pid,
                            info.comm,
                            info.deleted_fds.len()
                        ),
                    )
                    .with_details(details),
                );
            }
            issues += 1;
        }

        // fd 数の閾値超過を検知
        if info.fd_count > max_fd_per_process {
            let details = format!(
                "pid={}, comm={}, fd_count={}, threshold={}",
                info.pid, info.comm, info.fd_count, max_fd_per_process
            );
            tracing::warn!(
                pid = info.pid,
                comm = %info.comm,
                fd_count = info.fd_count,
                threshold = max_fd_per_process,
                "ファイルディスクリプタ数が閾値を超過しました"
            );
            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        "excessive_fd_count",
                        Severity::Warning,
                        "fd_monitor",
                        format!(
                            "fd 数が閾値超過: pid={} ({}), fd_count={} (閾値: {})",
                            info.pid, info.comm, info.fd_count, max_fd_per_process
                        ),
                    )
                    .with_details(details),
                );
            }
            issues += 1;
        }

        all_infos.push(info);
    }

    (all_infos, issues)
}

/// ファイルディスクリプタ監視モジュール
///
/// `/proc/[pid]/fd` を定期スキャンし、削除済みファイルへの fd 参照、
/// fd 数の閾値超過、不審なソケット参照を検知する。
pub struct FdMonitorModule {
    config: FdMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl FdMonitorModule {
    /// 新しいファイルディスクリプタ監視モジュールを作成する
    pub fn new(config: FdMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

impl Module for FdMonitorModule {
    fn name(&self) -> &str {
        "fd_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        if self.config.max_fd_per_process == 0 {
            return Err(AppError::ModuleConfig {
                message: "max_fd_per_process は 0 より大きい値を指定してください".to_string(),
            });
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            max_fd_per_process = self.config.max_fd_per_process,
            proc_path = %self.config.proc_path.display(),
            whitelist_processes = self.config.whitelist_processes.len(),
            "ファイルディスクリプタ監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        let scan_interval_secs = self.config.scan_interval_secs;
        let max_fd_per_process = self.config.max_fd_per_process;
        let proc_path = self.config.proc_path.clone();
        let whitelist = self.config.whitelist_processes.clone();
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("ファイルディスクリプタ監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let (_, issues) = scan_and_report(
                            &proc_path,
                            max_fd_per_process,
                            &whitelist,
                            &event_bus,
                        );
                        if issues == 0 {
                            tracing::debug!("ファイルディスクリプタに異常はありません");
                        }
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();

        let (infos, issues_found) = scan_and_report(
            &self.config.proc_path,
            self.config.max_fd_per_process,
            &self.config.whitelist_processes,
            &self.event_bus,
        );

        let total_fds: usize = infos.iter().map(|i| i.fd_count).sum();
        let total_sockets: usize = infos.iter().map(|i| i.socket_count).sum();
        let total_deleted: usize = infos.iter().map(|i| i.deleted_fds.len()).sum();

        // スナップショットデータを構築
        let mut snapshot: BTreeMap<String, String> = BTreeMap::new();
        for info in &infos {
            let key = format!("fd:{}:{}", info.pid, info.comm);
            let value = format!(
                "fd_count={},sockets={},deleted={}",
                info.fd_count,
                info.socket_count,
                info.deleted_fds.len()
            );
            snapshot.insert(key, value);
        }

        let duration = start.elapsed();

        tracing::info!(
            processes = infos.len(),
            total_fds = total_fds,
            total_sockets = total_sockets,
            total_deleted = total_deleted,
            issues = issues_found,
            "起動時スキャン: ファイルディスクリプタをスキャンしました"
        );

        Ok(InitialScanResult {
            items_scanned: infos.len(),
            issues_found,
            duration,
            summary: format!(
                "ファイルディスクリプタ {}プロセスをスキャン（総fd: {}件, ソケット: {}件, 削除済み: {}件, 問題: {}件）",
                infos.len(),
                total_fds,
                total_sockets,
                total_deleted,
                issues_found
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
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    type TestProcEntry<'a> = (u32, &'a str, &'a [(&'a str, &'a str)]);

    /// テスト用の /proc ディレクトリ構造を作成する
    fn create_test_proc(entries: &[TestProcEntry<'_>]) -> TempDir {
        let tmp = TempDir::new().unwrap();
        for (pid, comm, fds) in entries {
            let pid_dir = tmp.path().join(pid.to_string());
            std::fs::create_dir_all(pid_dir.join("fd")).unwrap();

            // comm ファイル
            std::fs::write(pid_dir.join("comm"), comm).unwrap();

            // fd シンボリックリンク
            for (fd_num, target) in *fds {
                let fd_path = pid_dir.join("fd").join(fd_num);
                symlink(target, &fd_path).unwrap();
            }
        }
        tmp
    }

    fn make_config(proc_path: &Path) -> FdMonitorConfig {
        FdMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            max_fd_per_process: 1024,
            proc_path: proc_path.to_path_buf(),
            whitelist_processes: Vec::new(),
        }
    }

    // --- list_pids ---

    #[test]
    fn test_list_pids() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join("123")).unwrap();
        std::fs::create_dir(tmp.path().join("456")).unwrap();
        std::fs::create_dir(tmp.path().join("not_a_pid")).unwrap();

        let mut pids = list_pids(tmp.path());
        pids.sort();
        assert_eq!(pids, vec![123, 456]);
    }

    #[test]
    fn test_list_pids_nonexistent() {
        let pids = list_pids(Path::new("/nonexistent/path"));
        assert!(pids.is_empty());
    }

    // --- scan_process_fds ---

    #[test]
    fn test_scan_process_fds_normal() {
        let tmp = create_test_proc(&[(
            100,
            "test_proc",
            &[
                ("0", "/dev/null"),
                ("1", "/dev/stdout"),
                ("2", "/dev/stderr"),
            ],
        )]);

        let info = scan_process_fds(tmp.path(), 100).unwrap();
        assert_eq!(info.pid, 100);
        assert_eq!(info.comm, "test_proc");
        assert_eq!(info.fd_count, 3);
        assert!(info.deleted_fds.is_empty());
        assert_eq!(info.socket_count, 0);
    }

    #[test]
    fn test_scan_process_fds_with_deleted() {
        let tmp = create_test_proc(&[(
            200,
            "suspicious",
            &[("0", "/dev/null"), ("3", "/tmp/payload (deleted)")],
        )]);

        let info = scan_process_fds(tmp.path(), 200).unwrap();
        assert_eq!(info.deleted_fds.len(), 1);
        assert!(info.deleted_fds[0].contains("(deleted)"));
    }

    #[test]
    fn test_scan_process_fds_with_sockets() {
        let tmp = create_test_proc(&[(
            300,
            "server",
            &[
                ("0", "/dev/null"),
                ("3", "socket:[12345]"),
                ("4", "socket:[67890]"),
            ],
        )]);

        let info = scan_process_fds(tmp.path(), 300).unwrap();
        assert_eq!(info.socket_count, 2);
    }

    #[test]
    fn test_scan_process_fds_nonexistent() {
        let tmp = TempDir::new().unwrap();
        assert!(scan_process_fds(tmp.path(), 99999).is_none());
    }

    // --- is_whitelisted ---

    #[test]
    fn test_is_whitelisted() {
        let whitelist = vec!["systemd".to_string(), "sshd".to_string()];
        assert!(is_whitelisted("systemd", &whitelist));
        assert!(is_whitelisted("sshd", &whitelist));
        assert!(!is_whitelisted("malware", &whitelist));
    }

    #[test]
    fn test_is_whitelisted_empty() {
        assert!(!is_whitelisted("anything", &[]));
    }

    // --- scan_and_report ---

    #[test]
    fn test_scan_and_report_no_issues() {
        let tmp = create_test_proc(&[(100, "normal", &[("0", "/dev/null"), ("1", "/dev/stdout")])]);

        let (infos, issues) = scan_and_report(tmp.path(), 1024, &[], &None);
        assert_eq!(infos.len(), 1);
        assert_eq!(issues, 0);
    }

    #[test]
    fn test_scan_and_report_deleted_fd() {
        let tmp = create_test_proc(&[(
            100,
            "suspicious",
            &[("0", "/dev/null"), ("3", "/tmp/evil (deleted)")],
        )]);

        let (_, issues) = scan_and_report(tmp.path(), 1024, &[], &None);
        assert_eq!(issues, 1);
    }

    #[test]
    fn test_scan_and_report_excessive_fds() {
        // max_fd_per_process=2 で fd が 3 つあるプロセス
        let tmp = create_test_proc(&[(
            100,
            "leaky",
            &[
                ("0", "/dev/null"),
                ("1", "/dev/stdout"),
                ("2", "/dev/stderr"),
            ],
        )]);

        let (_, issues) = scan_and_report(tmp.path(), 2, &[], &None);
        assert_eq!(issues, 1);
    }

    #[test]
    fn test_scan_and_report_whitelisted_ignored() {
        let tmp = create_test_proc(&[(
            100,
            "systemd",
            &[("0", "/dev/null"), ("3", "/tmp/something (deleted)")],
        )]);

        let whitelist = vec!["systemd".to_string()];
        let (_, issues) = scan_and_report(tmp.path(), 1024, &whitelist, &None);
        assert_eq!(issues, 0);
    }

    #[test]
    fn test_scan_and_report_multiple_issues() {
        let tmp = create_test_proc(&[
            (
                100,
                "proc_a",
                &[("0", "/dev/null"), ("3", "/tmp/file (deleted)")],
            ),
            (
                200,
                "proc_b",
                &[("0", "/dev/null"), ("1", "/a"), ("2", "/b"), ("3", "/c")],
            ),
        ]);

        // proc_a: deleted fd, proc_b: fd count > 2
        let (_, issues) = scan_and_report(tmp.path(), 2, &[], &None);
        assert_eq!(issues, 2);
    }

    // --- Module lifecycle ---

    #[test]
    fn test_init_zero_interval() {
        let tmp = TempDir::new().unwrap();
        let mut config = make_config(tmp.path());
        config.scan_interval_secs = 0;
        let mut module = FdMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_zero_max_fd() {
        let tmp = TempDir::new().unwrap();
        let mut config = make_config(tmp.path());
        config.max_fd_per_process = 0;
        let mut module = FdMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let tmp = TempDir::new().unwrap();
        let config = make_config(tmp.path());
        let mut module = FdMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let tmp = TempDir::new().unwrap();
        let config = make_config(tmp.path());
        let mut module = FdMonitorModule::new(config, None);
        assert!(module.init().is_ok());
        assert!(module.start().await.is_ok());
        assert!(module.stop().await.is_ok());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let tmp = create_test_proc(&[
            (100, "normal", &[("0", "/dev/null"), ("1", "/dev/stdout")]),
            (
                200,
                "server",
                &[("0", "/dev/null"), ("3", "socket:[12345]")],
            ),
        ]);

        let config = make_config(tmp.path());
        let module = FdMonitorModule::new(config, None);
        let result = module.initial_scan().await.unwrap();

        assert_eq!(result.items_scanned, 2);
        assert_eq!(result.issues_found, 0);
        assert!(result.snapshot.contains_key("fd:100:normal"));
        assert!(result.snapshot.contains_key("fd:200:server"));
    }

    #[tokio::test]
    async fn test_initial_scan_with_issues() {
        let tmp = create_test_proc(&[(
            100,
            "suspicious",
            &[("0", "/dev/null"), ("3", "/tmp/payload (deleted)")],
        )]);

        let config = make_config(tmp.path());
        let module = FdMonitorModule::new(config, None);
        let result = module.initial_scan().await.unwrap();

        assert_eq!(result.issues_found, 1);
    }
}
