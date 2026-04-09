//! プロセス権限昇格検知モジュール
//!
//! `/proc/[pid]/status` を定期スキャンし、プロセスの UID/GID 変化を追跡して
//! 不正な権限昇格を検知する。
//!
//! 検知対象:
//! - Effective UID が 0（root）に変化
//! - Effective UID が非特権（≥1000）から特権（<1000）に変化
//! - Effective GID が 0（root）に変化
//! - Saved UID の変化
//! - その他の UID/GID 変化

use crate::config::PrivilegeEscalationMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use tokio_util::sync::CancellationToken;

/// プロセスの UID/GID 情報
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessUidGid {
    /// プロセス ID
    pid: u32,
    /// プロセス名（/proc/[pid]/comm から取得）
    comm: String,
    /// UID: [Real, Effective, Saved, FS]
    uid: [u32; 4],
    /// GID: [Real, Effective, Saved, FS]
    gid: [u32; 4],
}

/// プロセス権限昇格検知モジュール
///
/// `/proc/[pid]/status` を定期スキャンし、UID/GID の変化を検知する。
pub struct PrivilegeEscalationMonitorModule {
    config: PrivilegeEscalationMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl PrivilegeEscalationMonitorModule {
    /// 新しいプロセス権限昇格検知モジュールを作成する
    pub fn new(config: PrivilegeEscalationMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// `/proc/[pid]/comm` からプロセス名を読み取る
    fn read_comm(proc_path: &Path, pid: u32) -> Option<String> {
        let comm_path = proc_path.join(pid.to_string()).join("comm");
        std::fs::read_to_string(&comm_path)
            .ok()
            .map(|s| s.trim().to_string())
    }

    /// `/proc/[pid]/status` から Uid: と Gid: 行をパースする
    fn parse_status(proc_path: &Path, pid: u32) -> Option<([u32; 4], [u32; 4])> {
        let status_path = proc_path.join(pid.to_string()).join("status");
        let content = std::fs::read_to_string(&status_path).ok()?;
        Self::parse_uid_gid_from_status(&content)
    }

    /// status ファイルの内容から UID/GID をパースする
    fn parse_uid_gid_from_status(content: &str) -> Option<([u32; 4], [u32; 4])> {
        let mut uid: Option<[u32; 4]> = None;
        let mut gid: Option<[u32; 4]> = None;

        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                let values: Vec<u32> = rest
                    .split_whitespace()
                    .filter_map(|v| v.parse().ok())
                    .collect();
                if values.len() >= 4 {
                    uid = Some([values[0], values[1], values[2], values[3]]);
                }
            } else if let Some(rest) = line.strip_prefix("Gid:") {
                let values: Vec<u32> = rest
                    .split_whitespace()
                    .filter_map(|v| v.parse().ok())
                    .collect();
                if values.len() >= 4 {
                    gid = Some([values[0], values[1], values[2], values[3]]);
                }
            }
            if uid.is_some() && gid.is_some() {
                break;
            }
        }

        match (uid, gid) {
            (Some(u), Some(g)) => Some((u, g)),
            _ => None,
        }
    }

    /// /proc から全プロセスの UID/GID スナップショットを取得する
    fn scan(proc_path: &Path, whitelist_processes: &[String]) -> HashMap<u32, ProcessUidGid> {
        let mut snapshot = HashMap::new();

        let entries = match std::fs::read_dir(proc_path) {
            Ok(e) => e,
            Err(err) => {
                tracing::debug!(
                    error = %err,
                    path = %proc_path.display(),
                    "/proc の読み取りに失敗しました"
                );
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
            let pid: u32 = match name.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            // プロセス名を取得
            let comm = match Self::read_comm(proc_path, pid) {
                Some(c) => c,
                None => continue,
            };

            // ホワイトリストチェック
            if whitelist_processes.iter().any(|w| w == &comm) {
                continue;
            }

            // UID/GID を取得
            if let Some((uid, gid)) = Self::parse_status(proc_path, pid) {
                snapshot.insert(
                    pid,
                    ProcessUidGid {
                        pid,
                        comm,
                        uid,
                        gid,
                    },
                );
            }
        }

        snapshot
    }

    /// ベースラインと現在のスナップショットを比較し、権限昇格を検知する
    fn detect_and_report(
        baseline: &HashMap<u32, ProcessUidGid>,
        current: &HashMap<u32, ProcessUidGid>,
        event_bus: &Option<EventBus>,
    ) -> bool {
        let mut has_changes = false;

        for (pid, cur_info) in current {
            let prev_info = match baseline.get(pid) {
                Some(p) => p,
                None => continue, // 新規プロセスは変化検知の対象外
            };

            // プロセス名が変わっていたらスキップ（PID 再利用）
            if prev_info.comm != cur_info.comm {
                continue;
            }

            // Effective UID の変化チェック
            let prev_euid = prev_info.uid[1];
            let cur_euid = cur_info.uid[1];

            if prev_euid != cur_euid {
                if cur_euid == 0 {
                    // root への権限昇格
                    let msg = format!(
                        "プロセスの Effective UID が root(0) に変化しました: pid={}, comm={}, prev_euid={}",
                        pid, cur_info.comm, prev_euid
                    );
                    tracing::warn!(%pid, comm = %cur_info.comm, prev_euid, "権限昇格を検知（root）");
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "privilege_escalation_to_root",
                                Severity::Critical,
                                "privilege_escalation_monitor",
                                &msg,
                            )
                            .with_details(format!(
                                "pid={}, comm={}, uid=[{},{},{},{}]->[{},{},{},{}]",
                                pid,
                                cur_info.comm,
                                prev_info.uid[0],
                                prev_info.uid[1],
                                prev_info.uid[2],
                                prev_info.uid[3],
                                cur_info.uid[0],
                                cur_info.uid[1],
                                cur_info.uid[2],
                                cur_info.uid[3],
                            )),
                        );
                    }
                    has_changes = true;
                } else if prev_euid >= 1000 && cur_euid < 1000 {
                    // 非特権から特権への昇格
                    let msg = format!(
                        "プロセスの Effective UID が特権ユーザーに変化しました: pid={}, comm={}, {}->{}",
                        pid, cur_info.comm, prev_euid, cur_euid
                    );
                    tracing::warn!(%pid, comm = %cur_info.comm, prev_euid, cur_euid, "権限昇格を検知");
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "privilege_escalation",
                                Severity::Warning,
                                "privilege_escalation_monitor",
                                &msg,
                            )
                            .with_details(format!(
                                "pid={}, comm={}, uid=[{},{},{},{}]->[{},{},{},{}]",
                                pid,
                                cur_info.comm,
                                prev_info.uid[0],
                                prev_info.uid[1],
                                prev_info.uid[2],
                                prev_info.uid[3],
                                cur_info.uid[0],
                                cur_info.uid[1],
                                cur_info.uid[2],
                                cur_info.uid[3],
                            )),
                        );
                    }
                    has_changes = true;
                } else {
                    // その他の UID 変化
                    let msg = format!(
                        "プロセスの UID が変化しました: pid={}, comm={}, euid: {}->{}",
                        pid, cur_info.comm, prev_euid, cur_euid
                    );
                    tracing::info!(%pid, comm = %cur_info.comm, prev_euid, cur_euid, "UID 変化を検知");
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "uid_gid_changed",
                                Severity::Info,
                                "privilege_escalation_monitor",
                                &msg,
                            )
                            .with_details(format!(
                                "pid={}, comm={}, uid=[{},{},{},{}]->[{},{},{},{}]",
                                pid,
                                cur_info.comm,
                                prev_info.uid[0],
                                prev_info.uid[1],
                                prev_info.uid[2],
                                prev_info.uid[3],
                                cur_info.uid[0],
                                cur_info.uid[1],
                                cur_info.uid[2],
                                cur_info.uid[3],
                            )),
                        );
                    }
                    has_changes = true;
                }
            }

            // Effective GID の変化チェック
            let prev_egid = prev_info.gid[1];
            let cur_egid = cur_info.gid[1];

            if prev_egid != cur_egid && cur_egid == 0 {
                let msg = format!(
                    "プロセスの Effective GID が root(0) に変化しました: pid={}, comm={}, prev_egid={}",
                    pid, cur_info.comm, prev_egid
                );
                tracing::warn!(%pid, comm = %cur_info.comm, prev_egid, "GID 昇格を検知（root）");
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "gid_escalation_to_root",
                            Severity::Warning,
                            "privilege_escalation_monitor",
                            &msg,
                        )
                        .with_details(format!(
                            "pid={}, comm={}, gid=[{},{},{},{}]->[{},{},{},{}]",
                            pid,
                            cur_info.comm,
                            prev_info.gid[0],
                            prev_info.gid[1],
                            prev_info.gid[2],
                            prev_info.gid[3],
                            cur_info.gid[0],
                            cur_info.gid[1],
                            cur_info.gid[2],
                            cur_info.gid[3],
                        )),
                    );
                }
                has_changes = true;
            }

            // Saved UID の変化チェック
            let prev_suid = prev_info.uid[2];
            let cur_suid = cur_info.uid[2];

            if prev_suid != cur_suid {
                let msg = format!(
                    "プロセスの Saved UID が変化しました: pid={}, comm={}, {}->{}",
                    pid, cur_info.comm, prev_suid, cur_suid
                );
                tracing::info!(%pid, comm = %cur_info.comm, prev_suid, cur_suid, "Saved UID 変化を検知");
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "saved_uid_changed",
                            Severity::Info,
                            "privilege_escalation_monitor",
                            &msg,
                        )
                        .with_details(format!(
                            "pid={}, comm={}, saved_uid: {}->{}",
                            pid, cur_info.comm, prev_suid, cur_suid
                        )),
                    );
                }
                has_changes = true;
            }
        }

        has_changes
    }
}

impl Module for PrivilegeEscalationMonitorModule {
    fn name(&self) -> &str {
        "privilege_escalation_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        if !self.config.proc_path.exists() {
            tracing::warn!(
                path = %self.config.proc_path.display(),
                "/proc が存在しません。権限昇格検知が動作しない可能性があります"
            );
        }

        tracing::info!(
            proc_path = %self.config.proc_path.display(),
            scan_interval_secs = self.config.scan_interval_secs,
            whitelist_count = self.config.whitelist_processes.len(),
            "プロセス権限昇格検知モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<(), AppError> {
        let baseline = Self::scan(&self.config.proc_path, &self.config.whitelist_processes);
        tracing::info!(
            process_count = baseline.len(),
            "権限昇格検知ベースラインスキャンが完了しました"
        );

        let proc_path = self.config.proc_path.clone();
        let scan_interval_secs = self.config.scan_interval_secs;
        let whitelist_processes = self.config.whitelist_processes.clone();
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
                        tracing::info!("プロセス権限昇格検知モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = PrivilegeEscalationMonitorModule::scan(
                            &proc_path,
                            &whitelist_processes,
                        );
                        let changed = PrivilegeEscalationMonitorModule::detect_and_report(
                            &baseline,
                            &current,
                            &event_bus,
                        );

                        if changed {
                            baseline = current;
                        } else {
                            tracing::debug!("プロセス権限に変更はありません");
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

        let snapshot = Self::scan(&self.config.proc_path, &self.config.whitelist_processes);

        let mut issues_found = 0;

        // Effective UID が root のプロセスを記録
        for info in snapshot.values() {
            if info.uid[1] == 0 {
                tracing::info!(
                    pid = info.pid,
                    comm = %info.comm,
                    "root 権限で実行中のプロセスを検出"
                );
                issues_found += 1;
            }
        }

        let items_scanned = snapshot.len();

        // スナップショットデータの構築
        let mut scan_snapshot = BTreeMap::new();
        for (pid, info) in &snapshot {
            scan_snapshot.insert(
                format!("pid:{}", pid),
                format!(
                    "comm={},uid=[{},{},{},{}],gid=[{},{},{},{}]",
                    info.comm,
                    info.uid[0],
                    info.uid[1],
                    info.uid[2],
                    info.uid[3],
                    info.gid[0],
                    info.gid[1],
                    info.gid[2],
                    info.gid[3],
                ),
            );
        }

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "プロセス権限をスキャンしました（{}プロセス）。root 権限プロセス: {}件",
                items_scanned, issues_found
            ),
            snapshot: scan_snapshot,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn create_mock_proc(base: &Path, pid: u32, comm: &str, uid: [u32; 4], gid: [u32; 4]) {
        let pid_dir = base.join(pid.to_string());
        fs::create_dir_all(&pid_dir).unwrap();
        fs::write(pid_dir.join("comm"), format!("{}\n", comm)).unwrap();
        let status_content = format!(
            "Name:\t{}\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t{}\nNgid:\t0\nPid:\t{}\nUid:\t{}\t{}\t{}\t{}\nGid:\t{}\t{}\t{}\t{}\n",
            comm, pid, pid, uid[0], uid[1], uid[2], uid[3], gid[0], gid[1], gid[2], gid[3],
        );
        fs::write(pid_dir.join("status"), status_content).unwrap();
    }

    #[test]
    fn test_parse_uid_gid_from_status() {
        let content = "\
Name:\tbash
Umask:\t0022
State:\tS (sleeping)
Tgid:\t1234
Pid:\t1234
Uid:\t1000\t1000\t1000\t1000
Gid:\t1000\t1000\t1000\t1000
";
        let result = PrivilegeEscalationMonitorModule::parse_uid_gid_from_status(content);
        assert!(result.is_some());
        let (uid, gid) = result.unwrap();
        assert_eq!(uid, [1000, 1000, 1000, 1000]);
        assert_eq!(gid, [1000, 1000, 1000, 1000]);
    }

    #[test]
    fn test_parse_uid_gid_from_status_root() {
        let content = "\
Name:\tinit
Uid:\t0\t0\t0\t0
Gid:\t0\t0\t0\t0
";
        let result = PrivilegeEscalationMonitorModule::parse_uid_gid_from_status(content);
        assert!(result.is_some());
        let (uid, gid) = result.unwrap();
        assert_eq!(uid, [0, 0, 0, 0]);
        assert_eq!(gid, [0, 0, 0, 0]);
    }

    #[test]
    fn test_parse_uid_gid_from_status_incomplete() {
        let content = "Name:\tbash\nUid:\t1000\t1000\n";
        let result = PrivilegeEscalationMonitorModule::parse_uid_gid_from_status(content);
        assert!(result.is_none());
    }

    #[test]
    fn test_scan_mock_proc() {
        let tmp = tempfile::tempdir().unwrap();
        let proc_path = tmp.path();

        create_mock_proc(
            proc_path,
            100,
            "bash",
            [1000, 1000, 1000, 1000],
            [1000, 1000, 1000, 1000],
        );
        create_mock_proc(proc_path, 200, "nginx", [33, 33, 33, 33], [33, 33, 33, 33]);

        let whitelist: Vec<String> = vec![];
        let snapshot = PrivilegeEscalationMonitorModule::scan(proc_path, &whitelist);

        assert_eq!(snapshot.len(), 2);
        assert_eq!(snapshot[&100].comm, "bash");
        assert_eq!(snapshot[&200].comm, "nginx");
    }

    #[test]
    fn test_scan_whitelist_filtering() {
        let tmp = tempfile::tempdir().unwrap();
        let proc_path = tmp.path();

        create_mock_proc(
            proc_path,
            100,
            "bash",
            [1000, 1000, 1000, 1000],
            [1000, 1000, 1000, 1000],
        );
        create_mock_proc(proc_path, 200, "sudo", [0, 0, 0, 0], [0, 0, 0, 0]);
        create_mock_proc(proc_path, 300, "sshd", [0, 0, 0, 0], [0, 0, 0, 0]);

        let whitelist = vec!["sudo".to_string(), "sshd".to_string()];
        let snapshot = PrivilegeEscalationMonitorModule::scan(proc_path, &whitelist);

        assert_eq!(snapshot.len(), 1);
        assert!(snapshot.contains_key(&100));
        assert!(!snapshot.contains_key(&200));
        assert!(!snapshot.contains_key(&300));
    }

    #[test]
    fn test_detect_escalation_to_root() {
        let mut baseline = HashMap::new();
        baseline.insert(
            100,
            ProcessUidGid {
                pid: 100,
                comm: "exploit".to_string(),
                uid: [1000, 1000, 1000, 1000],
                gid: [1000, 1000, 1000, 1000],
            },
        );

        let mut current = HashMap::new();
        current.insert(
            100,
            ProcessUidGid {
                pid: 100,
                comm: "exploit".to_string(),
                uid: [1000, 0, 1000, 1000],
                gid: [1000, 1000, 1000, 1000],
            },
        );

        let changed =
            PrivilegeEscalationMonitorModule::detect_and_report(&baseline, &current, &None);
        assert!(changed);
    }

    #[test]
    fn test_detect_escalation_to_privileged() {
        let mut baseline = HashMap::new();
        baseline.insert(
            100,
            ProcessUidGid {
                pid: 100,
                comm: "app".to_string(),
                uid: [1000, 1000, 1000, 1000],
                gid: [1000, 1000, 1000, 1000],
            },
        );

        let mut current = HashMap::new();
        current.insert(
            100,
            ProcessUidGid {
                pid: 100,
                comm: "app".to_string(),
                uid: [1000, 33, 1000, 1000], // www-data (33)
                gid: [1000, 1000, 1000, 1000],
            },
        );

        let changed =
            PrivilegeEscalationMonitorModule::detect_and_report(&baseline, &current, &None);
        assert!(changed);
    }

    #[test]
    fn test_detect_gid_escalation_to_root() {
        let mut baseline = HashMap::new();
        baseline.insert(
            100,
            ProcessUidGid {
                pid: 100,
                comm: "app".to_string(),
                uid: [1000, 1000, 1000, 1000],
                gid: [1000, 1000, 1000, 1000],
            },
        );

        let mut current = HashMap::new();
        current.insert(
            100,
            ProcessUidGid {
                pid: 100,
                comm: "app".to_string(),
                uid: [1000, 1000, 1000, 1000],
                gid: [1000, 0, 1000, 1000],
            },
        );

        let changed =
            PrivilegeEscalationMonitorModule::detect_and_report(&baseline, &current, &None);
        assert!(changed);
    }

    #[test]
    fn test_detect_saved_uid_changed() {
        let mut baseline = HashMap::new();
        baseline.insert(
            100,
            ProcessUidGid {
                pid: 100,
                comm: "app".to_string(),
                uid: [1000, 1000, 1000, 1000],
                gid: [1000, 1000, 1000, 1000],
            },
        );

        let mut current = HashMap::new();
        current.insert(
            100,
            ProcessUidGid {
                pid: 100,
                comm: "app".to_string(),
                uid: [1000, 1000, 0, 1000],
                gid: [1000, 1000, 1000, 1000],
            },
        );

        let changed =
            PrivilegeEscalationMonitorModule::detect_and_report(&baseline, &current, &None);
        assert!(changed);
    }

    #[test]
    fn test_no_change_detected() {
        let mut baseline = HashMap::new();
        baseline.insert(
            100,
            ProcessUidGid {
                pid: 100,
                comm: "bash".to_string(),
                uid: [1000, 1000, 1000, 1000],
                gid: [1000, 1000, 1000, 1000],
            },
        );

        let current = baseline.clone();

        let changed =
            PrivilegeEscalationMonitorModule::detect_and_report(&baseline, &current, &None);
        assert!(!changed);
    }

    #[test]
    fn test_pid_reuse_skipped() {
        let mut baseline = HashMap::new();
        baseline.insert(
            100,
            ProcessUidGid {
                pid: 100,
                comm: "old_process".to_string(),
                uid: [1000, 1000, 1000, 1000],
                gid: [1000, 1000, 1000, 1000],
            },
        );

        let mut current = HashMap::new();
        current.insert(
            100,
            ProcessUidGid {
                pid: 100,
                comm: "new_process".to_string(),
                uid: [0, 0, 0, 0],
                gid: [0, 0, 0, 0],
            },
        );

        // PID was reused, comm differs — should not trigger
        let changed =
            PrivilegeEscalationMonitorModule::detect_and_report(&baseline, &current, &None);
        assert!(!changed);
    }

    #[test]
    fn test_new_process_not_flagged() {
        let baseline: HashMap<u32, ProcessUidGid> = HashMap::new();

        let mut current = HashMap::new();
        current.insert(
            100,
            ProcessUidGid {
                pid: 100,
                comm: "root_process".to_string(),
                uid: [0, 0, 0, 0],
                gid: [0, 0, 0, 0],
            },
        );

        // New process not in baseline should not trigger change detection
        let changed =
            PrivilegeEscalationMonitorModule::detect_and_report(&baseline, &current, &None);
        assert!(!changed);
    }

    #[tokio::test]
    async fn test_initial_scan_counts_root_processes() {
        let tmp = tempfile::tempdir().unwrap();
        let proc_path = tmp.path();

        create_mock_proc(proc_path, 1, "init", [0, 0, 0, 0], [0, 0, 0, 0]);
        create_mock_proc(
            proc_path,
            100,
            "bash",
            [1000, 1000, 1000, 1000],
            [1000, 1000, 1000, 1000],
        );
        create_mock_proc(proc_path, 200, "daemon", [0, 0, 0, 0], [0, 0, 0, 0]);

        let config = PrivilegeEscalationMonitorConfig {
            enabled: true,
            scan_interval_secs: 5,
            whitelist_processes: vec![],
            proc_path: proc_path.to_path_buf(),
        };

        let module = PrivilegeEscalationMonitorModule::new(config, None);
        let result = module.initial_scan().await.unwrap();

        assert_eq!(result.items_scanned, 3);
        assert_eq!(result.issues_found, 2); // init and daemon are root
    }

    #[test]
    fn test_scan_non_numeric_dirs_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        let proc_path = tmp.path();

        // Create non-numeric dirs like /proc/self, /proc/net
        fs::create_dir_all(proc_path.join("self")).unwrap();
        fs::create_dir_all(proc_path.join("net")).unwrap();
        create_mock_proc(
            proc_path,
            42,
            "test",
            [1000, 1000, 1000, 1000],
            [1000, 1000, 1000, 1000],
        );

        let whitelist: Vec<String> = vec![];
        let snapshot = PrivilegeEscalationMonitorModule::scan(proc_path, &whitelist);

        assert_eq!(snapshot.len(), 1);
        assert!(snapshot.contains_key(&42));
    }
}
