//! namespaces 詳細監視モジュール
//!
//! 全プロセスの `/proc/[pid]/ns/` 配下の namespace リンクを定期スキャンし、
//! 前回スキャンとの差分を検出する。init プロセス（PID 1）の namespace を
//! ベースラインとして各プロセスの namespace 構成を比較し、コンテナ脱出や
//! サンドボックス回避の兆候を検知する。
//!
//! 検知対象:
//! - プロセスの namespace inode が前回スキャンから変化した場合
//! - init namespace と異なる namespace を持つ新規プロセスの出現
//! - namespace スキャン中の異常（大量変化等）

use crate::config::NamespaceMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use tokio_util::sync::CancellationToken;

/// プロセスごとの namespace スナップショット（namespace名 → inode番号）
type NsInodes = BTreeMap<String, u64>;

/// 全プロセスの namespace スナップショット（PID → namespace inodes）
#[derive(Debug, Clone)]
struct ProcessNamespaceSnapshot {
    /// 各プロセスの namespace inode（PID → (namespace名 → inode)）
    processes: HashMap<u32, ProcessInfo>,
    /// init プロセス（PID 1）の namespace inode
    init_namespaces: NsInodes,
}

/// 個別プロセスの情報
#[derive(Debug, Clone)]
struct ProcessInfo {
    /// プロセス名（/proc/[pid]/comm から取得）
    comm: String,
    /// namespace inode マップ
    namespaces: NsInodes,
}

/// `/proc/[pid]/ns/{name}` の inode 番号を取得する
fn read_namespace_inode(ns_dir: &Path, ns_name: &str) -> Option<u64> {
    let ns_path = ns_dir.join(ns_name);
    let metadata = match std::fs::symlink_metadata(&ns_path) {
        Ok(m) => m,
        Err(_) => return None,
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(metadata.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

/// `/proc/[pid]/comm` からプロセス名を取得する
fn read_process_comm(proc_path: &Path, pid: u32) -> String {
    let comm_path = proc_path.join(format!("{}/comm", pid));
    std::fs::read_to_string(&comm_path)
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// 特定プロセスの namespace inode を取得する
fn read_process_namespaces(proc_path: &Path, pid: u32, watch_namespaces: &[String]) -> NsInodes {
    let ns_dir = proc_path.join(format!("{}/ns", pid));
    let mut namespaces = BTreeMap::new();
    for ns_name in watch_namespaces {
        if let Some(inode) = read_namespace_inode(&ns_dir, ns_name) {
            namespaces.insert(ns_name.clone(), inode);
        }
    }
    namespaces
}

/// `/proc/` から全 PID を列挙する
fn list_pids(proc_path: &Path) -> Vec<u32> {
    let entries = match std::fs::read_dir(proc_path) {
        Ok(e) => e,
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

/// 全プロセスの namespace スナップショットを取得する
fn take_snapshot(
    proc_path: &Path,
    watch_namespaces: &[String],
    exclude_processes: &[String],
) -> ProcessNamespaceSnapshot {
    let pids = list_pids(proc_path);

    // init プロセスの namespace を取得
    let init_namespaces = read_process_namespaces(proc_path, 1, watch_namespaces);

    let mut processes = HashMap::new();
    for pid in pids {
        let comm = read_process_comm(proc_path, pid);
        // 除外プロセスをスキップ
        if exclude_processes.contains(&comm) {
            continue;
        }
        let namespaces = read_process_namespaces(proc_path, pid, watch_namespaces);
        if !namespaces.is_empty() {
            processes.insert(pid, ProcessInfo { comm, namespaces });
        }
    }

    ProcessNamespaceSnapshot {
        processes,
        init_namespaces,
    }
}

/// namespaces 詳細監視モジュール
///
/// 全プロセスの `/proc/[pid]/ns/` を定期スキャンし、
/// namespace の変更やコンテナ脱出の兆候を検知する。
pub struct NamespaceMonitorModule {
    config: NamespaceMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl NamespaceMonitorModule {
    /// 新しい namespaces 詳細監視モジュールを作成する
    pub fn new(config: NamespaceMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// 前回スナップショットと現在のスナップショットを比較し、変更を検知してイベント発行する
    fn detect_changes(
        prev: &ProcessNamespaceSnapshot,
        current: &ProcessNamespaceSnapshot,
        event_bus: &Option<EventBus>,
        alert_on_new_ns: bool,
    ) -> usize {
        let mut change_count = 0;

        // 既知プロセスの namespace 変更を検知
        for (pid, current_info) in &current.processes {
            if let Some(prev_info) = prev.processes.get(pid) {
                // 同一 PID のプロセスの namespace inode が変化したか確認
                for (ns_name, current_inode) in &current_info.namespaces {
                    if let Some(prev_inode) = prev_info.namespaces.get(ns_name)
                        && prev_inode != current_inode
                    {
                        let details = format!(
                            "PID={}, プロセス名={}, namespace={}, 旧inode={}, 新inode={}",
                            pid, current_info.comm, ns_name, prev_inode, current_inode
                        );
                        tracing::warn!(
                            pid = pid,
                            comm = %current_info.comm,
                            namespace = %ns_name,
                            old_inode = prev_inode,
                            new_inode = current_inode,
                            "プロセスの namespace inode が変化しました"
                        );
                        if let Some(bus) = event_bus {
                            bus.publish(
                                SecurityEvent::new(
                                    "namespace_changed",
                                    Severity::Critical,
                                    "namespace_monitor",
                                    "プロセスの namespace inode が変化しました（コンテナ脱出/サンドボックス回避の疑い）",
                                )
                                .with_details(details),
                            );
                        }
                        change_count += 1;
                    }
                }
            }
        }

        // init namespace と異なる namespace を持つ新規プロセスの検知
        if alert_on_new_ns && !current.init_namespaces.is_empty() {
            for (pid, current_info) in &current.processes {
                // 前回スキャンに存在しなかったプロセスのみ
                if prev.processes.contains_key(pid) {
                    continue;
                }
                // PID 1 自体はスキップ
                if *pid == 1 {
                    continue;
                }
                // init namespace と比較
                let has_different_ns = current_info.namespaces.iter().any(|(ns_name, inode)| {
                    current
                        .init_namespaces
                        .get(ns_name)
                        .is_some_and(|init_inode| init_inode != inode)
                });
                if has_different_ns {
                    let diff_ns: Vec<String> = current_info
                        .namespaces
                        .iter()
                        .filter(|(ns_name, inode)| {
                            current
                                .init_namespaces
                                .get(*ns_name)
                                .is_some_and(|init_inode| init_inode != *inode)
                        })
                        .map(|(ns_name, _)| ns_name.clone())
                        .collect();
                    let details = format!(
                        "PID={}, プロセス名={}, 差異のある namespace={}",
                        pid,
                        current_info.comm,
                        diff_ns.join(", ")
                    );
                    tracing::info!(
                        pid = pid,
                        comm = %current_info.comm,
                        different_namespaces = ?diff_ns,
                        "init namespace と異なる namespace を持つ新規プロセスを検出"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "new_namespace_detected",
                                Severity::Warning,
                                "namespace_monitor",
                                "init namespace と異なる namespace を持つ新規プロセスを検出",
                            )
                            .with_details(details),
                        );
                    }
                    change_count += 1;
                }
            }
        }

        // 大量変化の異常検知
        if change_count > 10 {
            let details = format!("namespace 変化件数={}", change_count);
            tracing::warn!(
                change_count = change_count,
                "namespace の大量変化を検知しました"
            );
            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        "namespace_scan_anomaly",
                        Severity::Critical,
                        "namespace_monitor",
                        "namespace の大量変化を検知しました（攻撃の可能性）",
                    )
                    .with_details(details),
                );
            }
        }

        change_count
    }
}

impl Module for NamespaceMonitorModule {
    fn name(&self) -> &str {
        "namespace_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }
        if self.config.watch_namespaces.is_empty() {
            return Err(AppError::ModuleConfig {
                message: "watch_namespaces に少なくとも 1 つの名前空間を指定してください"
                    .to_string(),
            });
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            watch_namespaces = ?self.config.watch_namespaces,
            exclude_processes = ?self.config.exclude_processes,
            alert_on_new_ns = self.config.alert_on_new_ns,
            "namespaces 詳細監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        let baseline = take_snapshot(
            Path::new("/proc"),
            &self.config.watch_namespaces,
            &self.config.exclude_processes,
        );
        tracing::info!(
            process_count = baseline.processes.len(),
            init_ns_count = baseline.init_namespaces.len(),
            "namespaces 詳細監視ベースラインスキャンが完了しました"
        );

        let watch_namespaces = self.config.watch_namespaces.clone();
        let exclude_processes = self.config.exclude_processes.clone();
        let scan_interval_secs = self.config.scan_interval_secs;
        let alert_on_new_ns = self.config.alert_on_new_ns;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            interval.tick().await;

            let mut prev_snapshot = baseline;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("namespaces 詳細監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = take_snapshot(
                            Path::new("/proc"),
                            &watch_namespaces,
                            &exclude_processes,
                        );
                        let changes = Self::detect_changes(
                            &prev_snapshot,
                            &current,
                            &event_bus,
                            alert_on_new_ns,
                        );

                        if changes > 0 {
                            tracing::info!(
                                changes = changes,
                                "namespace 変更を検知しました"
                            );
                        } else {
                            tracing::debug!("namespace に変更はありません");
                        }

                        prev_snapshot = current;
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();
        let snapshot = take_snapshot(
            Path::new("/proc"),
            &self.config.watch_namespaces,
            &self.config.exclude_processes,
        );

        let items_scanned = snapshot.processes.len();
        let mut issues_found = 0;

        // init namespace と異なる namespace を持つプロセスを検出
        if !snapshot.init_namespaces.is_empty() {
            for (pid, info) in &snapshot.processes {
                if *pid == 1 {
                    continue;
                }
                let has_different_ns = info.namespaces.iter().any(|(ns_name, inode)| {
                    snapshot
                        .init_namespaces
                        .get(ns_name)
                        .is_some_and(|init_inode| init_inode != inode)
                });
                if has_different_ns {
                    tracing::info!(
                        pid = pid,
                        comm = %info.comm,
                        "起動時スキャン: init namespace と異なるプロセスを検出"
                    );
                    if let Some(bus) = &self.event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "namespace_startup_detected",
                                Severity::Info,
                                "namespace_monitor",
                                "起動時スキャン: init namespace と異なるプロセスを検出",
                            )
                            .with_details(format!("PID={}, プロセス名={}", pid, info.comm)),
                        );
                    }
                    issues_found += 1;
                }
            }
        }

        // init namespace の情報をログに記録
        for (ns_name, inode) in &snapshot.init_namespaces {
            tracing::info!(
                namespace = %ns_name,
                inode = inode,
                "起動時スキャン: init namespace を記録"
            );
        }

        // スナップショットデータの構築
        let mut scan_snapshot = BTreeMap::new();
        for (ns_name, inode) in &snapshot.init_namespaces {
            scan_snapshot.insert(format!("init_ns:{}", ns_name), inode.to_string());
        }
        scan_snapshot.insert("process_count".to_string(), items_scanned.to_string());
        scan_snapshot.insert("non_init_ns_count".to_string(), issues_found.to_string());

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "プロセス {}件をスキャン、init namespace と異なるプロセス {}件を検出",
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

    fn default_config() -> NamespaceMonitorConfig {
        NamespaceMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            watch_namespaces: vec![
                "pid".to_string(),
                "net".to_string(),
                "mnt".to_string(),
                "uts".to_string(),
                "ipc".to_string(),
                "user".to_string(),
            ],
            exclude_processes: vec!["containerd".to_string(), "dockerd".to_string()],
            alert_on_new_ns: true,
        }
    }

    #[test]
    fn test_list_pids() {
        let pids = list_pids(Path::new("/proc"));
        if cfg!(target_os = "linux") {
            assert!(!pids.is_empty());
            // PID 1 (init) は常に存在する
            assert!(pids.contains(&1));
        }
    }

    #[test]
    fn test_list_pids_nonexistent() {
        let pids = list_pids(Path::new("/nonexistent"));
        assert!(pids.is_empty());
    }

    #[test]
    fn test_read_process_comm() {
        if cfg!(target_os = "linux") {
            let comm = read_process_comm(Path::new("/proc"), 1);
            assert!(!comm.is_empty());
        }
    }

    #[test]
    fn test_read_process_namespaces() {
        if cfg!(target_os = "linux") {
            let ns = read_process_namespaces(
                Path::new("/proc"),
                1,
                &["pid".to_string(), "net".to_string()],
            );
            assert!(!ns.is_empty());
        }
    }

    #[test]
    fn test_read_process_namespaces_nonexistent() {
        let ns = read_process_namespaces(Path::new("/proc"), 999_999_999, &["pid".to_string()]);
        assert!(ns.is_empty());
    }

    #[test]
    fn test_read_namespace_inode_valid() {
        let ns_dir = Path::new("/proc/self/ns");
        if ns_dir.exists() && cfg!(target_os = "linux") {
            let inode = read_namespace_inode(ns_dir, "pid");
            assert!(inode.is_some());
            assert!(inode.unwrap() > 0);
        }
    }

    #[test]
    fn test_read_namespace_inode_nonexistent() {
        let inode = read_namespace_inode(Path::new("/nonexistent"), "pid");
        assert!(inode.is_none());
    }

    #[test]
    fn test_take_snapshot() {
        let snapshot = take_snapshot(
            Path::new("/proc"),
            &["pid".to_string(), "net".to_string()],
            &[],
        );
        if cfg!(target_os = "linux") {
            assert!(!snapshot.processes.is_empty());
            assert!(!snapshot.init_namespaces.is_empty());
        }
    }

    #[test]
    fn test_take_snapshot_with_exclusion() {
        // systemd は PID 1 のプロセス名（exclude しても PID 1 の ns は init_namespaces に入る）
        let snapshot = take_snapshot(
            Path::new("/proc"),
            &["pid".to_string()],
            &["systemd".to_string()],
        );
        // 除外プロセスは processes に含まれない
        for info in snapshot.processes.values() {
            assert_ne!(info.comm, "systemd");
        }
    }

    #[test]
    fn test_take_snapshot_nonexistent_proc() {
        let snapshot = take_snapshot(Path::new("/nonexistent"), &["pid".to_string()], &[]);
        assert!(snapshot.processes.is_empty());
        assert!(snapshot.init_namespaces.is_empty());
    }

    #[test]
    fn test_detect_no_changes() {
        let init_ns = BTreeMap::from([("pid".to_string(), 100u64), ("net".to_string(), 200u64)]);
        let processes = HashMap::from([(
            42,
            ProcessInfo {
                comm: "test_proc".to_string(),
                namespaces: init_ns.clone(),
            },
        )]);
        let snapshot = ProcessNamespaceSnapshot {
            processes,
            init_namespaces: init_ns,
        };

        let changes = NamespaceMonitorModule::detect_changes(&snapshot, &snapshot, &None, true);
        assert_eq!(changes, 0);
    }

    #[test]
    fn test_detect_namespace_changed() {
        let init_ns = BTreeMap::from([("pid".to_string(), 100u64)]);
        let prev = ProcessNamespaceSnapshot {
            processes: HashMap::from([(
                42,
                ProcessInfo {
                    comm: "test_proc".to_string(),
                    namespaces: BTreeMap::from([("pid".to_string(), 100u64)]),
                },
            )]),
            init_namespaces: init_ns.clone(),
        };
        let current = ProcessNamespaceSnapshot {
            processes: HashMap::from([(
                42,
                ProcessInfo {
                    comm: "test_proc".to_string(),
                    namespaces: BTreeMap::from([("pid".to_string(), 999u64)]),
                },
            )]),
            init_namespaces: init_ns,
        };

        let changes = NamespaceMonitorModule::detect_changes(&prev, &current, &None, true);
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_detect_new_namespace_process() {
        let init_ns = BTreeMap::from([("pid".to_string(), 100u64)]);
        let prev = ProcessNamespaceSnapshot {
            processes: HashMap::new(),
            init_namespaces: init_ns.clone(),
        };
        let current = ProcessNamespaceSnapshot {
            processes: HashMap::from([(
                42,
                ProcessInfo {
                    comm: "suspicious".to_string(),
                    namespaces: BTreeMap::from([("pid".to_string(), 999u64)]),
                },
            )]),
            init_namespaces: init_ns,
        };

        let changes = NamespaceMonitorModule::detect_changes(&prev, &current, &None, true);
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_detect_new_namespace_process_disabled() {
        let init_ns = BTreeMap::from([("pid".to_string(), 100u64)]);
        let prev = ProcessNamespaceSnapshot {
            processes: HashMap::new(),
            init_namespaces: init_ns.clone(),
        };
        let current = ProcessNamespaceSnapshot {
            processes: HashMap::from([(
                42,
                ProcessInfo {
                    comm: "container_proc".to_string(),
                    namespaces: BTreeMap::from([("pid".to_string(), 999u64)]),
                },
            )]),
            init_namespaces: init_ns,
        };

        // alert_on_new_ns = false の場合はアラートしない
        let changes = NamespaceMonitorModule::detect_changes(&prev, &current, &None, false);
        assert_eq!(changes, 0);
    }

    #[test]
    fn test_detect_same_namespace_new_process() {
        let init_ns = BTreeMap::from([("pid".to_string(), 100u64)]);
        let prev = ProcessNamespaceSnapshot {
            processes: HashMap::new(),
            init_namespaces: init_ns.clone(),
        };
        let current = ProcessNamespaceSnapshot {
            processes: HashMap::from([(
                42,
                ProcessInfo {
                    comm: "normal_proc".to_string(),
                    // init と同じ namespace → アラートしない
                    namespaces: BTreeMap::from([("pid".to_string(), 100u64)]),
                },
            )]),
            init_namespaces: init_ns,
        };

        let changes = NamespaceMonitorModule::detect_changes(&prev, &current, &None, true);
        assert_eq!(changes, 0);
    }

    #[test]
    fn test_init_zero_interval() {
        let config = NamespaceMonitorConfig {
            enabled: true,
            scan_interval_secs: 0,
            watch_namespaces: vec!["pid".to_string()],
            exclude_processes: vec![],
            alert_on_new_ns: true,
        };
        let mut module = NamespaceMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_empty_namespaces() {
        let config = NamespaceMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            watch_namespaces: vec![],
            exclude_processes: vec![],
            alert_on_new_ns: true,
        };
        let mut module = NamespaceMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let mut module = NamespaceMonitorModule::new(default_config(), None);
        assert!(module.init().is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let mut module = NamespaceMonitorModule::new(default_config(), None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let module = NamespaceMonitorModule::new(default_config(), None);

        let result = module.initial_scan().await.unwrap();
        assert!(result.summary.contains("プロセス"));
        if cfg!(target_os = "linux") {
            assert!(result.items_scanned > 0);
        }
    }
}
