//! System V IPC 監視モジュール
//!
//! `/proc/sysvipc/{shm,sem,msg}` を定期スキャンし、
//! System V IPC リソースの不正利用を検知する。
//!
//! 検知対象:
//! - 共有メモリセグメントの新規作成・削除・サイズ異常
//! - セマフォの新規作成・削除・数量異常
//! - メッセージキューの新規作成・削除・数量異常
//! - 過度に緩いパーミッション（world accessible）

use crate::config::IpcMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use tokio_util::sync::CancellationToken;

/// 共有メモリセグメント情報
#[derive(Debug, Clone, PartialEq, Eq)]
struct IpcShmEntry {
    /// セグメント ID
    shmid: i64,
    /// パーミッション
    perms: u32,
    /// サイズ（バイト）
    size: u64,
    /// 所有者 UID
    uid: u32,
}

/// セマフォセット情報
#[derive(Debug, Clone, PartialEq, Eq)]
struct IpcSemEntry {
    /// セマフォセット ID
    semid: i64,
    /// パーミッション
    perms: u32,
    /// セマフォ数
    nsems: u64,
    /// 所有者 UID
    uid: u32,
}

/// メッセージキュー情報
#[derive(Debug, Clone, PartialEq, Eq)]
struct IpcMsgEntry {
    /// メッセージキュー ID
    msqid: i64,
    /// パーミッション
    perms: u32,
    /// 現在のバイト数
    cbytes: u64,
    /// キュー内メッセージ数
    qnum: u64,
    /// 所有者 UID
    uid: u32,
}

/// IPC リソースのスナップショット
struct IpcSnapshot {
    /// 共有メモリセグメント（shmid → エントリ）
    shm: HashMap<i64, IpcShmEntry>,
    /// セマフォセット（semid → エントリ）
    sem: HashMap<i64, IpcSemEntry>,
    /// メッセージキュー（msqid → エントリ）
    msg: HashMap<i64, IpcMsgEntry>,
}

/// System V IPC 監視モジュール
///
/// `/proc/sysvipc/` を定期スキャンし、IPC リソースの変化を検知する。
pub struct IpcMonitorModule {
    config: IpcMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl IpcMonitorModule {
    /// 新しい IPC 監視モジュールを作成する
    pub fn new(config: IpcMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// パーミッションが world accessible（他者が読み書き可能）かどうかを判定する
    fn is_world_accessible(perms: u32) -> bool {
        // other の read(4) または write(2) ビットが立っている
        perms & 0o006 != 0
    }

    /// `/proc/sysvipc/shm` をパースする
    fn parse_shm(proc_sysvipc_path: &Path) -> HashMap<i64, IpcShmEntry> {
        let path = proc_sysvipc_path.join("shm");
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(err) => {
                tracing::debug!(
                    error = %err,
                    path = %path.display(),
                    "/proc/sysvipc/shm の読み取りに失敗しました"
                );
                return HashMap::new();
            }
        };

        let mut entries = HashMap::new();
        // ヘッダー行をスキップ
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // key shmid perms size cpid lpid nattch uid gid ...
            if fields.len() < 8 {
                continue;
            }
            let shmid = match fields[1].parse::<i64>() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let perms = match fields[2].parse::<u32>() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let size = match fields[3].parse::<u64>() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let uid = match fields[7].parse::<u32>() {
                Ok(v) => v,
                Err(_) => continue,
            };
            entries.insert(
                shmid,
                IpcShmEntry {
                    shmid,
                    perms,
                    size,
                    uid,
                },
            );
        }
        entries
    }

    /// `/proc/sysvipc/sem` をパースする
    fn parse_sem(proc_sysvipc_path: &Path) -> HashMap<i64, IpcSemEntry> {
        let path = proc_sysvipc_path.join("sem");
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(err) => {
                tracing::debug!(
                    error = %err,
                    path = %path.display(),
                    "/proc/sysvipc/sem の読み取りに失敗しました"
                );
                return HashMap::new();
            }
        };

        let mut entries = HashMap::new();
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // key semid perms nsems uid gid ...
            if fields.len() < 5 {
                continue;
            }
            let semid = match fields[1].parse::<i64>() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let perms = match fields[2].parse::<u32>() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let nsems = match fields[3].parse::<u64>() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let uid = match fields[4].parse::<u32>() {
                Ok(v) => v,
                Err(_) => continue,
            };
            entries.insert(
                semid,
                IpcSemEntry {
                    semid,
                    perms,
                    nsems,
                    uid,
                },
            );
        }
        entries
    }

    /// `/proc/sysvipc/msg` をパースする
    fn parse_msg(proc_sysvipc_path: &Path) -> HashMap<i64, IpcMsgEntry> {
        let path = proc_sysvipc_path.join("msg");
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(err) => {
                tracing::debug!(
                    error = %err,
                    path = %path.display(),
                    "/proc/sysvipc/msg の読み取りに失敗しました"
                );
                return HashMap::new();
            }
        };

        let mut entries = HashMap::new();
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // key msqid perms cbytes qnum lspid lrpid uid gid ...
            if fields.len() < 8 {
                continue;
            }
            let msqid = match fields[1].parse::<i64>() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let perms = match fields[2].parse::<u32>() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let cbytes = match fields[3].parse::<u64>() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let qnum = match fields[4].parse::<u64>() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let uid = match fields[7].parse::<u32>() {
                Ok(v) => v,
                Err(_) => continue,
            };
            entries.insert(
                msqid,
                IpcMsgEntry {
                    msqid,
                    perms,
                    cbytes,
                    qnum,
                    uid,
                },
            );
        }
        entries
    }

    /// 現在の IPC 状態のスナップショットを取得する
    fn scan(proc_sysvipc_path: &Path) -> IpcSnapshot {
        IpcSnapshot {
            shm: Self::parse_shm(proc_sysvipc_path),
            sem: Self::parse_sem(proc_sysvipc_path),
            msg: Self::parse_msg(proc_sysvipc_path),
        }
    }

    /// ベースラインと現在のスナップショットを比較し、変更を検知する。
    /// 変更があった場合は `true` を返す。
    fn detect_and_report(
        baseline: &IpcSnapshot,
        current: &IpcSnapshot,
        event_bus: &Option<EventBus>,
        config: &IpcMonitorConfig,
    ) -> bool {
        let mut has_changes = false;

        // --- 共有メモリセグメントの変化 ---
        for (shmid, entry) in &current.shm {
            if !baseline.shm.contains_key(shmid) {
                tracing::info!(
                    shmid = shmid,
                    size = entry.size,
                    perms = format!("{:o}", entry.perms),
                    uid = entry.uid,
                    "新規共有メモリセグメントが作成されました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "ipc_shm_created",
                            Severity::Info,
                            "ipc_monitor",
                            "新規共有メモリセグメントが作成されました",
                        )
                        .with_details(format!(
                            "shmid={}, size={}, perms={:o}, uid={}",
                            shmid, entry.size, entry.perms, entry.uid
                        )),
                    );
                }
                has_changes = true;

                // 大容量共有メモリセグメントの検知
                if entry.size > config.alert_on_large_shm_bytes {
                    tracing::warn!(
                        shmid = shmid,
                        size = entry.size,
                        threshold = config.alert_on_large_shm_bytes,
                        "大容量の共有メモリセグメントが検出されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "ipc_large_shm",
                                Severity::Warning,
                                "ipc_monitor",
                                "大容量の共有メモリセグメントが検出されました",
                            )
                            .with_details(format!(
                                "shmid={}, size={}bytes, threshold={}bytes",
                                shmid, entry.size, config.alert_on_large_shm_bytes
                            )),
                        );
                    }
                }

                // world accessible チェック
                if config.alert_on_world_accessible && Self::is_world_accessible(entry.perms) {
                    tracing::warn!(
                        shmid = shmid,
                        perms = format!("{:o}", entry.perms),
                        "world accessible な共有メモリセグメントが検出されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "ipc_world_accessible",
                                Severity::Warning,
                                "ipc_monitor",
                                "world accessible な共有メモリセグメントが検出されました",
                            )
                            .with_details(format!(
                                "type=shm, shmid={}, perms={:o}",
                                shmid, entry.perms
                            )),
                        );
                    }
                }
            }
        }

        // 共有メモリの削除検知
        for shmid in baseline.shm.keys() {
            if !current.shm.contains_key(shmid) {
                tracing::info!(shmid = shmid, "共有メモリセグメントが削除されました");
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "ipc_shm_removed",
                            Severity::Info,
                            "ipc_monitor",
                            "共有メモリセグメントが削除されました",
                        )
                        .with_details(format!("shmid={}", shmid)),
                    );
                }
                has_changes = true;
            }
        }

        // --- セマフォセットの変化 ---
        for (semid, entry) in &current.sem {
            if !baseline.sem.contains_key(semid) {
                tracing::info!(
                    semid = semid,
                    nsems = entry.nsems,
                    perms = format!("{:o}", entry.perms),
                    uid = entry.uid,
                    "新規セマフォセットが作成されました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "ipc_sem_created",
                            Severity::Info,
                            "ipc_monitor",
                            "新規セマフォセットが作成されました",
                        )
                        .with_details(format!(
                            "semid={}, nsems={}, perms={:o}, uid={}",
                            semid, entry.nsems, entry.perms, entry.uid
                        )),
                    );
                }
                has_changes = true;

                // world accessible チェック
                if config.alert_on_world_accessible && Self::is_world_accessible(entry.perms) {
                    tracing::warn!(
                        semid = semid,
                        perms = format!("{:o}", entry.perms),
                        "world accessible なセマフォセットが検出されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "ipc_world_accessible",
                                Severity::Warning,
                                "ipc_monitor",
                                "world accessible なセマフォセットが検出されました",
                            )
                            .with_details(format!(
                                "type=sem, semid={}, perms={:o}",
                                semid, entry.perms
                            )),
                        );
                    }
                }
            }
        }

        // セマフォ数の閾値チェック
        let sem_count = current.sem.len() as u64;
        if sem_count > config.alert_on_high_semaphore_count {
            tracing::warn!(
                count = sem_count,
                threshold = config.alert_on_high_semaphore_count,
                "セマフォセット数が閾値を超えています"
            );
            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        "ipc_high_semaphore_count",
                        Severity::Warning,
                        "ipc_monitor",
                        "セマフォセット数が閾値を超えています",
                    )
                    .with_details(format!(
                        "count={}, threshold={}",
                        sem_count, config.alert_on_high_semaphore_count
                    )),
                );
            }
            has_changes = true;
        }

        // セマフォの削除検知
        for semid in baseline.sem.keys() {
            if !current.sem.contains_key(semid) {
                tracing::info!(semid = semid, "セマフォセットが削除されました");
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "ipc_sem_removed",
                            Severity::Info,
                            "ipc_monitor",
                            "セマフォセットが削除されました",
                        )
                        .with_details(format!("semid={}", semid)),
                    );
                }
                has_changes = true;
            }
        }

        // --- メッセージキューの変化 ---
        for (msqid, entry) in &current.msg {
            if !baseline.msg.contains_key(msqid) {
                tracing::info!(
                    msqid = msqid,
                    cbytes = entry.cbytes,
                    qnum = entry.qnum,
                    perms = format!("{:o}", entry.perms),
                    uid = entry.uid,
                    "新規メッセージキューが作成されました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "ipc_msg_created",
                            Severity::Info,
                            "ipc_monitor",
                            "新規メッセージキューが作成されました",
                        )
                        .with_details(format!(
                            "msqid={}, cbytes={}, qnum={}, perms={:o}, uid={}",
                            msqid, entry.cbytes, entry.qnum, entry.perms, entry.uid
                        )),
                    );
                }
                has_changes = true;

                // world accessible チェック
                if config.alert_on_world_accessible && Self::is_world_accessible(entry.perms) {
                    tracing::warn!(
                        msqid = msqid,
                        perms = format!("{:o}", entry.perms),
                        "world accessible なメッセージキューが検出されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "ipc_world_accessible",
                                Severity::Warning,
                                "ipc_monitor",
                                "world accessible なメッセージキューが検出されました",
                            )
                            .with_details(format!(
                                "type=msg, msqid={}, perms={:o}",
                                msqid, entry.perms
                            )),
                        );
                    }
                }
            }
        }

        // メッセージキュー数の閾値チェック
        let msg_count = current.msg.len() as u64;
        if msg_count > config.alert_on_high_msg_queue_count {
            tracing::warn!(
                count = msg_count,
                threshold = config.alert_on_high_msg_queue_count,
                "メッセージキュー数が閾値を超えています"
            );
            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        "ipc_high_msg_queue_count",
                        Severity::Warning,
                        "ipc_monitor",
                        "メッセージキュー数が閾値を超えています",
                    )
                    .with_details(format!(
                        "count={}, threshold={}",
                        msg_count, config.alert_on_high_msg_queue_count
                    )),
                );
            }
            has_changes = true;
        }

        // メッセージキューの削除検知
        for msqid in baseline.msg.keys() {
            if !current.msg.contains_key(msqid) {
                tracing::info!(msqid = msqid, "メッセージキューが削除されました");
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "ipc_msg_removed",
                            Severity::Info,
                            "ipc_monitor",
                            "メッセージキューが削除されました",
                        )
                        .with_details(format!("msqid={}", msqid)),
                    );
                }
                has_changes = true;
            }
        }

        has_changes
    }
}

impl Module for IpcMonitorModule {
    fn name(&self) -> &str {
        "ipc_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        let shm_path = self.config.proc_sysvipc_path.join("shm");
        if !shm_path.exists() {
            tracing::warn!(
                path = %self.config.proc_sysvipc_path.display(),
                "/proc/sysvipc が存在しません。このシステムでは System V IPC 監視が動作しない可能性があります"
            );
        }

        tracing::info!(
            proc_sysvipc_path = %self.config.proc_sysvipc_path.display(),
            scan_interval_secs = self.config.scan_interval_secs,
            alert_on_world_accessible = self.config.alert_on_world_accessible,
            alert_on_large_shm_bytes = self.config.alert_on_large_shm_bytes,
            alert_on_high_semaphore_count = self.config.alert_on_high_semaphore_count,
            alert_on_high_msg_queue_count = self.config.alert_on_high_msg_queue_count,
            "IPC 監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<(), AppError> {
        let baseline = Self::scan(&self.config.proc_sysvipc_path);
        tracing::info!(
            shm_count = baseline.shm.len(),
            sem_count = baseline.sem.len(),
            msg_count = baseline.msg.len(),
            "IPC ベースラインスキャンが完了しました"
        );

        let proc_sysvipc_path = self.config.proc_sysvipc_path.clone();
        let scan_interval_secs = self.config.scan_interval_secs;
        let config = self.config.clone();
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
                        tracing::info!("IPC 監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = IpcMonitorModule::scan(&proc_sysvipc_path);
                        let changed = IpcMonitorModule::detect_and_report(
                            &baseline,
                            &current,
                            &event_bus,
                            &config,
                        );

                        if changed {
                            baseline = current;
                        } else {
                            tracing::debug!("IPC リソースに変更はありません");
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

        let snapshot = Self::scan(&self.config.proc_sysvipc_path);

        let mut issues_found = 0;

        // 共有メモリの問題検出
        for entry in snapshot.shm.values() {
            if self.config.alert_on_world_accessible && Self::is_world_accessible(entry.perms) {
                issues_found += 1;
            }
            if entry.size > self.config.alert_on_large_shm_bytes {
                issues_found += 1;
            }
        }

        // セマフォ数の閾値チェック
        if snapshot.sem.len() as u64 > self.config.alert_on_high_semaphore_count {
            issues_found += 1;
        }

        // メッセージキュー数の閾値チェック
        if snapshot.msg.len() as u64 > self.config.alert_on_high_msg_queue_count {
            issues_found += 1;
        }

        // world accessible チェック（セマフォ・メッセージキュー）
        if self.config.alert_on_world_accessible {
            for entry in snapshot.sem.values() {
                if Self::is_world_accessible(entry.perms) {
                    issues_found += 1;
                }
            }
            for entry in snapshot.msg.values() {
                if Self::is_world_accessible(entry.perms) {
                    issues_found += 1;
                }
            }
        }

        let items_scanned = snapshot.shm.len() + snapshot.sem.len() + snapshot.msg.len();

        // スナップショットデータの構築
        let mut scan_snapshot = BTreeMap::new();
        for (shmid, entry) in &snapshot.shm {
            scan_snapshot.insert(
                format!("shm:{}", shmid),
                format!(
                    "perms={:o},size={},uid={}",
                    entry.perms, entry.size, entry.uid
                ),
            );
        }
        for (semid, entry) in &snapshot.sem {
            scan_snapshot.insert(
                format!("sem:{}", semid),
                format!(
                    "perms={:o},nsems={},uid={}",
                    entry.perms, entry.nsems, entry.uid
                ),
            );
        }
        for (msqid, entry) in &snapshot.msg {
            scan_snapshot.insert(
                format!("msg:{}", msqid),
                format!(
                    "perms={:o},cbytes={},qnum={},uid={}",
                    entry.perms, entry.cbytes, entry.qnum, entry.uid
                ),
            );
        }

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "IPC リソースをスキャンしました（shm={}, sem={}, msg={}）。{}件の問題を検出",
                snapshot.shm.len(),
                snapshot.sem.len(),
                snapshot.msg.len(),
                issues_found
            ),
            snapshot: scan_snapshot,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn make_test_dir() -> TempDir {
        let dir = TempDir::new().unwrap();
        // ヘッダーのみのファイルを作成（空の IPC 状態）
        fs::write(
            dir.path().join("shm"),
            "       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime                   rss                  swap\n",
        ).unwrap();
        fs::write(
            dir.path().join("sem"),
            "       key      semid perms      nsems   uid   gid  cuid  cgid      otime      ctime\n",
        ).unwrap();
        fs::write(
            dir.path().join("msg"),
            "       key      msqid perms      cbytes       qnum lspid lrpid   uid   gid  cuid  cgid      stime      rtime      ctime\n",
        ).unwrap();
        dir
    }

    fn make_config(dir: &std::path::Path) -> IpcMonitorConfig {
        IpcMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            alert_on_world_accessible: true,
            alert_on_large_shm_bytes: 104_857_600,
            alert_on_high_semaphore_count: 100,
            alert_on_high_msg_queue_count: 50,
            proc_sysvipc_path: dir.to_path_buf(),
        }
    }

    #[test]
    fn test_parse_shm_empty() {
        let dir = make_test_dir();
        let entries = IpcMonitorModule::parse_shm(&dir.path().to_path_buf());
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_shm_with_entry() {
        let dir = make_test_dir();
        let content = "       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime                   rss                  swap\n         0      12345   666              1048576  1234  5678      2  1000   100  1000   100 1700000000 1700000000 1700000000              1048576                     0\n";
        fs::write(dir.path().join("shm"), content).unwrap();

        let entries = IpcMonitorModule::parse_shm(&dir.path().to_path_buf());
        assert_eq!(entries.len(), 1);
        let entry = entries.get(&12345).unwrap();
        assert_eq!(entry.shmid, 12345);
        assert_eq!(entry.perms, 666);
        assert_eq!(entry.size, 1_048_576);
        assert_eq!(entry.uid, 1000);
    }

    #[test]
    fn test_parse_sem_empty() {
        let dir = make_test_dir();
        let entries = IpcMonitorModule::parse_sem(&dir.path().to_path_buf());
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_sem_with_entry() {
        let dir = make_test_dir();
        let content = "       key      semid perms      nsems   uid   gid  cuid  cgid      otime      ctime\n         0        100   600          5  1000   100  1000   100 1700000000 1700000000\n";
        fs::write(dir.path().join("sem"), content).unwrap();

        let entries = IpcMonitorModule::parse_sem(&dir.path().to_path_buf());
        assert_eq!(entries.len(), 1);
        let entry = entries.get(&100).unwrap();
        assert_eq!(entry.semid, 100);
        assert_eq!(entry.perms, 600);
        assert_eq!(entry.nsems, 5);
        assert_eq!(entry.uid, 1000);
    }

    #[test]
    fn test_parse_msg_empty() {
        let dir = make_test_dir();
        let entries = IpcMonitorModule::parse_msg(&dir.path().to_path_buf());
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_msg_with_entry() {
        let dir = make_test_dir();
        let content = "       key      msqid perms      cbytes       qnum lspid lrpid   uid   gid  cuid  cgid      stime      rtime      ctime\n         0        200   644        4096         10  1234  5678  1000   100  1000   100 1700000000 1700000000 1700000000\n";
        fs::write(dir.path().join("msg"), content).unwrap();

        let entries = IpcMonitorModule::parse_msg(&dir.path().to_path_buf());
        assert_eq!(entries.len(), 1);
        let entry = entries.get(&200).unwrap();
        assert_eq!(entry.msqid, 200);
        assert_eq!(entry.perms, 644);
        assert_eq!(entry.cbytes, 4096);
        assert_eq!(entry.qnum, 10);
        assert_eq!(entry.uid, 1000);
    }

    #[test]
    fn test_parse_nonexistent_path() {
        let path = PathBuf::from("/tmp/nonexistent_zettai_ipc_test");
        assert!(IpcMonitorModule::parse_shm(&path).is_empty());
        assert!(IpcMonitorModule::parse_sem(&path).is_empty());
        assert!(IpcMonitorModule::parse_msg(&path).is_empty());
    }

    #[test]
    fn test_is_world_accessible() {
        assert!(IpcMonitorModule::is_world_accessible(0o666));
        assert!(IpcMonitorModule::is_world_accessible(0o664));
        assert!(IpcMonitorModule::is_world_accessible(0o662));
        assert!(IpcMonitorModule::is_world_accessible(0o646));
        assert!(!IpcMonitorModule::is_world_accessible(0o660));
        assert!(!IpcMonitorModule::is_world_accessible(0o600));
        assert!(!IpcMonitorModule::is_world_accessible(0o640));
    }

    #[test]
    fn test_detect_new_shm() {
        let baseline = IpcSnapshot {
            shm: HashMap::new(),
            sem: HashMap::new(),
            msg: HashMap::new(),
        };
        let mut current_shm = HashMap::new();
        current_shm.insert(
            1,
            IpcShmEntry {
                shmid: 1,
                perms: 0o600,
                size: 4096,
                uid: 1000,
            },
        );
        let current = IpcSnapshot {
            shm: current_shm,
            sem: HashMap::new(),
            msg: HashMap::new(),
        };
        let dir = make_test_dir();
        let config = make_config(dir.path());
        assert!(IpcMonitorModule::detect_and_report(
            &baseline, &current, &None, &config
        ));
    }

    #[test]
    fn test_detect_removed_shm() {
        let mut baseline_shm = HashMap::new();
        baseline_shm.insert(
            1,
            IpcShmEntry {
                shmid: 1,
                perms: 0o600,
                size: 4096,
                uid: 0,
            },
        );
        let baseline = IpcSnapshot {
            shm: baseline_shm,
            sem: HashMap::new(),
            msg: HashMap::new(),
        };
        let current = IpcSnapshot {
            shm: HashMap::new(),
            sem: HashMap::new(),
            msg: HashMap::new(),
        };
        let dir = make_test_dir();
        let config = make_config(dir.path());
        assert!(IpcMonitorModule::detect_and_report(
            &baseline, &current, &None, &config
        ));
    }

    #[test]
    fn test_detect_world_accessible_shm() {
        let baseline = IpcSnapshot {
            shm: HashMap::new(),
            sem: HashMap::new(),
            msg: HashMap::new(),
        };
        let mut current_shm = HashMap::new();
        current_shm.insert(
            1,
            IpcShmEntry {
                shmid: 1,
                perms: 0o666,
                size: 4096,
                uid: 1000,
            },
        );
        let current = IpcSnapshot {
            shm: current_shm,
            sem: HashMap::new(),
            msg: HashMap::new(),
        };
        let dir = make_test_dir();
        let config = make_config(dir.path());
        assert!(IpcMonitorModule::detect_and_report(
            &baseline, &current, &None, &config
        ));
    }

    #[test]
    fn test_detect_large_shm() {
        let baseline = IpcSnapshot {
            shm: HashMap::new(),
            sem: HashMap::new(),
            msg: HashMap::new(),
        };
        let mut current_shm = HashMap::new();
        current_shm.insert(
            1,
            IpcShmEntry {
                shmid: 1,
                perms: 0o600,
                size: 200_000_000, // 200MB > 100MB threshold
                uid: 1000,
            },
        );
        let current = IpcSnapshot {
            shm: current_shm,
            sem: HashMap::new(),
            msg: HashMap::new(),
        };
        let dir = make_test_dir();
        let config = make_config(dir.path());
        assert!(IpcMonitorModule::detect_and_report(
            &baseline, &current, &None, &config
        ));
    }

    #[test]
    fn test_detect_new_sem() {
        let baseline = IpcSnapshot {
            shm: HashMap::new(),
            sem: HashMap::new(),
            msg: HashMap::new(),
        };
        let mut current_sem = HashMap::new();
        current_sem.insert(
            10,
            IpcSemEntry {
                semid: 10,
                perms: 0o600,
                nsems: 5,
                uid: 1000,
            },
        );
        let current = IpcSnapshot {
            shm: HashMap::new(),
            sem: current_sem,
            msg: HashMap::new(),
        };
        let dir = make_test_dir();
        let config = make_config(dir.path());
        assert!(IpcMonitorModule::detect_and_report(
            &baseline, &current, &None, &config
        ));
    }

    #[test]
    fn test_detect_new_msg() {
        let baseline = IpcSnapshot {
            shm: HashMap::new(),
            sem: HashMap::new(),
            msg: HashMap::new(),
        };
        let mut current_msg = HashMap::new();
        current_msg.insert(
            20,
            IpcMsgEntry {
                msqid: 20,
                perms: 0o644,
                cbytes: 1024,
                qnum: 5,
                uid: 1000,
            },
        );
        let current = IpcSnapshot {
            shm: HashMap::new(),
            sem: HashMap::new(),
            msg: current_msg,
        };
        let dir = make_test_dir();
        let config = make_config(dir.path());
        assert!(IpcMonitorModule::detect_and_report(
            &baseline, &current, &None, &config
        ));
    }

    #[test]
    fn test_detect_high_semaphore_count() {
        let baseline = IpcSnapshot {
            shm: HashMap::new(),
            sem: HashMap::new(),
            msg: HashMap::new(),
        };
        let mut current_sem = HashMap::new();
        // 閾値を低く設定してテスト
        for i in 0..5 {
            current_sem.insert(
                i,
                IpcSemEntry {
                    semid: i,
                    perms: 0o600,
                    nsems: 1,
                    uid: 0,
                },
            );
        }
        let current = IpcSnapshot {
            shm: HashMap::new(),
            sem: current_sem,
            msg: HashMap::new(),
        };
        let dir = make_test_dir();
        let mut config = make_config(dir.path());
        config.alert_on_high_semaphore_count = 3; // 閾値を低く設定
        assert!(IpcMonitorModule::detect_and_report(
            &baseline, &current, &None, &config
        ));
    }

    #[test]
    fn test_detect_high_msg_queue_count() {
        let baseline = IpcSnapshot {
            shm: HashMap::new(),
            sem: HashMap::new(),
            msg: HashMap::new(),
        };
        let mut current_msg = HashMap::new();
        for i in 0..5 {
            current_msg.insert(
                i,
                IpcMsgEntry {
                    msqid: i,
                    perms: 0o600,
                    cbytes: 0,
                    qnum: 0,
                    uid: 0,
                },
            );
        }
        let current = IpcSnapshot {
            shm: HashMap::new(),
            sem: HashMap::new(),
            msg: current_msg,
        };
        let dir = make_test_dir();
        let mut config = make_config(dir.path());
        config.alert_on_high_msg_queue_count = 3;
        assert!(IpcMonitorModule::detect_and_report(
            &baseline, &current, &None, &config
        ));
    }

    #[test]
    fn test_detect_no_changes() {
        let mut shm = HashMap::new();
        shm.insert(
            1,
            IpcShmEntry {
                shmid: 1,
                perms: 0o600,
                size: 4096,
                uid: 0,
            },
        );
        let baseline = IpcSnapshot {
            shm: shm.clone(),
            sem: HashMap::new(),
            msg: HashMap::new(),
        };
        let current = IpcSnapshot {
            shm,
            sem: HashMap::new(),
            msg: HashMap::new(),
        };
        let dir = make_test_dir();
        let config = make_config(dir.path());
        assert!(!IpcMonitorModule::detect_and_report(
            &baseline, &current, &None, &config
        ));
    }

    #[test]
    fn test_init_zero_interval() {
        let dir = make_test_dir();
        let mut config = make_config(dir.path());
        config.scan_interval_secs = 0;
        let mut module = IpcMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let dir = make_test_dir();
        let config = make_config(dir.path());
        let mut module = IpcMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let dir = make_test_dir();
        let mut config = make_config(dir.path());
        config.scan_interval_secs = 3600;
        let mut module = IpcMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();
        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan_empty() {
        let dir = make_test_dir();
        let config = make_config(dir.path());
        let module = IpcMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
    }

    #[tokio::test]
    async fn test_initial_scan_with_issues() {
        let dir = make_test_dir();
        // world accessible な共有メモリを追加
        let shm_content = "       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime                   rss                  swap\n         0          1   666              4096  1234  5678      1  1000   100  1000   100 1700000000 1700000000 1700000000                 4096                     0\n";
        fs::write(dir.path().join("shm"), shm_content).unwrap();

        let config = make_config(dir.path());
        let module = IpcMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 1);
        assert!(result.issues_found >= 1); // world accessible
    }

    #[tokio::test]
    async fn test_initial_scan_large_shm() {
        let dir = make_test_dir();
        let shm_content = "       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime                   rss                  swap\n         0          1   600         200000000  1234  5678      1  1000   100  1000   100 1700000000 1700000000 1700000000             200000000                     0\n";
        fs::write(dir.path().join("shm"), shm_content).unwrap();

        let config = make_config(dir.path());
        let module = IpcMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 1);
        assert!(result.issues_found >= 1); // large shm
    }

    #[test]
    fn test_scan_full_snapshot() {
        let dir = make_test_dir();
        let shm_content = "       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime                   rss                  swap\n         0          1   600              4096  1234  5678      1     0     0     0     0 1700000000 1700000000 1700000000                 4096                     0\n";
        let sem_content = "       key      semid perms      nsems   uid   gid  cuid  cgid      otime      ctime\n         0         10   600          5     0     0     0     0 1700000000 1700000000\n";
        let msg_content = "       key      msqid perms      cbytes       qnum lspid lrpid   uid   gid  cuid  cgid      stime      rtime      ctime\n         0         20   644        1024          3  1234  5678     0     0     0     0 1700000000 1700000000 1700000000\n";

        fs::write(dir.path().join("shm"), shm_content).unwrap();
        fs::write(dir.path().join("sem"), sem_content).unwrap();
        fs::write(dir.path().join("msg"), msg_content).unwrap();

        let snapshot = IpcMonitorModule::scan(&dir.path().to_path_buf());
        assert_eq!(snapshot.shm.len(), 1);
        assert_eq!(snapshot.sem.len(), 1);
        assert_eq!(snapshot.msg.len(), 1);
    }

    #[test]
    fn test_parse_shm_malformed_line() {
        let dir = make_test_dir();
        let content = "       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime                   rss                  swap\nthis is not a valid line\n         0          1   600              4096  1234  5678      1     0     0     0     0 1700000000 1700000000 1700000000                 4096                     0\n";
        fs::write(dir.path().join("shm"), content).unwrap();

        let entries = IpcMonitorModule::parse_shm(&dir.path().to_path_buf());
        assert_eq!(entries.len(), 1); // 不正行はスキップ、有効行のみパース
    }

    #[test]
    fn test_parse_multiple_entries() {
        let dir = make_test_dir();
        let content = "       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime                   rss                  swap\n         0          1   600              4096  1234  5678      1     0     0     0     0 1700000000 1700000000 1700000000                 4096                     0\n         0          2   666              8192  2345  6789      2  1000   100  1000   100 1700000000 1700000000 1700000000                 8192                     0\n";
        fs::write(dir.path().join("shm"), content).unwrap();

        let entries = IpcMonitorModule::parse_shm(&dir.path().to_path_buf());
        assert_eq!(entries.len(), 2);
        assert!(entries.contains_key(&1));
        assert!(entries.contains_key(&2));
    }
}
