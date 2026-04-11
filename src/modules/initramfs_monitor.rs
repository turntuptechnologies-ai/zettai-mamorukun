//! initramfs 整合性監視モジュール
//!
//! `/boot/initrd.img-*`、`/boot/initramfs-*` の SHA-256 ハッシュ・パーミッション・オーナーを
//! 定期的にスキャンし、改ざんを検知する。
//!
//! 検知対象:
//! - ファイルのハッシュ変更（SHA-256）— Critical
//! - 既存ファイルの削除 — Critical
//! - 新規ファイルの出現 — Medium
//! - パーミッション・オーナーの変更 — High

use crate::config::InitramfsMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use glob::glob;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;

/// ファイルのスナップショット情報
#[derive(Debug, Clone, PartialEq)]
struct FileSnapshot {
    /// SHA-256 ハッシュ
    hash: String,
    /// ファイルパーミッション（モード）
    mode: u32,
    /// 所有者 UID
    uid: u32,
    /// 所有者 GID
    gid: u32,
}

/// initramfs ファイル群のスナップショット
struct InitramfsSnapshot {
    files: HashMap<PathBuf, FileSnapshot>,
}

/// initramfs 整合性監視モジュール
///
/// initramfs / initrd イメージを定期スキャンし、改ざんを検知する。
pub struct InitramfsMonitorModule {
    config: InitramfsMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl InitramfsMonitorModule {
    /// 新しい initramfs 整合性監視モジュールを作成する
    pub fn new(config: InitramfsMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// ファイルの SHA-256 ハッシュを計算する
    fn compute_hash(path: &Path) -> Option<String> {
        let content = match fs::read(path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "initramfs ファイルの読み取りに失敗しました"
                );
                return None;
            }
        };
        let mut hasher = Sha256::new();
        hasher.update(&content);
        Some(format!("{:x}", hasher.finalize()))
    }

    /// ファイルのスナップショットを取得する
    fn snapshot_file(path: &Path) -> Option<FileSnapshot> {
        let hash = Self::compute_hash(path)?;
        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "ファイルのメタデータ取得に失敗しました"
                );
                return None;
            }
        };
        Some(FileSnapshot {
            hash,
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
        })
    }

    /// glob パターンを展開してパスリストを構築する
    fn expand_glob_paths(patterns: &[String]) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        for pattern in patterns {
            match glob(pattern) {
                Ok(entries) => {
                    for entry in entries.flatten() {
                        paths.push(entry);
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        pattern = %pattern,
                        error = %e,
                        "glob パターンの解析に失敗しました"
                    );
                }
            }
        }
        paths.sort();
        paths.dedup();
        paths
    }

    /// スナップショットを取得する
    fn take_snapshot(patterns: &[String]) -> InitramfsSnapshot {
        let target_paths = Self::expand_glob_paths(patterns);
        let mut files = HashMap::new();
        for path in &target_paths {
            if let Some(snap) = Self::snapshot_file(path) {
                files.insert(path.clone(), snap);
            }
        }
        InitramfsSnapshot { files }
    }

    /// 2 つのスナップショットを比較し、変更を検知する。変更があれば true を返す。
    fn detect_changes(
        old: &InitramfsSnapshot,
        new: &InitramfsSnapshot,
        event_bus: &Option<EventBus>,
    ) -> bool {
        let mut changed = false;

        // 新規ファイル
        for path in new.files.keys() {
            if !old.files.contains_key(path) {
                changed = true;
                tracing::warn!(
                    path = %path.display(),
                    "新規 initramfs ファイルが出現しました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "initramfs_file_added",
                            Severity::Warning,
                            "initramfs_monitor",
                            "新規 initramfs ファイルが出現しました",
                        )
                        .with_details(format!("path={}", path.display())),
                    );
                }
            }
        }

        // 削除されたファイル（以前存在していたが新スナップにない）
        for path in old.files.keys() {
            if !new.files.contains_key(path) {
                changed = true;
                tracing::error!(
                    path = %path.display(),
                    "CRITICAL: initramfs ファイルが削除されました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "initramfs_file_deleted",
                            Severity::Critical,
                            "initramfs_monitor",
                            "initramfs ファイルが削除されました",
                        )
                        .with_details(format!("path={}", path.display())),
                    );
                }
            }
        }

        // 既存ファイルの変更
        for (path, new_snap) in &new.files {
            if let Some(old_snap) = old.files.get(path) {
                // ハッシュ変更
                if old_snap.hash != new_snap.hash {
                    changed = true;
                    tracing::error!(
                        path = %path.display(),
                        old_hash = %old_snap.hash,
                        new_hash = %new_snap.hash,
                        "CRITICAL: initramfs ファイルが改ざんされました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "initramfs_file_modified",
                                Severity::Critical,
                                "initramfs_monitor",
                                "initramfs ファイルが改ざんされました",
                            )
                            .with_details(format!(
                                "path={}, old_hash={}, new_hash={}",
                                path.display(),
                                old_snap.hash,
                                new_snap.hash
                            )),
                        );
                    }
                }

                // パーミッション変更
                if old_snap.mode != new_snap.mode
                    || old_snap.uid != new_snap.uid
                    || old_snap.gid != new_snap.gid
                {
                    changed = true;
                    tracing::warn!(
                        path = %path.display(),
                        old_mode = format!("{:o}", old_snap.mode),
                        new_mode = format!("{:o}", new_snap.mode),
                        old_uid = old_snap.uid,
                        new_uid = new_snap.uid,
                        old_gid = old_snap.gid,
                        new_gid = new_snap.gid,
                        "initramfs ファイルのパーミッション/オーナーが変更されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "initramfs_permission_changed",
                                Severity::Warning,
                                "initramfs_monitor",
                                "initramfs ファイルのパーミッション/オーナーが変更されました",
                            )
                            .with_details(format!(
                                "path={}, mode: {:o}->{:o}, uid: {}->{}, gid: {}->{}",
                                path.display(),
                                old_snap.mode,
                                new_snap.mode,
                                old_snap.uid,
                                new_snap.uid,
                                old_snap.gid,
                                new_snap.gid
                            )),
                        );
                    }
                }
            }
        }

        changed
    }
}

impl Module for InitramfsMonitorModule {
    fn name(&self) -> &str {
        "initramfs_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        let target_paths = Self::expand_glob_paths(&self.config.paths);

        let existing_count = target_paths.iter().filter(|p| p.exists()).count();
        if existing_count == 0 {
            tracing::warn!("監視対象の initramfs ファイルが 1 つも見つかりません");
        }

        tracing::info!(
            target_count = target_paths.len(),
            existing_count = existing_count,
            scan_interval_secs = self.config.scan_interval_secs,
            "initramfs 整合性監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        let patterns = self.config.paths.clone();
        let interval_secs = self.config.scan_interval_secs;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        // 初回スナップショット
        let initial_snapshot = Self::take_snapshot(&patterns);

        if initial_snapshot.files.is_empty() {
            tracing::warn!(
                "初回スナップショットにファイルがありません。監視を開始しますが検知は限定的です"
            );
        } else {
            tracing::info!(
                file_count = initial_snapshot.files.len(),
                "初回スナップショットを取得しました"
            );
        }

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            // 最初の tick は即座に発火するのでスキップ
            interval.tick().await;

            let mut snapshot = initial_snapshot;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("initramfs 整合性監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let new_snapshot = InitramfsMonitorModule::take_snapshot(&patterns);
                        let changed = InitramfsMonitorModule::detect_changes(
                            &snapshot,
                            &new_snapshot,
                            &event_bus,
                        );
                        if changed {
                            snapshot = new_snapshot;
                        } else {
                            tracing::debug!("initramfs ファイルの変更はありません");
                        }
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();
        let mut items_scanned = 0;
        let mut snapshot_map: BTreeMap<String, String> = BTreeMap::new();

        let target_paths = Self::expand_glob_paths(&self.config.paths);

        for path in &target_paths {
            if let Some(snap) = Self::snapshot_file(path) {
                items_scanned += 1;
                snapshot_map.insert(
                    path.display().to_string(),
                    format!(
                        "hash={},mode={:o},uid={},gid={}",
                        snap.hash, snap.mode, snap.uid, snap.gid
                    ),
                );
            }
        }

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found: 0,
            duration,
            summary: format!("initramfs ファイル {}件をスキャンしました", items_scanned),
            snapshot: snapshot_map,
        })
    }

    async fn stop(&mut self) -> Result<(), AppError> {
        self.cancel_token.cancel();
        tracing::info!("initramfs 整合性監視モジュールを停止しました");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn test_config(paths: Vec<String>) -> InitramfsMonitorConfig {
        InitramfsMonitorConfig {
            enabled: true,
            scan_interval_secs: 300,
            paths,
        }
    }

    #[test]
    fn test_expand_glob_paths_empty() {
        let result = InitramfsMonitorModule::expand_glob_paths(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_snapshot_nonexistent_file() {
        let snap = InitramfsMonitorModule::snapshot_file(Path::new("/nonexistent-initramfs"));
        assert!(snap.is_none());
    }

    #[test]
    fn test_compute_hash_nonexistent() {
        let hash = InitramfsMonitorModule::compute_hash(Path::new("/nonexistent-file"));
        assert!(hash.is_none());
    }

    #[test]
    fn test_detect_changes_no_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("initramfs-test");
        fs::write(&path, "content").unwrap();

        let pattern = path.display().to_string();
        let patterns = vec![pattern];

        let snap1 = InitramfsMonitorModule::take_snapshot(&patterns);
        let snap2 = InitramfsMonitorModule::take_snapshot(&patterns);

        assert!(!InitramfsMonitorModule::detect_changes(
            &snap1, &snap2, &None
        ));
    }

    #[test]
    fn test_detect_changes_file_added() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("initramfs-test");

        let pattern = path.display().to_string();
        let patterns = vec![pattern];

        let old = InitramfsMonitorModule::take_snapshot(&patterns);

        fs::write(&path, "new content").unwrap();
        let new = InitramfsMonitorModule::take_snapshot(&patterns);

        assert!(InitramfsMonitorModule::detect_changes(&old, &new, &None));
    }

    #[test]
    fn test_detect_changes_file_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("initramfs-test");
        fs::write(&path, "content").unwrap();

        let pattern = path.display().to_string();
        let patterns = vec![pattern];

        let old = InitramfsMonitorModule::take_snapshot(&patterns);

        fs::remove_file(&path).unwrap();
        let new = InitramfsMonitorModule::take_snapshot(&patterns);

        assert!(InitramfsMonitorModule::detect_changes(&old, &new, &None));
    }

    #[test]
    fn test_detect_changes_file_modified() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("initramfs-test");
        fs::write(&path, "original content").unwrap();

        let pattern = path.display().to_string();
        let patterns = vec![pattern];

        let old = InitramfsMonitorModule::take_snapshot(&patterns);

        fs::write(&path, "modified content").unwrap();
        let new = InitramfsMonitorModule::take_snapshot(&patterns);

        assert!(InitramfsMonitorModule::detect_changes(&old, &new, &None));
    }

    #[test]
    fn test_detect_changes_permission_changed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("initramfs-test");
        fs::write(&path, "content").unwrap();

        let pattern = path.display().to_string();
        let patterns = vec![pattern];

        let old = InitramfsMonitorModule::take_snapshot(&patterns);

        // パーミッションを変更
        fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();
        let new = InitramfsMonitorModule::take_snapshot(&patterns);

        assert!(InitramfsMonitorModule::detect_changes(&old, &new, &None));
    }

    #[test]
    fn test_init_zero_interval() {
        let config = InitramfsMonitorConfig {
            enabled: true,
            scan_interval_secs: 0,
            paths: vec![],
        };
        let mut module = InitramfsMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_module_name() {
        let config = test_config(vec![]);
        let module = InitramfsMonitorModule::new(config, None);
        assert_eq!(module.name(), "initramfs_monitor");
    }
}
