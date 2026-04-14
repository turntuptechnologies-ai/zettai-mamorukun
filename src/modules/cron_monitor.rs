//! Cron ジョブ改ざん検知モジュール
//!
//! cron 関連ファイルを定期的にスキャンし、SHA-256 ハッシュベースで変更を検知する。
//! inotify によるリアルタイム検知にも対応し、定期スキャンと併用して高速かつ確実な検知を実現する。
//!
//! 検知対象:
//! - 新規追加された cron ファイル
//! - 内容が変更された cron ファイル
//! - 削除された cron ファイル

use crate::config::CronMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use inotify::{Inotify, WatchDescriptor, WatchMask};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use walkdir::WalkDir;

/// Cron ファイル変更レポート
struct ChangeReport {
    modified: Vec<PathBuf>,
    added: Vec<PathBuf>,
    removed: Vec<PathBuf>,
}

impl ChangeReport {
    /// 変更があったかどうかを返す
    fn has_changes(&self) -> bool {
        !self.modified.is_empty() || !self.added.is_empty() || !self.removed.is_empty()
    }
}

/// Cron ジョブ改ざん検知モジュール
///
/// cron 関連ファイルを定期スキャンおよび inotify リアルタイム検知で変更を検知する。
pub struct CronMonitorModule {
    config: CronMonitorConfig,
    baseline: Option<HashMap<PathBuf, String>>,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl CronMonitorModule {
    /// 新しい Cron ジョブ改ざん検知モジュールを作成する
    pub fn new(config: CronMonitorConfig, event_bus: Option<EventBus>) -> Self {
        Self {
            config,
            baseline: None,
            cancel_token: CancellationToken::new(),
            event_bus,
        }
    }

    /// キャンセルトークンのクローンを返す
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    /// 監視対象パスをスキャンし、各ファイルの SHA-256 ハッシュを返す
    fn scan_files(watch_paths: &[PathBuf]) -> HashMap<PathBuf, String> {
        let mut result = HashMap::new();
        for path in watch_paths {
            if path.is_file() {
                match compute_hash(path) {
                    Ok(hash) => {
                        result.insert(path.clone(), hash);
                    }
                    Err(e) => {
                        tracing::warn!(path = %path.display(), error = %e, "cron ファイルの読み取りに失敗しました。スキャンを継続します");
                    }
                }
            } else if path.is_dir() {
                for entry in WalkDir::new(path).follow_links(false).into_iter() {
                    match entry {
                        Ok(entry) if entry.file_type().is_file() => {
                            let file_path = entry.into_path();
                            match compute_hash(&file_path) {
                                Ok(hash) => {
                                    result.insert(file_path, hash);
                                }
                                Err(e) => {
                                    tracing::warn!(path = %file_path.display(), error = %e, "cron ファイルの読み取りに失敗しました。スキャンを継続します");
                                }
                            }
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!(error = %e, "ディレクトリ走査中にエラーが発生しました。スキャンを継続します");
                        }
                    }
                }
            }
        }
        result
    }

    /// ベースラインと現在のスキャン結果を比較し、変更レポートを返す
    fn detect_changes(
        baseline: &HashMap<PathBuf, String>,
        current: &HashMap<PathBuf, String>,
    ) -> ChangeReport {
        let mut modified = Vec::new();
        let mut added = Vec::new();
        let mut removed = Vec::new();

        for (path, current_hash) in current {
            match baseline.get(path) {
                Some(baseline_hash) if baseline_hash != current_hash => {
                    modified.push(path.clone());
                }
                None => {
                    added.push(path.clone());
                }
                _ => {}
            }
        }

        for path in baseline.keys() {
            if !current.contains_key(path) {
                removed.push(path.clone());
            }
        }

        ChangeReport {
            modified,
            added,
            removed,
        }
    }

    /// inotify を初期化し、監視対象ディレクトリに watch を登録する
    fn setup_inotify(
        watch_paths: &[PathBuf],
    ) -> Result<(Inotify, HashMap<WatchDescriptor, PathBuf>), AppError> {
        let mut inotify = Inotify::init().map_err(|e| AppError::ModuleConfig {
            message: format!("inotify の初期化に失敗しました: {}", e),
        })?;

        let watch_mask =
            WatchMask::CLOSE_WRITE | WatchMask::MOVED_TO | WatchMask::DELETE | WatchMask::CREATE;

        let mut watch_map: HashMap<WatchDescriptor, PathBuf> = HashMap::new();

        for path in watch_paths {
            if path.is_dir() {
                Self::register_dir_watches(&mut inotify, path, watch_mask, &mut watch_map);
            } else if let Some(parent) = path.parent()
                && parent.is_dir()
                && !watch_map.values().any(|p| p == parent)
            {
                match inotify.watches().add(parent, watch_mask) {
                    Ok(wd) => {
                        watch_map.insert(wd, parent.to_path_buf());
                    }
                    Err(e) => {
                        tracing::warn!(
                            path = %parent.display(),
                            error = %e,
                            "inotify watch の登録に失敗しました"
                        );
                    }
                }
            }
        }

        Ok((inotify, watch_map))
    }

    /// ディレクトリとそのサブディレクトリに再帰的に inotify watch を登録する
    fn register_dir_watches(
        inotify: &mut Inotify,
        path: &std::path::Path,
        watch_mask: WatchMask,
        watch_map: &mut HashMap<WatchDescriptor, PathBuf>,
    ) {
        match inotify.watches().add(path, watch_mask) {
            Ok(wd) => {
                watch_map.insert(wd, path.to_path_buf());
            }
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "inotify watch の登録に失敗しました"
                );
                return;
            }
        }

        let entries = match std::fs::read_dir(path) {
            Ok(entries) => entries,
            Err(_) => return,
        };

        for entry in entries.filter_map(|e| e.ok()) {
            let entry_path = entry.path();
            let metadata = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                Self::register_dir_watches(inotify, &entry_path, watch_mask, watch_map);
            }
        }
    }

    /// 変更レポートを処理してイベントを発行する
    fn publish_changes(report: &ChangeReport, event_bus: &Option<EventBus>, detection: &str) {
        for path in &report.modified {
            tracing::warn!(path = %path.display(), change = "modified", detection = detection, "cron ファイルの変更を検知しました");
            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        "cron_modified",
                        Severity::Warning,
                        "cron_monitor",
                        format!("cron ファイルの変更を検知しました: {}", path.display()),
                    )
                    .with_details(format!(
                        "path={}, detection={}",
                        path.display(),
                        detection
                    )),
                );
            }
        }
        for path in &report.added {
            tracing::warn!(path = %path.display(), change = "added", detection = detection, "cron ファイルの追加を検知しました");
            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        "cron_added",
                        Severity::Warning,
                        "cron_monitor",
                        format!("cron ファイルの追加を検知しました: {}", path.display()),
                    )
                    .with_details(format!(
                        "path={}, detection={}",
                        path.display(),
                        detection
                    )),
                );
            }
        }
        for path in &report.removed {
            tracing::warn!(path = %path.display(), change = "removed", detection = detection, "cron ファイルの削除を検知しました");
            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        "cron_removed",
                        Severity::Warning,
                        "cron_monitor",
                        format!("cron ファイルの削除を検知しました: {}", path.display()),
                    )
                    .with_details(format!(
                        "path={}, detection={}",
                        path.display(),
                        detection
                    )),
                );
            }
        }
    }
}

/// ファイルの SHA-256 ハッシュを計算する
fn compute_hash(path: &PathBuf) -> Result<String, AppError> {
    let data = std::fs::read(path).map_err(|e| AppError::FileIo {
        path: path.clone(),
        source: e,
    })?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let hash = hasher.finalize();
    Ok(format!("{:x}", hash))
}

impl Module for CronMonitorModule {
    fn name(&self) -> &str {
        "cron_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        // パストラバーサル防止: canonicalize でパスを正規化
        let mut canonicalized = Vec::new();
        for path in &self.config.watch_paths {
            match std::fs::canonicalize(path) {
                Ok(canonical) => canonicalized.push(canonical),
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "監視対象パスが存在しないためスキップします"
                    );
                }
            }
        }
        self.config.watch_paths = canonicalized;

        tracing::info!(
            watch_paths = ?self.config.watch_paths,
            scan_interval_secs = self.config.scan_interval_secs,
            use_inotify = self.config.use_inotify,
            inotify_debounce_ms = self.config.inotify_debounce_ms,
            "Cron ジョブ改ざん検知モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        // 初回スキャンでベースライン作成
        let baseline = Self::scan_files(&self.config.watch_paths);
        tracing::info!(
            file_count = baseline.len(),
            "ベースラインスキャンが完了しました"
        );

        self.baseline = Some(baseline);

        // baseline の所有権をタスクに移動
        let mut baseline = self.baseline.take().ok_or_else(|| AppError::ModuleConfig {
            message: "ベースラインが未初期化です".to_string(),
        })?;

        let watch_paths = self.config.watch_paths.clone();
        let scan_interval_secs = self.config.scan_interval_secs;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();
        let use_inotify = self.config.use_inotify;
        let inotify_debounce_ms = self.config.inotify_debounce_ms;

        // inotify の初期化（有効時のみ）
        let inotify_state = if use_inotify {
            match Self::setup_inotify(&watch_paths) {
                Ok((inotify, watch_map)) => {
                    tracing::info!(
                        watch_count = watch_map.len(),
                        "cron 監視用の inotify watch を登録しました"
                    );
                    Some((inotify, watch_map))
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "inotify の初期化に失敗しました。定期スキャンのみで動作します"
                    );
                    None
                }
            }
        } else {
            None
        };

        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            // 最初の tick は即座に発火するのでスキップ
            interval.tick().await;

            if let Some((mut inotify, watch_map)) = inotify_state {
                let mut buffer = vec![0u8; 4096];
                let mut debounce_map: HashMap<PathBuf, Instant> = HashMap::new();
                let debounce_duration = Duration::from_millis(inotify_debounce_ms);
                let mut poll_interval = tokio::time::interval(Duration::from_millis(100));
                poll_interval.tick().await;

                loop {
                    tokio::select! {
                        _ = cancel_token.cancelled() => {
                            tracing::info!("Cron ジョブ改ざん検知モジュールを停止します");
                            break;
                        }
                        _ = interval.tick() => {
                            let current = CronMonitorModule::scan_files(&watch_paths);
                            let report = CronMonitorModule::detect_changes(&baseline, &current);

                            if report.has_changes() {
                                CronMonitorModule::publish_changes(&report, &event_bus, "periodic_scan");
                                baseline = current;
                            } else {
                                tracing::debug!("cron ファイルの変更はありません");
                            }
                        }
                        _ = poll_interval.tick() => {
                            let events = match inotify.read_events(&mut buffer) {
                                Ok(events) => events,
                                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                                Err(e) => {
                                    tracing::error!(error = %e, "inotify イベントの読み取りに失敗しました");
                                    continue;
                                }
                            };

                            let now = Instant::now();

                            for event in events {
                                let dir_path = match watch_map.get(&event.wd) {
                                    Some(p) => p.clone(),
                                    None => continue,
                                };

                                let file_path = match &event.name {
                                    Some(name) => dir_path.join(name),
                                    None => dir_path.clone(),
                                };

                                if let Some(last_time) = debounce_map.get(&file_path)
                                    && now.duration_since(*last_time) < debounce_duration
                                {
                                    continue;
                                }
                                debounce_map.insert(file_path.clone(), now);

                                let current = CronMonitorModule::scan_files(&watch_paths);
                                let report = CronMonitorModule::detect_changes(&baseline, &current);

                                if report.has_changes() {
                                    CronMonitorModule::publish_changes(&report, &event_bus, "inotify");
                                    baseline = current;
                                }

                                break;
                            }

                            if debounce_map.len() > 10000 {
                                let threshold = now - Duration::from_secs(60);
                                debounce_map.retain(|_, t| *t > threshold);
                            }
                        }
                    }
                }
            } else {
                loop {
                    tokio::select! {
                        _ = cancel_token.cancelled() => {
                            tracing::info!("Cron ジョブ改ざん検知モジュールを停止します");
                            break;
                        }
                        _ = interval.tick() => {
                            let current = CronMonitorModule::scan_files(&watch_paths);
                            let report = CronMonitorModule::detect_changes(&baseline, &current);

                            if report.has_changes() {
                                CronMonitorModule::publish_changes(&report, &event_bus, "periodic_scan");
                                baseline = current;
                            } else {
                                tracing::debug!("cron ファイルの変更はありません");
                            }
                        }
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();
        let files = Self::scan_files(&self.config.watch_paths);
        let items_scanned = files.len();
        let snapshot: BTreeMap<String, String> = files
            .iter()
            .map(|(path, hash)| (path.display().to_string(), hash.clone()))
            .collect();
        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found: 0,
            duration,
            summary: format!("cron ファイル {}件をスキャンしました", items_scanned),
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
    use std::io::Write;

    #[test]
    fn test_compute_hash() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "hello world").unwrap();
        let hash = compute_hash(&tmpfile.path().to_path_buf()).unwrap();
        // SHA-256 of "hello world"
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_compute_hash_nonexistent() {
        let result = compute_hash(&PathBuf::from("/tmp/nonexistent-file-zettai-cron-test"));
        assert!(result.is_err());
    }

    #[test]
    fn test_scan_files_with_directory() {
        let dir = tempfile::tempdir().unwrap();
        let file1 = dir.path().join("crontab1");
        let file2 = dir.path().join("crontab2");
        std::fs::write(&file1, "* * * * * /bin/true").unwrap();
        std::fs::write(&file2, "0 * * * * /bin/false").unwrap();

        let watch_paths = vec![dir.path().to_path_buf()];
        let result = CronMonitorModule::scan_files(&watch_paths);
        assert_eq!(result.len(), 2);
        assert!(result.contains_key(&file1));
        assert!(result.contains_key(&file2));
    }

    #[test]
    fn test_scan_files_with_single_file() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "* * * * * /bin/true").unwrap();
        let path = tmpfile.path().to_path_buf();

        let watch_paths = vec![path.clone()];
        let result = CronMonitorModule::scan_files(&watch_paths);
        assert_eq!(result.len(), 1);
        assert!(result.contains_key(&path));
    }

    #[test]
    fn test_scan_files_empty() {
        let watch_paths: Vec<PathBuf> = vec![];
        let result = CronMonitorModule::scan_files(&watch_paths);
        assert!(result.is_empty());
    }

    #[test]
    fn test_scan_files_nested() {
        let dir = tempfile::tempdir().unwrap();
        let sub1 = dir.path().join("cron.d");
        let sub2 = sub1.join("nested");
        std::fs::create_dir_all(&sub2).unwrap();

        let file_root = dir.path().join("crontab");
        let file_sub1 = sub1.join("job1");
        let file_sub2 = sub2.join("job2");
        std::fs::write(&file_root, "root").unwrap();
        std::fs::write(&file_sub1, "sub1").unwrap();
        std::fs::write(&file_sub2, "sub2").unwrap();

        let watch_paths = vec![dir.path().to_path_buf()];
        let result = CronMonitorModule::scan_files(&watch_paths);
        assert_eq!(result.len(), 3);
        assert!(result.contains_key(&file_root));
        assert!(result.contains_key(&file_sub1));
        assert!(result.contains_key(&file_sub2));
    }

    #[test]
    fn test_detect_changes_no_changes() {
        let mut baseline = HashMap::new();
        baseline.insert(PathBuf::from("/etc/crontab"), "hash1".to_string());

        let current = baseline.clone();
        let report = CronMonitorModule::detect_changes(&baseline, &current);
        assert!(!report.has_changes());
    }

    #[test]
    fn test_detect_changes_modified() {
        let mut baseline = HashMap::new();
        baseline.insert(PathBuf::from("/etc/crontab"), "hash1".to_string());

        let mut current = HashMap::new();
        current.insert(PathBuf::from("/etc/crontab"), "hash2".to_string());

        let report = CronMonitorModule::detect_changes(&baseline, &current);
        assert_eq!(report.modified.len(), 1);
        assert!(report.added.is_empty());
        assert!(report.removed.is_empty());
    }

    #[test]
    fn test_detect_changes_added() {
        let baseline = HashMap::new();
        let mut current = HashMap::new();
        current.insert(PathBuf::from("/etc/cron.d/new_job"), "hash1".to_string());

        let report = CronMonitorModule::detect_changes(&baseline, &current);
        assert!(report.modified.is_empty());
        assert_eq!(report.added.len(), 1);
        assert!(report.removed.is_empty());
    }

    #[test]
    fn test_detect_changes_removed() {
        let mut baseline = HashMap::new();
        baseline.insert(PathBuf::from("/etc/cron.d/old_job"), "hash1".to_string());

        let current = HashMap::new();
        let report = CronMonitorModule::detect_changes(&baseline, &current);
        assert!(report.modified.is_empty());
        assert!(report.added.is_empty());
        assert_eq!(report.removed.len(), 1);
    }

    #[test]
    fn test_detect_changes_combined() {
        let mut baseline = HashMap::new();
        baseline.insert(PathBuf::from("/etc/crontab"), "hash1".to_string());
        baseline.insert(PathBuf::from("/etc/cron.d/to_remove"), "hash2".to_string());
        baseline.insert(PathBuf::from("/etc/cron.d/to_modify"), "hash3".to_string());

        let mut current = HashMap::new();
        current.insert(PathBuf::from("/etc/crontab"), "hash1".to_string());
        current.insert(
            PathBuf::from("/etc/cron.d/to_modify"),
            "hash_changed".to_string(),
        );
        current.insert(PathBuf::from("/etc/cron.d/new_job"), "hash4".to_string());

        let report = CronMonitorModule::detect_changes(&baseline, &current);
        assert_eq!(report.modified.len(), 1);
        assert_eq!(report.added.len(), 1);
        assert_eq!(report.removed.len(), 1);
        assert!(
            report
                .modified
                .contains(&PathBuf::from("/etc/cron.d/to_modify"))
        );
        assert!(report.added.contains(&PathBuf::from("/etc/cron.d/new_job")));
        assert!(
            report
                .removed
                .contains(&PathBuf::from("/etc/cron.d/to_remove"))
        );
    }

    #[test]
    fn test_init_zero_interval() {
        let config = CronMonitorConfig {
            enabled: true,
            scan_interval_secs: 0,
            watch_paths: vec![],
            ..Default::default()
        };
        let mut module = CronMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_init_valid() {
        let dir = tempfile::tempdir().unwrap();
        let config = CronMonitorConfig {
            enabled: true,
            scan_interval_secs: 120,
            watch_paths: vec![dir.path().to_path_buf()],
            ..Default::default()
        };
        let mut module = CronMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_ok());
    }

    #[test]
    fn test_init_nonexistent_path() {
        let config = CronMonitorConfig {
            enabled: true,
            scan_interval_secs: 120,
            watch_paths: vec![PathBuf::from("/nonexistent-path-zettai-cron-test")],
            ..Default::default()
        };
        let mut module = CronMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_ok());
        assert!(module.config.watch_paths.is_empty());
    }

    #[test]
    fn test_init_canonicalizes_paths() {
        let dir = tempfile::tempdir().unwrap();
        let subdir = dir.path().join("sub");
        std::fs::create_dir(&subdir).unwrap();

        let non_canonical = dir.path().join("sub").join("..").join("sub");
        let config = CronMonitorConfig {
            enabled: true,
            scan_interval_secs: 120,
            watch_paths: vec![non_canonical],
            ..Default::default()
        };
        let mut module = CronMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_ok());
        assert_eq!(module.config.watch_paths.len(), 1);
        let canonical = &module.config.watch_paths[0];
        assert!(!canonical.to_string_lossy().contains(".."));
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let dir = tempfile::tempdir().unwrap();
        let file1 = dir.path().join("crontab");
        std::fs::write(&file1, "* * * * * /bin/true").unwrap();

        let config = CronMonitorConfig {
            enabled: true,
            scan_interval_secs: 3600,
            watch_paths: vec![dir.path().to_path_buf()],
            ..Default::default()
        };
        let mut module = CronMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[test]
    fn test_change_report_has_changes_empty() {
        let report = ChangeReport {
            modified: vec![],
            added: vec![],
            removed: vec![],
        };
        assert!(!report.has_changes());
    }

    #[tokio::test]
    async fn test_initial_scan_with_files() {
        let dir = tempfile::tempdir().unwrap();
        let file1 = dir.path().join("crontab");
        let file2 = dir.path().join("job1");
        std::fs::write(&file1, "* * * * * /bin/true").unwrap();
        std::fs::write(&file2, "0 * * * * /bin/false").unwrap();

        let config = CronMonitorConfig {
            enabled: true,
            scan_interval_secs: 120,
            watch_paths: vec![dir.path().to_path_buf()],
            ..Default::default()
        };
        let mut module = CronMonitorModule::new(config, None);
        module.init().unwrap();

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 2);
        assert_eq!(result.issues_found, 0);
        assert!(result.summary.contains("2件"));
    }

    #[tokio::test]
    async fn test_initial_scan_empty() {
        let config = CronMonitorConfig {
            enabled: true,
            scan_interval_secs: 120,
            watch_paths: vec![],
            ..Default::default()
        };
        let module = CronMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 0);
    }

    #[test]
    fn test_inotify_config_enabled_by_default() {
        let config = CronMonitorConfig::default();
        assert!(config.use_inotify);
        assert_eq!(config.inotify_debounce_ms, 500);
    }

    #[test]
    fn test_inotify_config_disabled() {
        let config = CronMonitorConfig {
            enabled: true,
            scan_interval_secs: 120,
            watch_paths: vec![],
            use_inotify: false,
            inotify_debounce_ms: 500,
        };
        assert!(!config.use_inotify);
    }

    #[tokio::test]
    async fn test_start_and_stop_with_inotify_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let file1 = dir.path().join("crontab");
        std::fs::write(&file1, "* * * * * /bin/true").unwrap();

        let config = CronMonitorConfig {
            enabled: true,
            scan_interval_secs: 3600,
            watch_paths: vec![dir.path().to_path_buf()],
            use_inotify: false,
            inotify_debounce_ms: 500,
        };
        let mut module = CronMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[test]
    fn test_setup_inotify_with_directory() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("cron.d");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("job"), "test").unwrap();

        let watch_paths = vec![dir.path().to_path_buf()];
        let result = CronMonitorModule::setup_inotify(&watch_paths);
        assert!(result.is_ok());
        let (_inotify, watch_map) = result.unwrap();
        assert!(watch_map.len() >= 1);
    }

    #[test]
    fn test_setup_inotify_with_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("crontab");
        std::fs::write(&file, "test").unwrap();

        let watch_paths = vec![file];
        let result = CronMonitorModule::setup_inotify(&watch_paths);
        assert!(result.is_ok());
        let (_inotify, watch_map) = result.unwrap();
        assert_eq!(watch_map.len(), 1);
    }

    #[test]
    fn test_publish_changes_detection_field() {
        let report = ChangeReport {
            modified: vec![PathBuf::from("/etc/crontab")],
            added: vec![],
            removed: vec![],
        };

        let event_bus = EventBus::new(16);
        let mut rx = event_bus.subscribe();

        CronMonitorModule::publish_changes(&report, &Some(event_bus), "inotify");

        let event = rx.try_recv().unwrap();
        assert!(
            event
                .details
                .as_ref()
                .unwrap()
                .contains("detection=inotify")
        );
    }

    #[test]
    fn test_publish_changes_periodic_scan_detection() {
        let report = ChangeReport {
            modified: vec![PathBuf::from("/etc/crontab")],
            added: vec![],
            removed: vec![],
        };

        let event_bus = EventBus::new(16);
        let mut rx = event_bus.subscribe();

        CronMonitorModule::publish_changes(&report, &Some(event_bus), "periodic_scan");

        let event = rx.try_recv().unwrap();
        assert!(
            event
                .details
                .as_ref()
                .unwrap()
                .contains("detection=periodic_scan")
        );
    }

    #[test]
    fn test_debounce_logic() {
        let mut debounce_map: HashMap<PathBuf, Instant> = HashMap::new();
        let debounce_duration = Duration::from_millis(500);
        let path = PathBuf::from("/etc/crontab");

        let now = Instant::now();
        assert!(debounce_map.get(&path).is_none());
        debounce_map.insert(path.clone(), now);

        let should_skip = debounce_map
            .get(&path)
            .is_some_and(|last_time| now.duration_since(*last_time) < debounce_duration);
        assert!(should_skip);
    }

    #[test]
    fn test_debounce_logic_expired() {
        let mut debounce_map: HashMap<PathBuf, Instant> = HashMap::new();
        let debounce_duration = Duration::from_millis(500);
        let path = PathBuf::from("/etc/crontab");

        let past = Instant::now() - Duration::from_secs(1);
        debounce_map.insert(path.clone(), past);

        let now = Instant::now();
        let should_skip = debounce_map
            .get(&path)
            .is_some_and(|last_time| now.duration_since(*last_time) < debounce_duration);
        assert!(!should_skip);
    }

    #[test]
    fn test_setup_inotify_with_recursive_subdirectories() {
        let dir = tempfile::tempdir().unwrap();
        let sub1 = dir.path().join("cron.d");
        let sub2 = sub1.join("nested");
        std::fs::create_dir_all(&sub2).unwrap();
        std::fs::write(sub2.join("job"), "test").unwrap();

        let watch_paths = vec![dir.path().to_path_buf()];
        let result = CronMonitorModule::setup_inotify(&watch_paths);
        assert!(result.is_ok());
        let (_inotify, watch_map) = result.unwrap();
        assert!(watch_map.len() >= 3);
    }

    #[test]
    fn test_publish_changes_added_event() {
        let report = ChangeReport {
            modified: vec![],
            added: vec![PathBuf::from("/etc/cron.d/new_job")],
            removed: vec![],
        };

        let event_bus = EventBus::new(16);
        let mut rx = event_bus.subscribe();

        CronMonitorModule::publish_changes(&report, &Some(event_bus), "inotify");

        let event = rx.try_recv().unwrap();
        assert_eq!(event.event_type, "cron_added");
        assert!(
            event
                .details
                .as_ref()
                .unwrap()
                .contains("detection=inotify")
        );
    }

    #[test]
    fn test_publish_changes_removed_event() {
        let report = ChangeReport {
            modified: vec![],
            added: vec![],
            removed: vec![PathBuf::from("/etc/cron.d/old_job")],
        };

        let event_bus = EventBus::new(16);
        let mut rx = event_bus.subscribe();

        CronMonitorModule::publish_changes(&report, &Some(event_bus), "periodic_scan");

        let event = rx.try_recv().unwrap();
        assert_eq!(event.event_type, "cron_removed");
        assert!(
            event
                .details
                .as_ref()
                .unwrap()
                .contains("detection=periodic_scan")
        );
    }

    #[test]
    fn test_publish_changes_no_changes() {
        let report = ChangeReport {
            modified: vec![],
            added: vec![],
            removed: vec![],
        };

        let event_bus = EventBus::new(16);
        let mut rx = event_bus.subscribe();

        CronMonitorModule::publish_changes(&report, &Some(event_bus), "inotify");

        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn test_setup_inotify_empty_paths() {
        let watch_paths: Vec<PathBuf> = vec![];
        let result = CronMonitorModule::setup_inotify(&watch_paths);
        assert!(result.is_ok());
        let (_inotify, watch_map) = result.unwrap();
        assert!(watch_map.is_empty());
    }

    #[test]
    fn test_debounce_map_cleanup() {
        let mut debounce_map: HashMap<PathBuf, Instant> = HashMap::new();
        let now = Instant::now();
        let old_time = now - Duration::from_secs(120);

        debounce_map.insert(PathBuf::from("/etc/cron.d/old"), old_time);
        debounce_map.insert(PathBuf::from("/etc/cron.d/recent"), now);

        let threshold = now - Duration::from_secs(60);
        debounce_map.retain(|_, t| *t > threshold);

        assert_eq!(debounce_map.len(), 1);
        assert!(debounce_map.contains_key(&PathBuf::from("/etc/cron.d/recent")));
    }
}
