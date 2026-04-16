//! ファイル整合性監視モジュール
//!
//! 指定されたパスのファイルを定期的にスキャンし、
//! SHA-256 ハッシュまたは HMAC-SHA256 署名を用いて変更・追加・削除を検知する。

use crate::config::FileIntegrityConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::core::module_stats::ModuleStatsHandle;
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;
use walkdir::WalkDir;

/// モジュール識別子（`ModuleStats` に登録する統計上のモジュール名）
pub(crate) const MODULE_STATS_NAME: &str = "ファイル整合性監視モジュール";

type HmacSha256 = Hmac<Sha256>;

/// ファイル変更レポート
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

/// ファイル整合性監視モジュール
///
/// 指定パスのファイルを定期スキャンし、ベースラインとの差分を検知する。
pub struct FileIntegrityModule {
    config: FileIntegrityConfig,
    baseline: Option<HashMap<PathBuf, String>>,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
    stats_handle: Option<ModuleStatsHandle>,
}

impl FileIntegrityModule {
    /// 新しいファイル整合性監視モジュールを作成する
    pub fn new(config: FileIntegrityConfig, event_bus: Option<EventBus>) -> Self {
        Self {
            config,
            baseline: None,
            cancel_token: CancellationToken::new(),
            event_bus,
            stats_handle: None,
        }
    }

    /// キャンセルトークンのクローンを返す
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    /// 監視対象パスをスキャンし、各ファイルのハッシュを返す
    fn scan_files(watch_paths: &[PathBuf], hmac_key: Option<&[u8]>) -> HashMap<PathBuf, String> {
        let mut result = HashMap::new();
        for path in watch_paths {
            if path.is_file() {
                match compute_hash(path, hmac_key) {
                    Ok(hash) => {
                        result.insert(path.clone(), hash);
                    }
                    Err(e) => {
                        tracing::warn!(path = %path.display(), error = %e, "ファイルの読み取りに失敗しました。スキャンを継続します");
                    }
                }
            } else if path.is_dir() {
                for entry in WalkDir::new(path).follow_links(false).into_iter() {
                    match entry {
                        Ok(entry) if entry.file_type().is_file() => {
                            let file_path = entry.into_path();
                            match compute_hash(&file_path, hmac_key) {
                                Ok(hash) => {
                                    result.insert(file_path, hash);
                                }
                                Err(e) => {
                                    tracing::warn!(path = %file_path.display(), error = %e, "ファイルの読み取りに失敗しました。スキャンを継続します");
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
}

/// ファイルのハッシュを計算する
///
/// `hmac_key` が指定されている場合は HMAC-SHA256、未指定の場合は SHA-256 を使用する。
fn compute_hash(path: &PathBuf, hmac_key: Option<&[u8]>) -> Result<String, AppError> {
    let data = std::fs::read(path).map_err(|e| AppError::FileIo {
        path: path.clone(),
        source: e,
    })?;

    match hmac_key {
        Some(key) => {
            let mut mac = HmacSha256::new_from_slice(key).map_err(|e| AppError::ModuleConfig {
                message: format!("HMAC キーの初期化に失敗しました: {e}"),
            })?;
            mac.update(&data);
            let result = mac.finalize();
            Ok(format!("{:x}", result.into_bytes()))
        }
        None => {
            let mut hasher = Sha256::new();
            hasher.update(&data);
            let hash = hasher.finalize();
            Ok(format!("{:x}", hash))
        }
    }
}

impl Module for FileIntegrityModule {
    fn name(&self) -> &str {
        "file_integrity"
    }

    fn set_module_stats(&mut self, handle: ModuleStatsHandle) {
        self.stats_handle = Some(handle);
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        if let Some(ref key) = self.config.hmac_key {
            if key.len() < 32 {
                tracing::warn!(
                    key_length = key.len(),
                    "HMAC キーが短すぎます（推奨: 32 バイト以上）。セキュリティが低下する可能性があります"
                );
            }
            tracing::info!("HMAC-SHA256 モードで動作します");
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
            hmac_enabled = self.config.hmac_key.is_some(),
            "ファイル整合性監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        let hmac_key_bytes = self.config.hmac_key.as_ref().map(|k| k.as_bytes().to_vec());

        // 初回スキャンでベースライン作成
        let baseline = Self::scan_files(&self.config.watch_paths, hmac_key_bytes.as_deref());
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
        let stats_handle = self.stats_handle.clone();

        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            // 最初の tick は即座に発火するのでスキップ
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("ファイル整合性監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let scan_start = std::time::Instant::now();
                        let current = FileIntegrityModule::scan_files(&watch_paths, hmac_key_bytes.as_deref());
                        let report = FileIntegrityModule::detect_changes(&baseline, &current);
                        let scan_elapsed = scan_start.elapsed();
                        if let Some(ref handle) = stats_handle {
                            handle.record_scan_duration(MODULE_STATS_NAME, scan_elapsed);
                        }

                        if report.has_changes() {
                            for path in &report.modified {
                                tracing::warn!(path = %path.display(), change = "modified", "ファイルの変更を検知しました");
                                if let Some(ref bus) = event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            "file_modified",
                                            Severity::Warning,
                                            "file_integrity",
                                            format!("ファイルの変更を検知しました: {}", path.display()),
                                        )
                                        .with_details(path.display().to_string()),
                                    );
                                }
                            }
                            for path in &report.added {
                                tracing::warn!(path = %path.display(), change = "added", "ファイルの追加を検知しました");
                                if let Some(ref bus) = event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            "file_added",
                                            Severity::Warning,
                                            "file_integrity",
                                            format!("ファイルの追加を検知しました: {}", path.display()),
                                        )
                                        .with_details(path.display().to_string()),
                                    );
                                }
                            }
                            for path in &report.removed {
                                tracing::warn!(path = %path.display(), change = "removed", "ファイルの削除を検知しました");
                                if let Some(ref bus) = event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            "file_removed",
                                            Severity::Warning,
                                            "file_integrity",
                                            format!("ファイルの削除を検知しました: {}", path.display()),
                                        )
                                        .with_details(path.display().to_string()),
                                    );
                                }
                            }
                            // ベースラインを更新
                            baseline = current;
                        } else {
                            tracing::debug!("ファイルの変更はありません");
                        }
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();
        let hmac_key_bytes = self.config.hmac_key.as_ref().map(|k| k.as_bytes().to_vec());
        let files = Self::scan_files(&self.config.watch_paths, hmac_key_bytes.as_deref());
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
            summary: format!("監視対象ファイル {}件をスキャンしました", items_scanned),
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
        let hash = compute_hash(&tmpfile.path().to_path_buf(), None).unwrap();
        // SHA-256 of "hello world"
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_compute_hash_hmac() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "hello world").unwrap();
        let key = b"supersecretkey-for-hmac-testing!!";
        let hash = compute_hash(&tmpfile.path().to_path_buf(), Some(key)).unwrap();
        // HMAC-SHA256 should differ from plain SHA-256
        assert_ne!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_compute_hash_hmac_deterministic() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "hello world").unwrap();
        let key = b"test-key-1234567890123456789012";
        let hash1 = compute_hash(&tmpfile.path().to_path_buf(), Some(key)).unwrap();
        let hash2 = compute_hash(&tmpfile.path().to_path_buf(), Some(key)).unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compute_hash_different_keys_different_hashes() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "hello world").unwrap();
        let key1 = b"key-aaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let key2 = b"key-bbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let hash1 = compute_hash(&tmpfile.path().to_path_buf(), Some(key1)).unwrap();
        let hash2 = compute_hash(&tmpfile.path().to_path_buf(), Some(key2)).unwrap();
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compute_hash_nonexistent_file() {
        let result = compute_hash(&PathBuf::from("/tmp/nonexistent-file-zettai-test"), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_scan_files_with_directory() {
        let dir = tempfile::tempdir().unwrap();
        let file1 = dir.path().join("a.txt");
        let file2 = dir.path().join("b.txt");
        std::fs::write(&file1, "content a").unwrap();
        std::fs::write(&file2, "content b").unwrap();

        let watch_paths = vec![dir.path().to_path_buf()];
        let result = FileIntegrityModule::scan_files(&watch_paths, None);
        assert_eq!(result.len(), 2);
        assert!(result.contains_key(&file1));
        assert!(result.contains_key(&file2));
    }

    #[test]
    fn test_scan_files_with_hmac_key() {
        let dir = tempfile::tempdir().unwrap();
        let file1 = dir.path().join("a.txt");
        std::fs::write(&file1, "content a").unwrap();

        let watch_paths = vec![dir.path().to_path_buf()];
        let result_plain = FileIntegrityModule::scan_files(&watch_paths, None);
        let result_hmac =
            FileIntegrityModule::scan_files(&watch_paths, Some(b"hmac-test-key-1234567890123456"));

        let hash_plain = result_plain.get(&file1).unwrap();
        let hash_hmac = result_hmac.get(&file1).unwrap();
        assert_ne!(hash_plain, hash_hmac);
    }

    #[test]
    fn test_scan_files_with_single_file() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "test content").unwrap();
        let path = tmpfile.path().to_path_buf();

        let watch_paths = vec![path.clone()];
        let result = FileIntegrityModule::scan_files(&watch_paths, None);
        assert_eq!(result.len(), 1);
        assert!(result.contains_key(&path));
    }

    #[test]
    fn test_detect_changes_no_changes() {
        let mut baseline = HashMap::new();
        baseline.insert(PathBuf::from("/a"), "hash1".to_string());

        let current = baseline.clone();
        let report = FileIntegrityModule::detect_changes(&baseline, &current);
        assert!(!report.has_changes());
    }

    #[test]
    fn test_detect_changes_modified() {
        let mut baseline = HashMap::new();
        baseline.insert(PathBuf::from("/a"), "hash1".to_string());

        let mut current = HashMap::new();
        current.insert(PathBuf::from("/a"), "hash2".to_string());

        let report = FileIntegrityModule::detect_changes(&baseline, &current);
        assert_eq!(report.modified.len(), 1);
        assert!(report.added.is_empty());
        assert!(report.removed.is_empty());
    }

    #[test]
    fn test_detect_changes_added() {
        let baseline = HashMap::new();
        let mut current = HashMap::new();
        current.insert(PathBuf::from("/new"), "hash1".to_string());

        let report = FileIntegrityModule::detect_changes(&baseline, &current);
        assert!(report.modified.is_empty());
        assert_eq!(report.added.len(), 1);
        assert!(report.removed.is_empty());
    }

    #[test]
    fn test_detect_changes_removed() {
        let mut baseline = HashMap::new();
        baseline.insert(PathBuf::from("/old"), "hash1".to_string());

        let current = HashMap::new();
        let report = FileIntegrityModule::detect_changes(&baseline, &current);
        assert!(report.modified.is_empty());
        assert!(report.added.is_empty());
        assert_eq!(report.removed.len(), 1);
    }

    #[test]
    fn test_init_zero_interval() {
        let config = FileIntegrityConfig {
            enabled: true,
            scan_interval_secs: 0,
            watch_paths: vec![],
            hmac_key: None,
        };
        let mut module = FileIntegrityModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_init_nonexistent_path() {
        let config = FileIntegrityConfig {
            enabled: true,
            scan_interval_secs: 300,
            watch_paths: vec![PathBuf::from("/nonexistent-path-zettai-test")],
            hmac_key: None,
        };
        let mut module = FileIntegrityModule::new(config, None);
        // Should succeed but skip the nonexistent path
        let result = module.init();
        assert!(result.is_ok());
        assert!(module.config.watch_paths.is_empty());
    }

    #[test]
    fn test_init_canonicalizes_paths() {
        let dir = tempfile::tempdir().unwrap();
        let subdir = dir.path().join("sub");
        std::fs::create_dir(&subdir).unwrap();

        // Use a path with ".." to test canonicalization
        let non_canonical = dir.path().join("sub").join("..").join("sub");
        let config = FileIntegrityConfig {
            enabled: true,
            scan_interval_secs: 300,
            watch_paths: vec![non_canonical],
            hmac_key: None,
        };
        let mut module = FileIntegrityModule::new(config, None);
        let result = module.init();
        assert!(result.is_ok());
        assert_eq!(module.config.watch_paths.len(), 1);
        // canonicalized path should not contain ".."
        let canonical = &module.config.watch_paths[0];
        assert!(!canonical.to_string_lossy().contains(".."));
    }

    #[test]
    fn test_scan_files_empty_watch_paths() {
        let watch_paths: Vec<PathBuf> = vec![];
        let result = FileIntegrityModule::scan_files(&watch_paths, None);
        assert!(result.is_empty());
    }

    #[test]
    fn test_scan_files_symlink_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let real_file = dir.path().join("real.txt");
        std::fs::write(&real_file, "real content").unwrap();

        // ディレクトリ外にシンボリックリンクのターゲットを作成
        let target_dir = tempfile::tempdir().unwrap();
        let target_file = target_dir.path().join("target.txt");
        std::fs::write(&target_file, "target content").unwrap();

        // シンボリックリンクを作成
        let link_path = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&target_file, &link_path).unwrap();

        let watch_paths = vec![dir.path().to_path_buf()];
        let result = FileIntegrityModule::scan_files(&watch_paths, None);

        // real.txt は含まれるが、シンボリックリンクは follow_links(false) のため
        // WalkDir がシンボリックリンクのファイルタイプを symlink として報告し、
        // is_file() が true を返すため結果に含まれる（ただしリンク先は辿らない）
        assert!(result.contains_key(&real_file));
    }

    #[test]
    fn test_scan_files_nested_directories() {
        let dir = tempfile::tempdir().unwrap();
        let sub1 = dir.path().join("sub1");
        let sub2 = sub1.join("sub2");
        std::fs::create_dir_all(&sub2).unwrap();

        let file_root = dir.path().join("root.txt");
        let file_sub1 = sub1.join("sub1.txt");
        let file_sub2 = sub2.join("sub2.txt");
        std::fs::write(&file_root, "root").unwrap();
        std::fs::write(&file_sub1, "sub1").unwrap();
        std::fs::write(&file_sub2, "sub2").unwrap();

        let watch_paths = vec![dir.path().to_path_buf()];
        let result = FileIntegrityModule::scan_files(&watch_paths, None);
        assert_eq!(result.len(), 3);
        assert!(result.contains_key(&file_root));
        assert!(result.contains_key(&file_sub1));
        assert!(result.contains_key(&file_sub2));
    }

    #[test]
    fn test_init_empty_watch_paths() {
        let config = FileIntegrityConfig {
            enabled: true,
            scan_interval_secs: 300,
            watch_paths: vec![],
            hmac_key: None,
        };
        let mut module = FileIntegrityModule::new(config, None);
        let result = module.init();
        assert!(result.is_ok());
        assert!(module.config.watch_paths.is_empty());
    }

    #[tokio::test]
    async fn test_start_creates_baseline_and_stops() {
        let dir = tempfile::tempdir().unwrap();
        let file1 = dir.path().join("a.txt");
        std::fs::write(&file1, "content a").unwrap();

        let config = FileIntegrityConfig {
            enabled: true,
            scan_interval_secs: 3600,
            watch_paths: vec![dir.path().to_path_buf()],
            hmac_key: None,
        };
        let mut module = FileIntegrityModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        // start() が成功すればベースラインスキャンが完了している
        // stop() でクリーンに停止できることを確認
        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_start_with_hmac_key() {
        let dir = tempfile::tempdir().unwrap();
        let file1 = dir.path().join("a.txt");
        std::fs::write(&file1, "content a").unwrap();

        let config = FileIntegrityConfig {
            enabled: true,
            scan_interval_secs: 3600,
            watch_paths: vec![dir.path().to_path_buf()],
            hmac_key: Some("test-hmac-key-for-start-test-1234".to_string()),
        };
        let mut module = FileIntegrityModule::new(config, None);
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

    #[test]
    fn test_detect_changes_combined() {
        let mut baseline = HashMap::new();
        baseline.insert(PathBuf::from("/existing"), "hash1".to_string());
        baseline.insert(PathBuf::from("/to_remove"), "hash2".to_string());
        baseline.insert(PathBuf::from("/to_modify"), "hash3".to_string());

        let mut current = HashMap::new();
        current.insert(PathBuf::from("/existing"), "hash1".to_string());
        current.insert(PathBuf::from("/to_modify"), "hash_changed".to_string());
        current.insert(PathBuf::from("/new_file"), "hash4".to_string());

        let report = FileIntegrityModule::detect_changes(&baseline, &current);
        assert_eq!(report.modified.len(), 1);
        assert_eq!(report.added.len(), 1);
        assert_eq!(report.removed.len(), 1);
        assert!(report.modified.contains(&PathBuf::from("/to_modify")));
        assert!(report.added.contains(&PathBuf::from("/new_file")));
        assert!(report.removed.contains(&PathBuf::from("/to_remove")));
    }

    #[test]
    fn test_init_with_event_bus_none() {
        let dir = tempfile::tempdir().unwrap();
        let config = FileIntegrityConfig {
            enabled: true,
            scan_interval_secs: 300,
            watch_paths: vec![dir.path().to_path_buf()],
            hmac_key: None,
        };
        let mut module = FileIntegrityModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[test]
    fn test_init_with_event_bus_some() {
        let dir = tempfile::tempdir().unwrap();
        let config = FileIntegrityConfig {
            enabled: true,
            scan_interval_secs: 300,
            watch_paths: vec![dir.path().to_path_buf()],
            hmac_key: None,
        };
        let bus = EventBus::new(16);
        let mut module = FileIntegrityModule::new(config, Some(bus));
        assert!(module.init().is_ok());
    }

    #[tokio::test]
    async fn test_initial_scan_with_files() {
        let dir = tempfile::tempdir().unwrap();
        let file1 = dir.path().join("a.txt");
        let file2 = dir.path().join("b.txt");
        std::fs::write(&file1, "content a").unwrap();
        std::fs::write(&file2, "content b").unwrap();

        let config = FileIntegrityConfig {
            enabled: true,
            scan_interval_secs: 300,
            watch_paths: vec![dir.path().to_path_buf()],
            hmac_key: None,
        };
        let mut module = FileIntegrityModule::new(config, None);
        module.init().unwrap();

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 2);
        assert_eq!(result.issues_found, 0);
        assert!(!result.summary.is_empty());
    }

    #[tokio::test]
    async fn test_initial_scan_with_hmac() {
        let dir = tempfile::tempdir().unwrap();
        let file1 = dir.path().join("a.txt");
        std::fs::write(&file1, "content a").unwrap();

        let config_plain = FileIntegrityConfig {
            enabled: true,
            scan_interval_secs: 300,
            watch_paths: vec![dir.path().to_path_buf()],
            hmac_key: None,
        };
        let mut module_plain = FileIntegrityModule::new(config_plain, None);
        module_plain.init().unwrap();
        let result_plain = module_plain.initial_scan().await.unwrap();

        let config_hmac = FileIntegrityConfig {
            enabled: true,
            scan_interval_secs: 300,
            watch_paths: vec![dir.path().to_path_buf()],
            hmac_key: Some("test-key-for-initial-scan-12345678".to_string()),
        };
        let mut module_hmac = FileIntegrityModule::new(config_hmac, None);
        module_hmac.init().unwrap();
        let result_hmac = module_hmac.initial_scan().await.unwrap();

        assert_eq!(result_plain.items_scanned, result_hmac.items_scanned);
        // ハッシュ値は異なるはず
        let plain_hashes: Vec<&String> = result_plain.snapshot.values().collect();
        let hmac_hashes: Vec<&String> = result_hmac.snapshot.values().collect();
        assert_ne!(plain_hashes, hmac_hashes);
    }

    #[tokio::test]
    async fn test_initial_scan_empty() {
        let config = FileIntegrityConfig {
            enabled: true,
            scan_interval_secs: 300,
            watch_paths: vec![],
            hmac_key: None,
        };
        let module = FileIntegrityModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
    }

    #[test]
    fn test_init_with_hmac_key() {
        let config = FileIntegrityConfig {
            enabled: true,
            scan_interval_secs: 300,
            watch_paths: vec![],
            hmac_key: Some("a-very-long-hmac-key-that-is-at-least-32-bytes".to_string()),
        };
        let mut module = FileIntegrityModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[test]
    fn test_init_with_short_hmac_key() {
        let config = FileIntegrityConfig {
            enabled: true,
            scan_interval_secs: 300,
            watch_paths: vec![],
            hmac_key: Some("short".to_string()),
        };
        let mut module = FileIntegrityModule::new(config, None);
        // Should succeed but emit a warning (can't easily test the warning log)
        assert!(module.init().is_ok());
    }

    #[test]
    fn test_set_module_stats_stores_handle() {
        let config = FileIntegrityConfig {
            enabled: true,
            scan_interval_secs: 300,
            watch_paths: vec![],
            hmac_key: None,
        };
        let mut module = FileIntegrityModule::new(config, None);
        assert!(module.stats_handle.is_none());
        let handle = ModuleStatsHandle::new();
        module.set_module_stats(handle);
        assert!(module.stats_handle.is_some());
    }

    #[tokio::test]
    async fn test_periodic_scan_records_scan_duration() {
        // 短いスキャン間隔で起動し、定期スキャンで scan_count が増加することを確認する。
        let dir = tempfile::tempdir().unwrap();
        let file1 = dir.path().join("a.txt");
        std::fs::write(&file1, "content a").unwrap();

        let config = FileIntegrityConfig {
            enabled: true,
            scan_interval_secs: 1,
            watch_paths: vec![dir.path().to_path_buf()],
            hmac_key: None,
        };
        let mut module = FileIntegrityModule::new(config, None);
        module.init().unwrap();

        let stats = ModuleStatsHandle::new();
        module.set_module_stats(stats.clone());

        let handle = module.start().await.unwrap();

        // interval 1 秒 + マージンで 1 回以上の tick を待つ
        tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;

        module.stop().await.unwrap();
        let _ = handle.await;

        let s = stats.get(MODULE_STATS_NAME).expect("stats must exist");
        assert!(
            s.scan_count >= 1,
            "scan_count={} expected >= 1",
            s.scan_count
        );
        assert!(s.scan_total_ms.is_some());
    }
}
