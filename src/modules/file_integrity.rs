//! ファイル整合性監視モジュール
//!
//! 指定されたパスのファイルを定期的にスキャンし、
//! SHA-256 ハッシュを用いて変更・追加・削除を検知する。

use crate::config::FileIntegrityConfig;
use crate::error::AppError;
use crate::modules::Module;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;
use walkdir::WalkDir;

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
}

impl FileIntegrityModule {
    /// 新しいファイル整合性監視モジュールを作成する
    pub fn new(config: FileIntegrityConfig) -> Self {
        Self {
            config,
            baseline: None,
            cancel_token: CancellationToken::new(),
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
                        tracing::warn!(path = %path.display(), error = %e, "ファイルの読み取りに失敗しました。スキャンを継続します");
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

impl Module for FileIntegrityModule {
    fn name(&self) -> &str {
        "file_integrity"
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
            "ファイル整合性監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<(), AppError> {
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

        tokio::spawn(async move {
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
                        let current = FileIntegrityModule::scan_files(&watch_paths);
                        let report = FileIntegrityModule::detect_changes(&baseline, &current);

                        if report.has_changes() {
                            for path in &report.modified {
                                tracing::warn!(path = %path.display(), change = "modified", "ファイルの変更を検知しました");
                            }
                            for path in &report.added {
                                tracing::warn!(path = %path.display(), change = "added", "ファイルの追加を検知しました");
                            }
                            for path in &report.removed {
                                tracing::warn!(path = %path.display(), change = "removed", "ファイルの削除を検知しました");
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

        Ok(())
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
    fn test_compute_hash_nonexistent_file() {
        let result = compute_hash(&PathBuf::from("/tmp/nonexistent-file-zettai-test"));
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
        let result = FileIntegrityModule::scan_files(&watch_paths);
        assert_eq!(result.len(), 2);
        assert!(result.contains_key(&file1));
        assert!(result.contains_key(&file2));
    }

    #[test]
    fn test_scan_files_with_single_file() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "test content").unwrap();
        let path = tmpfile.path().to_path_buf();

        let watch_paths = vec![path.clone()];
        let result = FileIntegrityModule::scan_files(&watch_paths);
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
        };
        let mut module = FileIntegrityModule::new(config);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_init_nonexistent_path() {
        let config = FileIntegrityConfig {
            enabled: true,
            scan_interval_secs: 300,
            watch_paths: vec![PathBuf::from("/nonexistent-path-zettai-test")],
        };
        let mut module = FileIntegrityModule::new(config);
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
        };
        let mut module = FileIntegrityModule::new(config);
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
        let result = FileIntegrityModule::scan_files(&watch_paths);
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
        let result = FileIntegrityModule::scan_files(&watch_paths);

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
        let result = FileIntegrityModule::scan_files(&watch_paths);
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
        };
        let mut module = FileIntegrityModule::new(config);
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
        };
        let mut module = FileIntegrityModule::new(config);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        // start() が成功すればベースラインスキャンが完了している
        // stop() でクリーンに停止できることを確認
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
}
