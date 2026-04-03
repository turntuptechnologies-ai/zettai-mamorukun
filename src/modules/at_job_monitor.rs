//! at/batch ジョブ監視モジュール
//!
//! at/batch 関連ファイルを定期的にスキャンし、SHA-256 ハッシュベースで変更を検知する。
//!
//! 検知対象:
//! - 新規追加された at ジョブファイル
//! - 内容が変更された at ジョブファイル
//! - 削除された at ジョブファイル
//! - at.allow / at.deny のアクセス制御ファイル変更

use crate::config::AtJobMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;
use walkdir::WalkDir;

/// at ファイル変更レポート
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

/// パスが at.allow / at.deny のアクセス制御ファイルかどうかを判定する
fn is_acl_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|name| name == "at.allow" || name == "at.deny")
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

/// at/batch ジョブ監視モジュール
///
/// at/batch 関連ファイルを定期スキャンし、ベースラインとの差分を検知する。
/// at.allow / at.deny のアクセス制御ファイル変更は High Severity で報告する。
pub struct AtJobMonitorModule {
    config: AtJobMonitorConfig,
    baseline: Option<HashMap<PathBuf, String>>,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl AtJobMonitorModule {
    /// 新しい at/batch ジョブ監視モジュールを作成する
    pub fn new(config: AtJobMonitorConfig, event_bus: Option<EventBus>) -> Self {
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
                        tracing::warn!(path = %path.display(), error = %e, "at ジョブファイルの読み取りに失敗しました。スキャンを継続します");
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
                                    tracing::warn!(path = %file_path.display(), error = %e, "at ジョブファイルの読み取りに失敗しました。スキャンを継続します");
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

impl Module for AtJobMonitorModule {
    fn name(&self) -> &str {
        "at_job_monitor"
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
            "at/batch ジョブ監視モジュールを初期化しました"
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
        let event_bus = self.event_bus.clone();

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            // 最初の tick は即座に発火するのでスキップ
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("at/batch ジョブ監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = AtJobMonitorModule::scan_files(&watch_paths);
                        let report = AtJobMonitorModule::detect_changes(&baseline, &current);

                        if report.has_changes() {
                            for path in &report.modified {
                                let (severity, event_name) = if is_acl_file(path) {
                                    (Severity::Critical, "at_access_control_modified")
                                } else {
                                    (Severity::Warning, "at_job_modified")
                                };
                                tracing::warn!(path = %path.display(), change = "modified", "at ジョブファイルの変更を検知しました");
                                if let Some(ref bus) = event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            event_name,
                                            severity,
                                            "at_job_monitor",
                                            format!("at ジョブファイルの変更を検知しました: {}", path.display()),
                                        )
                                        .with_details(path.display().to_string()),
                                    );
                                }
                            }
                            for path in &report.added {
                                let (severity, event_name) = if is_acl_file(path) {
                                    (Severity::Critical, "at_access_control_modified")
                                } else {
                                    (Severity::Warning, "at_job_added")
                                };
                                tracing::warn!(path = %path.display(), change = "added", "at ジョブファイルの追加を検知しました");
                                if let Some(ref bus) = event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            event_name,
                                            severity,
                                            "at_job_monitor",
                                            format!("at ジョブファイルの追加を検知しました: {}", path.display()),
                                        )
                                        .with_details(path.display().to_string()),
                                    );
                                }
                            }
                            for path in &report.removed {
                                let (severity, event_name) = if is_acl_file(path) {
                                    (Severity::Critical, "at_access_control_modified")
                                } else {
                                    (Severity::Warning, "at_job_removed")
                                };
                                tracing::warn!(path = %path.display(), change = "removed", "at ジョブファイルの削除を検知しました");
                                if let Some(ref bus) = event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            event_name,
                                            severity,
                                            "at_job_monitor",
                                            format!("at ジョブファイルの削除を検知しました: {}", path.display()),
                                        )
                                        .with_details(path.display().to_string()),
                                    );
                                }
                            }
                            // ベースラインを更新
                            baseline = current;
                        } else {
                            tracing::debug!("at ジョブファイルの変更はありません");
                        }
                    }
                }
            }
        });

        Ok(())
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
            summary: format!(
                "at/batch ジョブファイル {}件をスキャンしました",
                items_scanned
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
    use std::io::Write;

    #[test]
    fn test_compute_hash() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "hello world").unwrap();
        let hash = compute_hash(&tmpfile.path().to_path_buf()).unwrap();
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_compute_hash_nonexistent() {
        let result = compute_hash(&PathBuf::from("/tmp/nonexistent-file-zettai-at-test"));
        assert!(result.is_err());
    }

    #[test]
    fn test_is_acl_file() {
        assert!(is_acl_file(Path::new("/etc/at.allow")));
        assert!(is_acl_file(Path::new("/etc/at.deny")));
        assert!(!is_acl_file(Path::new("/var/spool/at/job123")));
        assert!(!is_acl_file(Path::new("/etc/crontab")));
    }

    #[test]
    fn test_scan_files_with_directory() {
        let dir = tempfile::tempdir().unwrap();
        let file1 = dir.path().join("job1");
        let file2 = dir.path().join("job2");
        std::fs::write(&file1, "echo hello").unwrap();
        std::fs::write(&file2, "echo world").unwrap();

        let watch_paths = vec![dir.path().to_path_buf()];
        let result = AtJobMonitorModule::scan_files(&watch_paths);
        assert_eq!(result.len(), 2);
        assert!(result.contains_key(&file1));
        assert!(result.contains_key(&file2));
    }

    #[test]
    fn test_scan_files_with_single_file() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "echo hello").unwrap();
        let path = tmpfile.path().to_path_buf();

        let watch_paths = vec![path.clone()];
        let result = AtJobMonitorModule::scan_files(&watch_paths);
        assert_eq!(result.len(), 1);
        assert!(result.contains_key(&path));
    }

    #[test]
    fn test_scan_files_empty() {
        let watch_paths: Vec<PathBuf> = vec![];
        let result = AtJobMonitorModule::scan_files(&watch_paths);
        assert!(result.is_empty());
    }

    #[test]
    fn test_scan_files_nested() {
        let dir = tempfile::tempdir().unwrap();
        let sub1 = dir.path().join("subdir");
        let sub2 = sub1.join("nested");
        std::fs::create_dir_all(&sub2).unwrap();

        let file_root = dir.path().join("job1");
        let file_sub1 = sub1.join("job2");
        let file_sub2 = sub2.join("job3");
        std::fs::write(&file_root, "root").unwrap();
        std::fs::write(&file_sub1, "sub1").unwrap();
        std::fs::write(&file_sub2, "sub2").unwrap();

        let watch_paths = vec![dir.path().to_path_buf()];
        let result = AtJobMonitorModule::scan_files(&watch_paths);
        assert_eq!(result.len(), 3);
        assert!(result.contains_key(&file_root));
        assert!(result.contains_key(&file_sub1));
        assert!(result.contains_key(&file_sub2));
    }

    #[test]
    fn test_detect_changes_no_changes() {
        let mut baseline = HashMap::new();
        baseline.insert(PathBuf::from("/var/spool/at/job1"), "hash1".to_string());

        let current = baseline.clone();
        let report = AtJobMonitorModule::detect_changes(&baseline, &current);
        assert!(!report.has_changes());
    }

    #[test]
    fn test_detect_changes_modified() {
        let mut baseline = HashMap::new();
        baseline.insert(PathBuf::from("/var/spool/at/job1"), "hash1".to_string());

        let mut current = HashMap::new();
        current.insert(PathBuf::from("/var/spool/at/job1"), "hash2".to_string());

        let report = AtJobMonitorModule::detect_changes(&baseline, &current);
        assert_eq!(report.modified.len(), 1);
        assert!(report.added.is_empty());
        assert!(report.removed.is_empty());
    }

    #[test]
    fn test_detect_changes_added() {
        let baseline = HashMap::new();
        let mut current = HashMap::new();
        current.insert(PathBuf::from("/var/spool/at/job_new"), "hash1".to_string());

        let report = AtJobMonitorModule::detect_changes(&baseline, &current);
        assert!(report.modified.is_empty());
        assert_eq!(report.added.len(), 1);
        assert!(report.removed.is_empty());
    }

    #[test]
    fn test_detect_changes_removed() {
        let mut baseline = HashMap::new();
        baseline.insert(PathBuf::from("/var/spool/at/job_old"), "hash1".to_string());

        let current = HashMap::new();
        let report = AtJobMonitorModule::detect_changes(&baseline, &current);
        assert!(report.modified.is_empty());
        assert!(report.added.is_empty());
        assert_eq!(report.removed.len(), 1);
    }

    #[test]
    fn test_detect_changes_combined() {
        let mut baseline = HashMap::new();
        baseline.insert(PathBuf::from("/var/spool/at/job1"), "hash1".to_string());
        baseline.insert(
            PathBuf::from("/var/spool/at/to_remove"),
            "hash2".to_string(),
        );
        baseline.insert(
            PathBuf::from("/var/spool/at/to_modify"),
            "hash3".to_string(),
        );

        let mut current = HashMap::new();
        current.insert(PathBuf::from("/var/spool/at/job1"), "hash1".to_string());
        current.insert(
            PathBuf::from("/var/spool/at/to_modify"),
            "hash_changed".to_string(),
        );
        current.insert(PathBuf::from("/var/spool/at/new_job"), "hash4".to_string());

        let report = AtJobMonitorModule::detect_changes(&baseline, &current);
        assert_eq!(report.modified.len(), 1);
        assert_eq!(report.added.len(), 1);
        assert_eq!(report.removed.len(), 1);
        assert!(
            report
                .modified
                .contains(&PathBuf::from("/var/spool/at/to_modify"))
        );
        assert!(
            report
                .added
                .contains(&PathBuf::from("/var/spool/at/new_job"))
        );
        assert!(
            report
                .removed
                .contains(&PathBuf::from("/var/spool/at/to_remove"))
        );
    }

    #[test]
    fn test_init_zero_interval() {
        let config = AtJobMonitorConfig {
            enabled: true,
            scan_interval_secs: 0,
            watch_paths: vec![],
        };
        let mut module = AtJobMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_init_valid() {
        let dir = tempfile::tempdir().unwrap();
        let config = AtJobMonitorConfig {
            enabled: true,
            scan_interval_secs: 120,
            watch_paths: vec![dir.path().to_path_buf()],
        };
        let mut module = AtJobMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_ok());
    }

    #[test]
    fn test_init_nonexistent_path() {
        let config = AtJobMonitorConfig {
            enabled: true,
            scan_interval_secs: 120,
            watch_paths: vec![PathBuf::from("/nonexistent-path-zettai-at-test")],
        };
        let mut module = AtJobMonitorModule::new(config, None);
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
        let config = AtJobMonitorConfig {
            enabled: true,
            scan_interval_secs: 120,
            watch_paths: vec![non_canonical],
        };
        let mut module = AtJobMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_ok());
        assert_eq!(module.config.watch_paths.len(), 1);
        let canonical = &module.config.watch_paths[0];
        assert!(!canonical.to_string_lossy().contains(".."));
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let dir = tempfile::tempdir().unwrap();
        let file1 = dir.path().join("job1");
        std::fs::write(&file1, "echo hello").unwrap();

        let config = AtJobMonitorConfig {
            enabled: true,
            scan_interval_secs: 3600,
            watch_paths: vec![dir.path().to_path_buf()],
        };
        let mut module = AtJobMonitorModule::new(config, None);
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
    fn test_change_report_has_changes_modified_only() {
        let report = ChangeReport {
            modified: vec![PathBuf::from("/tmp/job1")],
            added: vec![],
            removed: vec![],
        };
        assert!(report.has_changes());
    }

    #[test]
    fn test_change_report_has_changes_added_only() {
        let report = ChangeReport {
            modified: vec![],
            added: vec![PathBuf::from("/tmp/job1")],
            removed: vec![],
        };
        assert!(report.has_changes());
    }

    #[test]
    fn test_change_report_has_changes_removed_only() {
        let report = ChangeReport {
            modified: vec![],
            added: vec![],
            removed: vec![PathBuf::from("/tmp/job1")],
        };
        assert!(report.has_changes());
    }

    #[test]
    fn test_scan_files_empty_directory() {
        let dir = tempfile::tempdir().unwrap();
        // ディレクトリは存在するがファイルは空
        let watch_paths = vec![dir.path().to_path_buf()];
        let result = AtJobMonitorModule::scan_files(&watch_paths);
        assert!(result.is_empty());
    }

    #[test]
    fn test_scan_files_nonexistent_path() {
        let watch_paths = vec![PathBuf::from("/nonexistent-path-zettai-at-scan-test")];
        let result = AtJobMonitorModule::scan_files(&watch_paths);
        assert!(result.is_empty());
    }

    #[test]
    fn test_is_acl_file_edge_cases() {
        // 空のパス
        assert!(!is_acl_file(Path::new("")));
        // ファイル名のみ
        assert!(is_acl_file(Path::new("at.allow")));
        assert!(is_acl_file(Path::new("at.deny")));
        // 似た名前だが異なるファイル
        assert!(!is_acl_file(Path::new("at.allow.bak")));
        assert!(!is_acl_file(Path::new("at.deny.bak")));
        assert!(!is_acl_file(Path::new("at.allowx")));
        assert!(!is_acl_file(Path::new("xat.allow")));
        // 深いパスの at.allow / at.deny
        assert!(is_acl_file(Path::new("/etc/security/at.allow")));
        assert!(is_acl_file(Path::new("/etc/security/at.deny")));
    }

    #[test]
    fn test_module_name() {
        let config = AtJobMonitorConfig {
            enabled: true,
            scan_interval_secs: 120,
            watch_paths: vec![],
        };
        let module = AtJobMonitorModule::new(config, None);
        assert_eq!(module.name(), "at_job_monitor");
    }

    #[test]
    fn test_scan_detect_integration() {
        // 実ファイルを使ったスキャン→変更→再スキャン→検知の統合テスト
        let dir = tempfile::tempdir().unwrap();
        let file1 = dir.path().join("job1");
        let file2 = dir.path().join("job2");
        std::fs::write(&file1, "echo hello").unwrap();
        std::fs::write(&file2, "echo world").unwrap();

        let watch_paths = vec![dir.path().to_path_buf()];

        // ベースラインスキャン
        let baseline = AtJobMonitorModule::scan_files(&watch_paths);
        assert_eq!(baseline.len(), 2);

        // ファイル変更
        std::fs::write(&file1, "echo modified").unwrap();
        // ファイル追加
        let file3 = dir.path().join("job3");
        std::fs::write(&file3, "echo new").unwrap();
        // ファイル削除
        std::fs::remove_file(&file2).unwrap();

        // 再スキャン
        let current = AtJobMonitorModule::scan_files(&watch_paths);
        assert_eq!(current.len(), 2); // file1 + file3

        // 変更検知
        let report = AtJobMonitorModule::detect_changes(&baseline, &current);
        assert_eq!(report.modified.len(), 1);
        assert!(report.modified.contains(&file1));
        assert_eq!(report.added.len(), 1);
        assert!(report.added.contains(&file3));
        assert_eq!(report.removed.len(), 1);
        assert!(report.removed.contains(&file2));
    }

    #[test]
    fn test_detect_changes_both_empty() {
        let baseline = HashMap::new();
        let current = HashMap::new();
        let report = AtJobMonitorModule::detect_changes(&baseline, &current);
        assert!(!report.has_changes());
    }

    #[tokio::test]
    async fn test_initial_scan_with_files() {
        let dir = tempfile::tempdir().unwrap();
        let file1 = dir.path().join("job1");
        let file2 = dir.path().join("job2");
        std::fs::write(&file1, "echo hello").unwrap();
        std::fs::write(&file2, "echo world").unwrap();

        let config = AtJobMonitorConfig {
            enabled: true,
            scan_interval_secs: 120,
            watch_paths: vec![dir.path().to_path_buf()],
        };
        let mut module = AtJobMonitorModule::new(config, None);
        module.init().unwrap();

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 2);
        assert_eq!(result.issues_found, 0);
        assert!(result.summary.contains("2件"));
    }

    #[tokio::test]
    async fn test_initial_scan_empty() {
        let config = AtJobMonitorConfig {
            enabled: true,
            scan_interval_secs: 120,
            watch_paths: vec![],
        };
        let module = AtJobMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
    }
}
