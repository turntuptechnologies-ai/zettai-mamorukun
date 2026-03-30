//! sudoers ファイル監視モジュール
//!
//! /etc/sudoers および /etc/sudoers.d/ 配下のファイルを定期的にスキャンし、
//! SHA-256 ハッシュベースで変更を検知する。
//!
//! 検知対象:
//! - sudoers ファイルの追加・削除
//! - 設定行の追加・削除（行レベルの変更検知）

use crate::config::SudoersMonitorConfig;
use crate::error::AppError;
use crate::modules::Module;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;
use walkdir::WalkDir;

/// ファイルごとのスナップショット
struct FileSnapshot {
    /// ファイル全体の SHA-256 ハッシュ
    file_hash: String,
    /// 有効な設定行の各行の SHA-256 ハッシュ
    line_hashes: Vec<String>,
}

impl FileSnapshot {
    /// 有効な設定行の数を返す
    fn line_count(&self) -> usize {
        self.line_hashes.len()
    }
}

/// sudoers ファイル群のスナップショット
struct SudoersSnapshot {
    /// ファイルパスごとのスナップショット
    files: HashMap<PathBuf, FileSnapshot>,
}

/// sudoers ファイル監視モジュール
///
/// sudoers ファイルを定期スキャンし、ベースラインとの差分を検知する。
pub struct SudoersMonitorModule {
    config: SudoersMonitorConfig,
    cancel_token: CancellationToken,
}

impl SudoersMonitorModule {
    /// 新しい sudoers ファイル監視モジュールを作成する
    pub fn new(config: SudoersMonitorConfig) -> Self {
        Self {
            config,
            cancel_token: CancellationToken::new(),
        }
    }

    /// キャンセルトークンのクローンを返す
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    /// 監視対象パスをスキャンし、各ファイルのスナップショットを返す
    ///
    /// `watch_paths` にファイルが指定された場合は直接スキャンし、
    /// ディレクトリが指定された場合は配下を再帰的にスキャンする。
    fn scan_files(watch_paths: &[PathBuf]) -> SudoersSnapshot {
        let mut files = HashMap::new();
        for path in watch_paths {
            if path.is_file() {
                match build_file_snapshot(path) {
                    Ok(snapshot) => {
                        files.insert(path.clone(), snapshot);
                    }
                    Err(e) => {
                        tracing::debug!(path = %path.display(), error = %e, "sudoers ファイルの読み取りに失敗しました。スキャンを継続します");
                    }
                }
            } else if path.is_dir() {
                for entry in WalkDir::new(path)
                    .min_depth(1)
                    .into_iter()
                    .filter_map(|e| e.ok())
                {
                    let entry_path = entry.path().to_path_buf();
                    if entry_path.is_file() {
                        match build_file_snapshot(&entry_path) {
                            Ok(snapshot) => {
                                files.insert(entry_path, snapshot);
                            }
                            Err(e) => {
                                tracing::debug!(path = %entry.path().display(), error = %e, "sudoers ファイルの読み取りに失敗しました。スキャンを継続します");
                            }
                        }
                    }
                }
            } else {
                tracing::debug!(path = %path.display(), "sudoers パスが存在しません。スキップします");
            }
        }
        SudoersSnapshot { files }
    }

    /// ベースラインと現在のスナップショットを比較し、変更を検知してログ出力する。
    /// 変更があった場合は `true` を返す。
    fn detect_and_report(baseline: &SudoersSnapshot, current: &SudoersSnapshot) -> bool {
        let mut has_changes = false;

        // 新しいファイルの検知
        for path in current.files.keys() {
            if !baseline.files.contains_key(path) {
                let line_count = current.files[path].line_count();
                tracing::warn!(
                    path = %path.display(),
                    line_count,
                    "sudoers ファイルが追加されました"
                );
                has_changes = true;
            }
        }

        // 削除されたファイルの検知
        for path in baseline.files.keys() {
            if !current.files.contains_key(path) {
                tracing::warn!(
                    path = %path.display(),
                    "sudoers ファイルが削除されました"
                );
                has_changes = true;
            }
        }

        // 変更されたファイルの検知（ハッシュが異なる場合のみ行レベル比較）
        for (path, current_snapshot) in &current.files {
            if let Some(baseline_snapshot) = baseline.files.get(path)
                && baseline_snapshot.file_hash != current_snapshot.file_hash
            {
                has_changes = true;

                let baseline_set: HashSet<&String> = baseline_snapshot.line_hashes.iter().collect();
                let current_set: HashSet<&String> = current_snapshot.line_hashes.iter().collect();

                let added_count = current_set.difference(&baseline_set).count();
                let removed_count = baseline_set.difference(&current_set).count();

                if added_count > 0 {
                    tracing::warn!(
                        path = %path.display(),
                        added_count,
                        "sudoers 設定行が追加されました"
                    );
                }
                if removed_count > 0 {
                    tracing::warn!(
                        path = %path.display(),
                        removed_count,
                        "sudoers 設定行が削除されました"
                    );
                }

                tracing::warn!(
                    path = %path.display(),
                    before = baseline_snapshot.line_count(),
                    after = current_snapshot.line_count(),
                    "sudoers 設定行数が変化しました"
                );
            }
        }

        has_changes
    }
}

/// ファイルのスナップショットを作成する
fn build_file_snapshot(path: &PathBuf) -> Result<FileSnapshot, AppError> {
    let data = std::fs::read(path).map_err(|e| AppError::FileIo {
        path: path.clone(),
        source: e,
    })?;

    // ファイル全体のハッシュ
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let file_hash = format!("{:x}", hasher.finalize());

    // 行ごとのハッシュ（空行・コメント行はスキップ）
    let content = String::from_utf8_lossy(&data);
    let line_hashes = content
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        })
        .map(|line| {
            let mut hasher = Sha256::new();
            hasher.update(line.as_bytes());
            format!("{:x}", hasher.finalize())
        })
        .collect();

    Ok(FileSnapshot {
        file_hash,
        line_hashes,
    })
}

impl Module for SudoersMonitorModule {
    fn name(&self) -> &str {
        "sudoers_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        for path in &self.config.watch_paths {
            if !path.exists() {
                tracing::warn!(
                    path = %path.display(),
                    "監視対象の sudoers パスが存在しません"
                );
            }
        }

        tracing::info!(
            watch_paths = ?self.config.watch_paths,
            scan_interval_secs = self.config.scan_interval_secs,
            "sudoers ファイル監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<(), AppError> {
        let baseline = Self::scan_files(&self.config.watch_paths);
        let total_lines: usize = baseline.files.values().map(|s| s.line_count()).sum();
        tracing::info!(
            file_count = baseline.files.len(),
            total_lines,
            "ベースラインスキャンが完了しました"
        );

        let watch_paths = self.config.watch_paths.clone();
        let scan_interval_secs = self.config.scan_interval_secs;
        let cancel_token = self.cancel_token.clone();

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            interval.tick().await;

            let mut baseline = baseline;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("sudoers ファイル監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = SudoersMonitorModule::scan_files(&watch_paths);
                        let changed = SudoersMonitorModule::detect_and_report(&baseline, &current);

                        if changed {
                            baseline = current;
                        } else {
                            tracing::debug!("sudoers ファイルの変更はありません");
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
    fn test_build_file_snapshot_basic() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "root ALL=(ALL:ALL) ALL\n%admin ALL=(ALL) ALL\n").unwrap();
        let snapshot = build_file_snapshot(&tmpfile.path().to_path_buf()).unwrap();
        assert!(!snapshot.file_hash.is_empty());
        assert_eq!(snapshot.file_hash.len(), 64);
        assert_eq!(snapshot.line_count(), 2);
        assert_eq!(snapshot.line_hashes.len(), 2);
    }

    #[test]
    fn test_build_file_snapshot_skips_comments_and_empty() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(
            tmpfile,
            "# This is a comment\n\nroot ALL=(ALL:ALL) ALL\n\n# Another comment\n"
        )
        .unwrap();
        let snapshot = build_file_snapshot(&tmpfile.path().to_path_buf()).unwrap();
        assert_eq!(snapshot.line_count(), 1);
    }

    #[test]
    fn test_build_file_snapshot_empty_file() {
        let tmpfile = tempfile::NamedTempFile::new().unwrap();
        let snapshot = build_file_snapshot(&tmpfile.path().to_path_buf()).unwrap();
        assert_eq!(snapshot.line_count(), 0);
        assert!(snapshot.line_hashes.is_empty());
    }

    #[test]
    fn test_build_file_snapshot_nonexistent() {
        let result = build_file_snapshot(&PathBuf::from("/tmp/nonexistent-zettai-sudoers-test"));
        assert!(result.is_err());
    }

    #[test]
    fn test_build_file_snapshot_deterministic() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "root ALL=(ALL:ALL) ALL\n").unwrap();
        let snapshot1 = build_file_snapshot(&tmpfile.path().to_path_buf()).unwrap();
        let snapshot2 = build_file_snapshot(&tmpfile.path().to_path_buf()).unwrap();
        assert_eq!(snapshot1.file_hash, snapshot2.file_hash);
        assert_eq!(snapshot1.line_hashes, snapshot2.line_hashes);
    }

    #[test]
    fn test_scan_files_with_single_file() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "root ALL=(ALL:ALL) ALL\n").unwrap();
        let path = tmpfile.path().to_path_buf();

        let watch_paths = vec![path.clone()];
        let result = SudoersMonitorModule::scan_files(&watch_paths);
        assert_eq!(result.files.len(), 1);
        assert!(result.files.contains_key(&path));
    }

    #[test]
    fn test_scan_files_with_directory() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let file1 = tmpdir.path().join("00-defaults");
        let file2 = tmpdir.path().join("99-custom");
        std::fs::write(&file1, "Defaults env_reset\n").unwrap();
        std::fs::write(&file2, "user ALL=(ALL) NOPASSWD: ALL\n").unwrap();

        let watch_paths = vec![tmpdir.path().to_path_buf()];
        let result = SudoersMonitorModule::scan_files(&watch_paths);
        assert_eq!(result.files.len(), 2);
        assert!(result.files.contains_key(&file1));
        assert!(result.files.contains_key(&file2));
    }

    #[test]
    fn test_scan_files_empty() {
        let watch_paths: Vec<PathBuf> = vec![];
        let result = SudoersMonitorModule::scan_files(&watch_paths);
        assert!(result.files.is_empty());
    }

    #[test]
    fn test_scan_files_nonexistent_skipped() {
        let watch_paths = vec![PathBuf::from("/tmp/nonexistent_zettai_sudoers_test")];
        let result = SudoersMonitorModule::scan_files(&watch_paths);
        assert!(result.files.is_empty());
    }

    #[test]
    fn test_detect_no_changes() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "root ALL=(ALL:ALL) ALL\n").unwrap();
        let path = tmpfile.path().to_path_buf();

        let watch_paths = vec![path];
        let snapshot1 = SudoersMonitorModule::scan_files(&watch_paths);
        let snapshot2 = SudoersMonitorModule::scan_files(&watch_paths);
        let changed = SudoersMonitorModule::detect_and_report(&snapshot1, &snapshot2);
        assert!(!changed);
    }

    #[test]
    fn test_detect_file_added() {
        let baseline = SudoersSnapshot {
            files: HashMap::new(),
        };
        let mut current_files = HashMap::new();
        current_files.insert(
            PathBuf::from("/tmp/test_sudoers_added"),
            FileSnapshot {
                file_hash: "hash1".to_string(),
                line_hashes: vec!["linehash1".to_string()],
            },
        );
        let current = SudoersSnapshot {
            files: current_files,
        };
        let changed = SudoersMonitorModule::detect_and_report(&baseline, &current);
        assert!(changed);
    }

    #[test]
    fn test_detect_file_removed() {
        let mut baseline_files = HashMap::new();
        baseline_files.insert(
            PathBuf::from("/tmp/test_sudoers_removed"),
            FileSnapshot {
                file_hash: "hash1".to_string(),
                line_hashes: vec!["linehash1".to_string()],
            },
        );
        let baseline = SudoersSnapshot {
            files: baseline_files,
        };
        let current = SudoersSnapshot {
            files: HashMap::new(),
        };
        let changed = SudoersMonitorModule::detect_and_report(&baseline, &current);
        assert!(changed);
    }

    #[test]
    fn test_detect_line_added() {
        let path = PathBuf::from("/tmp/test_sudoers_line_change");
        let mut baseline_files = HashMap::new();
        baseline_files.insert(
            path.clone(),
            FileSnapshot {
                file_hash: "hash1".to_string(),
                line_hashes: vec!["linehash1".to_string()],
            },
        );
        let baseline = SudoersSnapshot {
            files: baseline_files,
        };

        let mut current_files = HashMap::new();
        current_files.insert(
            path,
            FileSnapshot {
                file_hash: "hash2".to_string(),
                line_hashes: vec!["linehash1".to_string(), "linehash2".to_string()],
            },
        );
        let current = SudoersSnapshot {
            files: current_files,
        };

        let changed = SudoersMonitorModule::detect_and_report(&baseline, &current);
        assert!(changed);
    }

    #[test]
    fn test_detect_line_removed() {
        let path = PathBuf::from("/tmp/test_sudoers_line_removed");
        let mut baseline_files = HashMap::new();
        baseline_files.insert(
            path.clone(),
            FileSnapshot {
                file_hash: "hash1".to_string(),
                line_hashes: vec!["linehash1".to_string(), "linehash2".to_string()],
            },
        );
        let baseline = SudoersSnapshot {
            files: baseline_files,
        };

        let mut current_files = HashMap::new();
        current_files.insert(
            path,
            FileSnapshot {
                file_hash: "hash2".to_string(),
                line_hashes: vec!["linehash1".to_string()],
            },
        );
        let current = SudoersSnapshot {
            files: current_files,
        };

        let changed = SudoersMonitorModule::detect_and_report(&baseline, &current);
        assert!(changed);
    }

    #[test]
    fn test_init_zero_interval() {
        let config = SudoersMonitorConfig {
            enabled: true,
            scan_interval_secs: 0,
            watch_paths: vec![],
        };
        let mut module = SudoersMonitorModule::new(config);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_init_valid() {
        let config = SudoersMonitorConfig {
            enabled: true,
            scan_interval_secs: 120,
            watch_paths: vec![PathBuf::from("/etc/sudoers")],
        };
        let mut module = SudoersMonitorModule::new(config);
        let result = module.init();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "root ALL=(ALL:ALL) ALL\n").unwrap();

        let config = SudoersMonitorConfig {
            enabled: true,
            scan_interval_secs: 3600,
            watch_paths: vec![tmpfile.path().to_path_buf()],
        };
        let mut module = SudoersMonitorModule::new(config);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[test]
    fn test_scan_files_mixed_file_and_dir() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let dir_file = tmpdir.path().join("custom-sudoers");
        std::fs::write(&dir_file, "user ALL=(ALL) ALL\n").unwrap();

        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "root ALL=(ALL:ALL) ALL\n").unwrap();

        let watch_paths = vec![tmpfile.path().to_path_buf(), tmpdir.path().to_path_buf()];
        let result = SudoersMonitorModule::scan_files(&watch_paths);
        assert_eq!(result.files.len(), 2);
    }

    #[test]
    fn test_detect_directory_file_added() {
        let tmpdir = tempfile::TempDir::new().unwrap();

        // ベースライン: ディレクトリは空
        let watch_paths = vec![tmpdir.path().to_path_buf()];
        let baseline = SudoersMonitorModule::scan_files(&watch_paths);
        assert!(baseline.files.is_empty());

        // ファイルを追加
        let new_file = tmpdir.path().join("new-sudoers-entry");
        std::fs::write(&new_file, "attacker ALL=(ALL) NOPASSWD: ALL\n").unwrap();

        let current = SudoersMonitorModule::scan_files(&watch_paths);
        assert_eq!(current.files.len(), 1);

        let changed = SudoersMonitorModule::detect_and_report(&baseline, &current);
        assert!(changed);
    }
}
