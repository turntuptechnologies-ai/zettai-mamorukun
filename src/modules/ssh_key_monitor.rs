//! SSH公開鍵ファイル監視モジュール
//!
//! authorized_keys ファイルを定期的にスキャンし、SHA-256 ハッシュベースで変更を検知する。
//!
//! 検知対象:
//! - authorized_keys ファイルの追加・削除
//! - SSH鍵の追加・削除（行レベルの変更検知）

use crate::config::SshKeyMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

/// ファイルごとのスナップショット
struct FileSnapshot {
    /// ファイル全体の SHA-256 ハッシュ
    file_hash: String,
    /// 有効な鍵の各行の SHA-256 ハッシュ
    key_hashes: Vec<String>,
}

impl FileSnapshot {
    /// 有効な鍵の数を返す
    fn key_count(&self) -> usize {
        self.key_hashes.len()
    }
}

/// authorized_keys ファイル群のスナップショット
struct AuthorizedKeysSnapshot {
    /// ファイルパスごとのスナップショット
    files: HashMap<PathBuf, FileSnapshot>,
}

/// SSH公開鍵ファイル監視モジュール
///
/// authorized_keys ファイルを定期スキャンし、ベースラインとの差分を検知する。
pub struct SshKeyMonitorModule {
    config: SshKeyMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl SshKeyMonitorModule {
    /// 新しいSSH公開鍵ファイル監視モジュールを作成する
    pub fn new(config: SshKeyMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// 監視対象パスをスキャンし、各ファイルのスナップショットを返す
    fn scan_files(watch_paths: &[PathBuf]) -> AuthorizedKeysSnapshot {
        let mut files = HashMap::new();
        for path in watch_paths {
            if path.is_file() {
                match build_file_snapshot(path) {
                    Ok(snapshot) => {
                        files.insert(path.clone(), snapshot);
                    }
                    Err(e) => {
                        tracing::debug!(path = %path.display(), error = %e, "authorized_keys ファイルの読み取りに失敗しました。スキャンを継続します");
                    }
                }
            } else {
                tracing::debug!(path = %path.display(), "authorized_keys ファイルが存在しません。スキップします");
            }
        }
        AuthorizedKeysSnapshot { files }
    }

    /// ベースラインと現在のスナップショットを比較し、変更を検知してログ出力する。
    /// 変更があった場合は `true` を返す。
    fn detect_and_report(
        baseline: &AuthorizedKeysSnapshot,
        current: &AuthorizedKeysSnapshot,
        event_bus: &Option<EventBus>,
    ) -> bool {
        let mut has_changes = false;

        // 新しいファイルの検知
        for path in current.files.keys() {
            if !baseline.files.contains_key(path) {
                let key_count = current.files[path].key_count();
                tracing::warn!(
                    path = %path.display(),
                    key_count,
                    "authorized_keys ファイルが追加されました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "ssh_key_file_added",
                            Severity::Warning,
                            "ssh_key_monitor",
                            format!(
                                "authorized_keys ファイルが追加されました: {}",
                                path.display()
                            ),
                        )
                        .with_details(path.display().to_string()),
                    );
                }
                has_changes = true;
            }
        }

        // 削除されたファイルの検知
        for path in baseline.files.keys() {
            if !current.files.contains_key(path) {
                tracing::warn!(
                    path = %path.display(),
                    "authorized_keys ファイルが削除されました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "ssh_key_file_removed",
                            Severity::Warning,
                            "ssh_key_monitor",
                            format!(
                                "authorized_keys ファイルが削除されました: {}",
                                path.display()
                            ),
                        )
                        .with_details(path.display().to_string()),
                    );
                }
                has_changes = true;
            }
        }

        // 変更されたファイルの検知（ハッシュが異なる場合のみ行レベル比較）
        for (path, current_snapshot) in &current.files {
            if let Some(baseline_snapshot) = baseline.files.get(path)
                && baseline_snapshot.file_hash != current_snapshot.file_hash
            {
                has_changes = true;

                let baseline_set: HashSet<&String> = baseline_snapshot.key_hashes.iter().collect();
                let current_set: HashSet<&String> = current_snapshot.key_hashes.iter().collect();

                let added_count = current_set.difference(&baseline_set).count();
                let removed_count = baseline_set.difference(&current_set).count();

                if added_count > 0 {
                    tracing::warn!(
                        path = %path.display(),
                        added_count,
                        "SSH鍵が追加されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "ssh_key_added",
                                Severity::Warning,
                                "ssh_key_monitor",
                                format!("SSH鍵が追加されました: {}", path.display()),
                            )
                            .with_details(path.display().to_string()),
                        );
                    }
                }
                if removed_count > 0 {
                    tracing::warn!(
                        path = %path.display(),
                        removed_count,
                        "SSH鍵が削除されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "ssh_key_removed",
                                Severity::Warning,
                                "ssh_key_monitor",
                                format!("SSH鍵が削除されました: {}", path.display()),
                            )
                            .with_details(path.display().to_string()),
                        );
                    }
                }

                tracing::warn!(
                    path = %path.display(),
                    before = baseline_snapshot.key_count(),
                    after = current_snapshot.key_count(),
                    "SSH鍵数が変化しました"
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
    let key_hashes = content
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
        key_hashes,
    })
}

impl Module for SshKeyMonitorModule {
    fn name(&self) -> &str {
        "ssh_key_monitor"
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
                    "監視対象の authorized_keys ファイルが存在しません"
                );
            }
        }

        tracing::info!(
            watch_paths = ?self.config.watch_paths,
            scan_interval_secs = self.config.scan_interval_secs,
            "SSH公開鍵ファイル監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<(), AppError> {
        // 初回スキャンでベースライン作成
        let baseline = Self::scan_files(&self.config.watch_paths);
        let total_keys: usize = baseline.files.values().map(|s| s.key_count()).sum();
        tracing::info!(
            file_count = baseline.files.len(),
            total_keys,
            "ベースラインスキャンが完了しました"
        );

        let watch_paths = self.config.watch_paths.clone();
        let scan_interval_secs = self.config.scan_interval_secs;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            // 最初の tick は即座に発火するのでスキップ
            interval.tick().await;

            let mut baseline = baseline;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("SSH公開鍵ファイル監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = SshKeyMonitorModule::scan_files(&watch_paths);
                        let changed = SshKeyMonitorModule::detect_and_report(&baseline, &current, &event_bus);

                        if changed {
                            baseline = current;
                        } else {
                            tracing::debug!("authorized_keys ファイルの変更はありません");
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

        let snapshot = Self::scan_files(&self.config.watch_paths);
        let items_scanned = snapshot.files.len();

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found: 0,
            duration,
            summary: format!("SSH 公開鍵ファイル {}件をスキャンしました", items_scanned),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_build_file_snapshot_basic() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(
            tmpfile,
            "ssh-rsa AAAAB3... user@host\nssh-ed25519 AAAAC3... admin@host\n"
        )
        .unwrap();
        let snapshot = build_file_snapshot(&tmpfile.path().to_path_buf()).unwrap();
        assert!(!snapshot.file_hash.is_empty());
        assert_eq!(snapshot.file_hash.len(), 64);
        assert_eq!(snapshot.key_count(), 2);
        assert_eq!(snapshot.key_hashes.len(), 2);
    }

    #[test]
    fn test_build_file_snapshot_skips_comments_and_empty() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(
            tmpfile,
            "# This is a comment\n\nssh-rsa AAAAB3... user@host\n\n# Another comment\n"
        )
        .unwrap();
        let snapshot = build_file_snapshot(&tmpfile.path().to_path_buf()).unwrap();
        assert_eq!(snapshot.key_count(), 1);
    }

    #[test]
    fn test_build_file_snapshot_empty_file() {
        let tmpfile = tempfile::NamedTempFile::new().unwrap();
        let snapshot = build_file_snapshot(&tmpfile.path().to_path_buf()).unwrap();
        assert_eq!(snapshot.key_count(), 0);
        assert!(snapshot.key_hashes.is_empty());
    }

    #[test]
    fn test_build_file_snapshot_nonexistent() {
        let result = build_file_snapshot(&PathBuf::from("/tmp/nonexistent-zettai-ssh-test"));
        assert!(result.is_err());
    }

    #[test]
    fn test_build_file_snapshot_deterministic() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "ssh-rsa AAAAB3... user@host\n").unwrap();
        let snapshot1 = build_file_snapshot(&tmpfile.path().to_path_buf()).unwrap();
        let snapshot2 = build_file_snapshot(&tmpfile.path().to_path_buf()).unwrap();
        assert_eq!(snapshot1.file_hash, snapshot2.file_hash);
        assert_eq!(snapshot1.key_hashes, snapshot2.key_hashes);
    }

    #[test]
    fn test_scan_files_with_single_file() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "ssh-rsa AAAAB3... user@host\n").unwrap();
        let path = tmpfile.path().to_path_buf();

        let watch_paths = vec![path.clone()];
        let result = SshKeyMonitorModule::scan_files(&watch_paths);
        assert_eq!(result.files.len(), 1);
        assert!(result.files.contains_key(&path));
    }

    #[test]
    fn test_scan_files_empty() {
        let watch_paths: Vec<PathBuf> = vec![];
        let result = SshKeyMonitorModule::scan_files(&watch_paths);
        assert!(result.files.is_empty());
    }

    #[test]
    fn test_scan_files_nonexistent_skipped() {
        let watch_paths = vec![PathBuf::from("/tmp/nonexistent_zettai_ssh_test")];
        let result = SshKeyMonitorModule::scan_files(&watch_paths);
        assert!(result.files.is_empty());
    }

    #[test]
    fn test_detect_no_changes() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "ssh-rsa AAAAB3... user@host\n").unwrap();
        let path = tmpfile.path().to_path_buf();

        let watch_paths = vec![path];
        let snapshot1 = SshKeyMonitorModule::scan_files(&watch_paths);
        let snapshot2 = SshKeyMonitorModule::scan_files(&watch_paths);
        let changed = SshKeyMonitorModule::detect_and_report(&snapshot1, &snapshot2, &None);
        assert!(!changed);
    }

    #[test]
    fn test_detect_file_added() {
        let baseline = AuthorizedKeysSnapshot {
            files: HashMap::new(),
        };
        let mut current_files = HashMap::new();
        current_files.insert(
            PathBuf::from("/tmp/test_added"),
            FileSnapshot {
                file_hash: "hash1".to_string(),
                key_hashes: vec!["keyhash1".to_string()],
            },
        );
        let current = AuthorizedKeysSnapshot {
            files: current_files,
        };
        let changed = SshKeyMonitorModule::detect_and_report(&baseline, &current, &None);
        assert!(changed);
    }

    #[test]
    fn test_detect_file_removed() {
        let mut baseline_files = HashMap::new();
        baseline_files.insert(
            PathBuf::from("/tmp/test_removed"),
            FileSnapshot {
                file_hash: "hash1".to_string(),
                key_hashes: vec!["keyhash1".to_string()],
            },
        );
        let baseline = AuthorizedKeysSnapshot {
            files: baseline_files,
        };
        let current = AuthorizedKeysSnapshot {
            files: HashMap::new(),
        };
        let changed = SshKeyMonitorModule::detect_and_report(&baseline, &current, &None);
        assert!(changed);
    }

    #[test]
    fn test_detect_key_added() {
        let path = PathBuf::from("/tmp/test_key_change");
        let mut baseline_files = HashMap::new();
        baseline_files.insert(
            path.clone(),
            FileSnapshot {
                file_hash: "hash1".to_string(),
                key_hashes: vec!["keyhash1".to_string()],
            },
        );
        let baseline = AuthorizedKeysSnapshot {
            files: baseline_files,
        };

        let mut current_files = HashMap::new();
        current_files.insert(
            path,
            FileSnapshot {
                file_hash: "hash2".to_string(),
                key_hashes: vec!["keyhash1".to_string(), "keyhash2".to_string()],
            },
        );
        let current = AuthorizedKeysSnapshot {
            files: current_files,
        };

        let changed = SshKeyMonitorModule::detect_and_report(&baseline, &current, &None);
        assert!(changed);
    }

    #[test]
    fn test_detect_key_removed() {
        let path = PathBuf::from("/tmp/test_key_removed");
        let mut baseline_files = HashMap::new();
        baseline_files.insert(
            path.clone(),
            FileSnapshot {
                file_hash: "hash1".to_string(),
                key_hashes: vec!["keyhash1".to_string(), "keyhash2".to_string()],
            },
        );
        let baseline = AuthorizedKeysSnapshot {
            files: baseline_files,
        };

        let mut current_files = HashMap::new();
        current_files.insert(
            path,
            FileSnapshot {
                file_hash: "hash2".to_string(),
                key_hashes: vec!["keyhash1".to_string()],
            },
        );
        let current = AuthorizedKeysSnapshot {
            files: current_files,
        };

        let changed = SshKeyMonitorModule::detect_and_report(&baseline, &current, &None);
        assert!(changed);
    }

    #[test]
    fn test_init_zero_interval() {
        let config = SshKeyMonitorConfig {
            enabled: true,
            scan_interval_secs: 0,
            watch_paths: vec![],
        };
        let mut module = SshKeyMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_init_valid() {
        let config = SshKeyMonitorConfig {
            enabled: true,
            scan_interval_secs: 120,
            watch_paths: vec![PathBuf::from("/root/.ssh/authorized_keys")],
        };
        let mut module = SshKeyMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "ssh-rsa AAAAB3... user@host\n").unwrap();

        let config = SshKeyMonitorConfig {
            enabled: true,
            scan_interval_secs: 3600,
            watch_paths: vec![tmpfile.path().to_path_buf()],
        };
        let mut module = SshKeyMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan_with_files() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let key_file = tmpdir.path().join("authorized_keys");
        std::fs::write(
            &key_file,
            "ssh-rsa AAAAB3... user@host\nssh-ed25519 AAAAC3... admin@host\n",
        )
        .unwrap();

        let config = SshKeyMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            watch_paths: vec![key_file],
        };
        let module = SshKeyMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 1);
        assert_eq!(result.issues_found, 0);
        assert!(result.summary.contains("SSH 公開鍵ファイル 1件"));
    }

    #[tokio::test]
    async fn test_initial_scan_empty_paths() {
        let config = SshKeyMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            watch_paths: vec![],
        };
        let module = SshKeyMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
    }

    #[tokio::test]
    async fn test_initial_scan_nonexistent_file() {
        let config = SshKeyMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            watch_paths: vec![PathBuf::from("/nonexistent/authorized_keys")],
        };
        let module = SshKeyMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
    }
}
