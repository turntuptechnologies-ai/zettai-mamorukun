//! ログファイル改ざん検知モジュール
//!
//! ログファイルのメタデータ（サイズ・inode・パーミッション）を定期的にスキャンし、
//! ベースラインとの差分から改ざんやローテーションを検知する。
//!
//! 検知対象:
//! - サイズ減少（切り詰め・改ざんの可能性）
//! - ファイル削除
//! - パーミッション変更
//! - inode 変更（ログローテーション）
//! - 新規ファイル追加
//!
//! ## `logrotate` の `copytruncate` モードについて
//!
//! `logrotate` の `copytruncate` モードでは、ログファイルを新しいファイルにコピーした後、
//! 元のファイルを truncate（サイズ 0 に切り詰め）する。この場合、inode は変更されないが
//! サイズが減少するため、本モジュールは warn レベルの警告を出力する。
//! `copytruncate` を使用している環境では、この警告が定期的に発生することが想定される。
//! `create` モード（デフォルト）では inode が変更されるため、info レベルのローテーション
//! 検知として扱われる。

use crate::config::LogTamperConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

/// ファイルの状態を保持する構造体
#[derive(Debug, Clone, PartialEq)]
struct FileState {
    /// ファイルサイズ（バイト）
    size: u64,
    /// inode 番号
    inode: u64,
    /// パーミッション（モードビット）
    permissions: u32,
}

/// ファイル変更レポート
struct ChangeReport {
    /// サイズが減少したファイル
    size_decreased: Vec<PathBuf>,
    /// 削除されたファイル
    deleted: Vec<PathBuf>,
    /// パーミッションが変更されたファイル
    permission_changed: Vec<PathBuf>,
    /// ローテーション（inode 変更）されたファイル
    rotated: Vec<PathBuf>,
    /// 新規追加されたファイル
    new_files: Vec<PathBuf>,
}

impl ChangeReport {
    /// 変更があったかどうかを返す
    fn has_changes(&self) -> bool {
        !self.size_decreased.is_empty()
            || !self.deleted.is_empty()
            || !self.permission_changed.is_empty()
            || !self.rotated.is_empty()
            || !self.new_files.is_empty()
    }
}

/// ログファイル改ざん検知モジュール
///
/// ログファイルのメタデータを定期スキャンし、ベースラインとの差分を検知する。
pub struct LogTamperModule {
    config: LogTamperConfig,
    baseline: Option<HashMap<PathBuf, FileState>>,
    event_bus: Option<EventBus>,
    cancel_token: CancellationToken,
}

impl LogTamperModule {
    /// 新しいログファイル改ざん検知モジュールを作成する
    pub fn new(config: LogTamperConfig, event_bus: Option<EventBus>) -> Self {
        Self {
            config,
            baseline: None,
            event_bus,
            cancel_token: CancellationToken::new(),
        }
    }

    /// キャンセルトークンのクローンを返す
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    /// 監視対象パスをスキャンし、各ファイルの FileState を返す
    fn scan_files(watch_paths: &[PathBuf]) -> HashMap<PathBuf, FileState> {
        let mut result = HashMap::new();
        for path in watch_paths {
            match std::fs::metadata(path) {
                Ok(metadata) => {
                    if metadata.is_file() {
                        result.insert(
                            path.clone(),
                            FileState {
                                size: metadata.size(),
                                inode: metadata.ino(),
                                permissions: metadata.mode(),
                            },
                        );
                    }
                }
                Err(e) => {
                    tracing::debug!(
                        path = %path.display(),
                        error = %e,
                        "ログファイルのメタデータ取得に失敗しました"
                    );
                }
            }
        }
        result
    }

    /// ベースラインと現在のスキャン結果を比較し、変更レポートを返す
    fn detect_changes(
        baseline: &HashMap<PathBuf, FileState>,
        current: &HashMap<PathBuf, FileState>,
    ) -> ChangeReport {
        let mut size_decreased = Vec::new();
        let mut deleted = Vec::new();
        let mut permission_changed = Vec::new();
        let mut rotated = Vec::new();
        let mut new_files = Vec::new();

        // ベースラインに存在するファイルをチェック
        for (path, baseline_state) in baseline {
            match current.get(path) {
                Some(current_state) => {
                    if baseline_state.inode == current_state.inode {
                        // 同じ inode: サイズ減少とパーミッション変更をチェック
                        if current_state.size < baseline_state.size {
                            size_decreased.push(path.clone());
                        }
                        if current_state.permissions != baseline_state.permissions {
                            permission_changed.push(path.clone());
                        }
                    } else {
                        // inode 変更: ローテーション
                        rotated.push(path.clone());
                    }
                }
                None => {
                    // ファイルが削除された
                    deleted.push(path.clone());
                }
            }
        }

        // 新規ファイルをチェック
        for path in current.keys() {
            if !baseline.contains_key(path) {
                new_files.push(path.clone());
            }
        }

        ChangeReport {
            size_decreased,
            deleted,
            permission_changed,
            rotated,
            new_files,
        }
    }
}

impl Module for LogTamperModule {
    fn name(&self) -> &str {
        "log_tamper"
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
            "ログファイル改ざん検知モジュールを初期化しました"
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
                        tracing::info!("ログファイル改ざん検知モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = LogTamperModule::scan_files(&watch_paths);
                        let report = LogTamperModule::detect_changes(&baseline, &current);

                        if report.has_changes() {
                            for path in &report.size_decreased {
                                tracing::warn!(
                                    path = %path.display(),
                                    change = "size_decreased",
                                    "ログファイルのサイズ減少を検知しました（切り詰め・改ざんの可能性）"
                                );
                                if let Some(ref bus) = event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            "log_size_decreased",
                                            Severity::Warning,
                                            "log_tamper",
                                            format!("ログファイルのサイズ減少を検知しました: {}", path.display()),
                                        )
                                        .with_details(path.display().to_string()),
                                    );
                                }
                            }
                            for path in &report.deleted {
                                tracing::warn!(
                                    path = %path.display(),
                                    change = "deleted",
                                    "ログファイルの削除を検知しました"
                                );
                                if let Some(ref bus) = event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            "log_deleted",
                                            Severity::Warning,
                                            "log_tamper",
                                            format!("ログファイルの削除を検知しました: {}", path.display()),
                                        )
                                        .with_details(path.display().to_string()),
                                    );
                                }
                            }
                            for path in &report.permission_changed {
                                tracing::warn!(
                                    path = %path.display(),
                                    change = "permission_changed",
                                    "ログファイルのパーミッション変更を検知しました"
                                );
                                if let Some(ref bus) = event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            "log_permission_changed",
                                            Severity::Warning,
                                            "log_tamper",
                                            format!("ログファイルのパーミッション変更を検知しました: {}", path.display()),
                                        )
                                        .with_details(path.display().to_string()),
                                    );
                                }
                            }
                            for path in &report.rotated {
                                tracing::info!(
                                    path = %path.display(),
                                    change = "rotated",
                                    "ログファイルのローテーションを検知しました"
                                );
                                if let Some(ref bus) = event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            "log_rotated",
                                            Severity::Info,
                                            "log_tamper",
                                            format!("ログファイルのローテーションを検知しました: {}", path.display()),
                                        )
                                        .with_details(path.display().to_string()),
                                    );
                                }
                            }
                            for path in &report.new_files {
                                tracing::info!(
                                    path = %path.display(),
                                    change = "new_file",
                                    "新規ログファイルを検知しました"
                                );
                                if let Some(ref bus) = event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            "log_new_file",
                                            Severity::Info,
                                            "log_tamper",
                                            format!("新規ログファイルを検知しました: {}", path.display()),
                                        )
                                        .with_details(path.display().to_string()),
                                    );
                                }
                            }
                            // ベースラインを更新
                            baseline = current;
                        } else {
                            tracing::debug!("ログファイルの変更はありません");
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
        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found: 0,
            duration,
            summary: format!("ログファイル {}件をスキャンしました", items_scanned),
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
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn test_scan_files_single_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.log");
        std::fs::write(&file, "log content").unwrap();

        let watch_paths = vec![file.clone()];
        let result = LogTamperModule::scan_files(&watch_paths);
        assert_eq!(result.len(), 1);
        assert!(result.contains_key(&file));
        let state = &result[&file];
        assert_eq!(state.size, 11); // "log content" = 11 bytes
    }

    #[test]
    fn test_scan_files_empty() {
        let watch_paths: Vec<PathBuf> = vec![];
        let result = LogTamperModule::scan_files(&watch_paths);
        assert!(result.is_empty());
    }

    #[test]
    fn test_scan_files_nonexistent() {
        let watch_paths = vec![PathBuf::from("/tmp/nonexistent-zettai-log-test-file")];
        let result = LogTamperModule::scan_files(&watch_paths);
        assert!(result.is_empty());
    }

    #[test]
    fn test_detect_changes_no_changes() {
        let mut baseline = HashMap::new();
        baseline.insert(
            PathBuf::from("/var/log/syslog"),
            FileState {
                size: 1000,
                inode: 12345,
                permissions: 0o644,
            },
        );

        let current = baseline.clone();
        let report = LogTamperModule::detect_changes(&baseline, &current);
        assert!(!report.has_changes());
    }

    #[test]
    fn test_detect_changes_size_decreased() {
        let mut baseline = HashMap::new();
        baseline.insert(
            PathBuf::from("/var/log/syslog"),
            FileState {
                size: 1000,
                inode: 12345,
                permissions: 0o644,
            },
        );

        let mut current = HashMap::new();
        current.insert(
            PathBuf::from("/var/log/syslog"),
            FileState {
                size: 500,
                inode: 12345,
                permissions: 0o644,
            },
        );

        let report = LogTamperModule::detect_changes(&baseline, &current);
        assert!(report.has_changes());
        assert_eq!(report.size_decreased.len(), 1);
        assert!(report.deleted.is_empty());
        assert!(report.permission_changed.is_empty());
        assert!(report.rotated.is_empty());
        assert!(report.new_files.is_empty());
    }

    #[test]
    fn test_detect_changes_deleted() {
        let mut baseline = HashMap::new();
        baseline.insert(
            PathBuf::from("/var/log/syslog"),
            FileState {
                size: 1000,
                inode: 12345,
                permissions: 0o644,
            },
        );

        let current = HashMap::new();
        let report = LogTamperModule::detect_changes(&baseline, &current);
        assert!(report.has_changes());
        assert_eq!(report.deleted.len(), 1);
        assert!(report.size_decreased.is_empty());
    }

    #[test]
    fn test_detect_changes_permission_changed() {
        let mut baseline = HashMap::new();
        baseline.insert(
            PathBuf::from("/var/log/syslog"),
            FileState {
                size: 1000,
                inode: 12345,
                permissions: 0o644,
            },
        );

        let mut current = HashMap::new();
        current.insert(
            PathBuf::from("/var/log/syslog"),
            FileState {
                size: 1000,
                inode: 12345,
                permissions: 0o666,
            },
        );

        let report = LogTamperModule::detect_changes(&baseline, &current);
        assert!(report.has_changes());
        assert_eq!(report.permission_changed.len(), 1);
        assert!(report.size_decreased.is_empty());
        assert!(report.rotated.is_empty());
    }

    #[test]
    fn test_detect_changes_new_file() {
        let baseline = HashMap::new();

        let mut current = HashMap::new();
        current.insert(
            PathBuf::from("/var/log/new.log"),
            FileState {
                size: 100,
                inode: 99999,
                permissions: 0o644,
            },
        );

        let report = LogTamperModule::detect_changes(&baseline, &current);
        assert!(report.has_changes());
        assert_eq!(report.new_files.len(), 1);
        assert!(report.deleted.is_empty());
    }

    #[test]
    fn test_detect_changes_rotated() {
        let mut baseline = HashMap::new();
        baseline.insert(
            PathBuf::from("/var/log/syslog"),
            FileState {
                size: 1000,
                inode: 12345,
                permissions: 0o644,
            },
        );

        let mut current = HashMap::new();
        current.insert(
            PathBuf::from("/var/log/syslog"),
            FileState {
                size: 0,
                inode: 99999, // inode changed
                permissions: 0o644,
            },
        );

        let report = LogTamperModule::detect_changes(&baseline, &current);
        assert!(report.has_changes());
        assert_eq!(report.rotated.len(), 1);
        assert!(report.size_decreased.is_empty()); // inode changed, so not size_decreased
    }

    #[test]
    fn test_init_zero_interval() {
        let config = LogTamperConfig {
            enabled: true,
            scan_interval_secs: 0,
            watch_paths: vec![],
        };
        let mut module = LogTamperModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_init_valid() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.log");
        std::fs::write(&file, "test").unwrap();

        let config = LogTamperConfig {
            enabled: true,
            scan_interval_secs: 30,
            watch_paths: vec![file],
        };
        let mut module = LogTamperModule::new(config, None);
        let result = module.init();
        assert!(result.is_ok());
    }

    #[test]
    fn test_init_nonexistent_path() {
        let config = LogTamperConfig {
            enabled: true,
            scan_interval_secs: 30,
            watch_paths: vec![PathBuf::from("/nonexistent-path-zettai-log-test")],
        };
        let mut module = LogTamperModule::new(config, None);
        let result = module.init();
        assert!(result.is_ok());
        assert!(module.config.watch_paths.is_empty());
    }

    #[test]
    fn test_init_canonicalizes_paths() {
        let dir = tempfile::tempdir().unwrap();
        let subdir = dir.path().join("sub");
        std::fs::create_dir(&subdir).unwrap();
        let file = subdir.join("test.log");
        std::fs::write(&file, "test").unwrap();

        let non_canonical = dir
            .path()
            .join("sub")
            .join("..")
            .join("sub")
            .join("test.log");
        let config = LogTamperConfig {
            enabled: true,
            scan_interval_secs: 30,
            watch_paths: vec![non_canonical],
        };
        let mut module = LogTamperModule::new(config, None);
        let result = module.init();
        assert!(result.is_ok());
        assert_eq!(module.config.watch_paths.len(), 1);
        let canonical = &module.config.watch_paths[0];
        assert!(!canonical.to_string_lossy().contains(".."));
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.log");
        std::fs::write(&file, "log content").unwrap();

        let config = LogTamperConfig {
            enabled: true,
            scan_interval_secs: 3600,
            watch_paths: vec![file],
        };
        let mut module = LogTamperModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[test]
    fn test_change_report_has_changes_empty() {
        let report = ChangeReport {
            size_decreased: vec![],
            deleted: vec![],
            permission_changed: vec![],
            rotated: vec![],
            new_files: vec![],
        };
        assert!(!report.has_changes());
    }

    #[test]
    fn test_scan_files_with_real_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.log");
        std::fs::write(&file, "hello").unwrap();

        // Set specific permissions
        let perms = std::fs::Permissions::from_mode(0o640);
        std::fs::set_permissions(&file, perms).unwrap();

        let watch_paths = vec![file.clone()];
        let result = LogTamperModule::scan_files(&watch_paths);
        let state = &result[&file];
        assert_eq!(state.size, 5);
        // Check that permissions include the mode bits we set
        assert_eq!(state.permissions & 0o777, 0o640);
        assert!(state.inode > 0);
    }

    #[tokio::test]
    async fn test_initial_scan_with_files() {
        let dir = tempfile::tempdir().unwrap();
        let file1 = dir.path().join("test1.log");
        let file2 = dir.path().join("test2.log");
        std::fs::write(&file1, "log content 1").unwrap();
        std::fs::write(&file2, "log content 2").unwrap();

        let config = LogTamperConfig {
            enabled: true,
            scan_interval_secs: 30,
            watch_paths: vec![file1, file2],
        };
        let mut module = LogTamperModule::new(config, None);
        module.init().unwrap();

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 2);
        assert_eq!(result.issues_found, 0);
        assert!(result.summary.contains("2件"));
    }

    #[tokio::test]
    async fn test_initial_scan_empty() {
        let config = LogTamperConfig {
            enabled: true,
            scan_interval_secs: 30,
            watch_paths: vec![],
        };
        let module = LogTamperModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
    }
}
