//! 一時ディレクトリ実行ファイル検知モジュール
//!
//! /tmp, /dev/shm, /var/tmp 等の一時ディレクトリを定期スキャンし、
//! 実行権限が付与されたファイルを検知する。
//!
//! 検知対象:
//! - 実行可能ファイルの新規出現
//! - 実行可能ファイルの消失（証拠隠滅の可能性）
//! - ファイルサイズ・パーミッションの変更

use crate::config::TmpExecMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::{BTreeMap, HashMap};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;
use walkdir::WalkDir;

/// 実行可能ファイルの情報
#[derive(Debug, Clone, PartialEq, Eq)]
struct ExecutableFileInfo {
    /// ファイルサイズ（バイト）
    size: u64,
    /// ファイルのパーミッション（mode ビット）
    mode: u32,
}

/// 一時ディレクトリ内の実行可能ファイルのスナップショット
struct TmpExecSnapshot {
    /// ファイルパスごとの実行可能ファイル情報
    files: HashMap<PathBuf, ExecutableFileInfo>,
}

/// 一時ディレクトリ実行ファイル検知モジュール
///
/// 一時ディレクトリを定期スキャンし、実行可能ファイルの出現・消失・変更を検知する。
pub struct TmpExecMonitorModule {
    config: TmpExecMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl TmpExecMonitorModule {
    /// 新しい一時ディレクトリ実行ファイル検知モジュールを作成する
    pub fn new(config: TmpExecMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// 監視対象ディレクトリを再帰走査し、実行可能ファイルのスナップショットを返す
    fn scan_dirs(watch_dirs: &[PathBuf]) -> TmpExecSnapshot {
        let mut files = HashMap::new();
        for dir in watch_dirs {
            if !dir.exists() {
                tracing::debug!(dir = %dir.display(), "監視対象ディレクトリが存在しません。スキップします");
                continue;
            }
            for entry in WalkDir::new(dir).into_iter().filter_map(|e| match e {
                Ok(entry) => Some(entry),
                Err(err) => {
                    tracing::debug!(error = %err, "ディレクトリエントリの読み取りに失敗しました。スキップします");
                    None
                }
            }) {
                if !entry.file_type().is_file() {
                    continue;
                }
                match entry.metadata() {
                    Ok(metadata) => {
                        let mode = metadata.permissions().mode();
                        if mode & 0o111 != 0 {
                            files.insert(
                                entry.path().to_path_buf(),
                                ExecutableFileInfo {
                                    size: metadata.len(),
                                    mode,
                                },
                            );
                        }
                    }
                    Err(err) => {
                        tracing::debug!(
                            path = %entry.path().display(),
                            error = %err,
                            "ファイルメタデータの取得に失敗しました。スキップします"
                        );
                    }
                }
            }
        }
        TmpExecSnapshot { files }
    }

    /// ベースラインと現在のスナップショットを比較し、変更を検知してログ出力する。
    /// 変更があった場合は `true` を返す。
    fn detect_and_report(
        baseline: &TmpExecSnapshot,
        current: &TmpExecSnapshot,
        event_bus: &Option<EventBus>,
    ) -> bool {
        let mut has_changes = false;

        // 新規出現の検知
        for (path, info) in &current.files {
            if !baseline.files.contains_key(path) {
                tracing::warn!(
                    path = %path.display(),
                    size = info.size,
                    mode = format!("{:o}", info.mode),
                    "一時ディレクトリに実行可能ファイルが出現しました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "tmp_exec_new",
                            Severity::Warning,
                            "tmp_exec_monitor",
                            "一時ディレクトリに実行可能ファイルが出現しました",
                        )
                        .with_details(path.display().to_string()),
                    );
                }
                has_changes = true;
            }
        }

        // 消失の検知
        for path in baseline.files.keys() {
            if !current.files.contains_key(path) {
                tracing::warn!(
                    path = %path.display(),
                    "一時ディレクトリから実行可能ファイルが消失しました（証拠隠滅の可能性）"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "tmp_exec_removed",
                            Severity::Warning,
                            "tmp_exec_monitor",
                            "一時ディレクトリから実行可能ファイルが消失しました（証拠隠滅の可能性）",
                        )
                        .with_details(path.display().to_string()),
                    );
                }
                has_changes = true;
            }
        }

        // サイズ・パーミッション変更の検知
        for (path, current_info) in &current.files {
            if let Some(baseline_info) = baseline.files.get(path) {
                if baseline_info.size != current_info.size {
                    tracing::warn!(
                        path = %path.display(),
                        before = baseline_info.size,
                        after = current_info.size,
                        "一時ディレクトリの実行可能ファイルのサイズが変更されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "tmp_exec_size_changed",
                                Severity::Warning,
                                "tmp_exec_monitor",
                                "一時ディレクトリの実行可能ファイルのサイズが変更されました",
                            )
                            .with_details(path.display().to_string()),
                        );
                    }
                    has_changes = true;
                }
                if baseline_info.mode != current_info.mode {
                    tracing::warn!(
                        path = %path.display(),
                        before = format!("{:o}", baseline_info.mode),
                        after = format!("{:o}", current_info.mode),
                        "一時ディレクトリの実行可能ファイルのパーミッションが変更されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "tmp_exec_permission_changed",
                                Severity::Warning,
                                "tmp_exec_monitor",
                                "一時ディレクトリの実行可能ファイルのパーミッションが変更されました",
                            )
                            .with_details(path.display().to_string()),
                        );
                    }
                    has_changes = true;
                }
            }
        }

        has_changes
    }
}

impl Module for TmpExecMonitorModule {
    fn name(&self) -> &str {
        "tmp_exec_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        for dir in &self.config.watch_dirs {
            if !dir.exists() {
                tracing::warn!(
                    dir = %dir.display(),
                    "監視対象の一時ディレクトリが存在しません"
                );
            }
        }

        tracing::info!(
            watch_dirs = ?self.config.watch_dirs,
            scan_interval_secs = self.config.scan_interval_secs,
            "一時ディレクトリ実行ファイル検知モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<(), AppError> {
        let baseline = Self::scan_dirs(&self.config.watch_dirs);
        tracing::info!(
            executable_count = baseline.files.len(),
            "ベースラインスキャンが完了しました"
        );

        let watch_dirs = self.config.watch_dirs.clone();
        let scan_interval_secs = self.config.scan_interval_secs;
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
                        tracing::info!("一時ディレクトリ実行ファイル検知モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = TmpExecMonitorModule::scan_dirs(&watch_dirs);
                        let changed = TmpExecMonitorModule::detect_and_report(&baseline, &current, &event_bus);

                        if changed {
                            baseline = current;
                        } else {
                            tracing::debug!("一時ディレクトリの実行可能ファイルに変更はありません");
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

        let snapshot = Self::scan_dirs(&self.config.watch_dirs);
        let items_scanned = snapshot.files.len();
        let issues_found = items_scanned;
        let scan_snapshot: BTreeMap<String, String> = snapshot
            .files
            .iter()
            .map(|(path, info)| {
                (
                    path.display().to_string(),
                    format!("mode={:o},size={}", info.mode, info.size),
                )
            })
            .collect();

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "一時ディレクトリから実行可能ファイル {}件を検出しました",
                items_scanned
            ),
            snapshot: scan_snapshot,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    #[test]
    fn test_scan_dirs_with_executable() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("test_exec");
        fs::write(&file_path, "#!/bin/sh\necho hello").unwrap();
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o755)).unwrap();

        let snapshot = TmpExecMonitorModule::scan_dirs(&[dir.path().to_path_buf()]);
        assert_eq!(snapshot.files.len(), 1);
        assert!(snapshot.files.contains_key(&file_path));
    }

    #[test]
    fn test_scan_dirs_without_executable() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("test_noexec");
        fs::write(&file_path, "just data").unwrap();
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o644)).unwrap();

        let snapshot = TmpExecMonitorModule::scan_dirs(&[dir.path().to_path_buf()]);
        assert!(snapshot.files.is_empty());
    }

    #[test]
    fn test_scan_dirs_empty() {
        let dir = TempDir::new().unwrap();
        let snapshot = TmpExecMonitorModule::scan_dirs(&[dir.path().to_path_buf()]);
        assert!(snapshot.files.is_empty());
    }

    #[test]
    fn test_scan_dirs_nonexistent_skipped() {
        let snapshot =
            TmpExecMonitorModule::scan_dirs(&[PathBuf::from("/tmp/nonexistent_zettai_te_test")]);
        assert!(snapshot.files.is_empty());
    }

    #[test]
    fn test_scan_dirs_recursive() {
        let dir = TempDir::new().unwrap();
        let sub_dir = dir.path().join("subdir");
        fs::create_dir(&sub_dir).unwrap();
        let file_path = sub_dir.join("nested_exec");
        fs::write(&file_path, "#!/bin/sh").unwrap();
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o755)).unwrap();

        let snapshot = TmpExecMonitorModule::scan_dirs(&[dir.path().to_path_buf()]);
        assert_eq!(snapshot.files.len(), 1);
        assert!(snapshot.files.contains_key(&file_path));
    }

    #[test]
    fn test_detect_new_file() {
        let baseline = TmpExecSnapshot {
            files: HashMap::new(),
        };
        let mut current_files = HashMap::new();
        current_files.insert(
            PathBuf::from("/tmp/new_exec"),
            ExecutableFileInfo {
                size: 100,
                mode: 0o100755,
            },
        );
        let current = TmpExecSnapshot {
            files: current_files,
        };
        assert!(TmpExecMonitorModule::detect_and_report(
            &baseline, &current, &None
        ));
    }

    #[test]
    fn test_detect_removed_file() {
        let mut baseline_files = HashMap::new();
        baseline_files.insert(
            PathBuf::from("/tmp/removed_exec"),
            ExecutableFileInfo {
                size: 100,
                mode: 0o100755,
            },
        );
        let baseline = TmpExecSnapshot {
            files: baseline_files,
        };
        let current = TmpExecSnapshot {
            files: HashMap::new(),
        };
        assert!(TmpExecMonitorModule::detect_and_report(
            &baseline, &current, &None
        ));
    }

    #[test]
    fn test_detect_size_change() {
        let path = PathBuf::from("/tmp/size_change");
        let mut baseline_files = HashMap::new();
        baseline_files.insert(
            path.clone(),
            ExecutableFileInfo {
                size: 100,
                mode: 0o100755,
            },
        );
        let baseline = TmpExecSnapshot {
            files: baseline_files,
        };

        let mut current_files = HashMap::new();
        current_files.insert(
            path,
            ExecutableFileInfo {
                size: 200,
                mode: 0o100755,
            },
        );
        let current = TmpExecSnapshot {
            files: current_files,
        };
        assert!(TmpExecMonitorModule::detect_and_report(
            &baseline, &current, &None
        ));
    }

    #[test]
    fn test_detect_permission_change() {
        let path = PathBuf::from("/tmp/perm_change");
        let mut baseline_files = HashMap::new();
        baseline_files.insert(
            path.clone(),
            ExecutableFileInfo {
                size: 100,
                mode: 0o100755,
            },
        );
        let baseline = TmpExecSnapshot {
            files: baseline_files,
        };

        let mut current_files = HashMap::new();
        current_files.insert(
            path,
            ExecutableFileInfo {
                size: 100,
                mode: 0o100777,
            },
        );
        let current = TmpExecSnapshot {
            files: current_files,
        };
        assert!(TmpExecMonitorModule::detect_and_report(
            &baseline, &current, &None
        ));
    }

    #[test]
    fn test_detect_no_changes() {
        let path = PathBuf::from("/tmp/no_change");
        let info = ExecutableFileInfo {
            size: 100,
            mode: 0o100755,
        };

        let mut baseline_files = HashMap::new();
        baseline_files.insert(path.clone(), info.clone());
        let baseline = TmpExecSnapshot {
            files: baseline_files,
        };

        let mut current_files = HashMap::new();
        current_files.insert(path, info);
        let current = TmpExecSnapshot {
            files: current_files,
        };
        assert!(!TmpExecMonitorModule::detect_and_report(
            &baseline, &current, &None
        ));
    }

    #[test]
    fn test_init_zero_interval() {
        let config = TmpExecMonitorConfig {
            enabled: true,
            scan_interval_secs: 0,
            watch_dirs: vec![],
        };
        let mut module = TmpExecMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let dir = TempDir::new().unwrap();
        let config = TmpExecMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            watch_dirs: vec![dir.path().to_path_buf()],
        };
        let mut module = TmpExecMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let dir = TempDir::new().unwrap();
        let config = TmpExecMonitorConfig {
            enabled: true,
            scan_interval_secs: 3600,
            watch_dirs: vec![dir.path().to_path_buf()],
        };
        let mut module = TmpExecMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan_with_executables() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("test_exec");
        fs::write(&file_path, "#!/bin/sh\necho hello").unwrap();
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o755)).unwrap();

        let config = TmpExecMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            watch_dirs: vec![dir.path().to_path_buf()],
        };
        let module = TmpExecMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 1);
        assert_eq!(result.issues_found, 1);
        assert!(result.summary.contains("実行可能ファイル 1件"));
    }

    #[tokio::test]
    async fn test_initial_scan_no_executables() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("not_exec");
        fs::write(&file_path, "data").unwrap();
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o644)).unwrap();

        let config = TmpExecMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            watch_dirs: vec![dir.path().to_path_buf()],
        };
        let module = TmpExecMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
    }

    #[tokio::test]
    async fn test_initial_scan_empty_dirs() {
        let config = TmpExecMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            watch_dirs: vec![],
        };
        let module = TmpExecMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
    }
}
