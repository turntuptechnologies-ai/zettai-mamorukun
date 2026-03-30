//! SUID/SGID ファイル監視モジュール
//!
//! 指定ディレクトリを定期スキャンし、setuid/setgid ビットが設定された
//! ファイルの変更を検知する。
//!
//! 検知対象:
//! - SUID/SGID ファイルの新規出現
//! - SUID/SGID ファイルの消失（証拠隠滅の可能性）
//! - ファイルサイズ・パーミッションの変更
//! - ファイル所有者(uid)の変更

use crate::config::SuidSgidMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::Module;
use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;
use walkdir::WalkDir;

/// SUID/SGID ビットのマスク
const SUID_BIT: u32 = 0o4000;
const SGID_BIT: u32 = 0o2000;

/// SUID/SGID ファイルの情報
#[derive(Debug, Clone, PartialEq, Eq)]
struct SuidSgidFileInfo {
    /// ファイルサイズ（バイト）
    size: u64,
    /// ファイルのパーミッション（mode ビット）
    mode: u32,
    /// ファイル所有者の UID
    uid: u32,
}

/// SUID/SGID ファイルのスナップショット
struct SuidSgidSnapshot {
    /// ファイルパスごとの SUID/SGID ファイル情報
    files: HashMap<PathBuf, SuidSgidFileInfo>,
}

/// SUID/SGID ファイル監視モジュール
///
/// 指定ディレクトリを定期スキャンし、SUID/SGID ファイルの出現・消失・変更を検知する。
pub struct SuidSgidMonitorModule {
    config: SuidSgidMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl SuidSgidMonitorModule {
    /// 新しい SUID/SGID ファイル監視モジュールを作成する
    pub fn new(config: SuidSgidMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// 監視対象ディレクトリを再帰走査し、SUID/SGID ファイルのスナップショットを返す
    fn scan_dirs(watch_dirs: &[PathBuf]) -> SuidSgidSnapshot {
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
                        let mode = metadata.mode();
                        if mode & SUID_BIT != 0 || mode & SGID_BIT != 0 {
                            files.insert(
                                entry.path().to_path_buf(),
                                SuidSgidFileInfo {
                                    size: metadata.len(),
                                    mode,
                                    uid: metadata.uid(),
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
        SuidSgidSnapshot { files }
    }

    /// SUID/SGID のタイプを判定して文字列で返す
    fn suid_sgid_type(mode: u32) -> &'static str {
        match (mode & SUID_BIT != 0, mode & SGID_BIT != 0) {
            (true, true) => "SUID+SGID",
            (true, false) => "SUID",
            (false, true) => "SGID",
            (false, false) => "none",
        }
    }

    /// ベースラインと現在のスナップショットを比較し、変更を検知してログ出力する。
    /// 変更があった場合は `true` を返す。
    fn detect_and_report(
        baseline: &SuidSgidSnapshot,
        current: &SuidSgidSnapshot,
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
                    uid = info.uid,
                    suid_sgid_type = Self::suid_sgid_type(info.mode),
                    "SUID/SGID ファイルが新たに出現しました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "suid_sgid_new",
                            Severity::Critical,
                            "suid_sgid_monitor",
                            "SUID/SGID ファイルが新たに出現しました",
                        )
                        .with_details(path.display().to_string()),
                    );
                }
                has_changes = true;
            }
        }

        // 消失の検知
        for (path, info) in &baseline.files {
            if !current.files.contains_key(path) {
                tracing::warn!(
                    path = %path.display(),
                    suid_sgid_type = Self::suid_sgid_type(info.mode),
                    "SUID/SGID ファイルが消失しました（証拠隠滅の可能性）"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "suid_sgid_removed",
                            Severity::Warning,
                            "suid_sgid_monitor",
                            "SUID/SGID ファイルが消失しました（証拠隠滅の可能性）",
                        )
                        .with_details(path.display().to_string()),
                    );
                }
                has_changes = true;
            }
        }

        // サイズ・パーミッション・所有者変更の検知
        for (path, current_info) in &current.files {
            if let Some(baseline_info) = baseline.files.get(path) {
                if baseline_info.size != current_info.size {
                    tracing::warn!(
                        path = %path.display(),
                        before = baseline_info.size,
                        after = current_info.size,
                        "SUID/SGID ファイルのサイズが変更されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "suid_sgid_size_changed",
                                Severity::Warning,
                                "suid_sgid_monitor",
                                "SUID/SGID ファイルのサイズが変更されました",
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
                        "SUID/SGID ファイルのパーミッションが変更されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "suid_sgid_permission_changed",
                                Severity::Warning,
                                "suid_sgid_monitor",
                                "SUID/SGID ファイルのパーミッションが変更されました",
                            )
                            .with_details(path.display().to_string()),
                        );
                    }
                    has_changes = true;
                }
                if baseline_info.uid != current_info.uid {
                    tracing::warn!(
                        path = %path.display(),
                        before = baseline_info.uid,
                        after = current_info.uid,
                        "SUID/SGID ファイルの所有者が変更されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "suid_sgid_owner_changed",
                                Severity::Critical,
                                "suid_sgid_monitor",
                                "SUID/SGID ファイルの所有者が変更されました",
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

impl Module for SuidSgidMonitorModule {
    fn name(&self) -> &str {
        "suid_sgid_monitor"
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
                    "監視対象ディレクトリが存在しません"
                );
            }
        }

        tracing::info!(
            watch_dirs = ?self.config.watch_dirs,
            scan_interval_secs = self.config.scan_interval_secs,
            "SUID/SGID ファイル監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<(), AppError> {
        let baseline = Self::scan_dirs(&self.config.watch_dirs);
        tracing::info!(
            suid_sgid_count = baseline.files.len(),
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
                        tracing::info!("SUID/SGID ファイル監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = SuidSgidMonitorModule::scan_dirs(&watch_dirs);
                        let changed = SuidSgidMonitorModule::detect_and_report(&baseline, &current, &event_bus);

                        if changed {
                            baseline = current;
                        } else {
                            tracing::debug!("SUID/SGID ファイルに変更はありません");
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
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    #[test]
    fn test_suid_sgid_type() {
        assert_eq!(SuidSgidMonitorModule::suid_sgid_type(0o104755), "SUID");
        assert_eq!(SuidSgidMonitorModule::suid_sgid_type(0o102755), "SGID");
        assert_eq!(SuidSgidMonitorModule::suid_sgid_type(0o106755), "SUID+SGID");
        assert_eq!(SuidSgidMonitorModule::suid_sgid_type(0o100755), "none");
    }

    #[test]
    fn test_scan_dirs_with_suid_file() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("test_suid");
        fs::write(&file_path, "#!/bin/sh\necho hello").unwrap();
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o4755)).unwrap();

        let snapshot = SuidSgidMonitorModule::scan_dirs(&[dir.path().to_path_buf()]);
        assert_eq!(snapshot.files.len(), 1);
        assert!(snapshot.files.contains_key(&file_path));
    }

    #[test]
    fn test_scan_dirs_with_sgid_file() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("test_sgid");
        fs::write(&file_path, "#!/bin/sh\necho hello").unwrap();
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o2755)).unwrap();

        let snapshot = SuidSgidMonitorModule::scan_dirs(&[dir.path().to_path_buf()]);
        assert_eq!(snapshot.files.len(), 1);
        assert!(snapshot.files.contains_key(&file_path));
    }

    #[test]
    fn test_scan_dirs_without_suid_sgid() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("test_normal");
        fs::write(&file_path, "just data").unwrap();
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o755)).unwrap();

        let snapshot = SuidSgidMonitorModule::scan_dirs(&[dir.path().to_path_buf()]);
        assert!(snapshot.files.is_empty());
    }

    #[test]
    fn test_scan_dirs_empty() {
        let dir = TempDir::new().unwrap();
        let snapshot = SuidSgidMonitorModule::scan_dirs(&[dir.path().to_path_buf()]);
        assert!(snapshot.files.is_empty());
    }

    #[test]
    fn test_scan_dirs_nonexistent_skipped() {
        let snapshot =
            SuidSgidMonitorModule::scan_dirs(&[PathBuf::from("/tmp/nonexistent_zettai_suid_test")]);
        assert!(snapshot.files.is_empty());
    }

    #[test]
    fn test_scan_dirs_recursive() {
        let dir = TempDir::new().unwrap();
        let sub_dir = dir.path().join("subdir");
        fs::create_dir(&sub_dir).unwrap();
        let file_path = sub_dir.join("nested_suid");
        fs::write(&file_path, "#!/bin/sh").unwrap();
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o4755)).unwrap();

        let snapshot = SuidSgidMonitorModule::scan_dirs(&[dir.path().to_path_buf()]);
        assert_eq!(snapshot.files.len(), 1);
        assert!(snapshot.files.contains_key(&file_path));
    }

    #[test]
    fn test_detect_new_file() {
        let baseline = SuidSgidSnapshot {
            files: HashMap::new(),
        };
        let mut current_files = HashMap::new();
        current_files.insert(
            PathBuf::from("/usr/bin/new_suid"),
            SuidSgidFileInfo {
                size: 100,
                mode: 0o104755,
                uid: 0,
            },
        );
        let current = SuidSgidSnapshot {
            files: current_files,
        };
        assert!(SuidSgidMonitorModule::detect_and_report(
            &baseline, &current, &None
        ));
    }

    #[test]
    fn test_detect_removed_file() {
        let mut baseline_files = HashMap::new();
        baseline_files.insert(
            PathBuf::from("/usr/bin/removed_suid"),
            SuidSgidFileInfo {
                size: 100,
                mode: 0o104755,
                uid: 0,
            },
        );
        let baseline = SuidSgidSnapshot {
            files: baseline_files,
        };
        let current = SuidSgidSnapshot {
            files: HashMap::new(),
        };
        assert!(SuidSgidMonitorModule::detect_and_report(
            &baseline, &current, &None
        ));
    }

    #[test]
    fn test_detect_size_change() {
        let path = PathBuf::from("/usr/bin/size_change");
        let mut baseline_files = HashMap::new();
        baseline_files.insert(
            path.clone(),
            SuidSgidFileInfo {
                size: 100,
                mode: 0o104755,
                uid: 0,
            },
        );
        let baseline = SuidSgidSnapshot {
            files: baseline_files,
        };

        let mut current_files = HashMap::new();
        current_files.insert(
            path,
            SuidSgidFileInfo {
                size: 200,
                mode: 0o104755,
                uid: 0,
            },
        );
        let current = SuidSgidSnapshot {
            files: current_files,
        };
        assert!(SuidSgidMonitorModule::detect_and_report(
            &baseline, &current, &None
        ));
    }

    #[test]
    fn test_detect_permission_change() {
        let path = PathBuf::from("/usr/bin/perm_change");
        let mut baseline_files = HashMap::new();
        baseline_files.insert(
            path.clone(),
            SuidSgidFileInfo {
                size: 100,
                mode: 0o104755,
                uid: 0,
            },
        );
        let baseline = SuidSgidSnapshot {
            files: baseline_files,
        };

        let mut current_files = HashMap::new();
        current_files.insert(
            path,
            SuidSgidFileInfo {
                size: 100,
                mode: 0o106755,
                uid: 0,
            },
        );
        let current = SuidSgidSnapshot {
            files: current_files,
        };
        assert!(SuidSgidMonitorModule::detect_and_report(
            &baseline, &current, &None
        ));
    }

    #[test]
    fn test_detect_uid_change() {
        let path = PathBuf::from("/usr/bin/uid_change");
        let mut baseline_files = HashMap::new();
        baseline_files.insert(
            path.clone(),
            SuidSgidFileInfo {
                size: 100,
                mode: 0o104755,
                uid: 0,
            },
        );
        let baseline = SuidSgidSnapshot {
            files: baseline_files,
        };

        let mut current_files = HashMap::new();
        current_files.insert(
            path,
            SuidSgidFileInfo {
                size: 100,
                mode: 0o104755,
                uid: 1000,
            },
        );
        let current = SuidSgidSnapshot {
            files: current_files,
        };
        assert!(SuidSgidMonitorModule::detect_and_report(
            &baseline, &current, &None
        ));
    }

    #[test]
    fn test_detect_no_changes() {
        let path = PathBuf::from("/usr/bin/no_change");
        let info = SuidSgidFileInfo {
            size: 100,
            mode: 0o104755,
            uid: 0,
        };

        let mut baseline_files = HashMap::new();
        baseline_files.insert(path.clone(), info.clone());
        let baseline = SuidSgidSnapshot {
            files: baseline_files,
        };

        let mut current_files = HashMap::new();
        current_files.insert(path, info);
        let current = SuidSgidSnapshot {
            files: current_files,
        };
        assert!(!SuidSgidMonitorModule::detect_and_report(
            &baseline, &current, &None
        ));
    }

    #[test]
    fn test_init_zero_interval() {
        let config = SuidSgidMonitorConfig {
            enabled: true,
            scan_interval_secs: 0,
            watch_dirs: vec![],
        };
        let mut module = SuidSgidMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let dir = TempDir::new().unwrap();
        let config = SuidSgidMonitorConfig {
            enabled: true,
            scan_interval_secs: 300,
            watch_dirs: vec![dir.path().to_path_buf()],
        };
        let mut module = SuidSgidMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let dir = TempDir::new().unwrap();
        let config = SuidSgidMonitorConfig {
            enabled: true,
            scan_interval_secs: 3600,
            watch_dirs: vec![dir.path().to_path_buf()],
        };
        let mut module = SuidSgidMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }
}
