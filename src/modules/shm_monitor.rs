//! 共有メモリ（/dev/shm）監視モジュール
//!
//! /dev/shm 内の不審なファイルを定期スキャンし、
//! プロセス間通信経由の攻撃を検知する。
//!
//! 検知対象:
//! - 実行権限が付与されたファイル
//! - ELF バイナリ（マジックバイト判定）
//! - 大容量ファイル（設定可能な閾値）
//! - 隠しファイル（ドットファイル）
//! - 新規ファイルの出現・消失

use crate::config::ShmMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::{BTreeMap, HashMap};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

/// ELF マジックバイト（先頭 4 バイト）
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// 共有メモリ内のファイル情報
#[derive(Debug, Clone, PartialEq, Eq)]
struct ShmFileInfo {
    /// ファイルサイズ（バイト）
    size: u64,
    /// ファイルのパーミッション（mode ビット）
    mode: u32,
    /// ファイル名がドットで始まる隠しファイルか
    is_hidden: bool,
    /// ELF バイナリか
    is_elf: bool,
}

/// 共有メモリ内のファイルスナップショット
struct ShmSnapshot {
    /// ファイルパスごとの情報
    files: HashMap<PathBuf, ShmFileInfo>,
}

/// 共有メモリ（/dev/shm）監視モジュール
///
/// /dev/shm を定期スキャンし、不審なファイルの出現・変更・消失を検知する。
pub struct ShmMonitorModule {
    config: ShmMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl ShmMonitorModule {
    /// 新しい共有メモリ監視モジュールを作成する
    pub fn new(config: ShmMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// ファイルが ELF バイナリかどうかを判定する
    fn is_elf_binary(path: &PathBuf) -> bool {
        match std::fs::File::open(path) {
            Ok(mut file) => {
                use std::io::Read;
                let mut buf = [0u8; 4];
                match file.read_exact(&mut buf) {
                    Ok(()) => buf == ELF_MAGIC,
                    Err(_) => false,
                }
            }
            Err(_) => false,
        }
    }

    /// 監視対象ディレクトリをスキャンし、ファイルのスナップショットを返す
    fn scan_dir(watch_dir: &PathBuf) -> ShmSnapshot {
        let mut files = HashMap::new();
        if !watch_dir.exists() {
            tracing::debug!(dir = %watch_dir.display(), "/dev/shm ディレクトリが存在しません。スキップします");
            return ShmSnapshot { files };
        }

        let entries = match std::fs::read_dir(watch_dir) {
            Ok(entries) => entries,
            Err(err) => {
                tracing::debug!(error = %err, dir = %watch_dir.display(), "ディレクトリの読み取りに失敗しました");
                return ShmSnapshot { files };
            }
        };

        for entry in entries.filter_map(|e| match e {
            Ok(entry) => Some(entry),
            Err(err) => {
                tracing::debug!(error = %err, "ディレクトリエントリの読み取りに失敗しました。スキップします");
                None
            }
        }) {
            let path = entry.path();
            // ファイルのみ対象（ディレクトリ・シンボリックリンクは除外）
            let metadata = match entry.metadata() {
                Ok(m) => m,
                Err(err) => {
                    tracing::debug!(
                        path = %path.display(),
                        error = %err,
                        "ファイルメタデータの取得に失敗しました。スキップします"
                    );
                    continue;
                }
            };

            if !metadata.is_file() {
                continue;
            }

            let mode = metadata.permissions().mode();
            let is_hidden = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|name| name.starts_with('.'));
            let is_elf = Self::is_elf_binary(&path);

            files.insert(
                path,
                ShmFileInfo {
                    size: metadata.len(),
                    mode,
                    is_hidden,
                    is_elf,
                },
            );
        }

        ShmSnapshot { files }
    }

    /// ベースラインと現在のスナップショットを比較し、変更を検知する。
    /// 変更があった場合は `true` を返す。
    fn detect_and_report(
        baseline: &ShmSnapshot,
        current: &ShmSnapshot,
        event_bus: &Option<EventBus>,
        large_file_threshold_bytes: u64,
    ) -> bool {
        let mut has_changes = false;

        // 新規ファイルの検知
        for (path, info) in &current.files {
            if !baseline.files.contains_key(path) {
                // ELF バイナリ検知（Critical）
                if info.is_elf {
                    tracing::error!(
                        path = %path.display(),
                        size = info.size,
                        "共有メモリに ELF バイナリが検出されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "shm_elf_binary",
                                Severity::Critical,
                                "shm_monitor",
                                "共有メモリに ELF バイナリが検出されました",
                            )
                            .with_details(path.display().to_string()),
                        );
                    }
                    has_changes = true;
                } else if info.mode & 0o111 != 0 {
                    // 実行権限付きファイル検知（Warning）— ELF でない場合
                    tracing::warn!(
                        path = %path.display(),
                        size = info.size,
                        mode = format!("{:o}", info.mode),
                        "共有メモリに実行権限付きファイルが出現しました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "shm_executable",
                                Severity::Warning,
                                "shm_monitor",
                                "共有メモリに実行権限付きファイルが出現しました",
                            )
                            .with_details(path.display().to_string()),
                        );
                    }
                    has_changes = true;
                } else {
                    // 通常の新規ファイル（Info）
                    tracing::info!(
                        path = %path.display(),
                        size = info.size,
                        "共有メモリに新規ファイルが出現しました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "shm_new_file",
                                Severity::Info,
                                "shm_monitor",
                                "共有メモリに新規ファイルが出現しました",
                            )
                            .with_details(path.display().to_string()),
                        );
                    }
                    has_changes = true;
                }

                // 大容量ファイル検知（Medium）— 独立して発行
                if info.size > large_file_threshold_bytes {
                    tracing::warn!(
                        path = %path.display(),
                        size = info.size,
                        threshold = large_file_threshold_bytes,
                        "共有メモリに大容量ファイルが検出されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "shm_large_file",
                                Severity::Warning,
                                "shm_monitor",
                                "共有メモリに大容量ファイルが検出されました",
                            )
                            .with_details(format!(
                                "{} (size={}bytes, threshold={}bytes)",
                                path.display(),
                                info.size,
                                large_file_threshold_bytes
                            )),
                        );
                    }
                    has_changes = true;
                }

                // 隠しファイル検知（Info）— 独立して発行
                if info.is_hidden {
                    tracing::info!(
                        path = %path.display(),
                        "共有メモリに隠しファイルが検出されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "shm_hidden_file",
                                Severity::Info,
                                "shm_monitor",
                                "共有メモリに隠しファイルが検出されました",
                            )
                            .with_details(path.display().to_string()),
                        );
                    }
                    has_changes = true;
                }
            }
        }

        // 消失の検知
        for path in baseline.files.keys() {
            if !current.files.contains_key(path) {
                tracing::warn!(
                    path = %path.display(),
                    "共有メモリからファイルが消失しました（証拠隠滅の可能性）"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "shm_file_removed",
                            Severity::Warning,
                            "shm_monitor",
                            "共有メモリからファイルが消失しました（証拠隠滅の可能性）",
                        )
                        .with_details(path.display().to_string()),
                    );
                }
                has_changes = true;
            }
        }

        has_changes
    }
}

impl Module for ShmMonitorModule {
    fn name(&self) -> &str {
        "shm_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        if !self.config.watch_dir.exists() {
            tracing::warn!(
                dir = %self.config.watch_dir.display(),
                "監視対象の共有メモリディレクトリが存在しません"
            );
        }

        tracing::info!(
            watch_dir = %self.config.watch_dir.display(),
            scan_interval_secs = self.config.scan_interval_secs,
            large_file_threshold_mb = self.config.large_file_threshold_mb,
            "共有メモリ監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        let baseline = Self::scan_dir(&self.config.watch_dir);
        tracing::info!(
            file_count = baseline.files.len(),
            "ベースラインスキャンが完了しました"
        );

        let watch_dir = self.config.watch_dir.clone();
        let scan_interval_secs = self.config.scan_interval_secs;
        let large_file_threshold_bytes = self.config.large_file_threshold_mb * 1024 * 1024;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            interval.tick().await;

            let mut baseline = baseline;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("共有メモリ監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = ShmMonitorModule::scan_dir(&watch_dir);
                        let changed = ShmMonitorModule::detect_and_report(
                            &baseline,
                            &current,
                            &event_bus,
                            large_file_threshold_bytes,
                        );

                        if changed {
                            baseline = current;
                        } else {
                            tracing::debug!("共有メモリに変更はありません");
                        }
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn stop(&mut self) -> Result<(), AppError> {
        self.cancel_token.cancel();
        Ok(())
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();

        let snapshot = Self::scan_dir(&self.config.watch_dir);
        let large_file_threshold_bytes = self.config.large_file_threshold_mb * 1024 * 1024;

        let mut issues_found = 0;
        for info in snapshot.files.values() {
            if info.is_elf || info.mode & 0o111 != 0 {
                issues_found += 1;
            }
            if info.size > large_file_threshold_bytes {
                issues_found += 1;
            }
            if info.is_hidden {
                issues_found += 1;
            }
        }

        let scan_snapshot: BTreeMap<String, String> = snapshot
            .files
            .iter()
            .map(|(path, info)| {
                (
                    path.display().to_string(),
                    format!(
                        "mode={:o},size={},hidden={},elf={}",
                        info.mode, info.size, info.is_hidden, info.is_elf
                    ),
                )
            })
            .collect();

        let items_scanned = snapshot.files.len();
        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "共有メモリから {}件のファイルをスキャンし、{}件の問題を検出しました",
                items_scanned, issues_found
            ),
            snapshot: scan_snapshot,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn make_config(dir: &std::path::Path) -> ShmMonitorConfig {
        ShmMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            watch_dir: dir.to_path_buf(),
            large_file_threshold_mb: 10,
        }
    }

    #[test]
    fn test_scan_dir_empty() {
        let dir = TempDir::new().unwrap();
        let snapshot = ShmMonitorModule::scan_dir(&dir.path().to_path_buf());
        assert!(snapshot.files.is_empty());
    }

    #[test]
    fn test_scan_dir_nonexistent() {
        let snapshot =
            ShmMonitorModule::scan_dir(&PathBuf::from("/tmp/nonexistent_zettai_shm_test"));
        assert!(snapshot.files.is_empty());
    }

    #[test]
    fn test_scan_dir_regular_file() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("regular");
        fs::write(&file_path, "data").unwrap();
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o644)).unwrap();

        let snapshot = ShmMonitorModule::scan_dir(&dir.path().to_path_buf());
        assert_eq!(snapshot.files.len(), 1);
        let info = snapshot.files.get(&file_path).unwrap();
        assert!(!info.is_hidden);
        assert!(!info.is_elf);
        assert_eq!(info.mode & 0o111, 0);
    }

    #[test]
    fn test_scan_dir_executable_file() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("exec_file");
        fs::write(&file_path, "#!/bin/sh\necho test").unwrap();
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o755)).unwrap();

        let snapshot = ShmMonitorModule::scan_dir(&dir.path().to_path_buf());
        assert_eq!(snapshot.files.len(), 1);
        let info = snapshot.files.get(&file_path).unwrap();
        assert_ne!(info.mode & 0o111, 0);
        assert!(!info.is_elf);
    }

    #[test]
    fn test_scan_dir_hidden_file() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join(".hidden");
        fs::write(&file_path, "secret").unwrap();

        let snapshot = ShmMonitorModule::scan_dir(&dir.path().to_path_buf());
        assert_eq!(snapshot.files.len(), 1);
        let info = snapshot.files.get(&file_path).unwrap();
        assert!(info.is_hidden);
    }

    #[test]
    fn test_scan_dir_elf_binary() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("elf_bin");
        let mut file = fs::File::create(&file_path).unwrap();
        // ELF マジックバイト + ダミーデータ
        file.write_all(&[0x7f, b'E', b'L', b'F', 0, 0, 0, 0])
            .unwrap();
        drop(file);

        let snapshot = ShmMonitorModule::scan_dir(&dir.path().to_path_buf());
        assert_eq!(snapshot.files.len(), 1);
        let info = snapshot.files.get(&file_path).unwrap();
        assert!(info.is_elf);
    }

    #[test]
    fn test_scan_dir_non_elf_short_file() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("short");
        fs::write(&file_path, "ab").unwrap();

        let snapshot = ShmMonitorModule::scan_dir(&dir.path().to_path_buf());
        assert_eq!(snapshot.files.len(), 1);
        let info = snapshot.files.get(&file_path).unwrap();
        assert!(!info.is_elf);
    }

    #[test]
    fn test_scan_dir_skips_directories() {
        let dir = TempDir::new().unwrap();
        fs::create_dir(dir.path().join("subdir")).unwrap();
        let file_path = dir.path().join("file");
        fs::write(&file_path, "data").unwrap();

        let snapshot = ShmMonitorModule::scan_dir(&dir.path().to_path_buf());
        assert_eq!(snapshot.files.len(), 1);
    }

    #[test]
    fn test_detect_new_regular_file() {
        let baseline = ShmSnapshot {
            files: HashMap::new(),
        };
        let mut current_files = HashMap::new();
        current_files.insert(
            PathBuf::from("/dev/shm/new_file"),
            ShmFileInfo {
                size: 100,
                mode: 0o100644,
                is_hidden: false,
                is_elf: false,
            },
        );
        let current = ShmSnapshot {
            files: current_files,
        };
        assert!(ShmMonitorModule::detect_and_report(
            &baseline,
            &current,
            &None,
            10 * 1024 * 1024
        ));
    }

    #[test]
    fn test_detect_new_executable() {
        let baseline = ShmSnapshot {
            files: HashMap::new(),
        };
        let mut current_files = HashMap::new();
        current_files.insert(
            PathBuf::from("/dev/shm/exec"),
            ShmFileInfo {
                size: 100,
                mode: 0o100755,
                is_hidden: false,
                is_elf: false,
            },
        );
        let current = ShmSnapshot {
            files: current_files,
        };
        assert!(ShmMonitorModule::detect_and_report(
            &baseline,
            &current,
            &None,
            10 * 1024 * 1024
        ));
    }

    #[test]
    fn test_detect_elf_binary() {
        let baseline = ShmSnapshot {
            files: HashMap::new(),
        };
        let mut current_files = HashMap::new();
        current_files.insert(
            PathBuf::from("/dev/shm/malware"),
            ShmFileInfo {
                size: 4096,
                mode: 0o100755,
                is_hidden: false,
                is_elf: true,
            },
        );
        let current = ShmSnapshot {
            files: current_files,
        };
        assert!(ShmMonitorModule::detect_and_report(
            &baseline,
            &current,
            &None,
            10 * 1024 * 1024
        ));
    }

    #[test]
    fn test_detect_large_file() {
        let baseline = ShmSnapshot {
            files: HashMap::new(),
        };
        let mut current_files = HashMap::new();
        current_files.insert(
            PathBuf::from("/dev/shm/large"),
            ShmFileInfo {
                size: 20 * 1024 * 1024,
                mode: 0o100644,
                is_hidden: false,
                is_elf: false,
            },
        );
        let current = ShmSnapshot {
            files: current_files,
        };
        assert!(ShmMonitorModule::detect_and_report(
            &baseline,
            &current,
            &None,
            10 * 1024 * 1024
        ));
    }

    #[test]
    fn test_detect_hidden_file() {
        let baseline = ShmSnapshot {
            files: HashMap::new(),
        };
        let mut current_files = HashMap::new();
        current_files.insert(
            PathBuf::from("/dev/shm/.secret"),
            ShmFileInfo {
                size: 50,
                mode: 0o100644,
                is_hidden: true,
                is_elf: false,
            },
        );
        let current = ShmSnapshot {
            files: current_files,
        };
        assert!(ShmMonitorModule::detect_and_report(
            &baseline,
            &current,
            &None,
            10 * 1024 * 1024
        ));
    }

    #[test]
    fn test_detect_removed_file() {
        let mut baseline_files = HashMap::new();
        baseline_files.insert(
            PathBuf::from("/dev/shm/removed"),
            ShmFileInfo {
                size: 100,
                mode: 0o100644,
                is_hidden: false,
                is_elf: false,
            },
        );
        let baseline = ShmSnapshot {
            files: baseline_files,
        };
        let current = ShmSnapshot {
            files: HashMap::new(),
        };
        assert!(ShmMonitorModule::detect_and_report(
            &baseline,
            &current,
            &None,
            10 * 1024 * 1024
        ));
    }

    #[test]
    fn test_detect_no_changes() {
        let path = PathBuf::from("/dev/shm/unchanged");
        let info = ShmFileInfo {
            size: 100,
            mode: 0o100644,
            is_hidden: false,
            is_elf: false,
        };

        let mut files = HashMap::new();
        files.insert(path.clone(), info.clone());
        let baseline = ShmSnapshot {
            files: files.clone(),
        };
        let current = ShmSnapshot { files };
        assert!(!ShmMonitorModule::detect_and_report(
            &baseline,
            &current,
            &None,
            10 * 1024 * 1024
        ));
    }

    #[test]
    fn test_init_zero_interval() {
        let dir = TempDir::new().unwrap();
        let config = ShmMonitorConfig {
            enabled: true,
            scan_interval_secs: 0,
            watch_dir: dir.path().to_path_buf(),
            large_file_threshold_mb: 10,
        };
        let mut module = ShmMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let dir = TempDir::new().unwrap();
        let config = make_config(dir.path());
        let mut module = ShmMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let dir = TempDir::new().unwrap();
        let config = ShmMonitorConfig {
            enabled: true,
            scan_interval_secs: 3600,
            watch_dir: dir.path().to_path_buf(),
            large_file_threshold_mb: 10,
        };
        let mut module = ShmMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();
        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan_with_issues() {
        let dir = TempDir::new().unwrap();

        // 実行可能ファイル
        let exec_path = dir.path().join("exec");
        fs::write(&exec_path, "#!/bin/sh").unwrap();
        fs::set_permissions(&exec_path, fs::Permissions::from_mode(0o755)).unwrap();

        // 隠しファイル
        let hidden_path = dir.path().join(".hidden");
        fs::write(&hidden_path, "secret").unwrap();

        let config = make_config(dir.path());
        let module = ShmMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 2);
        assert!(result.issues_found >= 2); // exec + hidden
    }

    #[tokio::test]
    async fn test_initial_scan_empty() {
        let dir = TempDir::new().unwrap();
        let config = make_config(dir.path());
        let module = ShmMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
    }

    #[tokio::test]
    async fn test_initial_scan_elf_detection() {
        let dir = TempDir::new().unwrap();
        let elf_path = dir.path().join("elf_bin");
        let mut file = fs::File::create(&elf_path).unwrap();
        file.write_all(&[0x7f, b'E', b'L', b'F', 0, 0, 0, 0])
            .unwrap();
        drop(file);

        let config = make_config(dir.path());
        let module = ShmMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 1);
        assert!(result.issues_found >= 1);
    }

    #[test]
    fn test_is_elf_binary_true() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("elf");
        let mut file = fs::File::create(&file_path).unwrap();
        file.write_all(&[0x7f, b'E', b'L', b'F', 1, 1, 1, 0])
            .unwrap();
        drop(file);
        assert!(ShmMonitorModule::is_elf_binary(&file_path));
    }

    #[test]
    fn test_is_elf_binary_false() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("not_elf");
        fs::write(&file_path, "not an elf binary").unwrap();
        assert!(!ShmMonitorModule::is_elf_binary(&file_path));
    }

    #[test]
    fn test_is_elf_binary_too_short() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("short");
        fs::write(&file_path, "ab").unwrap();
        assert!(!ShmMonitorModule::is_elf_binary(&file_path));
    }

    #[test]
    fn test_is_elf_binary_nonexistent() {
        assert!(!ShmMonitorModule::is_elf_binary(&PathBuf::from(
            "/tmp/nonexistent_elf_test"
        )));
    }
}
