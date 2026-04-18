//! 環境変数・LD_PRELOAD 監視モジュール
//!
//! `/etc/ld.so.preload`, `/etc/environment`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` を
//! 定期的にスキャンし、LD_PRELOAD ハイジャック攻撃を検知する。
//!
//! 検知対象:
//! - `/etc/ld.so.preload` の存在（通常は存在しない → Critical）
//! - `/etc/environment` 内の LD_PRELOAD / LD_LIBRARY_PATH 行（→ Critical）
//! - `/etc/ld.so.conf` 系ファイルの変更・追加・削除（→ Warning）

use crate::config::LdPreloadMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

/// 危険な環境変数名のリスト
const DANGEROUS_ENV_VARS: &[&str] = &["LD_PRELOAD", "LD_LIBRARY_PATH"];

/// ファイルごとのスナップショット
struct FileSnapshot {
    /// ファイル全体の SHA-256 ハッシュ
    file_hash: String,
}

/// 監視対象ファイル群のスナップショット
struct LdConfigSnapshot {
    /// ファイルパスごとのスナップショット
    files: HashMap<PathBuf, FileSnapshot>,
}

/// 環境変数・LD_PRELOAD 監視モジュール
///
/// 動的リンカ関連ファイルと環境変数設定を定期スキャンし、
/// LD_PRELOAD ハイジャック攻撃を検知する。
pub struct LdPreloadMonitorModule {
    config: LdPreloadMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl LdPreloadMonitorModule {
    /// 新しい LD_PRELOAD 監視モジュールを作成する
    pub fn new(config: LdPreloadMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// 監視対象パスをスキャンし、全ファイルのスナップショットを返す
    fn scan_files(watch_paths: &[PathBuf]) -> LdConfigSnapshot {
        let mut files = HashMap::new();
        for path in watch_paths {
            if path.is_dir() {
                // ディレクトリの場合は中のファイルをスキャン
                match std::fs::read_dir(path) {
                    Ok(entries) => {
                        for entry in entries.flatten() {
                            let entry_path = entry.path();
                            if entry_path.is_file()
                                && let Ok(snapshot) = build_file_snapshot(&entry_path)
                            {
                                files.insert(entry_path, snapshot);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!(
                            path = %path.display(),
                            error = %e,
                            "ディレクトリの読み取りに失敗しました。スキャンを継続します"
                        );
                    }
                }
            } else if path.is_file() {
                match build_file_snapshot(path) {
                    Ok(snapshot) => {
                        files.insert(path.clone(), snapshot);
                    }
                    Err(e) => {
                        tracing::debug!(
                            path = %path.display(),
                            error = %e,
                            "ファイルの読み取りに失敗しました。スキャンを継続します"
                        );
                    }
                }
            }
            // 存在しないパスはスキップ（ld.so.preload は通常存在しない）
        }
        LdConfigSnapshot { files }
    }

    /// `/etc/ld.so.preload` の存在チェック
    fn check_ld_so_preload(watch_paths: &[PathBuf], event_bus: &Option<EventBus>) {
        for path in watch_paths {
            if path.ends_with("ld.so.preload") && path.is_file() {
                tracing::error!(
                    path = %path.display(),
                    "ld.so.preload が存在します — LD_PRELOAD ハイジャックの疑いがあります"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "ld_preload_file_exists",
                            Severity::Critical,
                            "ld_preload_monitor",
                            format!(
                                "ld.so.preload が存在します — LD_PRELOAD ハイジャックの疑い: {}",
                                path.display()
                            ),
                        )
                        .with_details(path.display().to_string()),
                    );
                }
            }
        }
    }

    /// `/etc/environment` 内の危険な環境変数をチェック
    fn check_dangerous_env_vars(watch_paths: &[PathBuf], event_bus: &Option<EventBus>) {
        for path in watch_paths {
            let filename = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if filename != "environment" || !path.is_file() {
                continue;
            }
            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                for var in DANGEROUS_ENV_VARS {
                    if trimmed.starts_with(var) && trimmed[var.len()..].starts_with('=') {
                        tracing::error!(
                            path = %path.display(),
                            variable = var,
                            "危険な環境変数が設定されています"
                        );
                        if let Some(bus) = event_bus {
                            bus.publish(
                                SecurityEvent::new(
                                    "ld_preload_env_detected",
                                    Severity::Critical,
                                    "ld_preload_monitor",
                                    format!(
                                        "危険な環境変数が検出されました: {} ({})",
                                        var,
                                        path.display()
                                    ),
                                )
                                .with_details(format!(
                                    "{}={}",
                                    var,
                                    path.display()
                                )),
                            );
                        }
                    }
                }
            }
        }
    }

    /// ベースラインと現在のスナップショットを比較し、変更を検知する。
    /// 変更があった場合は `true` を返す。
    fn detect_and_report(
        baseline: &LdConfigSnapshot,
        current: &LdConfigSnapshot,
        event_bus: &Option<EventBus>,
    ) -> bool {
        let mut has_changes = false;

        // 新しいファイルの検知
        for path in current.files.keys() {
            if !baseline.files.contains_key(path) {
                tracing::warn!(
                    path = %path.display(),
                    "動的リンカ設定ファイルが追加されました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "ld_config_file_added",
                            Severity::Warning,
                            "ld_preload_monitor",
                            format!("動的リンカ設定ファイルが追加されました: {}", path.display()),
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
                    "動的リンカ設定ファイルが削除されました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "ld_config_file_removed",
                            Severity::Warning,
                            "ld_preload_monitor",
                            format!("動的リンカ設定ファイルが削除されました: {}", path.display()),
                        )
                        .with_details(path.display().to_string()),
                    );
                }
                has_changes = true;
            }
        }

        // 変更されたファイルの検知
        for (path, current_snapshot) in &current.files {
            if let Some(baseline_snapshot) = baseline.files.get(path)
                && baseline_snapshot.file_hash != current_snapshot.file_hash
            {
                tracing::warn!(
                    path = %path.display(),
                    "動的リンカ設定ファイルが変更されました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "ld_config_modified",
                            Severity::Warning,
                            "ld_preload_monitor",
                            format!("動的リンカ設定ファイルが変更されました: {}", path.display()),
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

/// ファイルのスナップショットを作成する
fn build_file_snapshot(path: &PathBuf) -> Result<FileSnapshot, AppError> {
    let data = std::fs::read(path).map_err(|e| AppError::FileIo {
        path: path.clone(),
        source: e,
    })?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let file_hash = format!("{:x}", hasher.finalize());
    Ok(FileSnapshot { file_hash })
}

impl Module for LdPreloadMonitorModule {
    fn name(&self) -> &str {
        "ld_preload_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        for path in &self.config.watch_paths {
            if !path.exists() {
                tracing::debug!(
                    path = %path.display(),
                    "監視対象パスが存在しません（起動時点）"
                );
            }
        }

        tracing::info!(
            watch_paths = ?self.config.watch_paths,
            scan_interval_secs = self.config.scan_interval_secs,
            "環境変数・LD_PRELOAD 監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        // 初回チェック
        Self::check_ld_so_preload(&self.config.watch_paths, &self.event_bus);
        Self::check_dangerous_env_vars(&self.config.watch_paths, &self.event_bus);

        let baseline = Self::scan_files(&self.config.watch_paths);
        tracing::info!(
            file_count = baseline.files.len(),
            "ベースラインスキャンが完了しました"
        );

        let watch_paths = self.config.watch_paths.clone();
        let scan_interval_secs = self.config.scan_interval_secs;
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
                        tracing::info!("環境変数・LD_PRELOAD 監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        // 毎回チェック: ld.so.preload の存在と危険な環境変数
                        LdPreloadMonitorModule::check_ld_so_preload(&watch_paths, &event_bus);
                        LdPreloadMonitorModule::check_dangerous_env_vars(&watch_paths, &event_bus);

                        let current = LdPreloadMonitorModule::scan_files(&watch_paths);
                        let changed = LdPreloadMonitorModule::detect_and_report(
                            &baseline, &current, &event_bus,
                        );

                        if changed {
                            baseline = current;
                        } else {
                            tracing::debug!("動的リンカ設定ファイルの変更はありません");
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

        let snapshot = Self::scan_files(&self.config.watch_paths);
        let items_scanned = snapshot.files.len();
        let scan_snapshot: BTreeMap<String, String> = snapshot
            .files
            .iter()
            .map(|(path, snap)| (path.display().to_string(), snap.file_hash.clone()))
            .collect();
        let mut issues_found = 0;

        // /etc/ld.so.preload の存在チェック
        for path in &self.config.watch_paths {
            if path.ends_with("ld.so.preload") && path.is_file() {
                issues_found += 1;
            }
        }

        // /etc/environment 内の危険な環境変数チェック
        for path in &self.config.watch_paths {
            let filename = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if filename != "environment" || !path.is_file() {
                continue;
            }
            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                for var in DANGEROUS_ENV_VARS {
                    if trimmed.starts_with(var) && trimmed[var.len()..].starts_with('=') {
                        issues_found += 1;
                    }
                }
            }
        }

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "動的リンカ設定ファイル {}件をスキャンしました（問題: {}件）",
                items_scanned, issues_found
            ),
            snapshot: scan_snapshot,
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
        writeln!(tmpfile, "/usr/lib/libevil.so").unwrap();
        let snapshot = build_file_snapshot(&tmpfile.path().to_path_buf()).unwrap();
        assert!(!snapshot.file_hash.is_empty());
        assert_eq!(snapshot.file_hash.len(), 64);
    }

    #[test]
    fn test_build_file_snapshot_deterministic() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmpfile, "/usr/lib/libtest.so").unwrap();
        let s1 = build_file_snapshot(&tmpfile.path().to_path_buf()).unwrap();
        let s2 = build_file_snapshot(&tmpfile.path().to_path_buf()).unwrap();
        assert_eq!(s1.file_hash, s2.file_hash);
    }

    #[test]
    fn test_build_file_snapshot_nonexistent() {
        let result = build_file_snapshot(&PathBuf::from("/tmp/nonexistent-zettai-ld-test"));
        assert!(result.is_err());
    }

    #[test]
    fn test_scan_files_with_file() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmpfile, "content").unwrap();
        let path = tmpfile.path().to_path_buf();
        let result = LdPreloadMonitorModule::scan_files(std::slice::from_ref(&path));
        assert_eq!(result.files.len(), 1);
        assert!(result.files.contains_key(&path));
    }

    #[test]
    fn test_scan_files_with_directory() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let file_path = tmpdir.path().join("test.conf");
        std::fs::write(&file_path, "content\n").unwrap();
        let result = LdPreloadMonitorModule::scan_files(&[tmpdir.path().to_path_buf()]);
        assert_eq!(result.files.len(), 1);
        assert!(result.files.contains_key(&file_path));
    }

    #[test]
    fn test_scan_files_empty() {
        let result = LdPreloadMonitorModule::scan_files(&[]);
        assert!(result.files.is_empty());
    }

    #[test]
    fn test_scan_files_nonexistent_skipped() {
        let result =
            LdPreloadMonitorModule::scan_files(&[PathBuf::from("/tmp/nonexistent_zettai_ld_test")]);
        assert!(result.files.is_empty());
    }

    #[test]
    fn test_detect_no_changes() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmpfile, "content").unwrap();
        let path = tmpfile.path().to_path_buf();
        let s1 = LdPreloadMonitorModule::scan_files(std::slice::from_ref(&path));
        let s2 = LdPreloadMonitorModule::scan_files(&[path]);
        let changed = LdPreloadMonitorModule::detect_and_report(&s1, &s2, &None);
        assert!(!changed);
    }

    #[test]
    fn test_detect_file_added() {
        let baseline = LdConfigSnapshot {
            files: HashMap::new(),
        };
        let mut current_files = HashMap::new();
        current_files.insert(
            PathBuf::from("/tmp/test_added"),
            FileSnapshot {
                file_hash: "hash1".to_string(),
            },
        );
        let current = LdConfigSnapshot {
            files: current_files,
        };
        let changed = LdPreloadMonitorModule::detect_and_report(&baseline, &current, &None);
        assert!(changed);
    }

    #[test]
    fn test_detect_file_removed() {
        let mut baseline_files = HashMap::new();
        baseline_files.insert(
            PathBuf::from("/tmp/test_removed"),
            FileSnapshot {
                file_hash: "hash1".to_string(),
            },
        );
        let baseline = LdConfigSnapshot {
            files: baseline_files,
        };
        let current = LdConfigSnapshot {
            files: HashMap::new(),
        };
        let changed = LdPreloadMonitorModule::detect_and_report(&baseline, &current, &None);
        assert!(changed);
    }

    #[test]
    fn test_detect_file_modified() {
        let path = PathBuf::from("/tmp/test_modified");
        let mut baseline_files = HashMap::new();
        baseline_files.insert(
            path.clone(),
            FileSnapshot {
                file_hash: "hash1".to_string(),
            },
        );
        let baseline = LdConfigSnapshot {
            files: baseline_files,
        };
        let mut current_files = HashMap::new();
        current_files.insert(
            path,
            FileSnapshot {
                file_hash: "hash2".to_string(),
            },
        );
        let current = LdConfigSnapshot {
            files: current_files,
        };
        let changed = LdPreloadMonitorModule::detect_and_report(&baseline, &current, &None);
        assert!(changed);
    }

    #[test]
    fn test_check_dangerous_env_vars_detects_ld_preload() {
        let tmpfile = tempfile::NamedTempFile::new().unwrap();
        // ファイル名が "environment" である必要がある
        let tmpdir = tempfile::TempDir::new().unwrap();
        let env_path = tmpdir.path().join("environment");
        std::fs::write(&env_path, "PATH=/usr/bin\nLD_PRELOAD=/tmp/evil.so\n").unwrap();

        // イベントバスなしで呼び出し（ログ出力のみ確認）
        LdPreloadMonitorModule::check_dangerous_env_vars(&[env_path], &None);
        // パニックしなければ OK（ログ出力は tracing でキャプチャ不要）

        // tmpfile を使わないようにする
        drop(tmpfile);
    }

    #[test]
    fn test_check_dangerous_env_vars_safe_file() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let env_path = tmpdir.path().join("environment");
        std::fs::write(&env_path, "PATH=/usr/bin\nEDITOR=vim\n").unwrap();
        LdPreloadMonitorModule::check_dangerous_env_vars(&[env_path], &None);
        // 安全なファイルでパニックしないことを確認
    }

    #[test]
    fn test_check_dangerous_env_vars_comments_ignored() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let env_path = tmpdir.path().join("environment");
        std::fs::write(&env_path, "# LD_PRELOAD=/tmp/evil.so\n").unwrap();
        LdPreloadMonitorModule::check_dangerous_env_vars(&[env_path], &None);
        // コメント行は無視される
    }

    #[test]
    fn test_check_ld_so_preload_nonexistent() {
        LdPreloadMonitorModule::check_ld_so_preload(
            &[PathBuf::from("/tmp/nonexistent/ld.so.preload")],
            &None,
        );
        // 存在しなければ何も起きない
    }

    #[test]
    fn test_init_zero_interval() {
        let config = LdPreloadMonitorConfig {
            enabled: true,
            scan_interval_secs: 0,
            watch_paths: vec![],
        };
        let mut module = LdPreloadMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_init_valid() {
        let config = LdPreloadMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            watch_paths: vec![PathBuf::from("/etc/ld.so.preload")],
        };
        let mut module = LdPreloadMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmpfile, "content").unwrap();

        let config = LdPreloadMonitorConfig {
            enabled: true,
            scan_interval_secs: 3600,
            watch_paths: vec![tmpfile.path().to_path_buf()],
        };
        let mut module = LdPreloadMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[test]
    fn test_check_dangerous_env_vars_ld_library_path() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let env_path = tmpdir.path().join("environment");
        std::fs::write(&env_path, "LD_LIBRARY_PATH=/tmp/evil\n").unwrap();
        LdPreloadMonitorModule::check_dangerous_env_vars(&[env_path], &None);
        // LD_LIBRARY_PATH も検知対象
    }

    #[test]
    fn test_check_dangerous_env_vars_nonexistent_file() {
        LdPreloadMonitorModule::check_dangerous_env_vars(
            &[PathBuf::from("/tmp/nonexistent/environment")],
            &None,
        );
        // 存在しないファイルでもパニックしない
    }

    #[test]
    fn test_scan_files_directory_with_multiple_files() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        std::fs::write(tmpdir.path().join("a.conf"), "aaa\n").unwrap();
        std::fs::write(tmpdir.path().join("b.conf"), "bbb\n").unwrap();
        let result = LdPreloadMonitorModule::scan_files(&[tmpdir.path().to_path_buf()]);
        assert_eq!(result.files.len(), 2);
    }

    #[test]
    fn test_check_dangerous_env_vars_partial_match_ignored() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let env_path = tmpdir.path().join("environment");
        // LD_PRELOAD_EXTRA は LD_PRELOAD= で始まらないため検知しない
        std::fs::write(&env_path, "LD_PRELOAD_EXTRA=foo\n").unwrap();
        LdPreloadMonitorModule::check_dangerous_env_vars(&[env_path], &None);
    }

    #[tokio::test]
    async fn test_initial_scan_no_issues() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let conf_path = tmpdir.path().join("ld.so.conf");
        std::fs::write(&conf_path, "/usr/lib\n").unwrap();

        let config = LdPreloadMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            watch_paths: vec![conf_path],
        };
        let module = LdPreloadMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 1);
        assert_eq!(result.issues_found, 0);
        assert!(result.summary.contains("1件"));
    }

    #[tokio::test]
    async fn test_initial_scan_detects_ld_so_preload() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let preload_path = tmpdir.path().join("ld.so.preload");
        std::fs::write(&preload_path, "/tmp/evil.so\n").unwrap();

        let config = LdPreloadMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            watch_paths: vec![preload_path],
        };
        let module = LdPreloadMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 1);
        assert_eq!(result.issues_found, 1);
        assert!(result.summary.contains("問題: 1件"));
    }

    #[tokio::test]
    async fn test_initial_scan_detects_dangerous_env() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let env_path = tmpdir.path().join("environment");
        std::fs::write(
            &env_path,
            "PATH=/usr/bin\nLD_PRELOAD=/tmp/evil.so\nLD_LIBRARY_PATH=/tmp\n",
        )
        .unwrap();

        let config = LdPreloadMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            watch_paths: vec![env_path],
        };
        let module = LdPreloadMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.issues_found, 2);
    }

    #[tokio::test]
    async fn test_initial_scan_empty_paths() {
        let config = LdPreloadMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            watch_paths: vec![],
        };
        let module = LdPreloadMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
    }
}
