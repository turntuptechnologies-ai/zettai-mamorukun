//! /etc/security/ 監視モジュール
//!
//! /etc/security/ 配下のセキュリティ設定ファイルを定期的にスキャンし、
//! SHA-256 ハッシュベースで変更を検知する。
//!
//! 検知対象:
//! - セキュリティ設定ファイルの追加・削除
//! - 設定行の追加・削除（行レベルの変更検知）
//! - limits.conf における危険なリソース無制限設定

use crate::config::SecurityFilesMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
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

/// セキュリティ設定ファイル群のスナップショット
struct SecurityFilesSnapshot {
    /// ファイルパスごとのスナップショット
    files: HashMap<PathBuf, FileSnapshot>,
}

/// 検出された危険パターンの識別子（ファイルパス + 行内容のハッシュ）
type DangerKey = String;

/// /etc/security/ 監視モジュール
///
/// セキュリティ設定ファイルを定期スキャンし、ベースラインとの差分および危険パターンを検知する。
pub struct SecurityFilesMonitorModule {
    config: SecurityFilesMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl SecurityFilesMonitorModule {
    /// 新しいセキュリティ設定ファイル監視モジュールを作成する
    pub fn new(config: SecurityFilesMonitorConfig, event_bus: Option<EventBus>) -> Self {
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
    fn scan_files(watch_paths: &[PathBuf]) -> SecurityFilesSnapshot {
        let mut files = HashMap::new();
        for path in watch_paths {
            if path.is_file() {
                match build_file_snapshot(path) {
                    Ok(snapshot) => {
                        files.insert(path.clone(), snapshot);
                    }
                    Err(e) => {
                        tracing::debug!(path = %path.display(), error = %e, "セキュリティ設定ファイルの読み取りに失敗しました。スキャンを継続します");
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
                                tracing::debug!(path = %entry.path().display(), error = %e, "セキュリティ設定ファイルの読み取りに失敗しました。スキャンを継続します");
                            }
                        }
                    }
                }
            } else {
                tracing::debug!(path = %path.display(), "セキュリティ設定パスが存在しません。スキップします");
            }
        }
        SecurityFilesSnapshot { files }
    }

    /// ベースラインと現在のスナップショットを比較し、変更を検知してイベントを発行する。
    /// 変更があった場合は `true` を返す。
    fn detect_and_report(
        baseline: &SecurityFilesSnapshot,
        current: &SecurityFilesSnapshot,
        event_bus: &Option<EventBus>,
    ) -> bool {
        let mut has_changes = false;

        // 新しいファイルの検知
        for path in current.files.keys() {
            if !baseline.files.contains_key(path) {
                let line_count = current.files[path].line_count();
                tracing::warn!(
                    path = %path.display(),
                    line_count,
                    "セキュリティ設定ファイルが追加されました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "security_file_added",
                            Severity::Critical,
                            "security_files_monitor",
                            format!(
                                "セキュリティ設定ファイルが追加されました: {}",
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
                    "セキュリティ設定ファイルが削除されました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "security_file_removed",
                            Severity::Warning,
                            "security_files_monitor",
                            format!(
                                "セキュリティ設定ファイルが削除されました: {}",
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

                let baseline_set: HashSet<&String> = baseline_snapshot.line_hashes.iter().collect();
                let current_set: HashSet<&String> = current_snapshot.line_hashes.iter().collect();

                let added_count = current_set.difference(&baseline_set).count();
                let removed_count = baseline_set.difference(&current_set).count();

                if added_count > 0 {
                    tracing::warn!(
                        path = %path.display(),
                        added_count,
                        "セキュリティ設定行が追加されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "security_lines_added",
                                Severity::Warning,
                                "security_files_monitor",
                                format!("セキュリティ設定行が追加されました: {}", path.display()),
                            )
                            .with_details(path.display().to_string()),
                        );
                    }
                }
                if removed_count > 0 {
                    tracing::warn!(
                        path = %path.display(),
                        removed_count,
                        "セキュリティ設定行が削除されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "security_lines_removed",
                                Severity::Warning,
                                "security_files_monitor",
                                format!("セキュリティ設定行が削除されました: {}", path.display()),
                            )
                            .with_details(path.display().to_string()),
                        );
                    }
                }

                tracing::warn!(
                    path = %path.display(),
                    before = baseline_snapshot.line_count(),
                    after = current_snapshot.line_count(),
                    "セキュリティ設定行数が変化しました"
                );
            }
        }

        has_changes
    }

    /// limits.conf 系ファイルの危険パターンを検出してイベントを発行する。
    /// 全ユーザー (`*`) に対する `unlimited` リソース設定を検知する。
    fn check_dangerous_patterns(
        watch_paths: &[PathBuf],
        reported_dangers: &mut HashSet<DangerKey>,
        event_bus: &Option<EventBus>,
    ) {
        for path in watch_paths {
            let files_to_check = collect_files_to_check(path);

            for file_path in &files_to_check {
                // limits.conf / limits.d/ のファイルのみ対象
                let file_name = file_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default();
                let parent_name = file_path
                    .parent()
                    .and_then(|p| p.file_name())
                    .and_then(|n| n.to_str())
                    .unwrap_or_default();

                let is_limits_file = file_name == "limits.conf" || parent_name == "limits.d";

                if !is_limits_file {
                    continue;
                }

                let content = match std::fs::read_to_string(file_path) {
                    Ok(c) => c,
                    Err(_) => continue,
                };

                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }

                    // limits.conf 形式: <domain> <type> <item> <value>
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() < 4 {
                        continue;
                    }

                    let domain = parts[0];
                    // parts[1] is type (soft/hard/-)
                    // parts[2] is item (nofile, nproc, etc.)
                    let value = parts[3];

                    // 全ユーザーに対する unlimited 設定を検出
                    if domain == "*" && value == "unlimited" {
                        let danger_key = format!("unlimited:{}:{}", file_path.display(), trimmed);
                        if !reported_dangers.contains(&danger_key) {
                            reported_dangers.insert(danger_key);
                            tracing::warn!(
                                path = %file_path.display(),
                                line = trimmed,
                                "全ユーザーに対する unlimited リソース設定が検出されました"
                            );
                            if let Some(bus) = event_bus {
                                bus.publish(
                                    SecurityEvent::new(
                                        "security_dangerous_unlimited",
                                        Severity::Critical,
                                        "security_files_monitor",
                                        format!(
                                            "全ユーザーに対する unlimited リソース設定が検出されました: {}",
                                            file_path.display()
                                        ),
                                    )
                                    .with_details(format!(
                                        "file={}, line={}",
                                        file_path.display(),
                                        trimmed
                                    )),
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

/// 指定パスからチェック対象ファイルのリストを収集する
fn collect_files_to_check(path: &PathBuf) -> Vec<PathBuf> {
    if path.is_file() {
        vec![path.clone()]
    } else if path.is_dir() {
        WalkDir::new(path)
            .min_depth(1)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .map(|e| e.path().to_path_buf())
            .collect()
    } else {
        vec![]
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

impl Module for SecurityFilesMonitorModule {
    fn name(&self) -> &str {
        "security_files_monitor"
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
                    "監視対象のセキュリティ設定パスが存在しません"
                );
            }
        }

        tracing::info!(
            watch_paths = ?self.config.watch_paths,
            scan_interval_secs = self.config.scan_interval_secs,
            "/etc/security/ 監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        let baseline = Self::scan_files(&self.config.watch_paths);
        let total_lines: usize = baseline.files.values().map(|s| s.line_count()).sum();
        tracing::info!(
            file_count = baseline.files.len(),
            total_lines,
            "セキュリティ設定ファイルのベースラインスキャンが完了しました"
        );

        let watch_paths = self.config.watch_paths.clone();
        let scan_interval_secs = self.config.scan_interval_secs;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        // 初回の危険パターンチェック
        let mut reported_dangers = HashSet::new();
        Self::check_dangerous_patterns(&watch_paths, &mut reported_dangers, &event_bus);

        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            interval.tick().await;

            let mut baseline = baseline;
            let mut reported_dangers = reported_dangers;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("/etc/security/ 監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = SecurityFilesMonitorModule::scan_files(&watch_paths);
                        let changed = SecurityFilesMonitorModule::detect_and_report(&baseline, &current, &event_bus);

                        if changed {
                            reported_dangers.clear();
                            SecurityFilesMonitorModule::check_dangerous_patterns(&watch_paths, &mut reported_dangers, &event_bus);
                            baseline = current;
                        } else {
                            tracing::debug!("セキュリティ設定ファイルの変更はありません");
                            SecurityFilesMonitorModule::check_dangerous_patterns(&watch_paths, &mut reported_dangers, &event_bus);
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

        for path in &self.config.watch_paths {
            let files_to_check = collect_files_to_check(path);

            for file_path in &files_to_check {
                let file_name = file_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default();
                let parent_name = file_path
                    .parent()
                    .and_then(|p| p.file_name())
                    .and_then(|n| n.to_str())
                    .unwrap_or_default();

                let is_limits_file = file_name == "limits.conf" || parent_name == "limits.d";

                if !is_limits_file {
                    continue;
                }

                let content = match std::fs::read_to_string(file_path) {
                    Ok(c) => c,
                    Err(_) => continue,
                };

                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }

                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() < 4 {
                        continue;
                    }

                    let domain = parts[0];
                    let value = parts[3];

                    if domain == "*" && value == "unlimited" {
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
                "セキュリティ設定ファイル {}件をスキャンしました（危険パターン: {}件）",
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
        write!(tmpfile, "* soft nofile 1024\n* hard nofile 4096\n").unwrap();
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
            "# limits configuration\n\n* soft nofile 1024\n\n# End\n"
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
        let result = build_file_snapshot(&PathBuf::from("/tmp/nonexistent-zettai-security-test"));
        assert!(result.is_err());
    }

    #[test]
    fn test_build_file_snapshot_deterministic() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "* soft nofile 1024\n").unwrap();
        let snapshot1 = build_file_snapshot(&tmpfile.path().to_path_buf()).unwrap();
        let snapshot2 = build_file_snapshot(&tmpfile.path().to_path_buf()).unwrap();
        assert_eq!(snapshot1.file_hash, snapshot2.file_hash);
        assert_eq!(snapshot1.line_hashes, snapshot2.line_hashes);
    }

    #[test]
    fn test_scan_files_with_single_file() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "* soft nofile 1024\n").unwrap();
        let path = tmpfile.path().to_path_buf();

        let watch_paths = vec![path.clone()];
        let result = SecurityFilesMonitorModule::scan_files(&watch_paths);
        assert_eq!(result.files.len(), 1);
        assert!(result.files.contains_key(&path));
    }

    #[test]
    fn test_scan_files_with_directory() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let file1 = tmpdir.path().join("limits.conf");
        let file2 = tmpdir.path().join("access.conf");
        std::fs::write(&file1, "* soft nofile 1024\n").unwrap();
        std::fs::write(&file2, "+ : ALL : LOCAL\n").unwrap();

        let watch_paths = vec![tmpdir.path().to_path_buf()];
        let result = SecurityFilesMonitorModule::scan_files(&watch_paths);
        assert_eq!(result.files.len(), 2);
        assert!(result.files.contains_key(&file1));
        assert!(result.files.contains_key(&file2));
    }

    #[test]
    fn test_scan_files_empty() {
        let watch_paths: Vec<PathBuf> = vec![];
        let result = SecurityFilesMonitorModule::scan_files(&watch_paths);
        assert!(result.files.is_empty());
    }

    #[test]
    fn test_scan_files_nonexistent_skipped() {
        let watch_paths = vec![PathBuf::from("/tmp/nonexistent_zettai_security_test")];
        let result = SecurityFilesMonitorModule::scan_files(&watch_paths);
        assert!(result.files.is_empty());
    }

    #[test]
    fn test_detect_no_changes() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "* soft nofile 1024\n").unwrap();
        let path = tmpfile.path().to_path_buf();

        let watch_paths = vec![path];
        let snapshot1 = SecurityFilesMonitorModule::scan_files(&watch_paths);
        let snapshot2 = SecurityFilesMonitorModule::scan_files(&watch_paths);
        let changed = SecurityFilesMonitorModule::detect_and_report(&snapshot1, &snapshot2, &None);
        assert!(!changed);
    }

    #[test]
    fn test_detect_file_added() {
        let baseline = SecurityFilesSnapshot {
            files: HashMap::new(),
        };
        let mut current_files = HashMap::new();
        current_files.insert(
            PathBuf::from("/tmp/test_security_added"),
            FileSnapshot {
                file_hash: "hash1".to_string(),
                line_hashes: vec!["linehash1".to_string()],
            },
        );
        let current = SecurityFilesSnapshot {
            files: current_files,
        };
        let changed = SecurityFilesMonitorModule::detect_and_report(&baseline, &current, &None);
        assert!(changed);
    }

    #[test]
    fn test_detect_file_removed() {
        let mut baseline_files = HashMap::new();
        baseline_files.insert(
            PathBuf::from("/tmp/test_security_removed"),
            FileSnapshot {
                file_hash: "hash1".to_string(),
                line_hashes: vec!["linehash1".to_string()],
            },
        );
        let baseline = SecurityFilesSnapshot {
            files: baseline_files,
        };
        let current = SecurityFilesSnapshot {
            files: HashMap::new(),
        };
        let changed = SecurityFilesMonitorModule::detect_and_report(&baseline, &current, &None);
        assert!(changed);
    }

    #[test]
    fn test_detect_line_added() {
        let path = PathBuf::from("/tmp/test_security_line_change");
        let mut baseline_files = HashMap::new();
        baseline_files.insert(
            path.clone(),
            FileSnapshot {
                file_hash: "hash1".to_string(),
                line_hashes: vec!["linehash1".to_string()],
            },
        );
        let baseline = SecurityFilesSnapshot {
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
        let current = SecurityFilesSnapshot {
            files: current_files,
        };

        let changed = SecurityFilesMonitorModule::detect_and_report(&baseline, &current, &None);
        assert!(changed);
    }

    #[test]
    fn test_detect_line_removed() {
        let path = PathBuf::from("/tmp/test_security_line_removed");
        let mut baseline_files = HashMap::new();
        baseline_files.insert(
            path.clone(),
            FileSnapshot {
                file_hash: "hash1".to_string(),
                line_hashes: vec!["linehash1".to_string(), "linehash2".to_string()],
            },
        );
        let baseline = SecurityFilesSnapshot {
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
        let current = SecurityFilesSnapshot {
            files: current_files,
        };

        let changed = SecurityFilesMonitorModule::detect_and_report(&baseline, &current, &None);
        assert!(changed);
    }

    #[test]
    fn test_dangerous_pattern_unlimited_resource() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let file = tmpdir.path().join("limits.conf");
        std::fs::write(&file, "* hard nofile unlimited\n").unwrap();

        let mut reported = HashSet::new();
        SecurityFilesMonitorModule::check_dangerous_patterns(&[file.clone()], &mut reported, &None);
        assert_eq!(reported.len(), 1);
        assert!(reported.iter().next().unwrap().starts_with("unlimited:"));
    }

    #[test]
    fn test_dangerous_pattern_safe_limits() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let file = tmpdir.path().join("limits.conf");
        std::fs::write(&file, "* soft nofile 1024\n* hard nofile 4096\n").unwrap();

        let mut reported = HashSet::new();
        SecurityFilesMonitorModule::check_dangerous_patterns(&[file.clone()], &mut reported, &None);
        assert!(reported.is_empty());
    }

    #[test]
    fn test_dangerous_pattern_non_wildcard_unlimited() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let file = tmpdir.path().join("limits.conf");
        std::fs::write(&file, "root hard nofile unlimited\n").unwrap();

        let mut reported = HashSet::new();
        SecurityFilesMonitorModule::check_dangerous_patterns(&[file.clone()], &mut reported, &None);
        // root ユーザー限定なので検出しない
        assert!(reported.is_empty());
    }

    #[test]
    fn test_dangerous_pattern_limits_d_directory() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let limits_d = tmpdir.path().join("limits.d");
        std::fs::create_dir(&limits_d).unwrap();
        let file = limits_d.join("99-custom.conf");
        std::fs::write(&file, "* soft nproc unlimited\n").unwrap();

        let mut reported = HashSet::new();
        SecurityFilesMonitorModule::check_dangerous_patterns(&[limits_d], &mut reported, &None);
        assert_eq!(reported.len(), 1);
    }

    #[test]
    fn test_dangerous_pattern_non_limits_file_ignored() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let file = tmpdir.path().join("access.conf");
        std::fs::write(&file, "* hard nofile unlimited\n").unwrap();

        let mut reported = HashSet::new();
        SecurityFilesMonitorModule::check_dangerous_patterns(&[file.clone()], &mut reported, &None);
        // access.conf は limits 形式ではないので検出しない
        assert!(reported.is_empty());
    }

    #[test]
    fn test_dangerous_pattern_comments_ignored() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let file = tmpdir.path().join("limits.conf");
        std::fs::write(&file, "# * hard nofile unlimited\n").unwrap();

        let mut reported = HashSet::new();
        SecurityFilesMonitorModule::check_dangerous_patterns(&[file.clone()], &mut reported, &None);
        assert!(reported.is_empty());
    }

    #[test]
    fn test_dangerous_pattern_dedup() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let file = tmpdir.path().join("limits.conf");
        std::fs::write(&file, "* hard nofile unlimited\n").unwrap();

        let mut reported = HashSet::new();
        SecurityFilesMonitorModule::check_dangerous_patterns(&[file.clone()], &mut reported, &None);
        assert_eq!(reported.len(), 1);

        // 二回目は新規検出なし
        let before = reported.len();
        SecurityFilesMonitorModule::check_dangerous_patterns(&[file.clone()], &mut reported, &None);
        assert_eq!(reported.len(), before);
    }

    #[test]
    fn test_dangerous_pattern_multiple_unlimited() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let file = tmpdir.path().join("limits.conf");
        std::fs::write(
            &file,
            "* hard nofile unlimited\n* soft nproc unlimited\n* - memlock unlimited\n",
        )
        .unwrap();

        let mut reported = HashSet::new();
        SecurityFilesMonitorModule::check_dangerous_patterns(&[file.clone()], &mut reported, &None);
        assert_eq!(reported.len(), 3);
    }

    #[test]
    fn test_init_zero_interval() {
        let config = SecurityFilesMonitorConfig {
            enabled: true,
            scan_interval_secs: 0,
            watch_paths: vec![],
        };
        let mut module = SecurityFilesMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_init_valid() {
        let config = SecurityFilesMonitorConfig {
            enabled: true,
            scan_interval_secs: 120,
            watch_paths: vec![PathBuf::from("/etc/security/limits.conf")],
        };
        let mut module = SecurityFilesMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "* soft nofile 1024\n").unwrap();

        let config = SecurityFilesMonitorConfig {
            enabled: true,
            scan_interval_secs: 3600,
            watch_paths: vec![tmpfile.path().to_path_buf()],
        };
        let mut module = SecurityFilesMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[test]
    fn test_scan_files_mixed_file_and_dir() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let dir_file = tmpdir.path().join("limits.conf");
        std::fs::write(&dir_file, "* soft nofile 1024\n").unwrap();

        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "+ : ALL : LOCAL\n").unwrap();

        let watch_paths = vec![tmpfile.path().to_path_buf(), tmpdir.path().to_path_buf()];
        let result = SecurityFilesMonitorModule::scan_files(&watch_paths);
        assert_eq!(result.files.len(), 2);
    }

    #[test]
    fn test_detect_directory_file_added() {
        let tmpdir = tempfile::TempDir::new().unwrap();

        let watch_paths = vec![tmpdir.path().to_path_buf()];
        let baseline = SecurityFilesMonitorModule::scan_files(&watch_paths);
        assert!(baseline.files.is_empty());

        let new_file = tmpdir.path().join("new-limits.conf");
        std::fs::write(&new_file, "* soft nofile 2048\n").unwrap();

        let current = SecurityFilesMonitorModule::scan_files(&watch_paths);
        assert_eq!(current.files.len(), 1);

        let changed = SecurityFilesMonitorModule::detect_and_report(&baseline, &current, &None);
        assert!(changed);
    }

    #[test]
    fn test_collect_files_to_check_file() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "test\n").unwrap();
        let result = collect_files_to_check(&tmpfile.path().to_path_buf());
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_collect_files_to_check_dir() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        std::fs::write(tmpdir.path().join("a.conf"), "a\n").unwrap();
        std::fs::write(tmpdir.path().join("b.conf"), "b\n").unwrap();
        let result = collect_files_to_check(&tmpdir.path().to_path_buf());
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_collect_files_to_check_nonexistent() {
        let result = collect_files_to_check(&PathBuf::from("/tmp/nonexistent_zettai_test"));
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_initial_scan_no_issues() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let conf_path = tmpdir.path().join("access.conf");
        std::fs::write(&conf_path, "# access configuration\n+ : root : ALL\n").unwrap();

        let config = SecurityFilesMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            watch_paths: vec![tmpdir.path().to_path_buf()],
        };
        let module = SecurityFilesMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 1);
        assert_eq!(result.issues_found, 0);
        assert!(result.summary.contains("セキュリティ設定ファイル"));
    }

    #[tokio::test]
    async fn test_initial_scan_detects_unlimited() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let limits_path = tmpdir.path().join("limits.conf");
        std::fs::write(
            &limits_path,
            "* soft nofile unlimited\n* hard nproc unlimited\n",
        )
        .unwrap();

        let config = SecurityFilesMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            watch_paths: vec![tmpdir.path().to_path_buf()],
        };
        let module = SecurityFilesMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 1);
        assert_eq!(result.issues_found, 2);
        assert!(result.summary.contains("危険パターン: 2件"));
    }

    #[tokio::test]
    async fn test_initial_scan_empty_paths() {
        let config = SecurityFilesMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            watch_paths: vec![],
        };
        let module = SecurityFilesMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
    }
}
