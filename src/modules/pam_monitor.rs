//! PAM 設定監視モジュール
//!
//! /etc/pam.d/ 配下の PAM 設定ファイルを定期的にスキャンし、
//! SHA-256 ハッシュベースで変更を検知する。
//!
//! 検知対象:
//! - PAM 設定ファイルの追加・削除
//! - 設定行の追加・削除（行レベルの変更検知）
//! - 危険な PAM 設定パターン（pam_permit.so, pam_exec.so, 未知モジュール）

use crate::config::PamMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::core::module_stats::ModuleStatsHandle;
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;
use walkdir::WalkDir;

/// モジュール識別子（`ModuleStats` に登録する統計上のモジュール名）
pub(crate) const MODULE_STATS_NAME: &str = "PAM 設定監視モジュール";

/// PAM モジュールの標準インストールパス
const STANDARD_PAM_MODULE_PATHS: &[&str] = &[
    "/lib/security/",
    "/lib64/security/",
    "/usr/lib/security/",
    "/usr/lib64/security/",
    "/lib/x86_64-linux-gnu/security/",
    "/usr/lib/x86_64-linux-gnu/security/",
];

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

/// PAM 設定ファイル群のスナップショット
struct PamSnapshot {
    /// ファイルパスごとのスナップショット
    files: HashMap<PathBuf, FileSnapshot>,
}

/// 検出された危険パターンの識別子（ファイルパス + 行内容のハッシュ）
type DangerKey = String;

/// PAM 設定監視モジュール
///
/// PAM 設定ファイルを定期スキャンし、ベースラインとの差分および危険パターンを検知する。
pub struct PamMonitorModule {
    config: PamMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
    stats_handle: Option<ModuleStatsHandle>,
}

impl PamMonitorModule {
    /// 新しい PAM 設定監視モジュールを作成する
    pub fn new(config: PamMonitorConfig, event_bus: Option<EventBus>) -> Self {
        Self {
            config,
            cancel_token: CancellationToken::new(),
            event_bus,
            stats_handle: None,
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
    fn scan_files(watch_paths: &[PathBuf]) -> PamSnapshot {
        let mut files = HashMap::new();
        for path in watch_paths {
            if path.is_file() {
                match build_file_snapshot(path) {
                    Ok(snapshot) => {
                        files.insert(path.clone(), snapshot);
                    }
                    Err(e) => {
                        tracing::debug!(path = %path.display(), error = %e, "PAM 設定ファイルの読み取りに失敗しました。スキャンを継続します");
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
                                tracing::debug!(path = %entry.path().display(), error = %e, "PAM 設定ファイルの読み取りに失敗しました。スキャンを継続します");
                            }
                        }
                    }
                }
            } else {
                tracing::debug!(path = %path.display(), "PAM パスが存在しません。スキップします");
            }
        }
        PamSnapshot { files }
    }

    /// ベースラインと現在のスナップショットを比較し、変更を検知してイベントを発行する。
    /// 変更があった場合は `true` を返す。
    fn detect_and_report(
        baseline: &PamSnapshot,
        current: &PamSnapshot,
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
                    "PAM 設定ファイルが追加されました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "pam_file_added",
                            Severity::Critical,
                            "pam_monitor",
                            format!("PAM 設定ファイルが追加されました: {}", path.display()),
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
                    "PAM 設定ファイルが削除されました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "pam_file_removed",
                            Severity::Warning,
                            "pam_monitor",
                            format!("PAM 設定ファイルが削除されました: {}", path.display()),
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
                        "PAM 設定行が追加されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "pam_lines_added",
                                Severity::Warning,
                                "pam_monitor",
                                format!("PAM 設定行が追加されました: {}", path.display()),
                            )
                            .with_details(path.display().to_string()),
                        );
                    }
                }
                if removed_count > 0 {
                    tracing::warn!(
                        path = %path.display(),
                        removed_count,
                        "PAM 設定行が削除されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "pam_lines_removed",
                                Severity::Warning,
                                "pam_monitor",
                                format!("PAM 設定行が削除されました: {}", path.display()),
                            )
                            .with_details(path.display().to_string()),
                        );
                    }
                }

                tracing::warn!(
                    path = %path.display(),
                    before = baseline_snapshot.line_count(),
                    after = current_snapshot.line_count(),
                    "PAM 設定行数が変化しました"
                );
            }
        }

        has_changes
    }

    /// PAM 設定ファイルの内容を解析し、危険パターンを検出してイベントを発行する。
    /// 報告済みパターンの集合を更新し、新規検出分のみ報告する。
    fn check_dangerous_patterns(
        watch_paths: &[PathBuf],
        reported_dangers: &mut HashSet<DangerKey>,
        event_bus: &Option<EventBus>,
    ) {
        for path in watch_paths {
            let files_to_check = if path.is_file() {
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
                continue;
            };

            for file_path in &files_to_check {
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
                    if parts.len() < 3 {
                        continue;
                    }

                    let pam_type = parts[0];
                    // parts[1] is control
                    let module_path = parts[2];

                    // パターン 1: pam_permit.so の不正追加
                    if module_path.contains("pam_permit.so") {
                        let danger_key = format!("permit:{}:{}", file_path.display(), trimmed);
                        if !reported_dangers.contains(&danger_key) {
                            reported_dangers.insert(danger_key);
                            let severity = if pam_type == "auth" {
                                Severity::Critical
                            } else {
                                Severity::Warning
                            };
                            let msg = if pam_type == "auth" {
                                format!(
                                    "pam_permit.so が auth 行で検出されました（パスワードなし認証）: {}",
                                    file_path.display()
                                )
                            } else {
                                format!(
                                    "pam_permit.so が {} 行で検出されました: {}",
                                    pam_type,
                                    file_path.display()
                                )
                            };
                            tracing::warn!(
                                path = %file_path.display(),
                                pam_type,
                                "pam_permit.so が検出されました"
                            );
                            if let Some(bus) = event_bus {
                                bus.publish(
                                    SecurityEvent::new(
                                        "pam_dangerous_permit",
                                        severity,
                                        "pam_monitor",
                                        msg,
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

                    // パターン 2: pam_exec.so による不審なスクリプト実行
                    if module_path.contains("pam_exec.so") {
                        let danger_key = format!("exec:{}:{}", file_path.display(), trimmed);
                        if !reported_dangers.contains(&danger_key) {
                            reported_dangers.insert(danger_key);
                            let script_args = if parts.len() > 3 {
                                parts[3..].join(" ")
                            } else {
                                "(引数なし)".to_string()
                            };
                            tracing::warn!(
                                path = %file_path.display(),
                                script = %script_args,
                                "pam_exec.so が検出されました"
                            );
                            if let Some(bus) = event_bus {
                                bus.publish(
                                    SecurityEvent::new(
                                        "pam_dangerous_exec",
                                        Severity::Critical,
                                        "pam_monitor",
                                        format!(
                                            "pam_exec.so が検出されました: {} (実行対象: {})",
                                            file_path.display(),
                                            script_args
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

                    // パターン 3: 未知の PAM モジュール（標準パス外の絶対パス指定）
                    if module_path.contains('/') {
                        let is_standard = STANDARD_PAM_MODULE_PATHS
                            .iter()
                            .any(|std_path| module_path.starts_with(std_path));
                        if !is_standard {
                            let danger_key = format!("unknown:{}:{}", file_path.display(), trimmed);
                            if !reported_dangers.contains(&danger_key) {
                                reported_dangers.insert(danger_key);
                                tracing::warn!(
                                    path = %file_path.display(),
                                    module_path,
                                    "標準パス外の PAM モジュールが検出されました"
                                );
                                if let Some(bus) = event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            "pam_unknown_module",
                                            Severity::Warning,
                                            "pam_monitor",
                                            format!(
                                                "標準パス外の PAM モジュールが検出されました: {} (モジュール: {})",
                                                file_path.display(),
                                                module_path
                                            ),
                                        )
                                        .with_details(format!(
                                            "file={}, module={}",
                                            file_path.display(),
                                            module_path
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

impl Module for PamMonitorModule {
    fn name(&self) -> &str {
        "pam_monitor"
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
                    "監視対象の PAM パスが存在しません"
                );
            }
        }

        tracing::info!(
            watch_paths = ?self.config.watch_paths,
            scan_interval_secs = self.config.scan_interval_secs,
            "PAM 設定監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        let baseline = Self::scan_files(&self.config.watch_paths);
        let total_lines: usize = baseline.files.values().map(|s| s.line_count()).sum();
        tracing::info!(
            file_count = baseline.files.len(),
            total_lines,
            "PAM ベースラインスキャンが完了しました"
        );

        let watch_paths = self.config.watch_paths.clone();
        let scan_interval_secs = self.config.scan_interval_secs;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();
        let stats_handle = self.stats_handle.clone();

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
                        tracing::info!("PAM 設定監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let scan_start = std::time::Instant::now();
                        let current = PamMonitorModule::scan_files(&watch_paths);
                        let changed = PamMonitorModule::detect_and_report(&baseline, &current, &event_bus);

                        if changed {
                            // 変更があった場合、危険パターンの報告済みセットをクリアして再チェック
                            reported_dangers.clear();
                            PamMonitorModule::check_dangerous_patterns(&watch_paths, &mut reported_dangers, &event_bus);
                            baseline = current;
                        } else {
                            tracing::debug!("PAM 設定ファイルの変更はありません");
                            // 変更がなくても危険パターンチェックは実行（初回以降の新規検出用）
                            PamMonitorModule::check_dangerous_patterns(&watch_paths, &mut reported_dangers, &event_bus);
                        }

                        let scan_elapsed = scan_start.elapsed();
                        if let Some(ref handle) = stats_handle {
                            handle.record_scan_duration(MODULE_STATS_NAME, scan_elapsed);
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

    fn set_module_stats(&mut self, handle: ModuleStatsHandle) {
        self.stats_handle = Some(handle);
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
            let files_to_check = if path.is_file() {
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
                continue;
            };

            for file_path in &files_to_check {
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
                    if parts.len() < 3 {
                        continue;
                    }

                    let module_path = parts[2];

                    if module_path.contains("pam_permit.so") {
                        issues_found += 1;
                    }
                    if module_path.contains("pam_exec.so") {
                        issues_found += 1;
                    }
                    if module_path.contains('/') {
                        let is_standard = STANDARD_PAM_MODULE_PATHS
                            .iter()
                            .any(|std_path| module_path.starts_with(std_path));
                        if !is_standard {
                            issues_found += 1;
                        }
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
                "PAM 設定ファイル {}件をスキャンしました（危険パターン: {}件）",
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
        write!(
            tmpfile,
            "auth required pam_unix.so\nsession optional pam_loginuid.so\n"
        )
        .unwrap();
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
            "# PAM configuration\n\nauth required pam_unix.so\n\n# End\n"
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
        let result = build_file_snapshot(&PathBuf::from("/tmp/nonexistent-zettai-pam-test"));
        assert!(result.is_err());
    }

    #[test]
    fn test_build_file_snapshot_deterministic() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "auth required pam_unix.so\n").unwrap();
        let snapshot1 = build_file_snapshot(&tmpfile.path().to_path_buf()).unwrap();
        let snapshot2 = build_file_snapshot(&tmpfile.path().to_path_buf()).unwrap();
        assert_eq!(snapshot1.file_hash, snapshot2.file_hash);
        assert_eq!(snapshot1.line_hashes, snapshot2.line_hashes);
    }

    #[test]
    fn test_scan_files_with_single_file() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "auth required pam_unix.so\n").unwrap();
        let path = tmpfile.path().to_path_buf();

        let watch_paths = vec![path.clone()];
        let result = PamMonitorModule::scan_files(&watch_paths);
        assert_eq!(result.files.len(), 1);
        assert!(result.files.contains_key(&path));
    }

    #[test]
    fn test_scan_files_with_directory() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let file1 = tmpdir.path().join("sshd");
        let file2 = tmpdir.path().join("login");
        std::fs::write(&file1, "auth required pam_unix.so\n").unwrap();
        std::fs::write(&file2, "auth required pam_securetty.so\n").unwrap();

        let watch_paths = vec![tmpdir.path().to_path_buf()];
        let result = PamMonitorModule::scan_files(&watch_paths);
        assert_eq!(result.files.len(), 2);
        assert!(result.files.contains_key(&file1));
        assert!(result.files.contains_key(&file2));
    }

    #[test]
    fn test_scan_files_empty() {
        let watch_paths: Vec<PathBuf> = vec![];
        let result = PamMonitorModule::scan_files(&watch_paths);
        assert!(result.files.is_empty());
    }

    #[test]
    fn test_scan_files_nonexistent_skipped() {
        let watch_paths = vec![PathBuf::from("/tmp/nonexistent_zettai_pam_test")];
        let result = PamMonitorModule::scan_files(&watch_paths);
        assert!(result.files.is_empty());
    }

    #[test]
    fn test_detect_no_changes() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "auth required pam_unix.so\n").unwrap();
        let path = tmpfile.path().to_path_buf();

        let watch_paths = vec![path];
        let snapshot1 = PamMonitorModule::scan_files(&watch_paths);
        let snapshot2 = PamMonitorModule::scan_files(&watch_paths);
        let changed = PamMonitorModule::detect_and_report(&snapshot1, &snapshot2, &None);
        assert!(!changed);
    }

    #[test]
    fn test_detect_file_added() {
        let baseline = PamSnapshot {
            files: HashMap::new(),
        };
        let mut current_files = HashMap::new();
        current_files.insert(
            PathBuf::from("/tmp/test_pam_added"),
            FileSnapshot {
                file_hash: "hash1".to_string(),
                line_hashes: vec!["linehash1".to_string()],
            },
        );
        let current = PamSnapshot {
            files: current_files,
        };
        let changed = PamMonitorModule::detect_and_report(&baseline, &current, &None);
        assert!(changed);
    }

    #[test]
    fn test_detect_file_removed() {
        let mut baseline_files = HashMap::new();
        baseline_files.insert(
            PathBuf::from("/tmp/test_pam_removed"),
            FileSnapshot {
                file_hash: "hash1".to_string(),
                line_hashes: vec!["linehash1".to_string()],
            },
        );
        let baseline = PamSnapshot {
            files: baseline_files,
        };
        let current = PamSnapshot {
            files: HashMap::new(),
        };
        let changed = PamMonitorModule::detect_and_report(&baseline, &current, &None);
        assert!(changed);
    }

    #[test]
    fn test_detect_line_added() {
        let path = PathBuf::from("/tmp/test_pam_line_change");
        let mut baseline_files = HashMap::new();
        baseline_files.insert(
            path.clone(),
            FileSnapshot {
                file_hash: "hash1".to_string(),
                line_hashes: vec!["linehash1".to_string()],
            },
        );
        let baseline = PamSnapshot {
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
        let current = PamSnapshot {
            files: current_files,
        };

        let changed = PamMonitorModule::detect_and_report(&baseline, &current, &None);
        assert!(changed);
    }

    #[test]
    fn test_detect_line_removed() {
        let path = PathBuf::from("/tmp/test_pam_line_removed");
        let mut baseline_files = HashMap::new();
        baseline_files.insert(
            path.clone(),
            FileSnapshot {
                file_hash: "hash1".to_string(),
                line_hashes: vec!["linehash1".to_string(), "linehash2".to_string()],
            },
        );
        let baseline = PamSnapshot {
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
        let current = PamSnapshot {
            files: current_files,
        };

        let changed = PamMonitorModule::detect_and_report(&baseline, &current, &None);
        assert!(changed);
    }

    #[test]
    fn test_dangerous_pattern_pam_permit_auth() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let file = tmpdir.path().join("test-pam");
        std::fs::write(&file, "auth sufficient pam_permit.so\n").unwrap();

        let mut reported = HashSet::new();
        PamMonitorModule::check_dangerous_patterns(
            &[tmpdir.path().to_path_buf()],
            &mut reported,
            &None,
        );
        assert_eq!(reported.len(), 1);
        assert!(reported.iter().next().unwrap().starts_with("permit:"));
    }

    #[test]
    fn test_dangerous_pattern_pam_exec() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let file = tmpdir.path().join("test-pam");
        std::fs::write(&file, "session optional pam_exec.so /tmp/evil.sh\n").unwrap();

        let mut reported = HashSet::new();
        PamMonitorModule::check_dangerous_patterns(
            &[tmpdir.path().to_path_buf()],
            &mut reported,
            &None,
        );
        assert_eq!(reported.len(), 1);
        assert!(reported.iter().next().unwrap().starts_with("exec:"));
    }

    #[test]
    fn test_dangerous_pattern_unknown_module() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let file = tmpdir.path().join("test-pam");
        std::fs::write(&file, "auth required /opt/custom/pam_backdoor.so\n").unwrap();

        let mut reported = HashSet::new();
        PamMonitorModule::check_dangerous_patterns(
            &[tmpdir.path().to_path_buf()],
            &mut reported,
            &None,
        );
        assert_eq!(reported.len(), 1);
        assert!(reported.iter().next().unwrap().starts_with("unknown:"));
    }

    #[test]
    fn test_dangerous_pattern_standard_module_not_flagged() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let file = tmpdir.path().join("test-pam");
        std::fs::write(&file, "auth required /lib/security/pam_unix.so\n").unwrap();

        let mut reported = HashSet::new();
        PamMonitorModule::check_dangerous_patterns(
            &[tmpdir.path().to_path_buf()],
            &mut reported,
            &None,
        );
        assert!(reported.is_empty());
    }

    #[test]
    fn test_dangerous_pattern_dedup() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let file = tmpdir.path().join("test-pam");
        std::fs::write(&file, "auth sufficient pam_permit.so\n").unwrap();

        let mut reported = HashSet::new();
        PamMonitorModule::check_dangerous_patterns(
            &[tmpdir.path().to_path_buf()],
            &mut reported,
            &None,
        );
        assert_eq!(reported.len(), 1);

        // 二回目は新規検出なし
        let before = reported.len();
        PamMonitorModule::check_dangerous_patterns(
            &[tmpdir.path().to_path_buf()],
            &mut reported,
            &None,
        );
        assert_eq!(reported.len(), before);
    }

    #[test]
    fn test_dangerous_pattern_multiple() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let file = tmpdir.path().join("test-pam");
        std::fs::write(
            &file,
            "auth sufficient pam_permit.so\nsession optional pam_exec.so /tmp/hook.sh\nauth required /opt/evil/pam_bad.so\n",
        )
        .unwrap();

        let mut reported = HashSet::new();
        PamMonitorModule::check_dangerous_patterns(
            &[tmpdir.path().to_path_buf()],
            &mut reported,
            &None,
        );
        assert_eq!(reported.len(), 3);
    }

    #[test]
    fn test_dangerous_pattern_safe_config() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let file = tmpdir.path().join("test-pam");
        std::fs::write(
            &file,
            "# PAM config\nauth required pam_unix.so\naccount required pam_unix.so\nsession required pam_loginuid.so\n",
        )
        .unwrap();

        let mut reported = HashSet::new();
        PamMonitorModule::check_dangerous_patterns(
            &[tmpdir.path().to_path_buf()],
            &mut reported,
            &None,
        );
        assert!(reported.is_empty());
    }

    #[test]
    fn test_init_zero_interval() {
        let config = PamMonitorConfig {
            enabled: true,
            scan_interval_secs: 0,
            watch_paths: vec![],
        };
        let mut module = PamMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_init_valid() {
        let config = PamMonitorConfig {
            enabled: true,
            scan_interval_secs: 120,
            watch_paths: vec![PathBuf::from("/etc/pam.d")],
        };
        let mut module = PamMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "auth required pam_unix.so\n").unwrap();

        let config = PamMonitorConfig {
            enabled: true,
            scan_interval_secs: 3600,
            watch_paths: vec![tmpfile.path().to_path_buf()],
        };
        let mut module = PamMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[test]
    fn test_scan_files_mixed_file_and_dir() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let dir_file = tmpdir.path().join("custom-pam");
        std::fs::write(&dir_file, "auth required pam_unix.so\n").unwrap();

        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "session required pam_loginuid.so\n").unwrap();

        let watch_paths = vec![tmpfile.path().to_path_buf(), tmpdir.path().to_path_buf()];
        let result = PamMonitorModule::scan_files(&watch_paths);
        assert_eq!(result.files.len(), 2);
    }

    #[test]
    fn test_detect_directory_file_added() {
        let tmpdir = tempfile::TempDir::new().unwrap();

        // ベースライン: ディレクトリは空
        let watch_paths = vec![tmpdir.path().to_path_buf()];
        let baseline = PamMonitorModule::scan_files(&watch_paths);
        assert!(baseline.files.is_empty());

        // ファイルを追加
        let new_file = tmpdir.path().join("new-pam-entry");
        std::fs::write(&new_file, "auth sufficient pam_permit.so\n").unwrap();

        let current = PamMonitorModule::scan_files(&watch_paths);
        assert_eq!(current.files.len(), 1);

        let changed = PamMonitorModule::detect_and_report(&baseline, &current, &None);
        assert!(changed);
    }

    #[test]
    fn test_dangerous_pattern_pam_permit_non_auth() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let file = tmpdir.path().join("test-pam");
        std::fs::write(&file, "account sufficient pam_permit.so\n").unwrap();

        let mut reported = HashSet::new();
        PamMonitorModule::check_dangerous_patterns(
            &[tmpdir.path().to_path_buf()],
            &mut reported,
            &None,
        );
        // account 行でも検出されるが、Severity は Warning（テストでは報告されることを確認）
        assert_eq!(reported.len(), 1);
    }

    #[test]
    fn test_dangerous_pattern_comments_ignored() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let file = tmpdir.path().join("test-pam");
        std::fs::write(&file, "# auth sufficient pam_permit.so\n").unwrap();

        let mut reported = HashSet::new();
        PamMonitorModule::check_dangerous_patterns(
            &[tmpdir.path().to_path_buf()],
            &mut reported,
            &None,
        );
        assert!(reported.is_empty());
    }

    #[test]
    fn test_dangerous_pattern_standard_paths_not_flagged() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let file = tmpdir.path().join("test-pam");
        std::fs::write(
            &file,
            "auth required /lib/security/pam_unix.so\nauth required /lib64/security/pam_unix.so\nauth required /usr/lib/x86_64-linux-gnu/security/pam_unix.so\n",
        )
        .unwrap();

        let mut reported = HashSet::new();
        PamMonitorModule::check_dangerous_patterns(
            &[tmpdir.path().to_path_buf()],
            &mut reported,
            &None,
        );
        assert!(reported.is_empty());
    }

    #[tokio::test]
    async fn test_initial_scan_no_issues() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let pam_file = tmpdir.path().join("common-auth");
        std::fs::write(&pam_file, "# PAM config\nauth required pam_unix.so\n").unwrap();

        let config = PamMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            watch_paths: vec![tmpdir.path().to_path_buf()],
        };
        let module = PamMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 1);
        assert_eq!(result.issues_found, 0);
        assert!(result.summary.contains("PAM 設定ファイル"));
    }

    #[tokio::test]
    async fn test_initial_scan_detects_dangerous_patterns() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let pam_file = tmpdir.path().join("backdoor");
        std::fs::write(
            &pam_file,
            "auth sufficient pam_permit.so\nsession required pam_exec.so /tmp/evil.sh\n",
        )
        .unwrap();

        let config = PamMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            watch_paths: vec![tmpdir.path().to_path_buf()],
        };
        let module = PamMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 1);
        assert!(result.issues_found >= 2);
        assert!(result.summary.contains("危険パターン"));
    }

    #[tokio::test]
    async fn test_initial_scan_empty_paths() {
        let config = PamMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            watch_paths: vec![],
        };
        let module = PamMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
    }

    #[test]
    fn test_set_module_stats_stores_handle() {
        let config = PamMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            watch_paths: vec![],
        };
        let mut module = PamMonitorModule::new(config, None);
        assert!(module.stats_handle.is_none());
        module.set_module_stats(ModuleStatsHandle::new());
        assert!(module.stats_handle.is_some());
    }

    #[tokio::test]
    async fn test_periodic_scan_records_scan_duration() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let file = tmpdir.path().join("sshd");
        std::fs::write(&file, "auth required pam_unix.so\n").unwrap();

        let config = PamMonitorConfig {
            enabled: true,
            scan_interval_secs: 1,
            watch_paths: vec![tmpdir.path().to_path_buf()],
        };
        let mut module = PamMonitorModule::new(config, None);
        module.init().unwrap();

        let stats = ModuleStatsHandle::new();
        module.set_module_stats(stats.clone());

        let handle = module.start().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
        module.stop().await.unwrap();
        let _ = handle.await;

        let s = stats.get(MODULE_STATS_NAME).expect("stats must exist");
        assert!(
            s.scan_count >= 1,
            "scan_count={} expected >= 1",
            s.scan_count
        );
    }
}
