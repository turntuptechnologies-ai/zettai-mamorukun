//! cgroup v2 リソース制限監視モジュール
//!
//! `/sys/fs/cgroup/` 配下を定期スキャンし、リソース制限の変更を検知する。
//!
//! 検知対象:
//! - リソース制限の緩和（値が増加 or "max" に変更）（Critical）
//! - リソース制限の厳格化（値が減少）（Info）
//! - 新規 cgroup の出現（Info）
//! - cgroup の消失（Warning）

use crate::config::CgroupMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::BTreeMap;
use std::path::Path;
use tokio_util::sync::CancellationToken;

/// cgroup スナップショット（cgroup パス → (ファイル名 → 値)）
type CgroupSnapshot = BTreeMap<String, BTreeMap<String, String>>;

/// cgroup パスを再帰的にスキャンし、スナップショットを作成する
///
/// `max_depth` で再帰の深さを制限し、シンボリックリンクは追従しない。
fn scan_cgroups(cgroup_path: &Path, watch_files: &[String], max_depth: usize) -> CgroupSnapshot {
    let mut snapshot = CgroupSnapshot::new();
    scan_dir_recursive(
        cgroup_path,
        cgroup_path,
        watch_files,
        max_depth,
        0,
        &mut snapshot,
    );
    snapshot
}

/// ディレクトリを再帰的にスキャンする内部関数
fn scan_dir_recursive(
    base_path: &Path,
    current_path: &Path,
    watch_files: &[String],
    max_depth: usize,
    current_depth: usize,
    snapshot: &mut CgroupSnapshot,
) {
    // 監視対象ファイルを読み取る
    let mut files = BTreeMap::new();
    for file_name in watch_files {
        let file_path = current_path.join(file_name);
        if let Ok(content) = std::fs::read_to_string(&file_path) {
            files.insert(file_name.clone(), content.trim().to_string());
        }
    }

    if !files.is_empty() {
        let relative = current_path.strip_prefix(base_path).unwrap_or(current_path);
        let key = relative.to_string_lossy().to_string();
        snapshot.insert(key, files);
    }

    // 深さ制限チェック
    if current_depth >= max_depth {
        return;
    }

    // サブディレクトリを再帰的にスキャン
    let entries = match std::fs::read_dir(current_path) {
        Ok(entries) => entries,
        Err(e) => {
            tracing::debug!(
                path = %current_path.display(),
                error = %e,
                "ディレクトリの読み取りに失敗しました"
            );
            return;
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        // symlink_metadata でシンボリックリンクを追従しない
        let metadata = match entry.path().symlink_metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };

        if metadata.is_dir() {
            scan_dir_recursive(
                base_path,
                &entry.path(),
                watch_files,
                max_depth,
                current_depth + 1,
                snapshot,
            );
        }
    }
}

/// cgroup の値を数値に変換する
///
/// "max" は `u64::MAX` として扱う。
/// `cpu.max` は "quota period" 形式なので quota 部分のみ返す。
fn parse_cgroup_value(file_name: &str, value: &str) -> Option<u64> {
    let effective_value = if file_name == "cpu.max" {
        // "quota period" 形式: quota 部分のみ比較
        value.split_whitespace().next().unwrap_or(value)
    } else {
        value
    };

    if effective_value == "max" {
        return Some(u64::MAX);
    }

    effective_value.parse::<u64>().ok()
}

/// ベースラインと現在のスナップショットを比較し、変更を検知してイベント発行する
fn detect_and_report(
    baseline: &CgroupSnapshot,
    current: &CgroupSnapshot,
    event_bus: &Option<EventBus>,
) -> bool {
    let mut has_changes = false;

    // 新規 cgroup の検知
    for (cgroup_path, current_files) in current {
        if !baseline.contains_key(cgroup_path) {
            let file_list: Vec<&str> = current_files.keys().map(|s| s.as_str()).collect();
            let details = format!(
                "cgroup={}, ファイル=[{}]",
                cgroup_path,
                file_list.join(", ")
            );
            tracing::info!(
                cgroup = %cgroup_path,
                "新規 cgroup を検知しました"
            );
            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        "cgroup_new",
                        Severity::Info,
                        "cgroup_monitor",
                        "新規 cgroup を検知しました",
                    )
                    .with_details(details),
                );
            }
            has_changes = true;
            continue;
        }

        // 既存 cgroup のファイル値比較
        if let Some(baseline_files) = baseline.get(cgroup_path) {
            for (file_name, current_value) in current_files {
                let baseline_value = match baseline_files.get(file_name) {
                    Some(v) => v,
                    None => continue,
                };

                if baseline_value == current_value {
                    continue;
                }

                let current_num = parse_cgroup_value(file_name, current_value);
                let baseline_num = parse_cgroup_value(file_name, baseline_value);

                let (severity, event_type, message) = match (baseline_num, current_num) {
                    (Some(old), Some(new)) if new > old => (
                        Severity::Critical,
                        "cgroup_limit_relaxed",
                        "cgroup リソース制限が緩和されました",
                    ),
                    (Some(old), Some(new)) if new < old => (
                        Severity::Info,
                        "cgroup_limit_tightened",
                        "cgroup リソース制限が厳格化されました",
                    ),
                    _ => {
                        // 数値比較できない場合は文字列比較でフォールバック
                        if current_value > baseline_value {
                            (
                                Severity::Critical,
                                "cgroup_limit_relaxed",
                                "cgroup リソース制限が緩和されました",
                            )
                        } else {
                            (
                                Severity::Info,
                                "cgroup_limit_tightened",
                                "cgroup リソース制限が厳格化されました",
                            )
                        }
                    }
                };

                let details = format!(
                    "cgroup={}, ファイル={}, 旧値={}, 新値={}",
                    cgroup_path, file_name, baseline_value, current_value
                );

                match severity {
                    Severity::Critical => tracing::warn!(
                        cgroup = %cgroup_path,
                        file = %file_name,
                        old_value = %baseline_value,
                        new_value = %current_value,
                        "cgroup リソース制限が緩和されました"
                    ),
                    _ => tracing::info!(
                        cgroup = %cgroup_path,
                        file = %file_name,
                        old_value = %baseline_value,
                        new_value = %current_value,
                        "cgroup リソース制限が厳格化されました"
                    ),
                }

                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(event_type, severity, "cgroup_monitor", message)
                            .with_details(details),
                    );
                }
                has_changes = true;
            }
        }
    }

    // cgroup の消失検知
    for cgroup_path in baseline.keys() {
        if !current.contains_key(cgroup_path) {
            let details = format!("cgroup={}", cgroup_path);
            tracing::warn!(
                cgroup = %cgroup_path,
                "cgroup が消失しました"
            );
            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        "cgroup_removed",
                        Severity::Warning,
                        "cgroup_monitor",
                        "cgroup が消失しました",
                    )
                    .with_details(details),
                );
            }
            has_changes = true;
        }
    }

    has_changes
}

/// cgroup v2 リソース制限監視モジュール
///
/// `/sys/fs/cgroup/` 配下を定期スキャンし、
/// リソース制限の変更を検知する。
pub struct CgroupMonitorModule {
    config: CgroupMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl CgroupMonitorModule {
    /// 新しい cgroup 監視モジュールを作成する
    pub fn new(config: CgroupMonitorConfig, event_bus: Option<EventBus>) -> Self {
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
}

impl Module for CgroupMonitorModule {
    fn name(&self) -> &str {
        "cgroup_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        if self.config.cgroup_path.contains("..") {
            return Err(AppError::ModuleConfig {
                message: format!(
                    "cgroup_path に '..' を含めることはできません: {}",
                    self.config.cgroup_path
                ),
            });
        }

        for file_name in &self.config.watch_files {
            if file_name.contains("..") {
                return Err(AppError::ModuleConfig {
                    message: format!(
                        "watch_files に '..' を含めることはできません: {}",
                        file_name
                    ),
                });
            }
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            cgroup_path = %self.config.cgroup_path,
            max_depth = self.config.max_depth,
            watch_files_count = self.config.watch_files.len(),
            "cgroup 監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<(), AppError> {
        let cgroup_path = self.config.cgroup_path.clone();
        let watch_files = self.config.watch_files.clone();
        let max_depth = self.config.max_depth;
        let scan_interval_secs = self.config.scan_interval_secs;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        let baseline = scan_cgroups(Path::new(&cgroup_path), &watch_files, max_depth);
        tracing::info!(
            cgroup_count = baseline.len(),
            "cgroup ベースラインスキャンが完了しました"
        );

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            interval.tick().await;

            let mut baseline = baseline;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("cgroup 監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = scan_cgroups(
                            Path::new(&cgroup_path),
                            &watch_files,
                            max_depth,
                        );
                        let changed = detect_and_report(
                            &baseline, &current, &event_bus,
                        );

                        if changed {
                            baseline = current;
                        } else {
                            tracing::debug!("cgroup に変更はありません");
                        }
                    }
                }
            }
        });

        Ok(())
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();
        let cgroup_path = Path::new(&self.config.cgroup_path);
        let snapshot = scan_cgroups(cgroup_path, &self.config.watch_files, self.config.max_depth);

        let mut items_scanned = 0;
        let mut scan_snapshot: BTreeMap<String, String> = BTreeMap::new();

        for (cgroup, files) in &snapshot {
            for (file_name, value) in files {
                items_scanned += 1;
                let key = if cgroup.is_empty() {
                    format!("cgroup:/{}", file_name)
                } else {
                    format!("cgroup:{}/{}", cgroup, file_name)
                };
                scan_snapshot.insert(key.clone(), value.clone());

                tracing::info!(
                    cgroup = %cgroup,
                    file = %file_name,
                    value = %value,
                    "起動時スキャン: cgroup リソース制限を検出"
                );
            }
        }

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found: 0,
            duration,
            summary: format!("cgroup {}件のリソース制限をスキャン", items_scanned),
            snapshot: scan_snapshot,
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
    use tempfile::TempDir;

    fn create_cgroup_files(dir: &TempDir, files: &[(&str, &str)]) {
        for (path, value) in files {
            let full_path = dir.path().join(path);
            if let Some(parent) = full_path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(full_path, value).unwrap();
        }
    }

    fn default_config_with_path(cgroup_path: &str) -> CgroupMonitorConfig {
        CgroupMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            cgroup_path: cgroup_path.to_string(),
            max_depth: 5,
            watch_files: vec![
                "memory.max".to_string(),
                "memory.high".to_string(),
                "cpu.max".to_string(),
                "pids.max".to_string(),
                "io.max".to_string(),
            ],
        }
    }

    #[test]
    fn test_init_valid() {
        let dir = TempDir::new().unwrap();
        let config = default_config_with_path(dir.path().to_str().unwrap());
        let mut module = CgroupMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[test]
    fn test_init_zero_interval() {
        let mut config = default_config_with_path("/sys/fs/cgroup");
        config.scan_interval_secs = 0;
        let mut module = CgroupMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_path_traversal_rejected() {
        let config = CgroupMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            cgroup_path: "/sys/fs/cgroup/../../../etc".to_string(),
            max_depth: 5,
            watch_files: vec!["memory.max".to_string()],
        };
        let mut module = CgroupMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains(".."));
    }

    #[test]
    fn test_init_watch_files_traversal_rejected() {
        let config = CgroupMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            cgroup_path: "/sys/fs/cgroup".to_string(),
            max_depth: 5,
            watch_files: vec!["../etc/passwd".to_string()],
        };
        let mut module = CgroupMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains(".."));
    }

    #[test]
    fn test_scan_cgroups_empty_dir() {
        let dir = TempDir::new().unwrap();
        let watch_files = vec!["memory.max".to_string()];
        let snapshot = scan_cgroups(dir.path(), &watch_files, 5);
        assert!(snapshot.is_empty());
    }

    #[test]
    fn test_scan_cgroups_with_files() {
        let dir = TempDir::new().unwrap();
        create_cgroup_files(
            &dir,
            &[
                ("memory.max", "max"),
                ("cpu.max", "100000 100000"),
                ("sub/memory.max", "1073741824"),
            ],
        );

        let watch_files = vec!["memory.max".to_string(), "cpu.max".to_string()];
        let snapshot = scan_cgroups(dir.path(), &watch_files, 5);

        // ルートディレクトリのファイル
        assert!(snapshot.contains_key(""));
        let root_files = snapshot.get("").unwrap();
        assert_eq!(root_files.get("memory.max").unwrap(), "max");
        assert_eq!(root_files.get("cpu.max").unwrap(), "100000 100000");

        // サブディレクトリのファイル
        assert!(snapshot.contains_key("sub"));
        let sub_files = snapshot.get("sub").unwrap();
        assert_eq!(sub_files.get("memory.max").unwrap(), "1073741824");
    }

    #[test]
    fn test_scan_cgroups_max_depth() {
        let dir = TempDir::new().unwrap();
        create_cgroup_files(
            &dir,
            &[
                ("memory.max", "max"),
                ("a/memory.max", "100"),
                ("a/b/memory.max", "200"),
                ("a/b/c/memory.max", "300"),
            ],
        );

        let watch_files = vec!["memory.max".to_string()];

        // max_depth=1 ではルート + 1 階層のみ
        let snapshot = scan_cgroups(dir.path(), &watch_files, 1);
        assert!(snapshot.contains_key(""));
        assert!(snapshot.contains_key("a"));
        // a/b は深さ 2 なのでスキャンされない
        assert!(!snapshot.contains_key("a/b"));
        assert!(!snapshot.contains_key("a/b/c"));
    }

    #[test]
    fn test_scan_cgroups_symlink_not_followed() {
        let dir = TempDir::new().unwrap();
        create_cgroup_files(&dir, &[("real/memory.max", "100")]);

        // シンボリックリンクを作成
        let link_path = dir.path().join("link");
        std::os::unix::fs::symlink(dir.path().join("real"), &link_path).unwrap();

        let watch_files = vec!["memory.max".to_string()];
        let snapshot = scan_cgroups(dir.path(), &watch_files, 5);

        // real ディレクトリはスキャンされる
        assert!(snapshot.contains_key("real"));
        // シンボリックリンクは追従されない
        assert!(!snapshot.contains_key("link"));
    }

    #[test]
    fn test_detect_no_changes() {
        let mut files = BTreeMap::new();
        files.insert("memory.max".to_string(), "max".to_string());
        let snapshot: CgroupSnapshot = BTreeMap::from([("".to_string(), files)]);

        assert!(!detect_and_report(&snapshot, &snapshot, &None));
    }

    #[test]
    fn test_detect_limit_relaxed() {
        let mut baseline_files = BTreeMap::new();
        baseline_files.insert("memory.max".to_string(), "1073741824".to_string());
        let baseline: CgroupSnapshot = BTreeMap::from([("test".to_string(), baseline_files)]);

        let mut current_files = BTreeMap::new();
        current_files.insert("memory.max".to_string(), "max".to_string());
        let current: CgroupSnapshot = BTreeMap::from([("test".to_string(), current_files)]);

        assert!(detect_and_report(&baseline, &current, &None));
    }

    #[test]
    fn test_detect_limit_tightened() {
        let mut baseline_files = BTreeMap::new();
        baseline_files.insert("memory.max".to_string(), "max".to_string());
        let baseline: CgroupSnapshot = BTreeMap::from([("test".to_string(), baseline_files)]);

        let mut current_files = BTreeMap::new();
        current_files.insert("memory.max".to_string(), "1073741824".to_string());
        let current: CgroupSnapshot = BTreeMap::from([("test".to_string(), current_files)]);

        assert!(detect_and_report(&baseline, &current, &None));
    }

    #[test]
    fn test_detect_new_cgroup() {
        let baseline: CgroupSnapshot = BTreeMap::new();

        let mut current_files = BTreeMap::new();
        current_files.insert("memory.max".to_string(), "max".to_string());
        let current: CgroupSnapshot = BTreeMap::from([("new_cgroup".to_string(), current_files)]);

        assert!(detect_and_report(&baseline, &current, &None));
    }

    #[test]
    fn test_detect_removed_cgroup() {
        let mut baseline_files = BTreeMap::new();
        baseline_files.insert("memory.max".to_string(), "max".to_string());
        let baseline: CgroupSnapshot =
            BTreeMap::from([("removed_cgroup".to_string(), baseline_files)]);

        let current: CgroupSnapshot = BTreeMap::new();

        assert!(detect_and_report(&baseline, &current, &None));
    }

    #[test]
    fn test_detect_cpu_max_format() {
        // cpu.max は "quota period" 形式。quota 部分のみ比較
        let mut baseline_files = BTreeMap::new();
        baseline_files.insert("cpu.max".to_string(), "100000 100000".to_string());
        let baseline: CgroupSnapshot = BTreeMap::from([("test".to_string(), baseline_files)]);

        // quota が増加（緩和）
        let mut current_files = BTreeMap::new();
        current_files.insert("cpu.max".to_string(), "200000 100000".to_string());
        let current: CgroupSnapshot = BTreeMap::from([("test".to_string(), current_files)]);

        assert!(detect_and_report(&baseline, &current, &None));

        // quota が "max" に変更（緩和）
        let mut current_files2 = BTreeMap::new();
        current_files2.insert("cpu.max".to_string(), "max 100000".to_string());
        let current2: CgroupSnapshot = BTreeMap::from([("test".to_string(), current_files2)]);

        assert!(detect_and_report(&baseline, &current2, &None));
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let dir = TempDir::new().unwrap();
        create_cgroup_files(&dir, &[("memory.max", "max")]);

        let config = default_config_with_path(dir.path().to_str().unwrap());
        let mut module = CgroupMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let dir = TempDir::new().unwrap();
        create_cgroup_files(
            &dir,
            &[
                ("memory.max", "max"),
                ("cpu.max", "100000 100000"),
                ("sub/memory.max", "1073741824"),
            ],
        );

        let config = default_config_with_path(dir.path().to_str().unwrap());
        let module = CgroupMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert!(result.items_scanned >= 3);
        assert_eq!(result.issues_found, 0);
        assert!(result.summary.contains("cgroup"));
    }
}
