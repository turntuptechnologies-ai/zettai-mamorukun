//! カーネルライブパッチ監視モジュール
//!
//! `/sys/kernel/livepatch/` を定期的に読み取り、kpatch/livepatch のロード状態を監視する。
//!
//! 検知対象:
//! - 新規ライブパッチの適用（不正パッチ挿入の可能性）
//! - ライブパッチの無効化（セキュリティパッチ解除の可能性）
//! - ライブパッチの削除（パッチ除去の可能性）
//! - transition 状態の異常（パッチ適用の不整合）

use crate::config::LivepatchMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::BTreeMap;
use tokio_util::sync::CancellationToken;

/// ライブパッチエントリ
///
/// `/sys/kernel/livepatch/<name>/` の状態を表す。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LivepatchEntry {
    /// パッチ名
    pub name: String,
    /// 有効状態（enabled ファイルの値）
    pub enabled: bool,
    /// トランジション状態（transition ファイルの値）
    pub transition: bool,
}

impl LivepatchEntry {
    /// スナップショット用のフォーマット文字列を返す
    pub fn snapshot_value(&self) -> String {
        format!("enabled={},transition={}", self.enabled, self.transition)
    }
}

/// ライブパッチの変更内容
#[derive(Debug, Clone, PartialEq, Eq)]
struct LivepatchChanges {
    /// 新しく追加されたパッチ
    added: Vec<LivepatchEntry>,
    /// 削除されたパッチ
    removed: Vec<LivepatchEntry>,
    /// enabled 状態が変更されたパッチ（名前, 旧値, 新値）
    enabled_changed: Vec<(String, bool, bool)>,
    /// transition 状態が変更されたパッチ（名前, 旧値, 新値）
    transition_changed: Vec<(String, bool, bool)>,
}

/// カーネルライブパッチ監視モジュール
///
/// `/sys/kernel/livepatch/` を定期スキャンし、ライブパッチの状態変化を検知してログに記録する。
pub struct LivepatchMonitorModule {
    config: LivepatchMonitorConfig,
    event_bus: Option<EventBus>,
    cancel_token: CancellationToken,
}

impl LivepatchMonitorModule {
    /// 新しいカーネルライブパッチ監視モジュールを作成する
    pub fn new(config: LivepatchMonitorConfig, event_bus: Option<EventBus>) -> Self {
        Self {
            config,
            event_bus,
            cancel_token: CancellationToken::new(),
        }
    }

    /// キャンセルトークンのクローンを返す
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    /// `/sys/kernel/livepatch/` ディレクトリを読み取りライブパッチ一覧を返す
    ///
    /// ディレクトリが存在しない場合は空リストを返す。
    fn read_livepatch_dir(sys_path: &str) -> Result<Vec<LivepatchEntry>, AppError> {
        let dir = std::path::Path::new(sys_path);
        if !dir.exists() {
            return Ok(Vec::new());
        }

        let entries = std::fs::read_dir(dir).map_err(|e| AppError::FileIo {
            path: sys_path.into(),
            source: e,
        })?;

        let mut patches = Vec::new();

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    tracing::debug!(error = %e, "ライブパッチディレクトリエントリの読み取りに失敗");
                    continue;
                }
            };

            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };

            let enabled = Self::read_sysfs_bool(&path.join("enabled"));
            let transition = Self::read_sysfs_bool(&path.join("transition"));

            patches.push(LivepatchEntry {
                name,
                enabled,
                transition,
            });
        }

        patches.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(patches)
    }

    /// sysfs のブール値ファイルを読み取る（"1" → true, それ以外 → false）
    fn read_sysfs_bool(path: &std::path::Path) -> bool {
        std::fs::read_to_string(path)
            .map(|s| s.trim() == "1")
            .unwrap_or(false)
    }

    /// `/proc/modules` から `[livepatch]` フラグのあるモジュールを抽出する
    fn read_livepatch_modules(proc_path: &str) -> Vec<String> {
        let modules_path = format!("{}/modules", proc_path);
        let content = match std::fs::read_to_string(&modules_path) {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!(error = %e, path = %modules_path, "/proc/modules の読み取りに失敗");
                return Vec::new();
            }
        };

        let mut result = Vec::new();
        for line in content.lines() {
            if line.contains("[livepatch]")
                && let Some(name) = line.split_whitespace().next()
            {
                result.push(name.to_string());
            }
        }
        result.sort();
        result
    }

    /// ベースラインと現在のライブパッチ状態を比較し、変更を検知する
    fn detect_changes(baseline: &[LivepatchEntry], current: &[LivepatchEntry]) -> LivepatchChanges {
        let baseline_map: BTreeMap<&str, &LivepatchEntry> =
            baseline.iter().map(|e| (e.name.as_str(), e)).collect();
        let current_map: BTreeMap<&str, &LivepatchEntry> =
            current.iter().map(|e| (e.name.as_str(), e)).collect();

        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut enabled_changed = Vec::new();
        let mut transition_changed = Vec::new();

        for (name, cur) in &current_map {
            match baseline_map.get(name) {
                None => {
                    added.push((*cur).clone());
                }
                Some(base) => {
                    if base.enabled != cur.enabled {
                        enabled_changed.push((name.to_string(), base.enabled, cur.enabled));
                    }
                    if base.transition != cur.transition {
                        transition_changed.push((
                            name.to_string(),
                            base.transition,
                            cur.transition,
                        ));
                    }
                }
            }
        }

        for (name, base) in &baseline_map {
            if !current_map.contains_key(name) {
                removed.push((*base).clone());
            }
        }

        LivepatchChanges {
            added,
            removed,
            enabled_changed,
            transition_changed,
        }
    }
}

impl Module for LivepatchMonitorModule {
    fn name(&self) -> &str {
        "livepatch_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            sys_path = %self.config.sys_path,
            "カーネルライブパッチ監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        let baseline = Self::read_livepatch_dir(&self.config.sys_path)?;

        tracing::info!(
            patch_count = baseline.len(),
            "カーネルライブパッチのベースラインを取得しました"
        );

        let livepatch_modules = Self::read_livepatch_modules(&self.config.proc_path);
        if !livepatch_modules.is_empty() {
            tracing::info!(
                modules = ?livepatch_modules,
                "livepatch カーネルモジュールを検出しました"
            );
        }

        let scan_interval_secs = self.config.scan_interval_secs;
        let sys_path = self.config.sys_path.clone();
        let proc_path = self.config.proc_path.clone();
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            interval.tick().await;

            let mut current_baseline = baseline;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("カーネルライブパッチ監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = match LivepatchMonitorModule::read_livepatch_dir(&sys_path) {
                            Ok(c) => c,
                            Err(e) => {
                                tracing::warn!(error = %e, "ライブパッチディレクトリの読み取りに失敗しました");
                                continue;
                            }
                        };

                        let changes = LivepatchMonitorModule::detect_changes(&current_baseline, &current);

                        for entry in &changes.added {
                            tracing::warn!(
                                patch_name = %entry.name,
                                enabled = entry.enabled,
                                transition = entry.transition,
                                "新規ライブパッチが検出されました"
                            );
                            if let Some(ref bus) = event_bus {
                                bus.publish(
                                    SecurityEvent::new(
                                        "livepatch_added",
                                        Severity::Warning,
                                        "livepatch_monitor",
                                        format!(
                                            "新規ライブパッチが検出されました: {} (enabled={}, transition={})",
                                            entry.name, entry.enabled, entry.transition
                                        ),
                                    )
                                    .with_details(format!("patch={}", entry.name)),
                                );
                            }
                        }

                        for entry in &changes.removed {
                            tracing::error!(
                                patch_name = %entry.name,
                                "ライブパッチが削除されました"
                            );
                            if let Some(ref bus) = event_bus {
                                bus.publish(
                                    SecurityEvent::new(
                                        "livepatch_removed",
                                        Severity::Critical,
                                        "livepatch_monitor",
                                        format!("ライブパッチが削除されました: {}", entry.name),
                                    )
                                    .with_details(format!("patch={}", entry.name)),
                                );
                            }
                        }

                        for (name, old, new) in &changes.enabled_changed {
                            let severity = if *old && !*new {
                                // enabled: true→false（無効化）
                                Severity::Warning
                            } else {
                                Severity::Warning
                            };
                            tracing::warn!(
                                patch_name = %name,
                                old_enabled = old,
                                new_enabled = new,
                                "ライブパッチの enabled 状態が変更されました"
                            );
                            if let Some(ref bus) = event_bus {
                                bus.publish(
                                    SecurityEvent::new(
                                        "livepatch_enabled_changed",
                                        severity,
                                        "livepatch_monitor",
                                        format!(
                                            "ライブパッチの enabled 状態が変更されました: {} ({} -> {})",
                                            name, old, new
                                        ),
                                    )
                                    .with_details(format!("patch={}", name)),
                                );
                            }
                        }

                        for (name, old, new) in &changes.transition_changed {
                            let severity = if !*old && *new {
                                // transition: false→true（異常状態）
                                Severity::Critical
                            } else {
                                Severity::Warning
                            };
                            tracing::warn!(
                                patch_name = %name,
                                old_transition = old,
                                new_transition = new,
                                "ライブパッチの transition 状態が変更されました"
                            );
                            if let Some(ref bus) = event_bus {
                                bus.publish(
                                    SecurityEvent::new(
                                        "livepatch_transition_changed",
                                        severity,
                                        "livepatch_monitor",
                                        format!(
                                            "ライブパッチの transition 状態が変更されました: {} ({} -> {})",
                                            name, old, new
                                        ),
                                    )
                                    .with_details(format!("patch={}", name)),
                                );
                            }
                        }

                        // livepatch モジュール情報も定期的にチェック
                        let lp_modules = LivepatchMonitorModule::read_livepatch_modules(&proc_path);
                        if !lp_modules.is_empty() {
                            tracing::debug!(
                                modules = ?lp_modules,
                                "livepatch カーネルモジュール一覧"
                            );
                        }

                        let total_changes = changes.added.len()
                            + changes.removed.len()
                            + changes.enabled_changed.len()
                            + changes.transition_changed.len();

                        if total_changes == 0 {
                            tracing::debug!("カーネルライブパッチに変化はありません");
                        }

                        current_baseline = current;
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();
        let entries = Self::read_livepatch_dir(&self.config.sys_path)?;
        let livepatch_modules = Self::read_livepatch_modules(&self.config.proc_path);
        let items_scanned = entries.len() + livepatch_modules.len();

        let mut snapshot: BTreeMap<String, String> = entries
            .iter()
            .map(|entry| (entry.name.clone(), entry.snapshot_value()))
            .collect();

        for module in &livepatch_modules {
            snapshot.insert(format!("module:{}", module), "livepatch_module".to_string());
        }

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found: 0,
            duration,
            summary: format!(
                "ライブパッチ {}件、livepatch モジュール {}件を検出しました",
                entries.len(),
                livepatch_modules.len()
            ),
            snapshot,
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

    fn make_entry(name: &str, enabled: bool, transition: bool) -> LivepatchEntry {
        LivepatchEntry {
            name: name.to_string(),
            enabled,
            transition,
        }
    }

    #[test]
    fn test_detect_changes_no_change() {
        let baseline = vec![make_entry("kpatch_cve_2024_1234", true, false)];
        let current = vec![make_entry("kpatch_cve_2024_1234", true, false)];
        let changes = LivepatchMonitorModule::detect_changes(&baseline, &current);
        assert!(changes.added.is_empty());
        assert!(changes.removed.is_empty());
        assert!(changes.enabled_changed.is_empty());
        assert!(changes.transition_changed.is_empty());
    }

    #[test]
    fn test_detect_changes_added() {
        let baseline = vec![];
        let current = vec![make_entry("kpatch_cve_2024_5678", true, false)];
        let changes = LivepatchMonitorModule::detect_changes(&baseline, &current);
        assert_eq!(changes.added.len(), 1);
        assert_eq!(changes.added[0].name, "kpatch_cve_2024_5678");
        assert!(changes.removed.is_empty());
        assert!(changes.enabled_changed.is_empty());
        assert!(changes.transition_changed.is_empty());
    }

    #[test]
    fn test_detect_changes_removed() {
        let baseline = vec![make_entry("kpatch_cve_2024_5678", true, false)];
        let current = vec![];
        let changes = LivepatchMonitorModule::detect_changes(&baseline, &current);
        assert!(changes.added.is_empty());
        assert_eq!(changes.removed.len(), 1);
        assert_eq!(changes.removed[0].name, "kpatch_cve_2024_5678");
        assert!(changes.enabled_changed.is_empty());
        assert!(changes.transition_changed.is_empty());
    }

    #[test]
    fn test_detect_changes_enabled_changed() {
        let baseline = vec![make_entry("kpatch_cve_2024_5678", true, false)];
        let current = vec![make_entry("kpatch_cve_2024_5678", false, false)];
        let changes = LivepatchMonitorModule::detect_changes(&baseline, &current);
        assert!(changes.added.is_empty());
        assert!(changes.removed.is_empty());
        assert_eq!(changes.enabled_changed.len(), 1);
        assert_eq!(
            changes.enabled_changed[0],
            ("kpatch_cve_2024_5678".to_string(), true, false)
        );
        assert!(changes.transition_changed.is_empty());
    }

    #[test]
    fn test_detect_changes_transition_changed() {
        let baseline = vec![make_entry("kpatch_cve_2024_5678", true, false)];
        let current = vec![make_entry("kpatch_cve_2024_5678", true, true)];
        let changes = LivepatchMonitorModule::detect_changes(&baseline, &current);
        assert!(changes.added.is_empty());
        assert!(changes.removed.is_empty());
        assert!(changes.enabled_changed.is_empty());
        assert_eq!(changes.transition_changed.len(), 1);
        assert_eq!(
            changes.transition_changed[0],
            ("kpatch_cve_2024_5678".to_string(), false, true)
        );
    }

    #[test]
    fn test_detect_changes_mixed() {
        let baseline = vec![
            make_entry("patch_a", true, false),
            make_entry("patch_b", true, false),
            make_entry("patch_c", false, false),
        ];
        let current = vec![
            make_entry("patch_a", false, true), // enabled & transition changed
            // patch_b removed
            make_entry("patch_c", false, false), // no change
            make_entry("patch_d", true, false),  // added
        ];
        let changes = LivepatchMonitorModule::detect_changes(&baseline, &current);
        assert_eq!(changes.added.len(), 1);
        assert_eq!(changes.added[0].name, "patch_d");
        assert_eq!(changes.removed.len(), 1);
        assert_eq!(changes.removed[0].name, "patch_b");
        assert_eq!(changes.enabled_changed.len(), 1);
        assert_eq!(
            changes.enabled_changed[0],
            ("patch_a".to_string(), true, false)
        );
        assert_eq!(changes.transition_changed.len(), 1);
        assert_eq!(
            changes.transition_changed[0],
            ("patch_a".to_string(), false, true)
        );
    }

    #[test]
    fn test_init_zero_interval() {
        let config = LivepatchMonitorConfig {
            enabled: true,
            scan_interval_secs: 0,
            sys_path: "/sys/kernel/livepatch".to_string(),
            proc_path: "/proc".to_string(),
        };
        let mut module = LivepatchMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_init_valid_config() {
        let config = LivepatchMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            sys_path: "/sys/kernel/livepatch".to_string(),
            proc_path: "/proc".to_string(),
        };
        let mut module = LivepatchMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_ok());
    }

    #[test]
    fn test_read_livepatch_dir_nonexistent() {
        let result = LivepatchMonitorModule::read_livepatch_dir("/nonexistent/path/livepatch");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_read_livepatch_modules_parsing() {
        let dir = tempfile::tempdir().unwrap();
        let modules_path = dir.path().join("modules");
        std::fs::write(
            &modules_path,
            "\
nf_tables 348160 0 - Live 0xffffffffc0800000
livepatch_cve_2024_1234 16384 1 - Live 0xffffffffc0900000 [livepatch]
ext4 1048576 1 - Live 0xffffffffc0a00000
livepatch_cve_2024_5678 8192 0 - Live 0xffffffffc0b00000 [livepatch]
",
        )
        .unwrap();

        let result = LivepatchMonitorModule::read_livepatch_modules(dir.path().to_str().unwrap());
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], "livepatch_cve_2024_1234");
        assert_eq!(result[1], "livepatch_cve_2024_5678");
    }

    #[test]
    fn test_livepatch_entry_snapshot() {
        let entry = make_entry("kpatch_test", true, false);
        assert_eq!(entry.snapshot_value(), "enabled=true,transition=false");

        let entry2 = make_entry("kpatch_test2", false, true);
        assert_eq!(entry2.snapshot_value(), "enabled=false,transition=true");
    }
}
