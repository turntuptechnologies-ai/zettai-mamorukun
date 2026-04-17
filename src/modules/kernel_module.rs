//! カーネルモジュール監視モジュール
//!
//! `/proc/modules` を定期的に読み取り、ロードされたカーネルモジュールを監視する。
//!
//! 検知対象:
//! - 起動後に新たにロードされたカーネルモジュール
//! - アンロードされたカーネルモジュール（情報レベルで記録）

use crate::config::KernelModuleConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::core::module_stats::ModuleStatsHandle;
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::{BTreeMap, HashSet};
use tokio_util::sync::CancellationToken;

/// モジュール識別子（`ModuleStats` に登録する統計上のモジュール名）
pub(crate) const MODULE_STATS_NAME: &str = "カーネルモジュール監視モジュール";

/// `/proc/modules` の各行をパースした結果
#[derive(Debug, Clone, PartialEq, Eq)]
struct KernelModuleEntry {
    /// モジュール名
    name: String,
    /// モジュールサイズ（バイト）
    size: u64,
    /// 使用カウント
    used_count: u32,
    /// モジュールの状態（Live, Loading, Unloading）
    state: String,
}

/// カーネルモジュール監視モジュール
///
/// `/proc/modules` を定期スキャンし、モジュールの変化を検知してログに記録する。
pub struct KernelModuleMonitor {
    config: KernelModuleConfig,
    event_bus: Option<EventBus>,
    cancel_token: CancellationToken,
    stats_handle: Option<ModuleStatsHandle>,
}

impl KernelModuleMonitor {
    /// 新しいカーネルモジュール監視モジュールを作成する
    pub fn new(config: KernelModuleConfig, event_bus: Option<EventBus>) -> Self {
        Self {
            config,
            event_bus,
            cancel_token: CancellationToken::new(),
            stats_handle: None,
        }
    }

    /// キャンセルトークンのクローンを返す
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    /// `/proc/modules` の内容を読み取る
    fn read_proc_modules() -> Result<String, AppError> {
        std::fs::read_to_string("/proc/modules").map_err(|e| AppError::FileIo {
            path: "/proc/modules".into(),
            source: e,
        })
    }

    /// `/proc/modules` の内容をパースしてモジュールエントリのリストを返す
    ///
    /// `/proc/modules` の各行は以下の形式:
    /// `module_name size used_count dependencies state address`
    fn parse_proc_modules(content: &str) -> Vec<KernelModuleEntry> {
        let mut entries = Vec::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 5 {
                tracing::debug!(line = line, "不正な /proc/modules 行をスキップしました");
                continue;
            }

            let size = match fields[1].parse::<u64>() {
                Ok(s) => s,
                Err(_) => {
                    tracing::debug!(line = line, "モジュールサイズのパースに失敗しました");
                    continue;
                }
            };

            let used_count = match fields[2].parse::<u32>() {
                Ok(c) => c,
                Err(_) => {
                    tracing::debug!(line = line, "使用カウントのパースに失敗しました");
                    continue;
                }
            };

            entries.push(KernelModuleEntry {
                name: fields[0].to_string(),
                size,
                used_count,
                state: fields[4].to_string(),
            });
        }

        entries
    }

    /// 現在のモジュール名セットとベースラインを比較し、差分を検知する
    fn detect_changes(
        baseline: &HashSet<String>,
        current: &HashSet<String>,
    ) -> (Vec<String>, Vec<String>) {
        let loaded: Vec<String> = current.difference(baseline).cloned().collect();
        let unloaded: Vec<String> = baseline.difference(current).cloned().collect();
        (loaded, unloaded)
    }
}

impl Module for KernelModuleMonitor {
    fn name(&self) -> &str {
        "kernel_module"
    }

    fn set_module_stats(&mut self, handle: ModuleStatsHandle) {
        self.stats_handle = Some(handle);
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            "カーネルモジュール監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        // 初回スキャンでベースラインを取得
        let content = Self::read_proc_modules()?;
        let entries = Self::parse_proc_modules(&content);
        let baseline: HashSet<String> = entries.iter().map(|e| e.name.clone()).collect();

        tracing::info!(
            module_count = baseline.len(),
            "カーネルモジュールのベースラインを取得しました"
        );

        let scan_interval_secs = self.config.scan_interval_secs;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();
        let stats_handle = self.stats_handle.clone();

        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            // 最初の tick は即座に発火するのでスキップ
            interval.tick().await;

            let mut current_baseline = baseline;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("カーネルモジュール監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let scan_start = std::time::Instant::now();
                        let content = match KernelModuleMonitor::read_proc_modules() {
                            Ok(c) => c,
                            Err(e) => {
                                tracing::warn!(error = %e, "/proc/modules の読み取りに失敗しました");
                                let scan_elapsed = scan_start.elapsed();
                                if let Some(ref handle) = stats_handle {
                                    handle.record_scan_duration(MODULE_STATS_NAME, scan_elapsed);
                                }
                                continue;
                            }
                        };

                        let entries = KernelModuleMonitor::parse_proc_modules(&content);
                        let current: HashSet<String> = entries.iter().map(|e| e.name.clone()).collect();

                        let (loaded, unloaded) = KernelModuleMonitor::detect_changes(&current_baseline, &current);
                        let scan_elapsed = scan_start.elapsed();
                        if let Some(ref handle) = stats_handle {
                            handle.record_scan_duration(MODULE_STATS_NAME, scan_elapsed);
                        }

                        for module_name in &loaded {
                            // 新しくロードされたモジュールの詳細を取得
                            let detail = entries.iter().find(|e| &e.name == module_name);
                            if let Some(entry) = detail {
                                tracing::warn!(
                                    module_name = %entry.name,
                                    size = entry.size,
                                    state = %entry.state,
                                    "新しいカーネルモジュールがロードされました"
                                );
                            } else {
                                tracing::warn!(
                                    module_name = %module_name,
                                    "新しいカーネルモジュールがロードされました"
                                );
                            }
                            if let Some(ref bus) = event_bus {
                                bus.publish(
                                    SecurityEvent::new(
                                        "kernel_module_loaded",
                                        Severity::Warning,
                                        "kernel_module",
                                        format!("新しいカーネルモジュールがロードされました: {}", module_name),
                                    )
                                    .with_details(module_name.clone()),
                                );
                            }
                        }

                        for module_name in &unloaded {
                            tracing::info!(
                                module_name = %module_name,
                                "カーネルモジュールがアンロードされました"
                            );
                            if let Some(ref bus) = event_bus {
                                bus.publish(
                                    SecurityEvent::new(
                                        "kernel_module_unloaded",
                                        Severity::Info,
                                        "kernel_module",
                                        format!("カーネルモジュールがアンロードされました: {}", module_name),
                                    )
                                    .with_details(module_name.clone()),
                                );
                            }
                        }

                        if loaded.is_empty() && unloaded.is_empty() {
                            tracing::debug!("カーネルモジュールに変化はありません");
                        }

                        // ベースラインを更新
                        current_baseline = current;
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();
        let content = Self::read_proc_modules()?;
        let entries = Self::parse_proc_modules(&content);
        let items_scanned = entries.len();
        let snapshot: BTreeMap<String, String> = entries
            .iter()
            .map(|entry| {
                (
                    entry.name.clone(),
                    format!("size={},state={}", entry.size, entry.state),
                )
            })
            .collect();
        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found: 0,
            duration,
            summary: format!("カーネルモジュール {}件を検出しました", items_scanned),
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

    #[test]
    fn test_parse_proc_modules_normal() {
        let content = "\
nf_tables 311296 0 - Live 0xffffffffc0a00000
nf_conntrack 188416 1 nf_tables, Live 0xffffffffc0900000
ip_tables 32768 0 - Live 0xffffffffc0800000";

        let entries = KernelModuleMonitor::parse_proc_modules(content);
        assert_eq!(entries.len(), 3);

        assert_eq!(entries[0].name, "nf_tables");
        assert_eq!(entries[0].size, 311296);
        assert_eq!(entries[0].used_count, 0);
        assert_eq!(entries[0].state, "Live");

        assert_eq!(entries[1].name, "nf_conntrack");
        assert_eq!(entries[1].size, 188416);
        assert_eq!(entries[1].used_count, 1);

        assert_eq!(entries[2].name, "ip_tables");
    }

    #[test]
    fn test_parse_proc_modules_empty() {
        let entries = KernelModuleMonitor::parse_proc_modules("");
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_proc_modules_blank_lines() {
        let content = "\n  \n\nnf_tables 311296 0 - Live 0xffffffffc0a00000\n\n";
        let entries = KernelModuleMonitor::parse_proc_modules(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "nf_tables");
    }

    #[test]
    fn test_parse_proc_modules_invalid_line() {
        let content = "too_short 123";
        let entries = KernelModuleMonitor::parse_proc_modules(content);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_proc_modules_invalid_size() {
        let content = "module_name not_a_number 0 - Live 0xffffffffc0a00000";
        let entries = KernelModuleMonitor::parse_proc_modules(content);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_proc_modules_invalid_used_count() {
        let content = "module_name 311296 bad - Live 0xffffffffc0a00000";
        let entries = KernelModuleMonitor::parse_proc_modules(content);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_detect_changes_new_module() {
        let baseline: HashSet<String> = vec!["mod_a".to_string(), "mod_b".to_string()]
            .into_iter()
            .collect();
        let current: HashSet<String> = vec![
            "mod_a".to_string(),
            "mod_b".to_string(),
            "mod_c".to_string(),
        ]
        .into_iter()
        .collect();

        let (loaded, unloaded) = KernelModuleMonitor::detect_changes(&baseline, &current);
        assert_eq!(loaded, vec!["mod_c".to_string()]);
        assert!(unloaded.is_empty());
    }

    #[test]
    fn test_detect_changes_unloaded_module() {
        let baseline: HashSet<String> = vec!["mod_a".to_string(), "mod_b".to_string()]
            .into_iter()
            .collect();
        let current: HashSet<String> = vec!["mod_a".to_string()].into_iter().collect();

        let (loaded, unloaded) = KernelModuleMonitor::detect_changes(&baseline, &current);
        assert!(loaded.is_empty());
        assert_eq!(unloaded, vec!["mod_b".to_string()]);
    }

    #[test]
    fn test_detect_changes_no_change() {
        let baseline: HashSet<String> = vec!["mod_a".to_string(), "mod_b".to_string()]
            .into_iter()
            .collect();
        let current = baseline.clone();

        let (loaded, unloaded) = KernelModuleMonitor::detect_changes(&baseline, &current);
        assert!(loaded.is_empty());
        assert!(unloaded.is_empty());
    }

    #[test]
    fn test_detect_changes_both() {
        let baseline: HashSet<String> = vec!["mod_a".to_string(), "mod_b".to_string()]
            .into_iter()
            .collect();
        let current: HashSet<String> = vec!["mod_a".to_string(), "mod_c".to_string()]
            .into_iter()
            .collect();

        let (loaded, unloaded) = KernelModuleMonitor::detect_changes(&baseline, &current);
        assert_eq!(loaded, vec!["mod_c".to_string()]);
        assert_eq!(unloaded, vec!["mod_b".to_string()]);
    }

    #[test]
    fn test_detect_changes_empty_baseline() {
        let baseline: HashSet<String> = HashSet::new();
        let current: HashSet<String> = vec!["mod_a".to_string()].into_iter().collect();

        let (loaded, unloaded) = KernelModuleMonitor::detect_changes(&baseline, &current);
        assert_eq!(loaded, vec!["mod_a".to_string()]);
        assert!(unloaded.is_empty());
    }

    #[test]
    fn test_detect_changes_empty_current() {
        let baseline: HashSet<String> = vec!["mod_a".to_string()].into_iter().collect();
        let current: HashSet<String> = HashSet::new();

        let (loaded, unloaded) = KernelModuleMonitor::detect_changes(&baseline, &current);
        assert!(loaded.is_empty());
        assert_eq!(unloaded, vec!["mod_a".to_string()]);
    }

    #[test]
    fn test_init_zero_interval() {
        let config = KernelModuleConfig {
            enabled: true,
            scan_interval_secs: 0,
        };
        let mut module = KernelModuleMonitor::new(config, None);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_init_valid_config() {
        let config = KernelModuleConfig {
            enabled: true,
            scan_interval_secs: 120,
        };
        let mut module = KernelModuleMonitor::new(config, None);
        let result = module.init();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let config = KernelModuleConfig {
            enabled: true,
            scan_interval_secs: 3600,
        };
        let mut module = KernelModuleMonitor::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[test]
    fn test_read_proc_modules() {
        // 実環境テスト: Linux では /proc/modules が存在する
        let result = KernelModuleMonitor::read_proc_modules();
        assert!(result.is_ok());
        let content = result.unwrap();
        // 少なくとも何かしらのモジュールがロードされているはず
        assert!(!content.is_empty());
    }

    #[test]
    fn test_kernel_module_entry_equality() {
        let entry1 = KernelModuleEntry {
            name: "test".to_string(),
            size: 100,
            used_count: 0,
            state: "Live".to_string(),
        };
        let entry2 = entry1.clone();
        assert_eq!(entry1, entry2);
    }

    #[tokio::test]
    async fn test_initial_scan_with_modules() {
        let config = KernelModuleConfig {
            enabled: true,
            scan_interval_secs: 120,
        };
        let module = KernelModuleMonitor::new(config, None);

        let result = module.initial_scan().await.unwrap();
        // Linux 環境では必ず何かしらのモジュールがロードされている
        assert!(result.items_scanned > 0);
        assert_eq!(result.issues_found, 0);
        assert!(result.summary.contains("件を検出しました"));
    }

    #[test]
    fn test_set_module_stats_stores_handle() {
        let config = KernelModuleConfig {
            enabled: true,
            scan_interval_secs: 60,
        };
        let mut module = KernelModuleMonitor::new(config, None);
        assert!(module.stats_handle.is_none());
        module.set_module_stats(ModuleStatsHandle::new());
        assert!(module.stats_handle.is_some());
    }

    #[tokio::test]
    async fn test_periodic_scan_records_scan_duration() {
        let config = KernelModuleConfig {
            enabled: true,
            scan_interval_secs: 1,
        };
        let mut module = KernelModuleMonitor::new(config, None);
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
