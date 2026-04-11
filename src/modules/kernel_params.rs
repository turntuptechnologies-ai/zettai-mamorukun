//! /proc/sys/ カーネルパラメータ監視モジュール
//!
//! `/proc/sys/` 配下のセキュリティ関連カーネルパラメータを定期スキャンし、
//! パラメータの変更・弱体化を検知する。
//!
//! 検知対象:
//! - `min_value` を下回る危険な値への変更（Critical）
//! - ベースラインからの値変更（High）
//! - `expected_value` との不一致（Warning）

use crate::config::{KernelParamRule, KernelParamsConfig};
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::BTreeMap;
use std::path::Path;
use tokio_util::sync::CancellationToken;

/// パラメータのスナップショット（パス → 値）
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParamSnapshot {
    /// 各パラメータの値（パス → trimmed 値文字列）
    values: BTreeMap<String, String>,
}

/// カーネルパラメータファイルを読み取る
///
/// ファイルが存在しない場合は `None` を返す。
fn read_param(proc_sys_path: &Path, param_path: &str) -> Option<String> {
    let full_path = proc_sys_path.join(param_path);
    match std::fs::read_to_string(&full_path) {
        Ok(content) => Some(content.trim().to_string()),
        Err(_) => None,
    }
}

/// 全監視対象パラメータのスナップショットを取得する
fn take_snapshot(proc_sys_path: &Path, watch_params: &[KernelParamRule]) -> ParamSnapshot {
    let mut values = BTreeMap::new();
    for rule in watch_params {
        if let Some(value) = read_param(proc_sys_path, &rule.path) {
            values.insert(rule.path.clone(), value);
        } else {
            tracing::info!(
                path = %rule.path,
                "パラメータファイルが存在しません（スキップ）"
            );
        }
    }
    ParamSnapshot { values }
}

/// /proc/sys/ カーネルパラメータ監視モジュール
///
/// セキュリティ関連カーネルパラメータを定期スキャンし、
/// 変更や弱体化を検知する。
pub struct KernelParamsModule {
    config: KernelParamsConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl KernelParamsModule {
    /// 新しいカーネルパラメータ監視モジュールを作成する
    pub fn new(config: KernelParamsConfig, event_bus: Option<EventBus>) -> Self {
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

    /// ベースラインと現在のスナップショットを比較し、変更を検知してイベント発行する
    fn detect_and_report(
        baseline: &ParamSnapshot,
        current: &ParamSnapshot,
        watch_params: &[KernelParamRule],
        event_bus: &Option<EventBus>,
    ) -> bool {
        let mut has_changes = false;

        for rule in watch_params {
            let current_value = match current.values.get(&rule.path) {
                Some(v) => v,
                None => continue,
            };

            // 1. min_value チェック: 値が最小値未満 → Critical
            if let Some(min_val) = rule.min_value
                && let Ok(numeric) = current_value.parse::<i64>()
                && numeric < min_val
            {
                let details = format!(
                    "パラメータ={}, 現在値={}, 最小値={}",
                    rule.path, numeric, min_val
                );
                tracing::error!(
                    path = %rule.path,
                    current_value = numeric,
                    min_value = min_val,
                    "カーネルパラメータが最小値を下回っています（セキュリティ弱体化）"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "kernel_param_below_minimum",
                            Severity::Critical,
                            "kernel_params",
                            "カーネルパラメータが最小値を下回っています（セキュリティ弱体化）",
                        )
                        .with_details(details),
                    );
                }
                has_changes = true;
                continue;
            }

            // 2. ベースラインからの値変更 → Warning
            if let Some(baseline_value) = baseline.values.get(&rule.path)
                && baseline_value != current_value
            {
                let details = format!(
                    "パラメータ={}, 旧値={}, 新値={}",
                    rule.path, baseline_value, current_value
                );
                tracing::warn!(
                    path = %rule.path,
                    old_value = %baseline_value,
                    new_value = %current_value,
                    "カーネルパラメータがベースラインから変更されました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "kernel_param_changed",
                            Severity::Warning,
                            "kernel_params",
                            "カーネルパラメータがベースラインから変更されました",
                        )
                        .with_details(details),
                    );
                }
                has_changes = true;
                continue;
            }

            // 3. expected_value との不一致 → Warning
            if let Some(ref expected) = rule.expected_value
                && current_value != expected
            {
                let details = format!(
                    "パラメータ={}, 現在値={}, 期待値={}",
                    rule.path, current_value, expected
                );
                tracing::warn!(
                    path = %rule.path,
                    current_value = %current_value,
                    expected_value = %expected,
                    "カーネルパラメータが期待値と一致しません"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "kernel_param_unexpected",
                            Severity::Warning,
                            "kernel_params",
                            "カーネルパラメータが期待値と一致しません",
                        )
                        .with_details(details),
                    );
                }
                has_changes = true;
            }
        }

        has_changes
    }
}

impl Module for KernelParamsModule {
    fn name(&self) -> &str {
        "kernel_params"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        if self.config.watch_params.is_empty() {
            return Err(AppError::ModuleConfig {
                message: "watch_params に少なくとも 1 つのパラメータルールを指定してください"
                    .to_string(),
            });
        }

        // パストラバーサル対策: path に ".." を含むルールを拒否
        for rule in &self.config.watch_params {
            if rule.path.contains("..") {
                return Err(AppError::ModuleConfig {
                    message: format!(
                        "watch_params のパスに '..' を含めることはできません: {}",
                        rule.path
                    ),
                });
            }
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            proc_sys_path = %self.config.proc_sys_path,
            watch_params_count = self.config.watch_params.len(),
            "カーネルパラメータ監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        let proc_sys_path = self.config.proc_sys_path.clone();
        let watch_params = self.config.watch_params.clone();
        let scan_interval_secs = self.config.scan_interval_secs;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        let baseline = take_snapshot(Path::new(&proc_sys_path), &watch_params);
        tracing::info!(
            param_count = baseline.values.len(),
            "カーネルパラメータベースラインスキャンが完了しました"
        );

        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            interval.tick().await;

            let mut baseline = baseline;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("カーネルパラメータ監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = take_snapshot(
                            Path::new(&proc_sys_path),
                            &watch_params,
                        );
                        let changed = KernelParamsModule::detect_and_report(
                            &baseline, &current, &watch_params, &event_bus,
                        );

                        if changed {
                            baseline = current;
                        } else {
                            tracing::debug!("カーネルパラメータに変更はありません");
                        }
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();
        let proc_sys_path = Path::new(&self.config.proc_sys_path);
        let snapshot = take_snapshot(proc_sys_path, &self.config.watch_params);

        let items_scanned = snapshot.values.len();
        let mut issues_found = 0;

        for rule in &self.config.watch_params {
            let current_value = match snapshot.values.get(&rule.path) {
                Some(v) => v,
                None => continue,
            };

            tracing::info!(
                path = %rule.path,
                value = %current_value,
                "起動時スキャン: カーネルパラメータを検出"
            );

            // min_value チェック
            if let Some(min_val) = rule.min_value
                && let Ok(numeric) = current_value.parse::<i64>()
                && numeric < min_val
            {
                tracing::warn!(
                    path = %rule.path,
                    value = numeric,
                    min_value = min_val,
                    "起動時スキャン: カーネルパラメータが最小値を下回っています"
                );
                if let Some(bus) = &self.event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "kernel_params_startup_below_minimum",
                            Severity::Critical,
                            "kernel_params",
                            "起動時スキャン: カーネルパラメータが最小値を下回っています",
                        )
                        .with_details(format!(
                            "パラメータ={}, 現在値={}, 最小値={}",
                            rule.path, numeric, min_val
                        )),
                    );
                }
                issues_found += 1;
                continue;
            }

            // expected_value チェック
            if let Some(ref expected) = rule.expected_value
                && current_value != expected
            {
                tracing::warn!(
                    path = %rule.path,
                    value = %current_value,
                    expected = %expected,
                    "起動時スキャン: カーネルパラメータが期待値と一致しません"
                );
                if let Some(bus) = &self.event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "kernel_params_startup_unexpected",
                            Severity::Warning,
                            "kernel_params",
                            "起動時スキャン: カーネルパラメータが期待値と一致しません",
                        )
                        .with_details(format!(
                            "パラメータ={}, 現在値={}, 期待値={}",
                            rule.path, current_value, expected
                        )),
                    );
                }
                issues_found += 1;
            }
        }

        let scan_snapshot: BTreeMap<String, String> = snapshot
            .values
            .iter()
            .map(|(path, value)| (format!("param:{}", path), value.clone()))
            .collect();

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "カーネルパラメータ {}件をスキャン（うち{}件が要注意）",
                items_scanned, issues_found
            ),
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

    fn create_test_proc_sys(dir: &TempDir, params: &[(&str, &str)]) {
        for (path, value) in params {
            let full_path = dir.path().join(path);
            if let Some(parent) = full_path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(full_path, format!("{}\n", value)).unwrap();
        }
    }

    fn default_config_with_path(proc_sys_path: &str) -> KernelParamsConfig {
        KernelParamsConfig {
            enabled: true,
            scan_interval_secs: 60,
            proc_sys_path: proc_sys_path.to_string(),
            watch_params: vec![
                KernelParamRule {
                    path: "kernel/kptr_restrict".to_string(),
                    min_value: Some(1),
                    expected_value: None,
                },
                KernelParamRule {
                    path: "kernel/randomize_va_space".to_string(),
                    min_value: Some(2),
                    expected_value: None,
                },
                KernelParamRule {
                    path: "kernel/sysrq".to_string(),
                    min_value: None,
                    expected_value: None,
                },
            ],
        }
    }

    #[test]
    fn test_init_valid() {
        let dir = TempDir::new().unwrap();
        let config = default_config_with_path(dir.path().to_str().unwrap());
        let mut module = KernelParamsModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[test]
    fn test_init_zero_interval() {
        let mut config = KernelParamsConfig::default();
        config.scan_interval_secs = 0;
        let mut module = KernelParamsModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_empty_watch_params() {
        let config = KernelParamsConfig {
            enabled: true,
            scan_interval_secs: 60,
            proc_sys_path: "/proc/sys".to_string(),
            watch_params: vec![],
        };
        let mut module = KernelParamsModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_path_traversal_rejected() {
        let config = KernelParamsConfig {
            enabled: true,
            scan_interval_secs: 60,
            proc_sys_path: "/proc/sys".to_string(),
            watch_params: vec![KernelParamRule {
                path: "../etc/passwd".to_string(),
                min_value: None,
                expected_value: None,
            }],
        };
        let mut module = KernelParamsModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains(".."));
    }

    #[test]
    fn test_take_snapshot() {
        let dir = TempDir::new().unwrap();
        create_test_proc_sys(
            &dir,
            &[
                ("kernel/kptr_restrict", "1"),
                ("kernel/randomize_va_space", "2"),
            ],
        );

        let rules = vec![
            KernelParamRule {
                path: "kernel/kptr_restrict".to_string(),
                min_value: Some(1),
                expected_value: None,
            },
            KernelParamRule {
                path: "kernel/randomize_va_space".to_string(),
                min_value: Some(2),
                expected_value: None,
            },
            KernelParamRule {
                path: "kernel/nonexistent".to_string(),
                min_value: None,
                expected_value: None,
            },
        ];

        let snapshot = take_snapshot(dir.path(), &rules);
        assert_eq!(snapshot.values.len(), 2);
        assert_eq!(snapshot.values.get("kernel/kptr_restrict").unwrap(), "1");
        assert_eq!(
            snapshot.values.get("kernel/randomize_va_space").unwrap(),
            "2"
        );
        assert!(!snapshot.values.contains_key("kernel/nonexistent"));
    }

    #[test]
    fn test_take_snapshot_trims_whitespace() {
        let dir = TempDir::new().unwrap();
        create_test_proc_sys(&dir, &[("kernel/sysrq", "176")]);

        let rules = vec![KernelParamRule {
            path: "kernel/sysrq".to_string(),
            min_value: None,
            expected_value: None,
        }];

        let snapshot = take_snapshot(dir.path(), &rules);
        assert_eq!(snapshot.values.get("kernel/sysrq").unwrap(), "176");
    }

    #[test]
    fn test_detect_no_changes() {
        let snapshot = ParamSnapshot {
            values: BTreeMap::from([
                ("kernel/kptr_restrict".to_string(), "1".to_string()),
                ("kernel/sysrq".to_string(), "0".to_string()),
            ]),
        };
        let rules = vec![
            KernelParamRule {
                path: "kernel/kptr_restrict".to_string(),
                min_value: Some(1),
                expected_value: None,
            },
            KernelParamRule {
                path: "kernel/sysrq".to_string(),
                min_value: None,
                expected_value: None,
            },
        ];

        assert!(!KernelParamsModule::detect_and_report(
            &snapshot, &snapshot, &rules, &None,
        ));
    }

    #[test]
    fn test_detect_below_minimum() {
        let baseline = ParamSnapshot {
            values: BTreeMap::from([("kernel/kptr_restrict".to_string(), "1".to_string())]),
        };
        let current = ParamSnapshot {
            values: BTreeMap::from([("kernel/kptr_restrict".to_string(), "0".to_string())]),
        };
        let rules = vec![KernelParamRule {
            path: "kernel/kptr_restrict".to_string(),
            min_value: Some(1),
            expected_value: None,
        }];

        assert!(KernelParamsModule::detect_and_report(
            &baseline, &current, &rules, &None,
        ));
    }

    #[test]
    fn test_detect_baseline_changed() {
        let baseline = ParamSnapshot {
            values: BTreeMap::from([("kernel/sysrq".to_string(), "0".to_string())]),
        };
        let current = ParamSnapshot {
            values: BTreeMap::from([("kernel/sysrq".to_string(), "1".to_string())]),
        };
        let rules = vec![KernelParamRule {
            path: "kernel/sysrq".to_string(),
            min_value: None,
            expected_value: None,
        }];

        assert!(KernelParamsModule::detect_and_report(
            &baseline, &current, &rules, &None,
        ));
    }

    #[test]
    fn test_detect_expected_value_mismatch() {
        let baseline = ParamSnapshot {
            values: BTreeMap::from([("kernel/core_pattern".to_string(), "core".to_string())]),
        };
        // Same as baseline (no baseline change), but differs from expected
        let current = ParamSnapshot {
            values: BTreeMap::from([("kernel/core_pattern".to_string(), "core".to_string())]),
        };
        let rules = vec![KernelParamRule {
            path: "kernel/core_pattern".to_string(),
            min_value: None,
            expected_value: Some("|/usr/share/apport/apport".to_string()),
        }];

        assert!(KernelParamsModule::detect_and_report(
            &baseline, &current, &rules, &None,
        ));
    }

    #[test]
    fn test_detect_priority_min_value_over_baseline() {
        // min_value violation should take priority (Critical) even if baseline also changed
        let baseline = ParamSnapshot {
            values: BTreeMap::from([("kernel/kptr_restrict".to_string(), "2".to_string())]),
        };
        let current = ParamSnapshot {
            values: BTreeMap::from([("kernel/kptr_restrict".to_string(), "0".to_string())]),
        };
        let rules = vec![KernelParamRule {
            path: "kernel/kptr_restrict".to_string(),
            min_value: Some(1),
            expected_value: None,
        }];

        // Should detect (Critical due to min_value)
        assert!(KernelParamsModule::detect_and_report(
            &baseline, &current, &rules, &None,
        ));
    }

    #[test]
    fn test_baseline_updated_after_change() {
        let dir = TempDir::new().unwrap();
        create_test_proc_sys(&dir, &[("kernel/sysrq", "0")]);

        let rules = vec![KernelParamRule {
            path: "kernel/sysrq".to_string(),
            min_value: None,
            expected_value: None,
        }];

        let baseline = take_snapshot(dir.path(), &rules);
        assert_eq!(baseline.values.get("kernel/sysrq").unwrap(), "0");

        // Change the value
        std::fs::write(dir.path().join("kernel/sysrq"), "1\n").unwrap();

        let current = take_snapshot(dir.path(), &rules);
        assert!(KernelParamsModule::detect_and_report(
            &baseline, &current, &rules, &None,
        ));

        // After updating baseline, no more changes
        assert!(!KernelParamsModule::detect_and_report(
            &current, &current, &rules, &None,
        ));
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let dir = TempDir::new().unwrap();
        create_test_proc_sys(&dir, &[("kernel/kptr_restrict", "1")]);

        let config = default_config_with_path(dir.path().to_str().unwrap());
        let mut module = KernelParamsModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let dir = TempDir::new().unwrap();
        create_test_proc_sys(
            &dir,
            &[
                ("kernel/kptr_restrict", "1"),
                ("kernel/randomize_va_space", "2"),
                ("kernel/sysrq", "0"),
            ],
        );

        let config = default_config_with_path(dir.path().to_str().unwrap());
        let module = KernelParamsModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 3);
        assert_eq!(result.issues_found, 0);
        assert!(result.summary.contains("カーネルパラメータ"));
    }

    #[tokio::test]
    async fn test_initial_scan_detects_issues() {
        let dir = TempDir::new().unwrap();
        create_test_proc_sys(
            &dir,
            &[
                ("kernel/kptr_restrict", "0"),      // Below min_value of 1
                ("kernel/randomize_va_space", "1"), // Below min_value of 2
            ],
        );

        let config = default_config_with_path(dir.path().to_str().unwrap());
        let module = KernelParamsModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.issues_found, 2);
    }

    #[tokio::test]
    async fn test_initial_scan_detects_expected_value_mismatch() {
        let dir = TempDir::new().unwrap();
        create_test_proc_sys(&dir, &[("kernel/core_pattern", "unexpected_value")]);

        let config = KernelParamsConfig {
            enabled: true,
            scan_interval_secs: 60,
            proc_sys_path: dir.path().to_str().unwrap().to_string(),
            watch_params: vec![KernelParamRule {
                path: "kernel/core_pattern".to_string(),
                min_value: None,
                expected_value: Some("core".to_string()),
            }],
        };
        let module = KernelParamsModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 1);
        assert_eq!(result.issues_found, 1);
    }

    #[test]
    fn test_nonexistent_proc_sys() {
        let rules = vec![KernelParamRule {
            path: "kernel/kptr_restrict".to_string(),
            min_value: Some(1),
            expected_value: None,
        }];
        let snapshot = take_snapshot(Path::new("/nonexistent_proc_sys"), &rules);
        assert!(snapshot.values.is_empty());
    }
}
