//! コアダンプ設定監視モジュール
//!
//! `/proc/sys/kernel/core_pattern`、`/proc/sys/kernel/core_pipe_limit`、
//! `/proc/sys/fs/suid_dumpable` を定期スキャンし、
//! コアダンプを悪用した権限昇格攻撃の兆候を検知する。
//!
//! 検知対象:
//! - `core_pattern` にパイプコマンドが設定された場合（Critical）
//! - `core_pattern` の変更（Warning）
//! - `suid_dumpable` が安全でない値に設定された場合（High）
//! - `core_pipe_limit` の変更（Medium）

use crate::config::CoredumpMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::BTreeMap;
use std::path::Path;
use tokio_util::sync::CancellationToken;

/// コアダンプ設定のスナップショット
#[derive(Debug, Clone, PartialEq, Eq)]
struct CoredumpSnapshot {
    core_pattern: Option<String>,
    core_pipe_limit: Option<String>,
    suid_dumpable: Option<String>,
}

/// proc ファイルを読み取り、trim した値を返す
fn read_proc_file(proc_path: &Path, relative: &str) -> Option<String> {
    let full_path = proc_path.join(relative);
    match std::fs::read_to_string(&full_path) {
        Ok(content) => Some(content.trim().to_string()),
        Err(_) => None,
    }
}

/// 3 つのコアダンプ関連ファイルを読み取りスナップショットを返す
fn take_snapshot(proc_path: &Path) -> CoredumpSnapshot {
    CoredumpSnapshot {
        core_pattern: read_proc_file(proc_path, "sys/kernel/core_pattern"),
        core_pipe_limit: read_proc_file(proc_path, "sys/kernel/core_pipe_limit"),
        suid_dumpable: read_proc_file(proc_path, "sys/fs/suid_dumpable"),
    }
}

/// コアダンプ設定監視モジュール
///
/// `/proc/sys/kernel/core_pattern`、`/proc/sys/kernel/core_pipe_limit`、
/// `/proc/sys/fs/suid_dumpable` を定期スキャンし、
/// コアダンプを悪用した権限昇格攻撃の兆候を検知する。
pub struct CoredumpMonitorModule {
    config: CoredumpMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl CoredumpMonitorModule {
    /// 新しいコアダンプ設定監視モジュールを作成する
    pub fn new(config: CoredumpMonitorConfig, event_bus: Option<EventBus>) -> Self {
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
        baseline: &CoredumpSnapshot,
        current: &CoredumpSnapshot,
        event_bus: &Option<EventBus>,
    ) -> bool {
        let mut has_changes = false;

        // 1. core_pattern: パイプコマンド検知 → Critical
        if let Some(ref pattern) = current.core_pattern {
            if pattern.starts_with('|') || pattern.trim().starts_with('|') {
                let details = format!("core_pattern={}", pattern);
                tracing::error!(
                    core_pattern = %pattern,
                    "core_pattern にパイプコマンドが設定されています（権限昇格の危険）"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "coredump_pipe_command_detected",
                            Severity::Critical,
                            "coredump_monitor",
                            "core_pattern にパイプコマンドが設定されています（権限昇格の危険）",
                        )
                        .with_details(details),
                    );
                }
                has_changes = true;
            } else if baseline.core_pattern.as_ref() != Some(pattern) {
                // 2. core_pattern: ベースラインから変更 → Warning
                let details = format!(
                    "旧値={}, 新値={}",
                    baseline.core_pattern.as_deref().unwrap_or("(未設定)"),
                    pattern
                );
                tracing::warn!(
                    old_value = baseline.core_pattern.as_deref().unwrap_or("(未設定)"),
                    new_value = %pattern,
                    "core_pattern がベースラインから変更されました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "coredump_core_pattern_changed",
                            Severity::Warning,
                            "coredump_monitor",
                            "core_pattern がベースラインから変更されました",
                        )
                        .with_details(details),
                    );
                }
                has_changes = true;
            }
        }

        // 3. suid_dumpable: 0 以外 → High
        if let Some(ref dumpable) = current.suid_dumpable
            && dumpable != "0"
        {
            let details = format!("suid_dumpable={}", dumpable);
            tracing::warn!(
                suid_dumpable = %dumpable,
                "suid_dumpable が安全でない値に設定されています"
            );
            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        "coredump_suid_dumpable_unsafe",
                        Severity::Critical,
                        "coredump_monitor",
                        "suid_dumpable が安全でない値に設定されています",
                    )
                    .with_details(details),
                );
            }
            has_changes = true;
        }

        // 4. core_pipe_limit: ベースラインから変更 → Medium
        if let Some(ref limit) = current.core_pipe_limit
            && baseline.core_pipe_limit.as_ref() != Some(limit)
        {
            let details = format!(
                "旧値={}, 新値={}",
                baseline.core_pipe_limit.as_deref().unwrap_or("(未設定)"),
                limit
            );
            tracing::warn!(
                old_value = baseline.core_pipe_limit.as_deref().unwrap_or("(未設定)"),
                new_value = %limit,
                "core_pipe_limit がベースラインから変更されました"
            );
            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        "coredump_pipe_limit_changed",
                        Severity::Warning,
                        "coredump_monitor",
                        "core_pipe_limit がベースラインから変更されました",
                    )
                    .with_details(details),
                );
            }
            has_changes = true;
        }

        has_changes
    }
}

impl Module for CoredumpMonitorModule {
    fn name(&self) -> &str {
        "coredump_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            proc_path = %self.config.proc_path,
            "コアダンプ設定監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        let proc_path = self.config.proc_path.clone();
        let scan_interval_secs = self.config.scan_interval_secs;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        let baseline = take_snapshot(Path::new(&proc_path));
        tracing::info!("コアダンプ設定ベースラインスキャンが完了しました");

        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            interval.tick().await;

            let mut baseline = baseline;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("コアダンプ設定監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = take_snapshot(Path::new(&proc_path));
                        let changed = CoredumpMonitorModule::detect_and_report(
                            &baseline, &current, &event_bus,
                        );

                        if changed {
                            baseline = current;
                        } else {
                            tracing::debug!("コアダンプ設定に変更はありません");
                        }
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();
        let proc_path = Path::new(&self.config.proc_path);
        let snapshot = take_snapshot(proc_path);

        let mut items_scanned = 0;
        let mut issues_found = 0;
        let mut scan_snapshot: BTreeMap<String, String> = BTreeMap::new();

        if let Some(ref pattern) = snapshot.core_pattern {
            items_scanned += 1;
            scan_snapshot.insert("coredump:core_pattern".to_string(), pattern.clone());

            tracing::info!(
                core_pattern = %pattern,
                "起動時スキャン: core_pattern を検出"
            );

            if pattern.starts_with('|') || pattern.trim().starts_with('|') {
                tracing::warn!(
                    core_pattern = %pattern,
                    "起動時スキャン: core_pattern にパイプコマンドが設定されています"
                );
                if let Some(bus) = &self.event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "coredump_startup_pipe_command",
                            Severity::Critical,
                            "coredump_monitor",
                            "起動時スキャン: core_pattern にパイプコマンドが設定されています",
                        )
                        .with_details(format!("core_pattern={}", pattern)),
                    );
                }
                issues_found += 1;
            }
        }

        if let Some(ref limit) = snapshot.core_pipe_limit {
            items_scanned += 1;
            scan_snapshot.insert("coredump:core_pipe_limit".to_string(), limit.clone());

            tracing::info!(
                core_pipe_limit = %limit,
                "起動時スキャン: core_pipe_limit を検出"
            );
        }

        if let Some(ref dumpable) = snapshot.suid_dumpable {
            items_scanned += 1;
            scan_snapshot.insert("coredump:suid_dumpable".to_string(), dumpable.clone());

            tracing::info!(
                suid_dumpable = %dumpable,
                "起動時スキャン: suid_dumpable を検出"
            );

            if dumpable != "0" {
                tracing::warn!(
                    suid_dumpable = %dumpable,
                    "起動時スキャン: suid_dumpable が安全でない値に設定されています"
                );
                if let Some(bus) = &self.event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "coredump_startup_suid_dumpable_unsafe",
                            Severity::Critical,
                            "coredump_monitor",
                            "起動時スキャン: suid_dumpable が安全でない値に設定されています",
                        )
                        .with_details(format!("suid_dumpable={}", dumpable)),
                    );
                }
                issues_found += 1;
            }
        }

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "コアダンプ設定 {}件をスキャン（うち{}件が要注意）",
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

    fn create_proc_file(dir: &TempDir, relative: &str, value: &str) {
        let full_path = dir.path().join(relative);
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(full_path, format!("{}\n", value)).unwrap();
    }

    fn default_config_with_path(proc_path: &str) -> CoredumpMonitorConfig {
        CoredumpMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            proc_path: proc_path.to_string(),
        }
    }

    #[test]
    fn test_read_proc_file() {
        let dir = TempDir::new().unwrap();
        create_proc_file(&dir, "sys/kernel/core_pattern", "core");
        let result = read_proc_file(dir.path(), "sys/kernel/core_pattern");
        assert_eq!(result, Some("core".to_string()));
    }

    #[test]
    fn test_read_proc_file_nonexistent() {
        let dir = TempDir::new().unwrap();
        let result = read_proc_file(dir.path(), "sys/kernel/nonexistent");
        assert_eq!(result, None);
    }

    #[test]
    fn test_take_snapshot() {
        let dir = TempDir::new().unwrap();
        create_proc_file(&dir, "sys/kernel/core_pattern", "core");
        create_proc_file(&dir, "sys/kernel/core_pipe_limit", "0");
        create_proc_file(&dir, "sys/fs/suid_dumpable", "0");

        let snapshot = take_snapshot(dir.path());
        assert_eq!(snapshot.core_pattern, Some("core".to_string()));
        assert_eq!(snapshot.core_pipe_limit, Some("0".to_string()));
        assert_eq!(snapshot.suid_dumpable, Some("0".to_string()));
    }

    #[test]
    fn test_detect_no_changes() {
        let snapshot = CoredumpSnapshot {
            core_pattern: Some("core".to_string()),
            core_pipe_limit: Some("0".to_string()),
            suid_dumpable: Some("0".to_string()),
        };
        assert!(!CoredumpMonitorModule::detect_and_report(
            &snapshot, &snapshot, &None,
        ));
    }

    #[test]
    fn test_detect_pipe_command() {
        let baseline = CoredumpSnapshot {
            core_pattern: Some("core".to_string()),
            core_pipe_limit: Some("0".to_string()),
            suid_dumpable: Some("0".to_string()),
        };
        let current = CoredumpSnapshot {
            core_pattern: Some("|/usr/bin/malicious".to_string()),
            core_pipe_limit: Some("0".to_string()),
            suid_dumpable: Some("0".to_string()),
        };
        assert!(CoredumpMonitorModule::detect_and_report(
            &baseline, &current, &None,
        ));
    }

    #[test]
    fn test_detect_core_pattern_changed() {
        let baseline = CoredumpSnapshot {
            core_pattern: Some("core".to_string()),
            core_pipe_limit: Some("0".to_string()),
            suid_dumpable: Some("0".to_string()),
        };
        let current = CoredumpSnapshot {
            core_pattern: Some("/tmp/cores/%e.%p".to_string()),
            core_pipe_limit: Some("0".to_string()),
            suid_dumpable: Some("0".to_string()),
        };
        assert!(CoredumpMonitorModule::detect_and_report(
            &baseline, &current, &None,
        ));
    }

    #[test]
    fn test_detect_suid_dumpable_unsafe() {
        let baseline = CoredumpSnapshot {
            core_pattern: Some("core".to_string()),
            core_pipe_limit: Some("0".to_string()),
            suid_dumpable: Some("0".to_string()),
        };
        let current = CoredumpSnapshot {
            core_pattern: Some("core".to_string()),
            core_pipe_limit: Some("0".to_string()),
            suid_dumpable: Some("2".to_string()),
        };
        assert!(CoredumpMonitorModule::detect_and_report(
            &baseline, &current, &None,
        ));
    }

    #[test]
    fn test_detect_pipe_limit_changed() {
        let baseline = CoredumpSnapshot {
            core_pattern: Some("core".to_string()),
            core_pipe_limit: Some("0".to_string()),
            suid_dumpable: Some("0".to_string()),
        };
        let current = CoredumpSnapshot {
            core_pattern: Some("core".to_string()),
            core_pipe_limit: Some("16".to_string()),
            suid_dumpable: Some("0".to_string()),
        };
        assert!(CoredumpMonitorModule::detect_and_report(
            &baseline, &current, &None,
        ));
    }

    #[test]
    fn test_init_valid() {
        let dir = TempDir::new().unwrap();
        let config = default_config_with_path(dir.path().to_str().unwrap());
        let mut module = CoredumpMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[test]
    fn test_init_zero_interval() {
        let config = CoredumpMonitorConfig {
            scan_interval_secs: 0,
            ..Default::default()
        };
        let mut module = CoredumpMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let dir = TempDir::new().unwrap();
        create_proc_file(&dir, "sys/kernel/core_pattern", "core");
        create_proc_file(&dir, "sys/kernel/core_pipe_limit", "0");
        create_proc_file(&dir, "sys/fs/suid_dumpable", "0");

        let config = default_config_with_path(dir.path().to_str().unwrap());
        let mut module = CoredumpMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let dir = TempDir::new().unwrap();
        create_proc_file(&dir, "sys/kernel/core_pattern", "core");
        create_proc_file(&dir, "sys/kernel/core_pipe_limit", "0");
        create_proc_file(&dir, "sys/fs/suid_dumpable", "0");

        let config = default_config_with_path(dir.path().to_str().unwrap());
        let module = CoredumpMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 3);
        assert_eq!(result.issues_found, 0);
        assert!(result.summary.contains("コアダンプ設定"));
        assert!(result.snapshot.contains_key("coredump:core_pattern"));
        assert!(result.snapshot.contains_key("coredump:core_pipe_limit"));
        assert!(result.snapshot.contains_key("coredump:suid_dumpable"));
    }

    #[tokio::test]
    async fn test_initial_scan_detects_pipe_command() {
        let dir = TempDir::new().unwrap();
        create_proc_file(&dir, "sys/kernel/core_pattern", "|/usr/bin/malicious");
        create_proc_file(&dir, "sys/kernel/core_pipe_limit", "0");
        create_proc_file(&dir, "sys/fs/suid_dumpable", "0");

        let config = default_config_with_path(dir.path().to_str().unwrap());
        let module = CoredumpMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.issues_found, 1);
    }

    #[tokio::test]
    async fn test_initial_scan_detects_suid_dumpable() {
        let dir = TempDir::new().unwrap();
        create_proc_file(&dir, "sys/kernel/core_pattern", "core");
        create_proc_file(&dir, "sys/kernel/core_pipe_limit", "0");
        create_proc_file(&dir, "sys/fs/suid_dumpable", "2");

        let config = default_config_with_path(dir.path().to_str().unwrap());
        let module = CoredumpMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.issues_found, 1);
    }
}
