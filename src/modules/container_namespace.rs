//! コンテナ・名前空間検知モジュール
//!
//! `/proc/self/ns/` の名前空間 inode と `/proc/self/cgroup` を定期スキャンし、
//! コンテナブレイクアウトや名前空間の不正操作を検知する。
//!
//! 検知対象:
//! - 名前空間 inode の変化（コンテナブレイクアウト・名前空間操作の疑い）
//! - cgroup パスの変化（cgroup エスケープの疑い）
//! - コンテナ環境マーカー（`/.dockerenv`, `/run/.containerenv`）の出現・消失

use crate::config::ContainerNamespaceConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::BTreeMap;
use std::path::Path;
use tokio_util::sync::CancellationToken;

/// 既知のコンテナ環境マーカーファイル
const CONTAINER_MARKER_FILES: &[&str] = &["/.dockerenv", "/run/.containerenv"];

/// 名前空間のスナップショット（名前空間名 → inode 番号）
#[derive(Debug, Clone, PartialEq, Eq)]
struct NamespaceSnapshot {
    /// 各名前空間の inode 番号
    namespaces: BTreeMap<String, u64>,
    /// cgroup の内容（パス情報）
    cgroup_content: String,
    /// コンテナ環境マーカーの存在状況
    container_markers: BTreeMap<String, bool>,
}

/// `/proc/self/ns/{name}` の inode 番号を取得する
fn read_namespace_inode(ns_dir: &Path, ns_name: &str) -> Option<u64> {
    let ns_path = ns_dir.join(ns_name);
    let metadata = match std::fs::symlink_metadata(&ns_path) {
        Ok(m) => m,
        Err(_) => return None,
    };
    // inode 番号を取得
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(metadata.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

/// cgroup ファイルの内容を読み取る
fn read_cgroup_content(proc_path: &Path) -> String {
    let cgroup_path = proc_path.join("self/cgroup");
    std::fs::read_to_string(&cgroup_path).unwrap_or_default()
}

/// コンテナ環境マーカーの存在を確認する
fn check_container_markers() -> BTreeMap<String, bool> {
    CONTAINER_MARKER_FILES
        .iter()
        .map(|&path| (path.to_string(), Path::new(path).exists()))
        .collect()
}

/// 名前空間・cgroup・コンテナマーカーのスナップショットを取得する
fn take_snapshot(
    proc_path: &Path,
    watch_namespaces: &[String],
    check_container_env: bool,
) -> NamespaceSnapshot {
    let ns_dir = proc_path.join("self/ns");

    let mut namespaces = BTreeMap::new();
    for ns_name in watch_namespaces {
        if let Some(inode) = read_namespace_inode(&ns_dir, ns_name) {
            namespaces.insert(ns_name.clone(), inode);
        }
    }

    let cgroup_content = read_cgroup_content(proc_path);

    let container_markers = if check_container_env {
        check_container_markers()
    } else {
        BTreeMap::new()
    };

    NamespaceSnapshot {
        namespaces,
        cgroup_content,
        container_markers,
    }
}

/// コンテナ・名前空間検知モジュール
///
/// `/proc/self/ns/` と `/proc/self/cgroup` を定期スキャンし、
/// コンテナブレイクアウトや名前空間の不正操作を検知する。
pub struct ContainerNamespaceModule {
    config: ContainerNamespaceConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl ContainerNamespaceModule {
    /// 新しいコンテナ・名前空間検知モジュールを作成する
    pub fn new(config: ContainerNamespaceConfig, event_bus: Option<EventBus>) -> Self {
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
        baseline: &NamespaceSnapshot,
        current: &NamespaceSnapshot,
        event_bus: &Option<EventBus>,
    ) -> bool {
        let mut has_changes = false;

        // 名前空間 inode の変化検知
        for (ns_name, current_inode) in &current.namespaces {
            if let Some(baseline_inode) = baseline.namespaces.get(ns_name)
                && baseline_inode != current_inode
            {
                let details = format!(
                    "名前空間={}, 旧inode={}, 新inode={}",
                    ns_name, baseline_inode, current_inode
                );
                tracing::warn!(
                    namespace = %ns_name,
                    old_inode = baseline_inode,
                    new_inode = current_inode,
                    "名前空間の inode が変化しました（コンテナブレイクアウト/名前空間操作の疑い）"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "namespace_inode_changed",
                            Severity::Critical,
                            "container_namespace",
                            "名前空間の inode が変化しました（コンテナブレイクアウト/名前空間操作の疑い）",
                        )
                        .with_details(details),
                    );
                }
                has_changes = true;
            }
        }

        // cgroup パスの変化検知
        if baseline.cgroup_content != current.cgroup_content {
            let details = format!(
                "旧cgroup:\n{}\n新cgroup:\n{}",
                baseline.cgroup_content.trim(),
                current.cgroup_content.trim()
            );
            tracing::warn!("cgroup パスが変化しました（cgroup エスケープの疑い）");
            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        "cgroup_path_changed",
                        Severity::Critical,
                        "container_namespace",
                        "cgroup パスが変化しました（cgroup エスケープの疑い）",
                    )
                    .with_details(details),
                );
            }
            has_changes = true;
        }

        // コンテナ環境マーカーの出現・消失検知
        for (marker, &current_exists) in &current.container_markers {
            let baseline_exists = baseline
                .container_markers
                .get(marker)
                .copied()
                .unwrap_or(false);

            if !baseline_exists && current_exists {
                let details = format!("コンテナマーカー {} が出現しました", marker);
                tracing::warn!(
                    marker = %marker,
                    "コンテナ環境マーカーが出現しました（環境変化）"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "container_env_appeared",
                            Severity::Warning,
                            "container_namespace",
                            "コンテナ環境マーカーが出現しました",
                        )
                        .with_details(details),
                    );
                }
                has_changes = true;
            } else if baseline_exists && !current_exists {
                let details = format!("コンテナマーカー {} が消失しました", marker);
                tracing::warn!(
                    marker = %marker,
                    "コンテナ環境マーカーが消失しました（環境変化）"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "container_env_disappeared",
                            Severity::Warning,
                            "container_namespace",
                            "コンテナ環境マーカーが消失しました",
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

impl Module for ContainerNamespaceModule {
    fn name(&self) -> &str {
        "container_namespace"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        if self.config.watch_namespaces.is_empty() {
            return Err(AppError::ModuleConfig {
                message: "watch_namespaces に少なくとも 1 つの名前空間を指定してください"
                    .to_string(),
            });
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            watch_namespaces = ?self.config.watch_namespaces,
            check_container_env = self.config.check_container_env,
            "コンテナ・名前空間検知モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        let baseline = take_snapshot(
            Path::new("/proc"),
            &self.config.watch_namespaces,
            self.config.check_container_env,
        );
        tracing::info!(
            namespace_count = baseline.namespaces.len(),
            cgroup_lines = baseline.cgroup_content.lines().count(),
            "コンテナ・名前空間ベースラインスキャンが完了しました"
        );

        let watch_namespaces = self.config.watch_namespaces.clone();
        let check_container_env = self.config.check_container_env;
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
                        tracing::info!("コンテナ・名前空間検知モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = take_snapshot(
                            Path::new("/proc"),
                            &watch_namespaces,
                            check_container_env,
                        );
                        let changed = ContainerNamespaceModule::detect_and_report(
                            &baseline, &current, &event_bus,
                        );

                        if changed {
                            baseline = current;
                        } else {
                            tracing::debug!("コンテナ・名前空間に変更はありません");
                        }
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();
        let snapshot = take_snapshot(
            Path::new("/proc"),
            &self.config.watch_namespaces,
            self.config.check_container_env,
        );

        let items_scanned = snapshot.namespaces.len() + snapshot.container_markers.len() + 1; // +1 for cgroup
        let mut issues_found = 0;

        // 名前空間情報をログに記録
        for (ns_name, inode) in &snapshot.namespaces {
            tracing::info!(
                namespace = %ns_name,
                inode = inode,
                "起動時スキャン: 名前空間を検出"
            );
        }

        // コンテナ環境マーカーの確認
        for (marker, &exists) in &snapshot.container_markers {
            if exists {
                tracing::warn!(
                    marker = %marker,
                    "起動時スキャン: コンテナ環境マーカーを検出"
                );
                if let Some(bus) = &self.event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "container_ns_startup_detected",
                            Severity::Info,
                            "container_namespace",
                            "起動時スキャン: コンテナ環境マーカーを検出",
                        )
                        .with_details(format!("マーカー: {}", marker)),
                    );
                }
                issues_found += 1;
            }
        }

        // スナップショットデータの構築
        let mut scan_snapshot: BTreeMap<String, String> = snapshot
            .namespaces
            .iter()
            .map(|(name, inode)| (format!("ns:{}", name), inode.to_string()))
            .collect();

        scan_snapshot.insert("cgroup".to_string(), snapshot.cgroup_content.clone());

        for (marker, &exists) in &snapshot.container_markers {
            scan_snapshot.insert(format!("marker:{}", marker), exists.to_string());
        }

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "名前空間 {}件、cgroup 1件、コンテナマーカー {}件を検出（うち{}件が要注意）",
                snapshot.namespaces.len(),
                snapshot.container_markers.values().filter(|&&v| v).count(),
                issues_found
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

    fn default_config() -> ContainerNamespaceConfig {
        ContainerNamespaceConfig {
            enabled: true,
            scan_interval_secs: 30,
            watch_namespaces: vec![
                "mnt".to_string(),
                "pid".to_string(),
                "net".to_string(),
                "ipc".to_string(),
                "uts".to_string(),
                "user".to_string(),
                "cgroup".to_string(),
            ],
            check_container_env: true,
        }
    }

    #[test]
    fn test_check_container_markers() {
        let markers = check_container_markers();
        // テスト環境ではコンテナマーカーは通常存在しない
        assert!(markers.contains_key("/.dockerenv"));
        assert!(markers.contains_key("/run/.containerenv"));
    }

    #[test]
    fn test_read_cgroup_content() {
        let content = read_cgroup_content(Path::new("/proc"));
        // Linux 環境では cgroup 情報が存在する
        // 非 Linux 環境では空文字列が返る
        if cfg!(target_os = "linux") {
            assert!(!content.is_empty());
        }
    }

    #[test]
    fn test_read_namespace_inode_valid() {
        let ns_dir = Path::new("/proc/self/ns");
        if ns_dir.exists() {
            let inode = read_namespace_inode(ns_dir, "pid");
            // Linux 環境では inode が取得できる
            if cfg!(target_os = "linux") {
                assert!(inode.is_some());
                assert!(inode.unwrap() > 0);
            }
        }
    }

    #[test]
    fn test_read_namespace_inode_nonexistent() {
        let inode = read_namespace_inode(Path::new("/nonexistent"), "pid");
        assert!(inode.is_none());
    }

    #[test]
    fn test_take_snapshot() {
        let snapshot = take_snapshot(
            Path::new("/proc"),
            &["pid".to_string(), "net".to_string()],
            true,
        );
        // Linux 環境では名前空間が取得できる
        if cfg!(target_os = "linux") {
            assert!(!snapshot.namespaces.is_empty());
        }
        assert!(snapshot.container_markers.contains_key("/.dockerenv"));
    }

    #[test]
    fn test_take_snapshot_no_container_check() {
        let snapshot = take_snapshot(Path::new("/proc"), &["pid".to_string()], false);
        assert!(snapshot.container_markers.is_empty());
    }

    #[test]
    fn test_detect_no_changes() {
        let snapshot = NamespaceSnapshot {
            namespaces: BTreeMap::from([("pid".to_string(), 12345), ("net".to_string(), 67890)]),
            cgroup_content: "0::/system.slice/test.service\n".to_string(),
            container_markers: BTreeMap::from([("/.dockerenv".to_string(), false)]),
        };

        assert!(!ContainerNamespaceModule::detect_and_report(
            &snapshot, &snapshot, &None,
        ));
    }

    #[test]
    fn test_detect_namespace_inode_changed() {
        let baseline = NamespaceSnapshot {
            namespaces: BTreeMap::from([("pid".to_string(), 12345)]),
            cgroup_content: "0::/\n".to_string(),
            container_markers: BTreeMap::new(),
        };
        let current = NamespaceSnapshot {
            namespaces: BTreeMap::from([("pid".to_string(), 99999)]),
            cgroup_content: "0::/\n".to_string(),
            container_markers: BTreeMap::new(),
        };

        assert!(ContainerNamespaceModule::detect_and_report(
            &baseline, &current, &None,
        ));
    }

    #[test]
    fn test_detect_cgroup_path_changed() {
        let baseline = NamespaceSnapshot {
            namespaces: BTreeMap::new(),
            cgroup_content: "0::/system.slice/test.service\n".to_string(),
            container_markers: BTreeMap::new(),
        };
        let current = NamespaceSnapshot {
            namespaces: BTreeMap::new(),
            cgroup_content: "0::/docker/abc123\n".to_string(),
            container_markers: BTreeMap::new(),
        };

        assert!(ContainerNamespaceModule::detect_and_report(
            &baseline, &current, &None,
        ));
    }

    #[test]
    fn test_detect_container_marker_appeared() {
        let baseline = NamespaceSnapshot {
            namespaces: BTreeMap::new(),
            cgroup_content: "".to_string(),
            container_markers: BTreeMap::from([("/.dockerenv".to_string(), false)]),
        };
        let current = NamespaceSnapshot {
            namespaces: BTreeMap::new(),
            cgroup_content: "".to_string(),
            container_markers: BTreeMap::from([("/.dockerenv".to_string(), true)]),
        };

        assert!(ContainerNamespaceModule::detect_and_report(
            &baseline, &current, &None,
        ));
    }

    #[test]
    fn test_detect_container_marker_disappeared() {
        let baseline = NamespaceSnapshot {
            namespaces: BTreeMap::new(),
            cgroup_content: "".to_string(),
            container_markers: BTreeMap::from([("/.dockerenv".to_string(), true)]),
        };
        let current = NamespaceSnapshot {
            namespaces: BTreeMap::new(),
            cgroup_content: "".to_string(),
            container_markers: BTreeMap::from([("/.dockerenv".to_string(), false)]),
        };

        assert!(ContainerNamespaceModule::detect_and_report(
            &baseline, &current, &None,
        ));
    }

    #[test]
    fn test_init_zero_interval() {
        let config = ContainerNamespaceConfig {
            enabled: true,
            scan_interval_secs: 0,
            watch_namespaces: vec!["pid".to_string()],
            check_container_env: true,
        };
        let mut module = ContainerNamespaceModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_empty_namespaces() {
        let config = ContainerNamespaceConfig {
            enabled: true,
            scan_interval_secs: 30,
            watch_namespaces: vec![],
            check_container_env: true,
        };
        let mut module = ContainerNamespaceModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let mut module = ContainerNamespaceModule::new(default_config(), None);
        assert!(module.init().is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let mut module = ContainerNamespaceModule::new(default_config(), None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let module = ContainerNamespaceModule::new(default_config(), None);

        let result = module.initial_scan().await.unwrap();
        assert!(result.summary.contains("名前空間"));
        assert!(result.items_scanned > 0);
    }

    #[test]
    fn test_take_snapshot_nonexistent_proc() {
        let snapshot = take_snapshot(Path::new("/nonexistent_proc"), &["pid".to_string()], true);
        assert!(snapshot.namespaces.is_empty());
        assert!(snapshot.cgroup_content.is_empty());
    }
}
