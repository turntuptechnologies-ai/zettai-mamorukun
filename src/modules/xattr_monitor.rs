//! ファイルシステム xattr（拡張属性）監視モジュール
//!
//! 指定パスの拡張属性（xattr）を定期スキャンし、
//! SELinux ラベル、capabilities 属性、ACL 等の不正変更を検知する。
//!
//! 検知対象:
//! - `security.*` 属性の変更（SELinux コンテキスト、capabilities）— High
//! - `system.*` 属性の変更（POSIX ACL）— Medium
//! - `user.*` 属性の変更 — Low
//! - 属性の追加・削除

use crate::config::XattrMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;

/// ファイルごとの xattr 情報
#[derive(Debug, Clone, PartialEq, Eq)]
struct XattrFileInfo {
    /// 属性名 → 値（バイナリ）
    attrs: BTreeMap<String, Vec<u8>>,
}

/// xattr スナップショット
struct XattrSnapshot {
    /// ファイルパスごとの xattr 情報
    files: HashMap<PathBuf, XattrFileInfo>,
}

/// ファイルシステム xattr（拡張属性）監視モジュール
///
/// 指定パスの拡張属性を定期スキャンし、変更・追加・削除を検知する。
pub struct XattrMonitorModule {
    config: XattrMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl XattrMonitorModule {
    /// 新しい xattr 監視モジュールを作成する
    pub fn new(config: XattrMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// 属性名が監視対象の名前空間に属するかを判定する
    fn matches_namespace(attr_name: &str, namespaces: &[String]) -> bool {
        namespaces
            .iter()
            .any(|ns| attr_name.starts_with(&format!("{ns}.")))
    }

    /// 属性名から Severity を決定する
    ///
    /// - `security.*` → Critical（SELinux, capabilities 改ざんは重大）
    /// - `system.*` → Warning（ACL 変更は警告）
    /// - `user.*` → Info（ユーザー定義属性は情報レベル）
    fn severity_for_attr(attr_name: &str) -> Severity {
        if attr_name.starts_with("security.") {
            Severity::Critical
        } else if attr_name.starts_with("system.") {
            Severity::Warning
        } else {
            Severity::Info
        }
    }

    /// 属性名からイベントタイプを決定する
    fn event_type_for_attr(attr_name: &str) -> &'static str {
        if attr_name.starts_with("security.") {
            "xattr_security_changed"
        } else if attr_name.starts_with("system.") {
            "xattr_system_changed"
        } else {
            "xattr_user_changed"
        }
    }

    /// 指定パスの xattr を読み取る
    fn read_xattrs(path: &Path, namespaces: &[String]) -> Option<XattrFileInfo> {
        let attr_names = match xattr::list(path) {
            Ok(names) => names,
            Err(_) => return None,
        };

        let mut attrs = BTreeMap::new();
        for name in attr_names {
            let name_str = name.to_string_lossy().to_string();
            if !Self::matches_namespace(&name_str, namespaces) {
                continue;
            }
            match xattr::get(path, &name) {
                Ok(Some(value)) => {
                    attrs.insert(name_str, value);
                }
                Ok(None) => {
                    attrs.insert(name_str, Vec::new());
                }
                Err(_) => continue,
            }
        }

        if attrs.is_empty() {
            None
        } else {
            Some(XattrFileInfo { attrs })
        }
    }

    /// 監視対象パスをスキャンし、スナップショットを返す
    fn scan_paths(watch_paths: &[PathBuf], namespaces: &[String]) -> XattrSnapshot {
        let mut files = HashMap::new();

        for watch_path in watch_paths {
            if !watch_path.exists() {
                tracing::debug!(
                    path = %watch_path.display(),
                    "監視対象パスが存在しません。スキップします"
                );
                continue;
            }

            if watch_path.is_file() {
                if let Some(info) = Self::read_xattrs(watch_path, namespaces) {
                    files.insert(watch_path.clone(), info);
                }
            } else if watch_path.is_dir() {
                Self::scan_dir_recursive(watch_path, namespaces, &mut files);
            }
        }

        XattrSnapshot { files }
    }

    /// ディレクトリを再帰的にスキャンする
    fn scan_dir_recursive(
        dir: &Path,
        namespaces: &[String],
        files: &mut HashMap<PathBuf, XattrFileInfo>,
    ) {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(err) => {
                tracing::debug!(
                    error = %err,
                    dir = %dir.display(),
                    "ディレクトリの読み取りに失敗しました"
                );
                return;
            }
        };

        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            let metadata = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };

            if metadata.is_file() {
                if let Some(info) = Self::read_xattrs(&path, namespaces) {
                    files.insert(path, info);
                }
            } else if metadata.is_dir() {
                // シンボリックリンクのディレクトリは追跡しない
                if !metadata.file_type().is_symlink() {
                    Self::scan_dir_recursive(&path, namespaces, files);
                }
            }
        }
    }

    /// ベースラインと現在のスナップショットを比較し、変更を検知する。
    /// 変更があった場合は `true` を返す。
    fn detect_and_report(
        baseline: &XattrSnapshot,
        current: &XattrSnapshot,
        event_bus: &Option<EventBus>,
    ) -> bool {
        let mut has_changes = false;

        // 現在のスナップショットを走査して、追加・変更を検知
        for (path, current_info) in &current.files {
            match baseline.files.get(path) {
                Some(baseline_info) => {
                    // 既存ファイルの属性変更を検知
                    for (attr_name, current_value) in &current_info.attrs {
                        match baseline_info.attrs.get(attr_name) {
                            Some(baseline_value) if baseline_value != current_value => {
                                // 属性値が変更された
                                let severity = Self::severity_for_attr(attr_name);
                                let event_type = Self::event_type_for_attr(attr_name);
                                tracing::warn!(
                                    path = %path.display(),
                                    attr = %attr_name,
                                    severity = %severity,
                                    "拡張属性が変更されました"
                                );
                                if let Some(bus) = event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            event_type,
                                            severity,
                                            "xattr_monitor",
                                            "拡張属性が変更されました",
                                        )
                                        .with_details(
                                            format!(
                                                "path={}, attr={}, old_len={}, new_len={}",
                                                path.display(),
                                                attr_name,
                                                baseline_value.len(),
                                                current_value.len()
                                            ),
                                        ),
                                    );
                                }
                                has_changes = true;
                            }
                            None => {
                                // 新しい属性が追加された
                                let severity = Self::severity_for_attr(attr_name);
                                let event_type = Self::event_type_for_attr(attr_name);
                                tracing::warn!(
                                    path = %path.display(),
                                    attr = %attr_name,
                                    severity = %severity,
                                    "拡張属性が追加されました"
                                );
                                if let Some(bus) = event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            event_type,
                                            severity,
                                            "xattr_monitor",
                                            "拡張属性が追加されました",
                                        )
                                        .with_details(
                                            format!(
                                                "path={}, attr={}, value_len={}",
                                                path.display(),
                                                attr_name,
                                                current_value.len()
                                            ),
                                        ),
                                    );
                                }
                                has_changes = true;
                            }
                            _ => {} // 値が同一 — 変更なし
                        }
                    }

                    // 削除された属性を検知
                    for attr_name in baseline_info.attrs.keys() {
                        if !current_info.attrs.contains_key(attr_name) {
                            let severity = Self::severity_for_attr(attr_name);
                            let event_type = Self::event_type_for_attr(attr_name);
                            tracing::warn!(
                                path = %path.display(),
                                attr = %attr_name,
                                severity = %severity,
                                "拡張属性が削除されました"
                            );
                            if let Some(bus) = event_bus {
                                bus.publish(
                                    SecurityEvent::new(
                                        event_type,
                                        severity,
                                        "xattr_monitor",
                                        "拡張属性が削除されました",
                                    )
                                    .with_details(format!(
                                        "path={}, attr={}",
                                        path.display(),
                                        attr_name
                                    )),
                                );
                            }
                            has_changes = true;
                        }
                    }
                }
                None => {
                    // 新しいファイルに xattr が出現
                    for attr_name in current_info.attrs.keys() {
                        let severity = Self::severity_for_attr(attr_name);
                        let event_type = Self::event_type_for_attr(attr_name);
                        tracing::info!(
                            path = %path.display(),
                            attr = %attr_name,
                            "新しいファイルに拡張属性が検出されました"
                        );
                        if let Some(bus) = event_bus {
                            bus.publish(
                                SecurityEvent::new(
                                    event_type,
                                    severity,
                                    "xattr_monitor",
                                    "新しいファイルに拡張属性が検出されました",
                                )
                                .with_details(format!(
                                    "path={}, attr={}",
                                    path.display(),
                                    attr_name
                                )),
                            );
                        }
                        has_changes = true;
                    }
                }
            }
        }

        // ベースラインにあるが現在はないファイルを検知
        for (path, baseline_info) in &baseline.files {
            if !current.files.contains_key(path) {
                for attr_name in baseline_info.attrs.keys() {
                    let severity = Self::severity_for_attr(attr_name);
                    let event_type = Self::event_type_for_attr(attr_name);
                    tracing::warn!(
                        path = %path.display(),
                        attr = %attr_name,
                        "拡張属性を持つファイルが消失しました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                event_type,
                                severity,
                                "xattr_monitor",
                                "拡張属性を持つファイルが消失しました",
                            )
                            .with_details(format!(
                                "path={}, attr={}",
                                path.display(),
                                attr_name
                            )),
                        );
                    }
                    has_changes = true;
                }
            }
        }

        has_changes
    }
}

impl Module for XattrMonitorModule {
    fn name(&self) -> &str {
        "xattr_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        if self.config.watch_paths.is_empty() {
            return Err(AppError::ModuleConfig {
                message: "watch_paths を 1 つ以上指定してください".to_string(),
            });
        }

        if self.config.namespaces.is_empty() {
            return Err(AppError::ModuleConfig {
                message: "namespaces を 1 つ以上指定してください".to_string(),
            });
        }

        tracing::info!(
            watch_paths = ?self.config.watch_paths,
            namespaces = ?self.config.namespaces,
            scan_interval_secs = self.config.scan_interval_secs,
            "xattr 監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<(), AppError> {
        let baseline = Self::scan_paths(&self.config.watch_paths, &self.config.namespaces);
        tracing::info!(
            file_count = baseline.files.len(),
            "xattr ベースラインスキャンが完了しました"
        );

        let watch_paths = self.config.watch_paths.clone();
        let namespaces = self.config.namespaces.clone();
        let scan_interval_secs = self.config.scan_interval_secs;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            interval.tick().await;

            let mut baseline = baseline;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("xattr 監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = XattrMonitorModule::scan_paths(&watch_paths, &namespaces);
                        let changed = XattrMonitorModule::detect_and_report(
                            &baseline,
                            &current,
                            &event_bus,
                        );

                        if changed {
                            baseline = current;
                        } else {
                            tracing::debug!("xattr に変更はありません");
                        }
                    }
                }
            }
        });

        Ok(())
    }

    async fn stop(&mut self) -> Result<(), AppError> {
        self.cancel_token.cancel();
        Ok(())
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();

        let snapshot = Self::scan_paths(&self.config.watch_paths, &self.config.namespaces);

        let mut total_attrs = 0;
        let scan_snapshot: BTreeMap<String, String> = snapshot
            .files
            .iter()
            .flat_map(|(path, info)| {
                total_attrs += info.attrs.len();
                info.attrs.iter().map(move |(attr_name, value)| {
                    (
                        format!("{}:{}", path.display(), attr_name),
                        format!("len={}", value.len()),
                    )
                })
            })
            .collect();

        let items_scanned = snapshot.files.len();
        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found: 0, // 初回スキャンでは問題なし（ベースライン取得のみ）
            duration,
            summary: format!(
                "{}件のファイルから{}件の拡張属性をスキャンしました",
                items_scanned, total_attrs
            ),
            snapshot: scan_snapshot,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn make_config(dir: &std::path::Path) -> XattrMonitorConfig {
        XattrMonitorConfig {
            enabled: true,
            scan_interval_secs: 300,
            watch_paths: vec![dir.to_path_buf()],
            namespaces: vec![
                "security".to_string(),
                "system".to_string(),
                "user".to_string(),
            ],
        }
    }

    #[test]
    fn test_matches_namespace() {
        let namespaces = vec![
            "security".to_string(),
            "system".to_string(),
            "user".to_string(),
        ];
        assert!(XattrMonitorModule::matches_namespace(
            "security.selinux",
            &namespaces
        ));
        assert!(XattrMonitorModule::matches_namespace(
            "system.posix_acl_access",
            &namespaces
        ));
        assert!(XattrMonitorModule::matches_namespace(
            "user.custom",
            &namespaces
        ));
        assert!(!XattrMonitorModule::matches_namespace(
            "trusted.something",
            &namespaces
        ));
    }

    #[test]
    fn test_severity_for_attr() {
        assert_eq!(
            XattrMonitorModule::severity_for_attr("security.selinux"),
            Severity::Critical
        );
        assert_eq!(
            XattrMonitorModule::severity_for_attr("system.posix_acl"),
            Severity::Warning
        );
        assert_eq!(
            XattrMonitorModule::severity_for_attr("user.custom"),
            Severity::Info
        );
    }

    #[test]
    fn test_event_type_for_attr() {
        assert_eq!(
            XattrMonitorModule::event_type_for_attr("security.capability"),
            "xattr_security_changed"
        );
        assert_eq!(
            XattrMonitorModule::event_type_for_attr("system.posix_acl_access"),
            "xattr_system_changed"
        );
        assert_eq!(
            XattrMonitorModule::event_type_for_attr("user.test"),
            "xattr_user_changed"
        );
    }

    #[test]
    fn test_scan_empty_dir() {
        let dir = TempDir::new().unwrap();
        let namespaces = vec!["user".to_string()];
        let snapshot = XattrMonitorModule::scan_paths(&[dir.path().to_path_buf()], &namespaces);
        assert!(snapshot.files.is_empty());
    }

    #[test]
    fn test_scan_nonexistent_path() {
        let namespaces = vec!["user".to_string()];
        let snapshot = XattrMonitorModule::scan_paths(
            &[PathBuf::from("/tmp/nonexistent_zettai_xattr_test")],
            &namespaces,
        );
        assert!(snapshot.files.is_empty());
    }

    #[test]
    fn test_scan_file_without_xattrs() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("regular");
        fs::write(&file_path, "data").unwrap();

        let namespaces = vec!["user".to_string()];
        let snapshot = XattrMonitorModule::scan_paths(&[dir.path().to_path_buf()], &namespaces);
        // 通常のファイルには xattr が無いため空
        assert!(snapshot.files.is_empty());
    }

    #[test]
    fn test_scan_file_with_user_xattr() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("with_xattr");
        fs::write(&file_path, "data").unwrap();

        // user.* xattr を設定（user 名前空間は非特権ユーザーでも設定可能）
        if xattr::set(&file_path, "user.test_attr", b"test_value").is_err() {
            // xattr がサポートされていないファイルシステムの場合はスキップ
            return;
        }

        let namespaces = vec!["user".to_string()];
        let snapshot = XattrMonitorModule::scan_paths(&[dir.path().to_path_buf()], &namespaces);
        assert_eq!(snapshot.files.len(), 1);
        let info = snapshot.files.get(&file_path).unwrap();
        assert_eq!(info.attrs.get("user.test_attr").unwrap(), b"test_value");
    }

    #[test]
    fn test_scan_namespace_filter() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("filtered");
        fs::write(&file_path, "data").unwrap();

        if xattr::set(&file_path, "user.visible", b"yes").is_err() {
            return;
        }

        // user 名前空間のみ監視（security は対象外）
        let namespaces = vec!["security".to_string()];
        let snapshot = XattrMonitorModule::scan_paths(&[dir.path().to_path_buf()], &namespaces);
        // user.visible は security 名前空間ではないのでスナップショットに含まれない
        assert!(snapshot.files.is_empty());
    }

    #[test]
    fn test_detect_no_changes() {
        let mut files = HashMap::new();
        let mut attrs = BTreeMap::new();
        attrs.insert("user.test".to_string(), b"value".to_vec());
        files.insert(PathBuf::from("/test/file"), XattrFileInfo { attrs });

        let baseline = XattrSnapshot {
            files: files.clone(),
        };
        let current = XattrSnapshot { files };
        assert!(!XattrMonitorModule::detect_and_report(
            &baseline, &current, &None
        ));
    }

    #[test]
    fn test_detect_attr_changed() {
        let path = PathBuf::from("/test/file");
        let mut baseline_attrs = BTreeMap::new();
        baseline_attrs.insert("security.selinux".to_string(), b"old_context".to_vec());
        let mut baseline_files = HashMap::new();
        baseline_files.insert(
            path.clone(),
            XattrFileInfo {
                attrs: baseline_attrs,
            },
        );

        let mut current_attrs = BTreeMap::new();
        current_attrs.insert("security.selinux".to_string(), b"new_context".to_vec());
        let mut current_files = HashMap::new();
        current_files.insert(
            path,
            XattrFileInfo {
                attrs: current_attrs,
            },
        );

        let baseline = XattrSnapshot {
            files: baseline_files,
        };
        let current = XattrSnapshot {
            files: current_files,
        };
        assert!(XattrMonitorModule::detect_and_report(
            &baseline, &current, &None
        ));
    }

    #[test]
    fn test_detect_attr_added() {
        let path = PathBuf::from("/test/file");
        let mut baseline_attrs = BTreeMap::new();
        baseline_attrs.insert("user.existing".to_string(), b"value".to_vec());
        let mut baseline_files = HashMap::new();
        baseline_files.insert(
            path.clone(),
            XattrFileInfo {
                attrs: baseline_attrs,
            },
        );

        let mut current_attrs = BTreeMap::new();
        current_attrs.insert("user.existing".to_string(), b"value".to_vec());
        current_attrs.insert("security.capability".to_string(), b"cap_data".to_vec());
        let mut current_files = HashMap::new();
        current_files.insert(
            path,
            XattrFileInfo {
                attrs: current_attrs,
            },
        );

        let baseline = XattrSnapshot {
            files: baseline_files,
        };
        let current = XattrSnapshot {
            files: current_files,
        };
        assert!(XattrMonitorModule::detect_and_report(
            &baseline, &current, &None
        ));
    }

    #[test]
    fn test_detect_attr_removed() {
        let path = PathBuf::from("/test/file");
        let mut baseline_attrs = BTreeMap::new();
        baseline_attrs.insert("security.selinux".to_string(), b"context".to_vec());
        baseline_attrs.insert("user.custom".to_string(), b"value".to_vec());
        let mut baseline_files = HashMap::new();
        baseline_files.insert(
            path.clone(),
            XattrFileInfo {
                attrs: baseline_attrs,
            },
        );

        let mut current_attrs = BTreeMap::new();
        current_attrs.insert("user.custom".to_string(), b"value".to_vec());
        let mut current_files = HashMap::new();
        current_files.insert(
            path,
            XattrFileInfo {
                attrs: current_attrs,
            },
        );

        let baseline = XattrSnapshot {
            files: baseline_files,
        };
        let current = XattrSnapshot {
            files: current_files,
        };
        assert!(XattrMonitorModule::detect_and_report(
            &baseline, &current, &None
        ));
    }

    #[test]
    fn test_detect_file_removed() {
        let mut baseline_attrs = BTreeMap::new();
        baseline_attrs.insert("security.selinux".to_string(), b"context".to_vec());
        let mut baseline_files = HashMap::new();
        baseline_files.insert(
            PathBuf::from("/test/removed"),
            XattrFileInfo {
                attrs: baseline_attrs,
            },
        );

        let baseline = XattrSnapshot {
            files: baseline_files,
        };
        let current = XattrSnapshot {
            files: HashMap::new(),
        };
        assert!(XattrMonitorModule::detect_and_report(
            &baseline, &current, &None
        ));
    }

    #[test]
    fn test_detect_new_file_with_xattr() {
        let baseline = XattrSnapshot {
            files: HashMap::new(),
        };

        let mut current_attrs = BTreeMap::new();
        current_attrs.insert("system.posix_acl_access".to_string(), b"acl_data".to_vec());
        let mut current_files = HashMap::new();
        current_files.insert(
            PathBuf::from("/test/new_file"),
            XattrFileInfo {
                attrs: current_attrs,
            },
        );
        let current = XattrSnapshot {
            files: current_files,
        };
        assert!(XattrMonitorModule::detect_and_report(
            &baseline, &current, &None
        ));
    }

    #[test]
    fn test_init_zero_interval() {
        let dir = TempDir::new().unwrap();
        let config = XattrMonitorConfig {
            enabled: true,
            scan_interval_secs: 0,
            watch_paths: vec![dir.path().to_path_buf()],
            namespaces: vec!["user".to_string()],
        };
        let mut module = XattrMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_empty_watch_paths() {
        let config = XattrMonitorConfig {
            enabled: true,
            scan_interval_secs: 300,
            watch_paths: vec![],
            namespaces: vec!["user".to_string()],
        };
        let mut module = XattrMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_empty_namespaces() {
        let dir = TempDir::new().unwrap();
        let config = XattrMonitorConfig {
            enabled: true,
            scan_interval_secs: 300,
            watch_paths: vec![dir.path().to_path_buf()],
            namespaces: vec![],
        };
        let mut module = XattrMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let dir = TempDir::new().unwrap();
        let config = make_config(dir.path());
        let mut module = XattrMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let dir = TempDir::new().unwrap();
        let config = XattrMonitorConfig {
            enabled: true,
            scan_interval_secs: 3600,
            watch_paths: vec![dir.path().to_path_buf()],
            namespaces: vec!["user".to_string()],
        };
        let mut module = XattrMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();
        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan_empty() {
        let dir = TempDir::new().unwrap();
        let config = make_config(dir.path());
        let module = XattrMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
    }

    #[tokio::test]
    async fn test_initial_scan_with_xattrs() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("test_file");
        fs::write(&file_path, "data").unwrap();

        if xattr::set(&file_path, "user.test", b"value").is_err() {
            // xattr がサポートされていない場合はスキップ
            return;
        }

        let config = make_config(dir.path());
        let module = XattrMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 1);
        assert_eq!(result.issues_found, 0);
        assert!(!result.snapshot.is_empty());
    }

    #[test]
    fn test_read_xattrs_nonexistent() {
        let result =
            XattrMonitorModule::read_xattrs(Path::new("/nonexistent"), &["user".to_string()]);
        assert!(result.is_none());
    }

    #[test]
    fn test_scan_recursive() {
        let dir = TempDir::new().unwrap();
        let subdir = dir.path().join("subdir");
        fs::create_dir(&subdir).unwrap();

        let file1 = dir.path().join("file1");
        let file2 = subdir.join("file2");
        fs::write(&file1, "data1").unwrap();
        fs::write(&file2, "data2").unwrap();

        if xattr::set(&file1, "user.attr1", b"val1").is_err() {
            return;
        }
        if xattr::set(&file2, "user.attr2", b"val2").is_err() {
            return;
        }

        let namespaces = vec!["user".to_string()];
        let snapshot = XattrMonitorModule::scan_paths(&[dir.path().to_path_buf()], &namespaces);
        assert_eq!(snapshot.files.len(), 2);
    }
}
