//! グループポリシー監視モジュール
//!
//! `/etc/group` と `/etc/gshadow` を定期的にパースし、前回のスナップショットと比較して
//! 不審な変更を検知する。
//!
//! 検知対象:
//! - 新規グループ追加 / グループ削除
//! - GID 0 グループの出現（root 以外） — CRITICAL
//! - GID 変更 / メンバー変更
//! - 特権グループへのメンバー追加 — CRITICAL
//! - gshadow のパスワード・管理者・メンバー変更

use crate::config::GroupMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use tokio_util::sync::CancellationToken;

/// `/etc/group` の 1 エントリを表す
#[derive(Debug, Clone, PartialEq)]
struct GroupEntry {
    name: String,
    gid: u32,
    members: Vec<String>,
}

/// `/etc/gshadow` の 1 エントリを表す
#[derive(Debug, Clone, PartialEq)]
struct GshadowEntry {
    name: String,
    password_hash: String,
    admins: Vec<String>,
    members: Vec<String>,
}

/// グループ情報のスナップショット
struct GroupSnapshot {
    groups: HashMap<String, GroupEntry>,
    gshadow: HashMap<String, GshadowEntry>,
}

/// グループポリシー監視モジュール
///
/// `/etc/group` と `/etc/gshadow` を定期スキャンし、不審な変更を検知する。
pub struct GroupMonitorModule {
    config: GroupMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl GroupMonitorModule {
    /// 新しいグループポリシー監視モジュールを作成する
    pub fn new(config: GroupMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// `/etc/group` の内容をパースする
    fn parse_group(content: &str) -> HashMap<String, GroupEntry> {
        let mut result = HashMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() != 4 {
                tracing::warn!(line = line, "group: フィールド数が不正です。スキップします");
                continue;
            }
            let gid = match fields[2].parse::<u32>() {
                Ok(v) => v,
                Err(_) => {
                    tracing::warn!(
                        line = line,
                        "group: GID のパースに失敗しました。スキップします"
                    );
                    continue;
                }
            };
            let members: Vec<String> = if fields[3].is_empty() {
                Vec::new()
            } else {
                fields[3].split(',').map(|s| s.to_string()).collect()
            };
            let entry = GroupEntry {
                name: fields[0].to_string(),
                gid,
                members,
            };
            result.insert(entry.name.clone(), entry);
        }
        result
    }

    /// `/etc/gshadow` の内容をパースする
    fn parse_gshadow(content: &str) -> HashMap<String, GshadowEntry> {
        let mut result = HashMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() != 4 {
                tracing::warn!(
                    line = line,
                    "gshadow: フィールド数が不正です。スキップします"
                );
                continue;
            }
            let parse_list = |s: &str| -> Vec<String> {
                if s.is_empty() {
                    Vec::new()
                } else {
                    s.split(',').map(|v| v.to_string()).collect()
                }
            };
            let entry = GshadowEntry {
                name: fields[0].to_string(),
                password_hash: fields[1].to_string(),
                admins: parse_list(fields[2]),
                members: parse_list(fields[3]),
            };
            result.insert(entry.name.clone(), entry);
        }
        result
    }

    /// スナップショットを取得する
    fn take_snapshot(group_path: &Path, gshadow_path: &Path) -> Option<GroupSnapshot> {
        let group_content = match std::fs::read_to_string(group_path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    path = %group_path.display(),
                    error = %e,
                    "group ファイルの読み取りに失敗しました"
                );
                return None;
            }
        };

        // gshadow はパーミッションが厳しいため、読み取り失敗は warn で続行
        let gshadow = match std::fs::read_to_string(gshadow_path) {
            Ok(c) => Self::parse_gshadow(&c),
            Err(e) => {
                tracing::warn!(
                    path = %gshadow_path.display(),
                    error = %e,
                    "gshadow ファイルの読み取りに失敗しました。gshadow 監視をスキップします"
                );
                HashMap::new()
            }
        };

        Some(GroupSnapshot {
            groups: Self::parse_group(&group_content),
            gshadow,
        })
    }

    /// 2 つのスナップショットを比較し、変更を検知する。変更があれば true を返す。
    fn detect_changes(
        old: &GroupSnapshot,
        new: &GroupSnapshot,
        privileged_groups: &[String],
        event_bus: &Option<EventBus>,
    ) -> bool {
        let mut changed = false;

        // --- /etc/group の変更検知 ---

        // 新規グループ
        for (name, entry) in &new.groups {
            if !old.groups.contains_key(name) {
                changed = true;
                tracing::warn!(group = %name, gid = entry.gid, "新規グループが追加されました");
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "group_policy_group_added",
                            Severity::Warning,
                            "group_monitor",
                            "新規グループが追加されました",
                        )
                        .with_details(format!("group={}, gid={}", name, entry.gid)),
                    );
                }
            }
        }

        // 削除されたグループ
        for name in old.groups.keys() {
            if !new.groups.contains_key(name) {
                changed = true;
                tracing::warn!(group = %name, "グループが削除されました");
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "group_policy_group_removed",
                            Severity::Warning,
                            "group_monitor",
                            "グループが削除されました",
                        )
                        .with_details(name.clone()),
                    );
                }
            }
        }

        // GID 0 チェック（root 以外）
        for (name, entry) in &new.groups {
            if entry.gid == 0 && name != "root" {
                changed = true;
                tracing::error!(
                    group = %name,
                    "CRITICAL: root 以外のグループが GID 0 を持っています"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "group_policy_gid_zero",
                            Severity::Critical,
                            "group_monitor",
                            "CRITICAL: root 以外のグループが GID 0 を持っています",
                        )
                        .with_details(name.clone()),
                    );
                }
            }
        }

        // 既存グループの変更
        for (name, new_entry) in &new.groups {
            if let Some(old_entry) = old.groups.get(name) {
                // GID 変更
                if old_entry.gid != new_entry.gid {
                    changed = true;
                    tracing::warn!(
                        group = %name,
                        old_gid = old_entry.gid,
                        new_gid = new_entry.gid,
                        "グループの GID が変更されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "group_policy_gid_changed",
                                Severity::Warning,
                                "group_monitor",
                                "グループの GID が変更されました",
                            )
                            .with_details(format!(
                                "group={}, old_gid={}, new_gid={}",
                                name, old_entry.gid, new_entry.gid
                            )),
                        );
                    }
                }

                // メンバー変更
                if old_entry.members != new_entry.members {
                    changed = true;

                    // 特権グループへのメンバー追加チェック
                    if privileged_groups.iter().any(|pg| pg == name) {
                        let added: Vec<&String> = new_entry
                            .members
                            .iter()
                            .filter(|m| !old_entry.members.contains(m))
                            .collect();
                        if !added.is_empty() {
                            tracing::error!(
                                group = %name,
                                added_members = ?added,
                                "CRITICAL: 特権グループにメンバーが追加されました"
                            );
                            if let Some(bus) = event_bus {
                                bus.publish(
                                    SecurityEvent::new(
                                        "group_policy_privileged_member_added",
                                        Severity::Critical,
                                        "group_monitor",
                                        "特権グループにメンバーが追加されました",
                                    )
                                    .with_details(format!("group={}, added={:?}", name, added)),
                                );
                            }
                        }
                    }

                    tracing::warn!(
                        group = %name,
                        old_members = ?old_entry.members,
                        new_members = ?new_entry.members,
                        "グループのメンバーが変更されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "group_policy_members_changed",
                                Severity::Warning,
                                "group_monitor",
                                "グループのメンバーが変更されました",
                            )
                            .with_details(format!(
                                "group={}, old={:?}, new={:?}",
                                name, old_entry.members, new_entry.members
                            )),
                        );
                    }
                }
            }
        }

        // --- /etc/gshadow の変更検知 ---

        // 新規 gshadow エントリ
        for name in new.gshadow.keys() {
            if !old.gshadow.contains_key(name) {
                changed = true;
                tracing::info!(group = %name, "gshadow にエントリが追加されました");
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "group_policy_gshadow_added",
                            Severity::Info,
                            "group_monitor",
                            "gshadow にエントリが追加されました",
                        )
                        .with_details(name.clone()),
                    );
                }
            }
        }

        // 削除された gshadow エントリ
        for name in old.gshadow.keys() {
            if !new.gshadow.contains_key(name) {
                changed = true;
                tracing::info!(group = %name, "gshadow からエントリが削除されました");
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "group_policy_gshadow_removed",
                            Severity::Info,
                            "group_monitor",
                            "gshadow からエントリが削除されました",
                        )
                        .with_details(name.clone()),
                    );
                }
            }
        }

        // 既存 gshadow エントリの変更
        for (name, new_entry) in &new.gshadow {
            if let Some(old_entry) = old.gshadow.get(name) {
                if old_entry.password_hash != new_entry.password_hash {
                    changed = true;
                    tracing::warn!(
                        group = %name,
                        "gshadow のパスワードハッシュが変更されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "group_policy_gshadow_password_changed",
                                Severity::Warning,
                                "group_monitor",
                                "gshadow のパスワードハッシュが変更されました",
                            )
                            .with_details(name.clone()),
                        );
                    }
                }
                if old_entry.admins != new_entry.admins {
                    changed = true;
                    tracing::warn!(
                        group = %name,
                        old_admins = ?old_entry.admins,
                        new_admins = ?new_entry.admins,
                        "gshadow の管理者が変更されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "group_policy_gshadow_admins_changed",
                                Severity::Warning,
                                "group_monitor",
                                "gshadow の管理者が変更されました",
                            )
                            .with_details(format!(
                                "group={}, old={:?}, new={:?}",
                                name, old_entry.admins, new_entry.admins
                            )),
                        );
                    }
                }
                if old_entry.members != new_entry.members {
                    changed = true;
                    tracing::warn!(
                        group = %name,
                        old_members = ?old_entry.members,
                        new_members = ?new_entry.members,
                        "gshadow のメンバーが変更されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "group_policy_gshadow_members_changed",
                                Severity::Warning,
                                "group_monitor",
                                "gshadow のメンバーが変更されました",
                            )
                            .with_details(format!(
                                "group={}, old={:?}, new={:?}",
                                name, old_entry.members, new_entry.members
                            )),
                        );
                    }
                }
            }
        }

        changed
    }
}

impl Module for GroupMonitorModule {
    fn name(&self) -> &str {
        "group_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        if !self.config.group_path.exists() {
            tracing::warn!(
                path = %self.config.group_path.display(),
                "group ファイルが存在しません"
            );
        }
        if !self.config.gshadow_path.exists() {
            tracing::warn!(
                path = %self.config.gshadow_path.display(),
                "gshadow ファイルが存在しません"
            );
        }

        tracing::info!(
            group_path = %self.config.group_path.display(),
            gshadow_path = %self.config.gshadow_path.display(),
            interval_secs = self.config.interval_secs,
            privileged_groups = ?self.config.privileged_groups,
            "グループポリシー監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        let group_path = self.config.group_path.clone();
        let gshadow_path = self.config.gshadow_path.clone();
        let interval_secs = self.config.interval_secs;
        let privileged_groups = self.config.privileged_groups.clone();
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        // 初回スナップショット
        let initial_snapshot =
            Self::take_snapshot(&group_path, &gshadow_path).ok_or_else(|| {
                AppError::ModuleConfig {
                    message: "初回スナップショットの取得に失敗しました".to_string(),
                }
            })?;

        tracing::info!(
            group_count = initial_snapshot.groups.len(),
            gshadow_count = initial_snapshot.gshadow.len(),
            "初回スナップショットを取得しました"
        );

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            // 最初の tick は即座に発火するのでスキップ
            interval.tick().await;

            let mut snapshot = initial_snapshot;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("グループポリシー監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        if let Some(new_snapshot) = GroupMonitorModule::take_snapshot(&group_path, &gshadow_path) {
                            let changed = GroupMonitorModule::detect_changes(
                                &snapshot,
                                &new_snapshot,
                                &privileged_groups,
                                &event_bus,
                            );
                            if changed {
                                snapshot = new_snapshot;
                            } else {
                                tracing::debug!("グループポリシーの変更はありません");
                            }
                        }
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();
        let mut items_scanned = 0;
        let mut issues_found = 0;
        let mut group_count = 0;
        let mut gshadow_count = 0;
        let mut snapshot: BTreeMap<String, String> = BTreeMap::new();

        if let Ok(content) = std::fs::read_to_string(&self.config.group_path) {
            let groups = Self::parse_group(&content);
            group_count = groups.len();
            items_scanned += group_count;

            // GID 0 のグループが root 以外にないかチェック
            for (name, entry) in &groups {
                if entry.gid == 0 && name != "root" {
                    issues_found += 1;
                }
                snapshot.insert(
                    format!("group:{}", name),
                    format!("gid={},members={}", entry.gid, entry.members.join(",")),
                );
            }
        }

        if let Ok(content) = std::fs::read_to_string(&self.config.gshadow_path) {
            let gshadow = Self::parse_gshadow(&content);
            gshadow_count = gshadow.len();
            items_scanned += gshadow_count;

            for (name, entry) in &gshadow {
                snapshot.insert(
                    format!("gshadow:{}", name),
                    format!(
                        "admins={},members={}",
                        entry.admins.join(","),
                        entry.members.join(",")
                    ),
                );
            }
        }

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "グループ {}件, gshadow {}件を読み取りました",
                group_count, gshadow_count
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
    use std::path::PathBuf;

    const SAMPLE_GROUP: &str = "\
root:x:0:
daemon:x:1:
sudo:x:27:testuser
docker:x:999:testuser,anotheruser
users:x:100:alice,bob
";

    const SAMPLE_GSHADOW: &str = "\
root:*::
daemon:*::
sudo:*::testuser
docker:!::testuser,anotheruser
users:!:alice:alice,bob
";

    #[test]
    fn test_parse_group_normal() {
        let result = GroupMonitorModule::parse_group(SAMPLE_GROUP);
        assert_eq!(result.len(), 5);

        let root = result.get("root").unwrap();
        assert_eq!(root.gid, 0);
        assert!(root.members.is_empty());

        let sudo = result.get("sudo").unwrap();
        assert_eq!(sudo.gid, 27);
        assert_eq!(sudo.members, vec!["testuser"]);

        let docker = result.get("docker").unwrap();
        assert_eq!(docker.gid, 999);
        assert_eq!(docker.members, vec!["testuser", "anotheruser"]);
    }

    #[test]
    fn test_parse_group_skip_invalid_lines() {
        let content = "\
root:x:0:
bad_line
short:x
badgid:x:abc:user1
";
        let result = GroupMonitorModule::parse_group(content);
        assert_eq!(result.len(), 1);
        assert!(result.contains_key("root"));
    }

    #[test]
    fn test_parse_group_skip_comments_and_empty() {
        let content = "\
# comment line
root:x:0:


";
        let result = GroupMonitorModule::parse_group(content);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_parse_gshadow_normal() {
        let result = GroupMonitorModule::parse_gshadow(SAMPLE_GSHADOW);
        assert_eq!(result.len(), 5);

        let root = result.get("root").unwrap();
        assert_eq!(root.password_hash, "*");
        assert!(root.admins.is_empty());
        assert!(root.members.is_empty());

        let users = result.get("users").unwrap();
        assert_eq!(users.password_hash, "!");
        assert_eq!(users.admins, vec!["alice"]);
        assert_eq!(users.members, vec!["alice", "bob"]);
    }

    #[test]
    fn test_parse_gshadow_skip_invalid() {
        let content = "\
root:*::
bad_line
short:x
";
        let result = GroupMonitorModule::parse_gshadow(content);
        assert_eq!(result.len(), 1);
        assert!(result.contains_key("root"));
    }

    #[test]
    fn test_detect_changes_no_changes() {
        let old = GroupSnapshot {
            groups: GroupMonitorModule::parse_group(SAMPLE_GROUP),
            gshadow: GroupMonitorModule::parse_gshadow(SAMPLE_GSHADOW),
        };
        let new = GroupSnapshot {
            groups: GroupMonitorModule::parse_group(SAMPLE_GROUP),
            gshadow: GroupMonitorModule::parse_gshadow(SAMPLE_GSHADOW),
        };
        let privileged = vec!["sudo".to_string(), "docker".to_string()];
        assert!(!GroupMonitorModule::detect_changes(
            &old,
            &new,
            &privileged,
            &None
        ));
    }

    #[test]
    fn test_detect_changes_group_added() {
        let old = GroupSnapshot {
            groups: GroupMonitorModule::parse_group("root:x:0:\n"),
            gshadow: HashMap::new(),
        };
        let new = GroupSnapshot {
            groups: GroupMonitorModule::parse_group("root:x:0:\nnewgroup:x:1001:\n"),
            gshadow: HashMap::new(),
        };
        let privileged = vec!["sudo".to_string()];
        assert!(GroupMonitorModule::detect_changes(
            &old,
            &new,
            &privileged,
            &None
        ));
    }

    #[test]
    fn test_detect_changes_group_deleted() {
        let old = GroupSnapshot {
            groups: GroupMonitorModule::parse_group("root:x:0:\noldgroup:x:1001:\n"),
            gshadow: HashMap::new(),
        };
        let new = GroupSnapshot {
            groups: GroupMonitorModule::parse_group("root:x:0:\n"),
            gshadow: HashMap::new(),
        };
        let privileged = vec!["sudo".to_string()];
        assert!(GroupMonitorModule::detect_changes(
            &old,
            &new,
            &privileged,
            &None
        ));
    }

    #[test]
    fn test_detect_changes_gid_changed() {
        let old = GroupSnapshot {
            groups: GroupMonitorModule::parse_group("mygroup:x:100:\n"),
            gshadow: HashMap::new(),
        };
        let new = GroupSnapshot {
            groups: GroupMonitorModule::parse_group("mygroup:x:200:\n"),
            gshadow: HashMap::new(),
        };
        let privileged = vec!["sudo".to_string()];
        assert!(GroupMonitorModule::detect_changes(
            &old,
            &new,
            &privileged,
            &None
        ));
    }

    #[test]
    fn test_detect_changes_members_changed() {
        let old = GroupSnapshot {
            groups: GroupMonitorModule::parse_group("users:x:100:alice\n"),
            gshadow: HashMap::new(),
        };
        let new = GroupSnapshot {
            groups: GroupMonitorModule::parse_group("users:x:100:alice,bob\n"),
            gshadow: HashMap::new(),
        };
        let privileged = vec!["sudo".to_string()];
        assert!(GroupMonitorModule::detect_changes(
            &old,
            &new,
            &privileged,
            &None
        ));
    }

    #[test]
    fn test_detect_changes_privileged_member_added() {
        let old = GroupSnapshot {
            groups: GroupMonitorModule::parse_group("sudo:x:27:alice\n"),
            gshadow: HashMap::new(),
        };
        let new = GroupSnapshot {
            groups: GroupMonitorModule::parse_group("sudo:x:27:alice,evil\n"),
            gshadow: HashMap::new(),
        };
        let privileged = vec!["sudo".to_string(), "docker".to_string()];
        assert!(GroupMonitorModule::detect_changes(
            &old,
            &new,
            &privileged,
            &None
        ));
    }

    #[test]
    fn test_detect_changes_gid_zero_non_root() {
        let old = GroupSnapshot {
            groups: GroupMonitorModule::parse_group("root:x:0:\n"),
            gshadow: HashMap::new(),
        };
        let new = GroupSnapshot {
            groups: GroupMonitorModule::parse_group("root:x:0:\nevil:x:0:\n"),
            gshadow: HashMap::new(),
        };
        let privileged = vec!["sudo".to_string()];
        assert!(GroupMonitorModule::detect_changes(
            &old,
            &new,
            &privileged,
            &None
        ));
    }

    #[test]
    fn test_detect_changes_gshadow_password_changed() {
        let old = GroupSnapshot {
            groups: HashMap::new(),
            gshadow: GroupMonitorModule::parse_gshadow("mygroup:!::\n"),
        };
        let new = GroupSnapshot {
            groups: HashMap::new(),
            gshadow: GroupMonitorModule::parse_gshadow("mygroup:$6$hash::\n"),
        };
        let privileged = vec!["sudo".to_string()];
        assert!(GroupMonitorModule::detect_changes(
            &old,
            &new,
            &privileged,
            &None
        ));
    }

    #[test]
    fn test_detect_changes_gshadow_admins_changed() {
        let old = GroupSnapshot {
            groups: HashMap::new(),
            gshadow: GroupMonitorModule::parse_gshadow("mygroup:!:alice:\n"),
        };
        let new = GroupSnapshot {
            groups: HashMap::new(),
            gshadow: GroupMonitorModule::parse_gshadow("mygroup:!:alice,bob:\n"),
        };
        let privileged = vec!["sudo".to_string()];
        assert!(GroupMonitorModule::detect_changes(
            &old,
            &new,
            &privileged,
            &None
        ));
    }

    #[test]
    fn test_detect_changes_gshadow_members_changed() {
        let old = GroupSnapshot {
            groups: HashMap::new(),
            gshadow: GroupMonitorModule::parse_gshadow("mygroup:!::alice\n"),
        };
        let new = GroupSnapshot {
            groups: HashMap::new(),
            gshadow: GroupMonitorModule::parse_gshadow("mygroup:!::alice,bob\n"),
        };
        let privileged = vec!["sudo".to_string()];
        assert!(GroupMonitorModule::detect_changes(
            &old,
            &new,
            &privileged,
            &None
        ));
    }

    #[test]
    fn test_detect_changes_gshadow_added() {
        let old = GroupSnapshot {
            groups: HashMap::new(),
            gshadow: GroupMonitorModule::parse_gshadow("root:*::\n"),
        };
        let new = GroupSnapshot {
            groups: HashMap::new(),
            gshadow: GroupMonitorModule::parse_gshadow("root:*::\nnewgroup:!::\n"),
        };
        let privileged = vec!["sudo".to_string()];
        assert!(GroupMonitorModule::detect_changes(
            &old,
            &new,
            &privileged,
            &None
        ));
    }

    #[test]
    fn test_detect_changes_gshadow_removed() {
        let old = GroupSnapshot {
            groups: HashMap::new(),
            gshadow: GroupMonitorModule::parse_gshadow("root:*::\noldgroup:!::\n"),
        };
        let new = GroupSnapshot {
            groups: HashMap::new(),
            gshadow: GroupMonitorModule::parse_gshadow("root:*::\n"),
        };
        let privileged = vec!["sudo".to_string()];
        assert!(GroupMonitorModule::detect_changes(
            &old,
            &new,
            &privileged,
            &None
        ));
    }

    #[test]
    fn test_init_zero_interval() {
        let config = GroupMonitorConfig {
            enabled: true,
            interval_secs: 0,
            group_path: PathBuf::from("/etc/group"),
            gshadow_path: PathBuf::from("/etc/gshadow"),
            privileged_groups: vec!["sudo".to_string()],
        };
        let mut module = GroupMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_init_valid() {
        let config = GroupMonitorConfig {
            enabled: true,
            interval_secs: 60,
            group_path: PathBuf::from("/etc/group"),
            gshadow_path: PathBuf::from("/etc/gshadow"),
            privileged_groups: vec!["sudo".to_string()],
        };
        let mut module = GroupMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_ok());
    }

    #[test]
    fn test_init_nonexistent_paths() {
        let config = GroupMonitorConfig {
            enabled: true,
            interval_secs: 60,
            group_path: PathBuf::from("/nonexistent-group"),
            gshadow_path: PathBuf::from("/nonexistent-gshadow"),
            privileged_groups: vec!["sudo".to_string()],
        };
        let mut module = GroupMonitorModule::new(config, None);
        // init は warn を出すが成功する
        let result = module.init();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let dir = tempfile::tempdir().unwrap();
        let group_path = dir.path().join("group");
        let gshadow_path = dir.path().join("gshadow");
        std::fs::write(&group_path, "root:x:0:\n").unwrap();
        std::fs::write(&gshadow_path, "root:*::\n").unwrap();

        let config = GroupMonitorConfig {
            enabled: true,
            interval_secs: 3600,
            group_path,
            gshadow_path,
            privileged_groups: vec!["sudo".to_string()],
        };
        let mut module = GroupMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_start_fails_without_group_file() {
        let config = GroupMonitorConfig {
            enabled: true,
            interval_secs: 60,
            group_path: PathBuf::from("/nonexistent-group-test"),
            gshadow_path: PathBuf::from("/nonexistent-gshadow-test"),
            privileged_groups: vec!["sudo".to_string()],
        };
        let mut module = GroupMonitorModule::new(config, None);
        module.init().unwrap();

        let result = module.start().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_initial_scan_with_files() {
        let dir = tempfile::tempdir().unwrap();
        let group_path = dir.path().join("group");
        let gshadow_path = dir.path().join("gshadow");
        std::fs::write(&group_path, SAMPLE_GROUP).unwrap();
        std::fs::write(&gshadow_path, SAMPLE_GSHADOW).unwrap();

        let config = GroupMonitorConfig {
            enabled: true,
            interval_secs: 60,
            group_path,
            gshadow_path,
            privileged_groups: vec!["sudo".to_string()],
        };
        let module = GroupMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        // 5 groups + 5 gshadow = 10
        assert_eq!(result.items_scanned, 10);
        assert_eq!(result.issues_found, 0);
        assert!(result.summary.contains("グループ 5件"));
        assert!(result.summary.contains("gshadow 5件"));
    }

    #[tokio::test]
    async fn test_initial_scan_nonexistent_files() {
        let config = GroupMonitorConfig {
            enabled: true,
            interval_secs: 60,
            group_path: PathBuf::from("/nonexistent-group-scan-test"),
            gshadow_path: PathBuf::from("/nonexistent-gshadow-scan-test"),
            privileged_groups: vec!["sudo".to_string()],
        };
        let module = GroupMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
    }

    #[tokio::test]
    async fn test_initial_scan_detects_gid_zero() {
        let dir = tempfile::tempdir().unwrap();
        let group_path = dir.path().join("group");
        let gshadow_path = dir.path().join("gshadow");
        let group_content = "\
root:x:0:
evil:x:0:
normal:x:1000:
";
        std::fs::write(&group_path, group_content).unwrap();
        std::fs::write(&gshadow_path, "root:*::\n").unwrap();

        let config = GroupMonitorConfig {
            enabled: true,
            interval_secs: 60,
            group_path,
            gshadow_path,
            privileged_groups: vec!["sudo".to_string()],
        };
        let module = GroupMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.issues_found, 1); // evil has GID 0
    }

    #[tokio::test]
    async fn test_start_without_gshadow_file() {
        let dir = tempfile::tempdir().unwrap();
        let group_path = dir.path().join("group");
        let gshadow_path = dir.path().join("gshadow_nonexistent");
        std::fs::write(&group_path, "root:x:0:\n").unwrap();
        // gshadow ファイルは作成しない

        let config = GroupMonitorConfig {
            enabled: true,
            interval_secs: 3600,
            group_path,
            gshadow_path,
            privileged_groups: vec!["sudo".to_string()],
        };
        let mut module = GroupMonitorModule::new(config, None);
        module.init().unwrap();

        // gshadow がなくても group があれば起動できる
        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }
}
