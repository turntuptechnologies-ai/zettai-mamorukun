//! ユーザーアカウント監視モジュール
//!
//! `/etc/passwd` と `/etc/group` を定期的にパースし、前回のスナップショットと比較して
//! 不審な変更を検知する。
//!
//! 検知対象:
//! - 新規ユーザー追加 / ユーザー削除
//! - UID 0 ユーザーの出現（root 以外） — CRITICAL
//! - シェル変更 / UID・GID 変更 / ホームディレクトリ変更
//! - 新規グループ追加 / グループ削除
//! - グループメンバー変更 / グループ GID 変更

use crate::config::UserAccountConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::HashMap;
use std::path::Path;
use tokio_util::sync::CancellationToken;

/// `/etc/passwd` の 1 エントリを表す
#[derive(Debug, Clone, PartialEq)]
struct PasswdEntry {
    username: String,
    uid: u32,
    gid: u32,
    home: String,
    shell: String,
}

/// `/etc/group` の 1 エントリを表す
#[derive(Debug, Clone, PartialEq)]
struct GroupEntry {
    name: String,
    gid: u32,
    members: Vec<String>,
}

/// ユーザー・グループのスナップショット
struct AccountSnapshot {
    users: HashMap<String, PasswdEntry>,
    groups: HashMap<String, GroupEntry>,
}

/// ユーザーアカウント監視モジュール
///
/// `/etc/passwd` と `/etc/group` を定期スキャンし、不審な変更を検知する。
pub struct UserAccountModule {
    config: UserAccountConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl UserAccountModule {
    /// 新しいユーザーアカウント監視モジュールを作成する
    pub fn new(config: UserAccountConfig, event_bus: Option<EventBus>) -> Self {
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

    /// `/etc/passwd` の内容をパースする
    fn parse_passwd(content: &str) -> HashMap<String, PasswdEntry> {
        let mut result = HashMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() != 7 {
                tracing::warn!(
                    line = line,
                    "passwd: フィールド数が不正です。スキップします"
                );
                continue;
            }
            let uid = match fields[2].parse::<u32>() {
                Ok(v) => v,
                Err(_) => {
                    tracing::warn!(
                        line = line,
                        "passwd: UID のパースに失敗しました。スキップします"
                    );
                    continue;
                }
            };
            let gid = match fields[3].parse::<u32>() {
                Ok(v) => v,
                Err(_) => {
                    tracing::warn!(
                        line = line,
                        "passwd: GID のパースに失敗しました。スキップします"
                    );
                    continue;
                }
            };
            let entry = PasswdEntry {
                username: fields[0].to_string(),
                uid,
                gid,
                home: fields[5].to_string(),
                shell: fields[6].to_string(),
            };
            result.insert(entry.username.clone(), entry);
        }
        result
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

    /// スナップショットを取得する
    fn take_snapshot(passwd_path: &Path, group_path: &Path) -> Option<AccountSnapshot> {
        let passwd_content = match std::fs::read_to_string(passwd_path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    path = %passwd_path.display(),
                    error = %e,
                    "passwd ファイルの読み取りに失敗しました"
                );
                return None;
            }
        };
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

        Some(AccountSnapshot {
            users: Self::parse_passwd(&passwd_content),
            groups: Self::parse_group(&group_content),
        })
    }

    /// 2 つのスナップショットを比較し、変更をログ出力する。変更があれば true を返す。
    fn detect_changes(
        old: &AccountSnapshot,
        new: &AccountSnapshot,
        event_bus: &Option<EventBus>,
    ) -> bool {
        let mut changed = false;

        // --- ユーザー変更 ---
        // 新規ユーザー
        for (username, entry) in &new.users {
            if !old.users.contains_key(username) {
                changed = true;
                tracing::warn!(username = %username, uid = entry.uid, "新規ユーザーが追加されました");
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "user_added",
                            Severity::Warning,
                            "user_account",
                            "新規ユーザーが追加されました",
                        )
                        .with_details(username.clone()),
                    );
                }
            }
        }
        // 削除されたユーザー
        for username in old.users.keys() {
            if !new.users.contains_key(username) {
                changed = true;
                tracing::warn!(username = %username, "ユーザーが削除されました");
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "user_removed",
                            Severity::Warning,
                            "user_account",
                            "ユーザーが削除されました",
                        )
                        .with_details(username.clone()),
                    );
                }
            }
        }
        // UID 0 チェック（root 以外）
        for (username, entry) in &new.users {
            if entry.uid == 0 && username != "root" {
                changed = true;
                tracing::error!(
                    username = %username,
                    "CRITICAL: root 以外のユーザーが UID 0 を持っています"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "user_uid_zero",
                            Severity::Critical,
                            "user_account",
                            "CRITICAL: root 以外のユーザーが UID 0 を持っています",
                        )
                        .with_details(username.clone()),
                    );
                }
            }
        }
        // 既存ユーザーの変更
        for (username, new_entry) in &new.users {
            if let Some(old_entry) = old.users.get(username) {
                if old_entry.shell != new_entry.shell {
                    changed = true;
                    tracing::warn!(
                        username = %username,
                        old_shell = %old_entry.shell,
                        new_shell = %new_entry.shell,
                        "ユーザーのシェルが変更されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "user_shell_changed",
                                Severity::Warning,
                                "user_account",
                                "ユーザーのシェルが変更されました",
                            )
                            .with_details(username.clone()),
                        );
                    }
                }
                if old_entry.uid != new_entry.uid {
                    changed = true;
                    tracing::warn!(
                        username = %username,
                        old_uid = old_entry.uid,
                        new_uid = new_entry.uid,
                        "ユーザーの UID が変更されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "user_uid_changed",
                                Severity::Warning,
                                "user_account",
                                "ユーザーの UID が変更されました",
                            )
                            .with_details(username.clone()),
                        );
                    }
                }
                if old_entry.gid != new_entry.gid {
                    changed = true;
                    tracing::warn!(
                        username = %username,
                        old_gid = old_entry.gid,
                        new_gid = new_entry.gid,
                        "ユーザーの GID が変更されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "user_gid_changed",
                                Severity::Warning,
                                "user_account",
                                "ユーザーの GID が変更されました",
                            )
                            .with_details(username.clone()),
                        );
                    }
                }
                if old_entry.home != new_entry.home {
                    changed = true;
                    tracing::warn!(
                        username = %username,
                        old_home = %old_entry.home,
                        new_home = %new_entry.home,
                        "ユーザーのホームディレクトリが変更されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "user_home_changed",
                                Severity::Warning,
                                "user_account",
                                "ユーザーのホームディレクトリが変更されました",
                            )
                            .with_details(username.clone()),
                        );
                    }
                }
            }
        }

        // --- グループ変更 ---
        // 新規グループ
        for (name, entry) in &new.groups {
            if !old.groups.contains_key(name) {
                changed = true;
                tracing::warn!(group = %name, gid = entry.gid, "新規グループが追加されました");
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "group_added",
                            Severity::Warning,
                            "user_account",
                            "新規グループが追加されました",
                        )
                        .with_details(name.clone()),
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
                            "group_removed",
                            Severity::Warning,
                            "user_account",
                            "グループが削除されました",
                        )
                        .with_details(name.clone()),
                    );
                }
            }
        }
        // 既存グループの変更
        for (name, new_entry) in &new.groups {
            if let Some(old_entry) = old.groups.get(name) {
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
                                "group_gid_changed",
                                Severity::Warning,
                                "user_account",
                                "グループの GID が変更されました",
                            )
                            .with_details(name.clone()),
                        );
                    }
                }
                if old_entry.members != new_entry.members {
                    changed = true;
                    tracing::warn!(
                        group = %name,
                        old_members = ?old_entry.members,
                        new_members = ?new_entry.members,
                        "グループのメンバーが変更されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "group_members_changed",
                                Severity::Warning,
                                "user_account",
                                "グループのメンバーが変更されました",
                            )
                            .with_details(name.clone()),
                        );
                    }
                }
            }
        }

        changed
    }
}

impl Module for UserAccountModule {
    fn name(&self) -> &str {
        "user_account"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        if !self.config.passwd_path.exists() {
            tracing::warn!(
                path = %self.config.passwd_path.display(),
                "passwd ファイルが存在しません"
            );
        }
        if !self.config.group_path.exists() {
            tracing::warn!(
                path = %self.config.group_path.display(),
                "group ファイルが存在しません"
            );
        }

        tracing::info!(
            passwd_path = %self.config.passwd_path.display(),
            group_path = %self.config.group_path.display(),
            scan_interval_secs = self.config.scan_interval_secs,
            "ユーザーアカウント監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<(), AppError> {
        let passwd_path = self.config.passwd_path.clone();
        let group_path = self.config.group_path.clone();
        let scan_interval_secs = self.config.scan_interval_secs;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        // 初回スナップショット
        let initial_snapshot = Self::take_snapshot(&passwd_path, &group_path).ok_or_else(|| {
            AppError::ModuleConfig {
                message: "初回スナップショットの取得に失敗しました".to_string(),
            }
        })?;

        tracing::info!(
            user_count = initial_snapshot.users.len(),
            group_count = initial_snapshot.groups.len(),
            "初回スナップショットを取得しました"
        );

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            // 最初の tick は即座に発火するのでスキップ
            interval.tick().await;

            let mut snapshot = initial_snapshot;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("ユーザーアカウント監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        if let Some(new_snapshot) = UserAccountModule::take_snapshot(&passwd_path, &group_path) {
                            let changed = UserAccountModule::detect_changes(&snapshot, &new_snapshot, &event_bus);
                            if changed {
                                snapshot = new_snapshot;
                            } else {
                                tracing::debug!("ユーザーアカウントの変更はありません");
                            }
                        }
                    }
                }
            }
        });

        Ok(())
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();
        let mut items_scanned = 0;
        let mut issues_found = 0;
        let mut user_count = 0;
        let mut group_count = 0;

        if let Ok(content) = std::fs::read_to_string(&self.config.passwd_path) {
            let users = Self::parse_passwd(&content);
            user_count = users.len();
            items_scanned += user_count;

            // UID 0 のユーザーが root 以外にいないかチェック
            for (username, entry) in &users {
                if entry.uid == 0 && username != "root" {
                    issues_found += 1;
                }
            }
        }

        if let Ok(content) = std::fs::read_to_string(&self.config.group_path) {
            let groups = Self::parse_group(&content);
            group_count = groups.len();
            items_scanned += group_count;
        }

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "ユーザー {}件, グループ {}件を読み取りました",
                user_count, group_count
            ),
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

    const SAMPLE_PASSWD: &str = "\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
testuser:x:1000:1000:Test User:/home/testuser:/bin/bash
";

    const SAMPLE_GROUP: &str = "\
root:x:0:
daemon:x:1:
sudo:x:27:testuser
users:x:100:testuser,anotheruser
";

    #[test]
    fn test_parse_passwd_normal() {
        let result = UserAccountModule::parse_passwd(SAMPLE_PASSWD);
        assert_eq!(result.len(), 4);

        let root = result.get("root").unwrap();
        assert_eq!(root.uid, 0);
        assert_eq!(root.gid, 0);
        assert_eq!(root.home, "/root");
        assert_eq!(root.shell, "/bin/bash");

        let testuser = result.get("testuser").unwrap();
        assert_eq!(testuser.uid, 1000);
        assert_eq!(testuser.gid, 1000);
        assert_eq!(testuser.home, "/home/testuser");
        assert_eq!(testuser.shell, "/bin/bash");
    }

    #[test]
    fn test_parse_passwd_skip_invalid_lines() {
        let content = "\
root:x:0:0:root:/root:/bin/bash
invalid_line_no_colons
short:x:1
baduid:x:abc:0:user:/home:/bin/sh
badgid:x:0:xyz:user:/home:/bin/sh
";
        let result = UserAccountModule::parse_passwd(content);
        assert_eq!(result.len(), 1);
        assert!(result.contains_key("root"));
    }

    #[test]
    fn test_parse_passwd_skip_comments_and_empty() {
        let content = "\
# comment line
root:x:0:0:root:/root:/bin/bash


";
        let result = UserAccountModule::parse_passwd(content);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_parse_group_normal() {
        let result = UserAccountModule::parse_group(SAMPLE_GROUP);
        assert_eq!(result.len(), 4);

        let root = result.get("root").unwrap();
        assert_eq!(root.gid, 0);
        assert!(root.members.is_empty());

        let sudo = result.get("sudo").unwrap();
        assert_eq!(sudo.gid, 27);
        assert_eq!(sudo.members, vec!["testuser"]);

        let users = result.get("users").unwrap();
        assert_eq!(users.gid, 100);
        assert_eq!(users.members, vec!["testuser", "anotheruser"]);
    }

    #[test]
    fn test_parse_group_skip_invalid_lines() {
        let content = "\
root:x:0:
bad_line
short:x
badgid:x:abc:user1
";
        let result = UserAccountModule::parse_group(content);
        assert_eq!(result.len(), 1);
        assert!(result.contains_key("root"));
    }

    #[test]
    fn test_detect_changes_no_changes() {
        let old = AccountSnapshot {
            users: UserAccountModule::parse_passwd(SAMPLE_PASSWD),
            groups: UserAccountModule::parse_group(SAMPLE_GROUP),
        };
        let new = AccountSnapshot {
            users: UserAccountModule::parse_passwd(SAMPLE_PASSWD),
            groups: UserAccountModule::parse_group(SAMPLE_GROUP),
        };
        assert!(!UserAccountModule::detect_changes(&old, &new, &None));
    }

    #[test]
    fn test_detect_changes_user_added() {
        let old = AccountSnapshot {
            users: UserAccountModule::parse_passwd("root:x:0:0:root:/root:/bin/bash\n"),
            groups: HashMap::new(),
        };
        let new_passwd = "\
root:x:0:0:root:/root:/bin/bash
newuser:x:1001:1001:New:/home/newuser:/bin/bash
";
        let new = AccountSnapshot {
            users: UserAccountModule::parse_passwd(new_passwd),
            groups: HashMap::new(),
        };
        assert!(UserAccountModule::detect_changes(&old, &new, &None));
    }

    #[test]
    fn test_detect_changes_user_deleted() {
        let old_passwd = "\
root:x:0:0:root:/root:/bin/bash
olduser:x:1001:1001:Old:/home/olduser:/bin/bash
";
        let old = AccountSnapshot {
            users: UserAccountModule::parse_passwd(old_passwd),
            groups: HashMap::new(),
        };
        let new = AccountSnapshot {
            users: UserAccountModule::parse_passwd("root:x:0:0:root:/root:/bin/bash\n"),
            groups: HashMap::new(),
        };
        assert!(UserAccountModule::detect_changes(&old, &new, &None));
    }

    #[test]
    fn test_detect_changes_uid_zero_non_root() {
        let old = AccountSnapshot {
            users: UserAccountModule::parse_passwd("root:x:0:0:root:/root:/bin/bash\n"),
            groups: HashMap::new(),
        };
        let new_passwd = "\
root:x:0:0:root:/root:/bin/bash
evil:x:0:0:evil:/root:/bin/bash
";
        let new = AccountSnapshot {
            users: UserAccountModule::parse_passwd(new_passwd),
            groups: HashMap::new(),
        };
        assert!(UserAccountModule::detect_changes(&old, &new, &None));
    }

    #[test]
    fn test_detect_changes_shell_changed() {
        let old_passwd = "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n";
        let new_passwd = "testuser:x:1000:1000:Test:/home/testuser:/bin/zsh\n";
        let old = AccountSnapshot {
            users: UserAccountModule::parse_passwd(old_passwd),
            groups: HashMap::new(),
        };
        let new = AccountSnapshot {
            users: UserAccountModule::parse_passwd(new_passwd),
            groups: HashMap::new(),
        };
        assert!(UserAccountModule::detect_changes(&old, &new, &None));
    }

    #[test]
    fn test_detect_changes_uid_changed() {
        let old_passwd = "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n";
        let new_passwd = "testuser:x:1001:1000:Test:/home/testuser:/bin/bash\n";
        let old = AccountSnapshot {
            users: UserAccountModule::parse_passwd(old_passwd),
            groups: HashMap::new(),
        };
        let new = AccountSnapshot {
            users: UserAccountModule::parse_passwd(new_passwd),
            groups: HashMap::new(),
        };
        assert!(UserAccountModule::detect_changes(&old, &new, &None));
    }

    #[test]
    fn test_detect_changes_gid_changed() {
        let old_passwd = "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n";
        let new_passwd = "testuser:x:1000:1001:Test:/home/testuser:/bin/bash\n";
        let old = AccountSnapshot {
            users: UserAccountModule::parse_passwd(old_passwd),
            groups: HashMap::new(),
        };
        let new = AccountSnapshot {
            users: UserAccountModule::parse_passwd(new_passwd),
            groups: HashMap::new(),
        };
        assert!(UserAccountModule::detect_changes(&old, &new, &None));
    }

    #[test]
    fn test_detect_changes_home_changed() {
        let old_passwd = "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n";
        let new_passwd = "testuser:x:1000:1000:Test:/home/other:/bin/bash\n";
        let old = AccountSnapshot {
            users: UserAccountModule::parse_passwd(old_passwd),
            groups: HashMap::new(),
        };
        let new = AccountSnapshot {
            users: UserAccountModule::parse_passwd(new_passwd),
            groups: HashMap::new(),
        };
        assert!(UserAccountModule::detect_changes(&old, &new, &None));
    }

    #[test]
    fn test_detect_changes_group_added() {
        let old = AccountSnapshot {
            users: HashMap::new(),
            groups: UserAccountModule::parse_group("root:x:0:\n"),
        };
        let new_group = "\
root:x:0:
newgroup:x:1001:
";
        let new = AccountSnapshot {
            users: HashMap::new(),
            groups: UserAccountModule::parse_group(new_group),
        };
        assert!(UserAccountModule::detect_changes(&old, &new, &None));
    }

    #[test]
    fn test_detect_changes_group_deleted() {
        let old_group = "\
root:x:0:
oldgroup:x:1001:
";
        let old = AccountSnapshot {
            users: HashMap::new(),
            groups: UserAccountModule::parse_group(old_group),
        };
        let new = AccountSnapshot {
            users: HashMap::new(),
            groups: UserAccountModule::parse_group("root:x:0:\n"),
        };
        assert!(UserAccountModule::detect_changes(&old, &new, &None));
    }

    #[test]
    fn test_detect_changes_group_members_changed() {
        let old = AccountSnapshot {
            users: HashMap::new(),
            groups: UserAccountModule::parse_group("sudo:x:27:alice\n"),
        };
        let new = AccountSnapshot {
            users: HashMap::new(),
            groups: UserAccountModule::parse_group("sudo:x:27:alice,bob\n"),
        };
        assert!(UserAccountModule::detect_changes(&old, &new, &None));
    }

    #[test]
    fn test_detect_changes_group_gid_changed() {
        let old = AccountSnapshot {
            users: HashMap::new(),
            groups: UserAccountModule::parse_group("mygroup:x:100:\n"),
        };
        let new = AccountSnapshot {
            users: HashMap::new(),
            groups: UserAccountModule::parse_group("mygroup:x:200:\n"),
        };
        assert!(UserAccountModule::detect_changes(&old, &new, &None));
    }

    #[test]
    fn test_init_zero_interval() {
        let config = UserAccountConfig {
            enabled: true,
            scan_interval_secs: 0,
            passwd_path: PathBuf::from("/etc/passwd"),
            group_path: PathBuf::from("/etc/group"),
        };
        let mut module = UserAccountModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_init_valid() {
        let config = UserAccountConfig {
            enabled: true,
            scan_interval_secs: 60,
            passwd_path: PathBuf::from("/etc/passwd"),
            group_path: PathBuf::from("/etc/group"),
        };
        let mut module = UserAccountModule::new(config, None);
        let result = module.init();
        assert!(result.is_ok());
    }

    #[test]
    fn test_init_nonexistent_paths() {
        let config = UserAccountConfig {
            enabled: true,
            scan_interval_secs: 60,
            passwd_path: PathBuf::from("/nonexistent-passwd"),
            group_path: PathBuf::from("/nonexistent-group"),
        };
        let mut module = UserAccountModule::new(config, None);
        // init は warn を出すが成功する
        let result = module.init();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        // テスト用の一時ファイルを作成
        let dir = tempfile::tempdir().unwrap();
        let passwd_path = dir.path().join("passwd");
        let group_path = dir.path().join("group");
        std::fs::write(&passwd_path, "root:x:0:0:root:/root:/bin/bash\n").unwrap();
        std::fs::write(&group_path, "root:x:0:\n").unwrap();

        let config = UserAccountConfig {
            enabled: true,
            scan_interval_secs: 3600,
            passwd_path,
            group_path,
        };
        let mut module = UserAccountModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_start_fails_without_files() {
        let config = UserAccountConfig {
            enabled: true,
            scan_interval_secs: 60,
            passwd_path: PathBuf::from("/nonexistent-passwd-test"),
            group_path: PathBuf::from("/nonexistent-group-test"),
        };
        let mut module = UserAccountModule::new(config, None);
        module.init().unwrap();

        let result = module.start().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_initial_scan_with_files() {
        let dir = tempfile::tempdir().unwrap();
        let passwd_path = dir.path().join("passwd");
        let group_path = dir.path().join("group");
        std::fs::write(&passwd_path, SAMPLE_PASSWD).unwrap();
        std::fs::write(&group_path, SAMPLE_GROUP).unwrap();

        let config = UserAccountConfig {
            enabled: true,
            scan_interval_secs: 60,
            passwd_path,
            group_path,
        };
        let module = UserAccountModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        // 4 users + 4 groups = 8
        assert_eq!(result.items_scanned, 8);
        assert_eq!(result.issues_found, 0);
        assert!(result.summary.contains("ユーザー 4件"));
        assert!(result.summary.contains("グループ 4件"));
    }

    #[tokio::test]
    async fn test_initial_scan_nonexistent_files() {
        let config = UserAccountConfig {
            enabled: true,
            scan_interval_secs: 60,
            passwd_path: PathBuf::from("/nonexistent-passwd-scan-test"),
            group_path: PathBuf::from("/nonexistent-group-scan-test"),
        };
        let module = UserAccountModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
    }

    #[tokio::test]
    async fn test_initial_scan_detects_uid_zero() {
        let dir = tempfile::tempdir().unwrap();
        let passwd_path = dir.path().join("passwd");
        let group_path = dir.path().join("group");
        let passwd_content = "\
root:x:0:0:root:/root:/bin/bash
evil:x:0:0:evil:/root:/bin/bash
normal:x:1000:1000:Normal:/home/normal:/bin/bash
";
        std::fs::write(&passwd_path, passwd_content).unwrap();
        std::fs::write(&group_path, "root:x:0:\n").unwrap();

        let config = UserAccountConfig {
            enabled: true,
            scan_interval_secs: 60,
            passwd_path,
            group_path,
        };
        let module = UserAccountModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.issues_found, 1); // evil has UID 0
    }
}
