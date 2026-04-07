//! 相関ルールプリセット集
//!
//! よくある攻撃パターンのプリセットルールを提供する。

use crate::config::{CorrelationRuleConfig, CorrelationStepConfig};

/// 全プリセットルールを返す
pub fn all_presets() -> Vec<CorrelationRuleConfig> {
    vec![
        privilege_escalation(),
        lateral_movement(),
        ransomware_indicators(),
        persistence_mechanism(),
        kernel_tampering(),
        container_escape(),
        credential_theft(),
        network_reconnaissance(),
    ]
}

/// プリセットルールとユーザー定義ルールをマージする
///
/// ユーザーが同名のルール（`preset:` プレフィックス付き）を定義している場合は
/// ユーザー定義を優先する。
pub fn merge_rules(
    user_rules: &[CorrelationRuleConfig],
    enable_presets: bool,
    disabled_presets: &[String],
) -> Vec<CorrelationRuleConfig> {
    let mut merged = Vec::new();

    if enable_presets {
        let presets = all_presets();
        for preset in presets {
            // ユーザーが同名ルールを定義している場合はスキップ
            let user_override = user_rules.iter().any(|r| r.name == preset.name);
            // disabled_presets に含まれる場合もスキップ
            let disabled = disabled_presets
                .iter()
                .any(|d| preset.name == format!("preset:{d}") || preset.name == *d);
            if !user_override && !disabled {
                merged.push(preset);
            }
        }
    }

    // ユーザー定義ルールを追加
    merged.extend(user_rules.iter().cloned());

    merged
}

/// ステップを簡潔に作成するヘルパー関数
fn step(name: &str, event_type: &str, min_severity: Option<&str>) -> CorrelationStepConfig {
    CorrelationStepConfig {
        name: name.to_string(),
        event_type: event_type.to_string(),
        source_module: None,
        min_severity: min_severity.map(|s| s.to_string()),
    }
}

/// プリセットルールを作成するヘルパー関数
fn preset_rule(
    name: &str,
    description: &str,
    within_secs: u64,
    steps: Vec<CorrelationStepConfig>,
) -> CorrelationRuleConfig {
    CorrelationRuleConfig {
        name: format!("preset:{name}"),
        description: description.to_string(),
        steps,
        within_secs: Some(within_secs),
    }
}

/// 1. 権限昇格パターン
fn privilege_escalation() -> CorrelationRuleConfig {
    preset_rule(
        "privilege_escalation",
        "sudoers 変更後に SUID ファイル作成または capabilities 変更を検知",
        1800, // 30分
        vec![
            step(
                "sudoers_changed",
                "sudoers_(lines_added|file_added)",
                Some("warning"),
            ),
            step("suid_or_caps", "(suid_sgid_new|capabilities_changed)", None),
        ],
    )
}

/// 2. ラテラルムーブメント
fn lateral_movement() -> CorrelationRuleConfig {
    preset_rule(
        "lateral_movement",
        "SSH ブルートフォース成功後にユーザー追加・SSH 鍵設置・cron 永続化を検知",
        3600, // 1時間
        vec![
            step("ssh_attack", "ssh_brute_force", Some("warning")),
            step("user_created", "user_added", None),
            step("ssh_key_installed", "ssh_key_(added|file_added)", None),
            step("persistence", "cron_(modified|added)", None),
        ],
    )
}

/// 3. ランサムウェア兆候
fn ransomware_indicators() -> CorrelationRuleConfig {
    preset_rule(
        "ransomware_indicators",
        "大量のファイル変更・プロセス異常・ネットワーク異常からランサムウェアの兆候を検知",
        900, // 15分
        vec![
            step(
                "mass_file_changes",
                "file_(modified|added|removed)",
                Some("warning"),
            ),
            step(
                "process_anomaly",
                "process_(anomaly|exec_suspicious_path)",
                None,
            ),
            step(
                "network_anomaly",
                "(traffic_bytes_anomaly|suspicious_port_connection|connection_count_exceeded)",
                None,
            ),
        ],
    )
}

/// 4. 永続化メカニズム
fn persistence_mechanism() -> CorrelationRuleConfig {
    preset_rule(
        "persistence_mechanism",
        "systemd サービス追加・cron 変更・シェル設定変更の組み合わせで永続化を検知",
        3600, // 1時間
        vec![
            step("systemd_persistence", "systemd_(added|modified)", None),
            step("cron_persistence", "cron_(modified|added)", None),
            step(
                "shell_persistence",
                "shell_config_(lines_added|added)",
                None,
            ),
        ],
    )
}

/// 5. カーネルレベル攻撃
fn kernel_tampering() -> CorrelationRuleConfig {
    preset_rule(
        "kernel_tampering",
        "カーネルモジュール追加・パラメータ変更・seccomp 無効化からカーネルレベルの攻撃を検知",
        1800, // 30分
        vec![
            step("kernel_module", "kernel_module_loaded", Some("warning")),
            step(
                "kernel_params",
                "kernel_param_(changed|below_minimum)",
                None,
            ),
            step(
                "seccomp_weakened",
                "(seccomp_disabled|seccomp_mode_changed)",
                None,
            ),
        ],
    )
}

/// 6. コンテナエスケープ兆候
fn container_escape() -> CorrelationRuleConfig {
    preset_rule(
        "container_escape",
        "名前空間変更・マウント変更・capabilities 変更からコンテナエスケープの兆候を検知",
        600, // 10分
        vec![
            step(
                "namespace_change",
                "(namespace_inode_changed|container_env_appeared)",
                None,
            ),
            step("mount_change", "mount_(added|modified)", None),
            step(
                "caps_change",
                "(capabilities_changed|capabilities_new_process)",
                None,
            ),
        ],
    )
}

/// 7. 認証情報窃取
fn credential_theft() -> CorrelationRuleConfig {
    preset_rule(
        "credential_theft",
        "PAM 設定変更・sudoers 変更・SSH 鍵追加の組み合わせで認証情報窃取を検知",
        1800, // 30分
        vec![
            step(
                "pam_tampered",
                "pam_(lines_added|dangerous_permit|dangerous_exec)",
                Some("warning"),
            ),
            step("sudoers_tampered", "sudoers_(lines_added|file_added)", None),
            step("ssh_key_theft", "ssh_key_(added|file_added)", None),
        ],
    )
}

/// 8. ネットワーク偵察
fn network_reconnaissance() -> CorrelationRuleConfig {
    preset_rule(
        "network_reconnaissance",
        "新規ポート開設・ネットワーク接続増加・DNS 設定変更からネットワーク偵察を検知",
        1800, // 30分
        vec![
            step(
                "new_port",
                "(new_listening_port|unauthorized_listening_port)",
                None,
            ),
            step(
                "connection_surge",
                "(connection_count_exceeded|traffic_bytes_anomaly)",
                None,
            ),
            step("dns_tampered", "dns_(modified|added)", None),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_presets_returns_eight_rules() {
        let presets = all_presets();
        assert_eq!(presets.len(), 8);
        // 全てに preset: プレフィックスがある
        for p in &presets {
            assert!(
                p.name.starts_with("preset:"),
                "プリセット名に prefix がありません: {}",
                p.name
            );
        }
    }

    #[test]
    fn test_all_presets_have_steps() {
        let presets = all_presets();
        for p in &presets {
            assert!(!p.steps.is_empty(), "ステップが空です: {}", p.name);
            assert!(p.within_secs.is_some(), "within_secs が未設定: {}", p.name);
        }
    }

    #[test]
    fn test_merge_rules_adds_presets() {
        let user_rules = vec![];
        let merged = merge_rules(&user_rules, true, &[]);
        assert_eq!(merged.len(), 8);
    }

    #[test]
    fn test_merge_rules_disabled_presets() {
        let merged = merge_rules(&[], true, &["preset:container_escape".to_string()]);
        assert_eq!(merged.len(), 7);
        assert!(!merged.iter().any(|r| r.name == "preset:container_escape"));
    }

    #[test]
    fn test_merge_rules_disabled_presets_without_prefix() {
        let merged = merge_rules(&[], true, &["container_escape".to_string()]);
        assert_eq!(merged.len(), 7);
        assert!(!merged.iter().any(|r| r.name == "preset:container_escape"));
    }

    #[test]
    fn test_merge_rules_user_override() {
        let user_rules = vec![CorrelationRuleConfig {
            name: "preset:privilege_escalation".to_string(),
            description: "カスタム".to_string(),
            steps: vec![step("custom", "custom_event", None)],
            within_secs: Some(60),
        }];
        let merged = merge_rules(&user_rules, true, &[]);
        // プリセット7 + ユーザー1 = 8 (プリセット版はオーバーライドされる)
        assert_eq!(merged.len(), 8);
        let custom = merged
            .iter()
            .find(|r| r.name == "preset:privilege_escalation")
            .expect("カスタムルールが見つかりません");
        assert_eq!(custom.description, "カスタム");
    }

    #[test]
    fn test_merge_rules_presets_disabled() {
        let merged = merge_rules(&[], false, &[]);
        assert_eq!(merged.len(), 0);
    }

    #[test]
    fn test_preset_rules_compile() {
        // 全プリセットのルールが正規表現として有効であることを検証
        let presets = all_presets();
        for preset in &presets {
            for s in &preset.steps {
                regex::Regex::new(&s.event_type).unwrap_or_else(|e| {
                    panic!(
                        "プリセット '{}' ステップ '{}' の正規表現エラー: {}",
                        preset.name, s.name, e
                    );
                });
            }
        }
    }
}
