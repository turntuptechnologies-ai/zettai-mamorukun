//! アクションエンジン — 検知イベントに対する設定ベースのアクション実行

use crate::config::ActionConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use std::time::Duration;
use tokio::sync::broadcast;

/// アクション種別
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionType {
    /// 追加のログ記録
    Log,
    /// 外部コマンド実行
    Command,
}

/// アクションルール
pub struct ActionRule {
    /// ルール名
    pub name: String,
    /// Severity フィルタ（None は全 Severity にマッチ）
    pub severity: Option<Severity>,
    /// モジュール名フィルタ（None は全モジュールにマッチ）
    pub module: Option<String>,
    /// アクション種別
    pub action: ActionType,
    /// 実行コマンド（ActionType::Command の場合に使用）
    pub command: Option<String>,
    /// コマンドタイムアウト（秒）
    pub timeout_secs: u64,
}

/// アクションエンジン — イベントに対するアクションを実行する
pub struct ActionEngine {
    rules: Vec<ActionRule>,
    receiver: broadcast::Receiver<SecurityEvent>,
}

impl std::fmt::Debug for ActionEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActionEngine")
            .field("rules_count", &self.rules.len())
            .finish()
    }
}

impl ActionEngine {
    /// 設定からアクションエンジンを構築する
    pub fn new(config: &ActionConfig, event_bus: &EventBus) -> Result<Self, AppError> {
        let mut rules = Vec::new();
        for rule_config in &config.rules {
            let severity = match &rule_config.severity {
                Some(s) => {
                    let sev = Severity::parse(s).ok_or_else(|| AppError::ActionConfig {
                        message: format!(
                            "ルール '{}' の severity '{}' が不正です（info, warning, critical のいずれかを指定してください）",
                            rule_config.name, s
                        ),
                    })?;
                    Some(sev)
                }
                None => None,
            };

            let action = match rule_config.action.to_lowercase().as_str() {
                "log" => ActionType::Log,
                "command" => {
                    if rule_config.command.is_none() {
                        return Err(AppError::ActionConfig {
                            message: format!(
                                "ルール '{}' のアクション種別が 'command' ですが、command フィールドが設定されていません",
                                rule_config.name
                            ),
                        });
                    }
                    ActionType::Command
                }
                other => {
                    return Err(AppError::ActionConfig {
                        message: format!(
                            "ルール '{}' のアクション種別 '{}' が不正です（log, command のいずれかを指定してください）",
                            rule_config.name, other
                        ),
                    });
                }
            };

            rules.push(ActionRule {
                name: rule_config.name.clone(),
                severity,
                module: rule_config.module.clone(),
                action,
                command: rule_config.command.clone(),
                timeout_secs: rule_config.timeout_secs,
            });
        }

        let receiver = event_bus.subscribe();
        Ok(Self { rules, receiver })
    }

    /// 非同期タスクとしてアクションエンジンを起動する
    pub fn spawn(self) {
        tokio::spawn(async move {
            Self::run_loop(self.rules, self.receiver).await;
        });
    }

    async fn run_loop(rules: Vec<ActionRule>, mut receiver: broadcast::Receiver<SecurityEvent>) {
        loop {
            match receiver.recv().await {
                Ok(event) => {
                    for rule in &rules {
                        if Self::matches(rule, &event) {
                            Self::execute_action(rule, &event).await;
                        }
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(
                        skipped = n,
                        "アクションエンジン: {} 件のイベントをスキップ（遅延）",
                        n
                    );
                }
                Err(broadcast::error::RecvError::Closed) => {
                    tracing::info!("イベントバスが閉じられました。アクションエンジンを終了します");
                    break;
                }
            }
        }
    }

    /// ルールがイベントにマッチするか判定する
    fn matches(rule: &ActionRule, event: &SecurityEvent) -> bool {
        if let Some(ref sev) = rule.severity
            && *sev != event.severity
        {
            return false;
        }
        if let Some(ref module) = rule.module
            && *module != event.source_module
        {
            return false;
        }
        true
    }

    /// アクションを実行する
    async fn execute_action(rule: &ActionRule, event: &SecurityEvent) {
        match rule.action {
            ActionType::Log => {
                tracing::info!(
                    rule = %rule.name,
                    event_type = %event.event_type,
                    source_module = %event.source_module,
                    severity = %event.severity,
                    "[ActionEngine] {}",
                    event.message
                );
            }
            ActionType::Command => {
                if let Some(ref cmd_template) = rule.command {
                    let cmd = Self::expand_placeholders(cmd_template, event);
                    let timeout = Duration::from_secs(rule.timeout_secs);
                    match Self::run_command(&cmd, timeout).await {
                        Ok(()) => {
                            tracing::info!(
                                rule = %rule.name,
                                command = %cmd,
                                "アクションコマンドを実行しました"
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                rule = %rule.name,
                                command = %cmd,
                                error = %e,
                                "アクションコマンドの実行に失敗しました"
                            );
                        }
                    }
                }
            }
        }
    }

    /// テンプレート内のプレースホルダを展開する
    fn expand_placeholders(template: &str, event: &SecurityEvent) -> String {
        template
            .replace("{{source}}", &event.source_module)
            .replace("{{message}}", &event.message)
            .replace("{{severity}}", &event.severity.to_string())
            .replace("{{event_type}}", &event.event_type)
            .replace("{{details}}", event.details.as_deref().unwrap_or(""))
    }

    /// 外部コマンドを実行する
    async fn run_command(command: &str, timeout: Duration) -> Result<(), AppError> {
        let result = tokio::time::timeout(
            timeout,
            tokio::process::Command::new("sh")
                .arg("-c")
                .arg(command)
                .output(),
        )
        .await;

        match result {
            Ok(Ok(output)) => {
                if output.status.success() {
                    Ok(())
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    Err(AppError::ActionExecution {
                        message: format!(
                            "コマンドが終了コード {} で終了しました: {}",
                            output.status.code().unwrap_or(-1),
                            stderr.trim()
                        ),
                    })
                }
            }
            Ok(Err(e)) => Err(AppError::ActionExecution {
                message: format!("コマンドの起動に失敗しました: {}", e),
            }),
            Err(_) => Err(AppError::ActionExecution {
                message: format!("コマンドがタイムアウトしました（{}秒）", timeout.as_secs()),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ActionConfig, ActionRuleConfig};

    fn make_event(severity: Severity, source_module: &str) -> SecurityEvent {
        SecurityEvent::new("test_event", severity, source_module, "テストメッセージ")
    }

    fn make_rule(severity: Option<Severity>, module: Option<String>) -> ActionRule {
        ActionRule {
            name: "test_rule".to_string(),
            severity,
            module,
            action: ActionType::Log,
            command: None,
            timeout_secs: 30,
        }
    }

    #[test]
    fn test_matches_all() {
        let rule = make_rule(None, None);
        let event = make_event(Severity::Info, "any_module");
        assert!(ActionEngine::matches(&rule, &event));

        let event2 = make_event(Severity::Critical, "other_module");
        assert!(ActionEngine::matches(&rule, &event2));
    }

    #[test]
    fn test_matches_severity() {
        let rule = make_rule(Some(Severity::Warning), None);
        let event_match = make_event(Severity::Warning, "any_module");
        assert!(ActionEngine::matches(&rule, &event_match));

        let event_no_match = make_event(Severity::Info, "any_module");
        assert!(!ActionEngine::matches(&rule, &event_no_match));
    }

    #[test]
    fn test_matches_module() {
        let rule = make_rule(None, Some("file_integrity".to_string()));
        let event_match = make_event(Severity::Info, "file_integrity");
        assert!(ActionEngine::matches(&rule, &event_match));

        let event_no_match = make_event(Severity::Info, "process_monitor");
        assert!(!ActionEngine::matches(&rule, &event_no_match));
    }

    #[test]
    fn test_matches_severity_and_module() {
        let rule = make_rule(Some(Severity::Critical), Some("file_integrity".to_string()));
        let event_match = make_event(Severity::Critical, "file_integrity");
        assert!(ActionEngine::matches(&rule, &event_match));

        let event_wrong_sev = make_event(Severity::Info, "file_integrity");
        assert!(!ActionEngine::matches(&rule, &event_wrong_sev));

        let event_wrong_mod = make_event(Severity::Critical, "other_module");
        assert!(!ActionEngine::matches(&rule, &event_wrong_mod));
    }

    #[test]
    fn test_matches_no_match() {
        let rule = make_rule(Some(Severity::Critical), Some("file_integrity".to_string()));
        let event = make_event(Severity::Info, "process_monitor");
        assert!(!ActionEngine::matches(&rule, &event));
    }

    #[test]
    fn test_expand_placeholders() {
        let event = SecurityEvent::new(
            "file_modified",
            Severity::Warning,
            "file_integrity",
            "ファイルが変更されました",
        )
        .with_details("/etc/passwd");

        let template = "alert: {{source}} {{message}} {{severity}} {{event_type}} {{details}}";
        let result = ActionEngine::expand_placeholders(template, &event);
        assert_eq!(
            result,
            "alert: file_integrity ファイルが変更されました WARNING file_modified /etc/passwd"
        );
    }

    #[test]
    fn test_expand_placeholders_no_details() {
        let event = SecurityEvent::new("test_event", Severity::Info, "test_module", "テスト");

        let template = "details={{details}}";
        let result = ActionEngine::expand_placeholders(template, &event);
        assert_eq!(result, "details=");
    }

    #[test]
    fn test_action_engine_new_valid() {
        let config = ActionConfig {
            enabled: true,
            rules: vec![
                ActionRuleConfig {
                    name: "log_all".to_string(),
                    severity: None,
                    module: None,
                    action: "log".to_string(),
                    command: None,
                    timeout_secs: 30,
                },
                ActionRuleConfig {
                    name: "critical_command".to_string(),
                    severity: Some("critical".to_string()),
                    module: Some("file_integrity".to_string()),
                    action: "command".to_string(),
                    command: Some("echo '{{message}}'".to_string()),
                    timeout_secs: 10,
                },
            ],
        };
        let bus = EventBus::new(16);
        let engine = ActionEngine::new(&config, &bus);
        assert!(engine.is_ok());
        let engine = engine.unwrap();
        assert_eq!(engine.rules.len(), 2);
        assert_eq!(engine.rules[0].name, "log_all");
        assert_eq!(engine.rules[0].action, ActionType::Log);
        assert_eq!(engine.rules[1].name, "critical_command");
        assert_eq!(engine.rules[1].action, ActionType::Command);
        assert_eq!(engine.rules[1].severity, Some(Severity::Critical));
    }

    #[test]
    fn test_action_engine_new_command_without_command_field() {
        let config = ActionConfig {
            enabled: true,
            rules: vec![ActionRuleConfig {
                name: "bad_rule".to_string(),
                severity: None,
                module: None,
                action: "command".to_string(),
                command: None,
                timeout_secs: 30,
            }],
        };
        let bus = EventBus::new(16);
        let result = ActionEngine::new(&config, &bus);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("command フィールドが設定されていません"));
    }

    #[test]
    fn test_action_engine_new_invalid_severity() {
        let config = ActionConfig {
            enabled: true,
            rules: vec![ActionRuleConfig {
                name: "bad_severity".to_string(),
                severity: Some("invalid".to_string()),
                module: None,
                action: "log".to_string(),
                command: None,
                timeout_secs: 30,
            }],
        };
        let bus = EventBus::new(16);
        let result = ActionEngine::new(&config, &bus);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("severity"));
    }

    #[tokio::test]
    async fn test_run_command_success() {
        let result = ActionEngine::run_command("echo hello", Duration::from_secs(5)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_command_timeout() {
        let result = ActionEngine::run_command("sleep 60", Duration::from_secs(1)).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("タイムアウト"));
    }
}
