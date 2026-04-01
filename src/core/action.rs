//! アクションエンジン — 検知イベントに対する設定ベースのアクション実行

use crate::config::ActionConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::{broadcast, watch};

/// アクション種別
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionType {
    /// 追加のログ記録
    Log,
    /// 外部コマンド実行
    Command,
    /// Webhook 送信
    Webhook,
}

/// アクションルール
#[derive(Debug, Clone)]
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
    /// Webhook URL
    pub url: Option<String>,
    /// HTTP メソッド（デフォルト: "POST"）
    pub method: String,
    /// HTTP ヘッダー
    pub headers: HashMap<String, String>,
    /// ボディテンプレート
    pub body_template: Option<String>,
    /// リトライ回数
    pub max_retries: u32,
}

/// Webhook のデフォルトタイムアウト（秒）
const WEBHOOK_DEFAULT_TIMEOUT_SECS: u64 = 10;

/// Webhook 送信パラメータ
struct WebhookParams {
    url: String,
    method: String,
    headers: HashMap<String, String>,
    body_template: Option<String>,
    max_retries: u32,
    timeout_secs: u64,
}

/// アクションエンジン — イベントに対するアクションを実行する
pub struct ActionEngine {
    rules: Vec<ActionRule>,
    receiver: broadcast::Receiver<SecurityEvent>,
    client: reqwest::Client,
    config_receiver: watch::Receiver<Vec<ActionRule>>,
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
    ///
    /// 戻り値のタプルの第2要素はアクションルール更新用の `watch::Sender`。
    /// SIGHUP リロード時にこの sender で新しいルールを送信すると、
    /// 実行中の ActionEngine がルールを動的に更新する。
    pub fn new(
        config: &ActionConfig,
        event_bus: &EventBus,
    ) -> Result<(Self, watch::Sender<Vec<ActionRule>>), AppError> {
        let rules = Self::parse_rules(config)?;
        let (config_sender, config_receiver) = watch::channel(rules.clone());
        let receiver = event_bus.subscribe();
        let client = reqwest::Client::new();
        Ok((
            Self {
                rules,
                receiver,
                client,
                config_receiver,
            },
            config_sender,
        ))
    }

    /// ActionConfig からアクションルールをパースする
    pub fn parse_rules(config: &ActionConfig) -> Result<Vec<ActionRule>, AppError> {
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
                "webhook" => {
                    if rule_config.url.is_none() {
                        return Err(AppError::ActionConfig {
                            message: format!(
                                "ルール '{}' のアクション種別が 'webhook' ですが、url フィールドが設定されていません",
                                rule_config.name
                            ),
                        });
                    }
                    ActionType::Webhook
                }
                other => {
                    return Err(AppError::ActionConfig {
                        message: format!(
                            "ルール '{}' のアクション種別 '{}' が不正です（log, command, webhook のいずれかを指定してください）",
                            rule_config.name, other
                        ),
                    });
                }
            };

            // Webhook の場合、デフォルトタイムアウトの 30 秒のままなら 10 秒に上書き
            let timeout_secs = if action == ActionType::Webhook && rule_config.timeout_secs == 30 {
                WEBHOOK_DEFAULT_TIMEOUT_SECS
            } else {
                rule_config.timeout_secs
            };

            rules.push(ActionRule {
                name: rule_config.name.clone(),
                severity,
                module: rule_config.module.clone(),
                action,
                command: rule_config.command.clone(),
                timeout_secs,
                url: rule_config.url.clone(),
                method: rule_config
                    .method
                    .clone()
                    .unwrap_or_else(|| "POST".to_string()),
                headers: rule_config.headers.clone().unwrap_or_default(),
                body_template: rule_config.body_template.clone(),
                max_retries: rule_config.max_retries.unwrap_or(3),
            });
        }

        Ok(rules)
    }

    /// 非同期タスクとしてアクションエンジンを起動する
    pub fn spawn(self) {
        let client = self.client;
        tokio::spawn(async move {
            Self::run_loop(self.rules, self.receiver, self.config_receiver, client).await;
        });
    }

    async fn run_loop(
        mut rules: Vec<ActionRule>,
        mut receiver: broadcast::Receiver<SecurityEvent>,
        mut config_receiver: watch::Receiver<Vec<ActionRule>>,
        client: reqwest::Client,
    ) {
        loop {
            tokio::select! {
                result = receiver.recv() => {
                    match result {
                        Ok(event) => {
                            for rule in &rules {
                                if Self::matches(rule, &event) {
                                    Self::execute_action(rule, &event, &client).await;
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
                result = config_receiver.changed() => {
                    match result {
                        Ok(()) => {
                            let new_rules = config_receiver.borrow_and_update().clone();
                            let new_count = new_rules.len();
                            let old_count = rules.len();
                            rules = new_rules;
                            tracing::info!(
                                old_rules = old_count,
                                new_rules = new_count,
                                "アクションエンジン: ルールをリロードしました"
                            );
                        }
                        Err(_) => {
                            tracing::info!("設定チャネルが閉じられました。アクションエンジンを終了します");
                            break;
                        }
                    }
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
    async fn execute_action(rule: &ActionRule, event: &SecurityEvent, client: &reqwest::Client) {
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
            ActionType::Webhook => {
                let client = client.clone();
                let rule_name = rule.name.clone();
                let params = WebhookParams {
                    url: rule.url.clone().unwrap_or_default(),
                    method: rule.method.clone(),
                    headers: rule.headers.clone(),
                    body_template: rule.body_template.clone(),
                    max_retries: rule.max_retries,
                    timeout_secs: rule.timeout_secs,
                };
                let event = event.clone();
                tokio::spawn(async move {
                    let masked = Self::mask_url(&params.url);
                    match Self::send_webhook(&client, &params, &event).await {
                        Ok(()) => {
                            tracing::info!(
                                rule = %rule_name,
                                url = %masked,
                                "Webhook を送信しました"
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                rule = %rule_name,
                                url = %masked,
                                error = %e,
                                "Webhook の送信に失敗しました"
                            );
                        }
                    }
                });
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

    /// Webhook を送信する（リトライ付き）
    async fn send_webhook(
        client: &reqwest::Client,
        params: &WebhookParams,
        event: &SecurityEvent,
    ) -> Result<(), AppError> {
        let body = match &params.body_template {
            Some(template) => Self::expand_placeholders(template, event),
            None => Self::default_webhook_body(event),
        };

        for attempt in 0..=params.max_retries {
            if attempt > 0 {
                let delay = std::cmp::min(1u64 << (attempt - 1), 30);
                tokio::time::sleep(Duration::from_secs(delay)).await;
            }

            let mut request = match params.method.to_uppercase().as_str() {
                "GET" => client.get(&params.url),
                _ => client.post(&params.url),
            };

            for (key, value) in &params.headers {
                request = request.header(key, &*Self::expand_placeholders(value, event));
            }

            let result = request
                .body(body.clone())
                .timeout(Duration::from_secs(params.timeout_secs))
                .send()
                .await;

            match result {
                Ok(response) => {
                    let status = response.status();
                    if status.is_success() {
                        return Ok(());
                    } else if status.is_client_error() {
                        return Err(AppError::WebhookSend {
                            message: format!("HTTP {}", status),
                        });
                    }
                    // 5xx はリトライ
                }
                Err(e) if e.is_timeout() || e.is_connect() => {
                    // ネットワークエラー/タイムアウトはリトライ
                }
                Err(e) => {
                    return Err(AppError::WebhookSend {
                        message: e.to_string(),
                    });
                }
            }
        }

        Err(AppError::WebhookSend {
            message: "最大リトライ回数に達しました".to_string(),
        })
    }

    /// デフォルトの Webhook ボディ（JSON）を生成する
    fn default_webhook_body(event: &SecurityEvent) -> String {
        fn escape_json(s: &str) -> String {
            s.replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n")
                .replace('\r', "\\r")
                .replace('\t', "\\t")
        }
        format!(
            r#"{{"event_type":"{}","severity":"{}","source_module":"{}","message":"{}","details":"{}"}}"#,
            escape_json(&event.event_type),
            escape_json(&event.severity.to_string()),
            escape_json(&event.source_module),
            escape_json(&event.message),
            escape_json(event.details.as_deref().unwrap_or("")),
        )
    }

    /// ログ出力用に URL をマスクする
    fn mask_url(url: &str) -> String {
        match url.find("://") {
            Some(pos) => {
                let after_scheme = &url[pos + 3..];
                match after_scheme.find('/') {
                    Some(slash) => format!("{}/*****", &url[..pos + 3 + slash]),
                    None => url.to_string(),
                }
            }
            None => "***".to_string(),
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
            url: None,
            method: "POST".to_string(),
            headers: HashMap::new(),
            body_template: None,
            max_retries: 3,
        }
    }

    fn make_rule_config(name: &str, action: &str, command: Option<&str>) -> ActionRuleConfig {
        ActionRuleConfig {
            name: name.to_string(),
            severity: None,
            module: None,
            action: action.to_string(),
            command: command.map(|s| s.to_string()),
            timeout_secs: 30,
            url: None,
            method: None,
            headers: None,
            body_template: None,
            max_retries: None,
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
                {
                    let r = make_rule_config("log_all", "log", None);
                    r
                },
                {
                    let mut r =
                        make_rule_config("critical_command", "command", Some("echo '{{message}}'"));
                    r.severity = Some("critical".to_string());
                    r.module = Some("file_integrity".to_string());
                    r.timeout_secs = 10;
                    r
                },
            ],
        };
        let bus = EventBus::new(16);
        let result = ActionEngine::new(&config, &bus);
        assert!(result.is_ok());
        let (engine, _sender) = result.unwrap();
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
            rules: vec![make_rule_config("bad_rule", "command", None)],
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
            rules: vec![{
                let mut r = make_rule_config("bad_severity", "log", None);
                r.severity = Some("invalid".to_string());
                r
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

    #[test]
    fn test_webhook_rule_validation() {
        let config = ActionConfig {
            enabled: true,
            rules: vec![{
                let mut r = make_rule_config("bad_webhook", "webhook", None);
                r
            }],
        };
        let bus = EventBus::new(16);
        let result = ActionEngine::new(&config, &bus);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("url フィールドが設定されていません"));
    }

    #[test]
    fn test_default_webhook_body() {
        let event = SecurityEvent::new(
            "file_modified",
            Severity::Warning,
            "file_integrity",
            "ファイルが変更されました",
        )
        .with_details("/etc/passwd");

        let body = ActionEngine::default_webhook_body(&event);
        assert!(body.contains("\"event_type\":\"file_modified\""));
        assert!(body.contains("\"severity\":\"WARNING\""));
        assert!(body.contains("\"source_module\":\"file_integrity\""));
        assert!(body.contains("\"message\":\"ファイルが変更されました\""));
        assert!(body.contains("\"details\":\"/etc/passwd\""));
    }

    #[test]
    fn test_default_webhook_body_escapes_json() {
        let event = SecurityEvent::new("test", Severity::Info, "test", "line1\nline2\t\"quoted\"");

        let body = ActionEngine::default_webhook_body(&event);
        assert!(body.contains("line1\\nline2\\t\\\"quoted\\\""));
    }

    #[test]
    fn test_mask_url() {
        assert_eq!(
            ActionEngine::mask_url("https://hooks.slack.com/services/xxx/yyy/zzz"),
            "https://hooks.slack.com/*****"
        );
        assert_eq!(
            ActionEngine::mask_url("https://example.com"),
            "https://example.com"
        );
        assert_eq!(ActionEngine::mask_url("not-a-url"), "***");
    }

    #[test]
    fn test_expand_placeholders_in_webhook_headers() {
        let event = SecurityEvent::new("test_event", Severity::Critical, "test_module", "テスト");

        let template = "Bearer {{severity}}-token";
        let result = ActionEngine::expand_placeholders(template, &event);
        assert_eq!(result, "Bearer CRITICAL-token");
    }

    #[test]
    fn test_webhook_default_timeout() {
        let config = ActionConfig {
            enabled: true,
            rules: vec![{
                let mut r = make_rule_config("webhook_rule", "webhook", None);
                r.url = Some("https://example.com/hook".to_string());
                // timeout_secs はデフォルトの 30
                r
            }],
        };
        let bus = EventBus::new(16);
        let (engine, _sender) = ActionEngine::new(&config, &bus).unwrap();
        // Webhook のデフォルトタイムアウトは 10 秒に上書きされる
        assert_eq!(engine.rules[0].timeout_secs, WEBHOOK_DEFAULT_TIMEOUT_SECS);
    }

    #[test]
    fn test_webhook_custom_timeout() {
        let config = ActionConfig {
            enabled: true,
            rules: vec![{
                let mut r = make_rule_config("webhook_rule", "webhook", None);
                r.url = Some("https://example.com/hook".to_string());
                r.timeout_secs = 15; // カスタム値
                r
            }],
        };
        let bus = EventBus::new(16);
        let (engine, _sender) = ActionEngine::new(&config, &bus).unwrap();
        // カスタム値はそのまま
        assert_eq!(engine.rules[0].timeout_secs, 15);
    }

    #[test]
    fn test_parse_rules_valid() {
        let config = ActionConfig {
            enabled: true,
            rules: vec![make_rule_config("log_all", "log", None), {
                let mut r = make_rule_config("cmd_rule", "command", Some("echo test"));
                r.severity = Some("warning".to_string());
                r
            }],
        };
        let rules = ActionEngine::parse_rules(&config).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].name, "log_all");
        assert_eq!(rules[1].name, "cmd_rule");
        assert_eq!(rules[1].severity, Some(Severity::Warning));
    }

    #[test]
    fn test_parse_rules_invalid_severity() {
        let config = ActionConfig {
            enabled: true,
            rules: vec![{
                let mut r = make_rule_config("bad", "log", None);
                r.severity = Some("invalid".to_string());
                r
            }],
        };
        let result = ActionEngine::parse_rules(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_rules_empty() {
        let config = ActionConfig {
            enabled: true,
            rules: vec![],
        };
        let rules = ActionEngine::parse_rules(&config).unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn test_new_returns_watch_sender() {
        let config = ActionConfig {
            enabled: true,
            rules: vec![make_rule_config("log_all", "log", None)],
        };
        let bus = EventBus::new(16);
        let (engine, sender) = ActionEngine::new(&config, &bus).unwrap();
        assert_eq!(engine.rules.len(), 1);

        // sender で新しいルールを送信できることを確認
        let new_rules = vec![
            make_rule(None, None),
            make_rule(Some(Severity::Critical), None),
        ];
        assert!(sender.send(new_rules).is_ok());
    }

    #[tokio::test]
    async fn test_hot_reload_updates_rules() {
        let config = ActionConfig {
            enabled: true,
            rules: vec![make_rule_config("initial_rule", "log", None)],
        };
        let bus = EventBus::new(16);
        let (engine, sender) = ActionEngine::new(&config, &bus).unwrap();

        // エンジンを起動
        engine.spawn();

        // 新しいルールを送信
        let new_config = ActionConfig {
            enabled: true,
            rules: vec![
                make_rule_config("rule_a", "log", None),
                make_rule_config("rule_b", "log", None),
            ],
        };
        let new_rules = ActionEngine::parse_rules(&new_config).unwrap();
        assert!(sender.send(new_rules).is_ok());

        // ルール更新が処理される時間を与える
        tokio::time::sleep(Duration::from_millis(50)).await;

        // イベントを発行して新しいルールで処理されることを確認
        let event = SecurityEvent::new("test_event", Severity::Info, "test", "テスト");
        bus.publish(event);

        tokio::time::sleep(Duration::from_millis(50)).await;
        // パニックせずに動作することを確認
    }
}
