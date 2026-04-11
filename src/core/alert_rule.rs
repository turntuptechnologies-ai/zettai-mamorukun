//! アラートルール DSL エンジン — カスタム条件でセキュリティイベントを監視しアクションを実行する

use crate::config::{AlertRuleConfig, AlertRulesConfig, AlertSubConditionConfig};
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use regex::Regex;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime};
use tokio::sync::{broadcast, watch};

/// マッチ対象フィールド
enum MatchField {
    EventType,
    SourceModule,
    Message,
    Details,
    Severity,
}

impl MatchField {
    fn parse(s: &str) -> Result<Self, AppError> {
        match s {
            "event_type" => Ok(Self::EventType),
            "source_module" => Ok(Self::SourceModule),
            "message" => Ok(Self::Message),
            "details" => Ok(Self::Details),
            "severity" => Ok(Self::Severity),
            other => Err(AppError::AlertRule(format!(
                "無効なフィールド名: '{}'",
                other
            ))),
        }
    }

    fn extract(&self, event: &SecurityEvent) -> String {
        match self {
            Self::EventType => event.event_type.clone(),
            Self::SourceModule => event.source_module.clone(),
            Self::Message => event.message.clone(),
            Self::Details => event.details.clone().unwrap_or_default(),
            Self::Severity => event.severity.to_string(),
        }
    }
}

/// 論理演算子
enum LogicalOperator {
    And,
    Or,
}

/// コンパイル済み条件
enum CompiledCondition {
    Threshold {
        count: u64,
        window: Duration,
        event_type: Option<String>,
        severity: Option<Severity>,
        module: Option<String>,
    },
    FieldMatch {
        field: MatchField,
        pattern: Regex,
        severity: Option<Severity>,
        module: Option<String>,
        event_type: Option<String>,
    },
    Compound {
        operator: LogicalOperator,
        conditions: Vec<CompiledCondition>,
    },
}

/// アクション種別
enum AlertActionType {
    Log,
    Command {
        command_template: String,
        timeout: Duration,
    },
    Webhook {
        url: String,
        method: String,
        headers: HashMap<String, String>,
        body_template: Option<String>,
        max_retries: u32,
        timeout: Duration,
    },
}

/// コンパイル済みアラートルール
struct CompiledAlertRule {
    name: String,
    description: String,
    condition: CompiledCondition,
    action: AlertActionType,
}

/// スライディングウィンドウキー
#[derive(Hash, Eq, PartialEq, Clone)]
struct WindowKey {
    rule_name: String,
    sub_condition_index: Option<usize>,
}

/// スライディングウィンドウ
struct SlidingWindow {
    timestamps: VecDeque<SystemTime>,
    window_duration: Duration,
    threshold: u64,
}

impl SlidingWindow {
    fn new(window_duration: Duration, threshold: u64) -> Self {
        Self {
            timestamps: VecDeque::new(),
            window_duration,
            threshold,
        }
    }

    fn push_and_check(&mut self, timestamp: SystemTime) -> bool {
        self.evict_expired(timestamp);
        self.timestamps.push_back(timestamp);
        self.timestamps.len() as u64 >= self.threshold
    }

    fn evict_expired(&mut self, now: SystemTime) {
        while let Some(&front) = self.timestamps.front() {
            if let Ok(elapsed) = now.duration_since(front) {
                if elapsed > self.window_duration {
                    self.timestamps.pop_front();
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }
}

/// ホットリロード用のランタイム設定
#[derive(Clone)]
pub struct AlertRuleEngineConfig {
    /// ルール設定
    pub rules: Vec<AlertRuleConfig>,
}

/// アラートルールエンジン
pub struct AlertRuleEngine {
    receiver: broadcast::Receiver<SecurityEvent>,
    config_receiver: watch::Receiver<AlertRuleEngineConfig>,
    rules: Vec<CompiledAlertRule>,
    windows: HashMap<WindowKey, SlidingWindow>,
    client: reqwest::Client,
}

impl AlertRuleEngine {
    /// 設定からアラートルールエンジンを構築する
    pub fn new(
        config: &AlertRulesConfig,
        event_bus: &EventBus,
    ) -> Result<(Self, watch::Sender<AlertRuleEngineConfig>), AppError> {
        let rules = Self::compile_rules(&config.rules)?;
        let engine_config = AlertRuleEngineConfig {
            rules: config.rules.clone(),
        };
        let (config_sender, config_receiver) = watch::channel(engine_config);
        let receiver = event_bus.subscribe();
        let client = reqwest::Client::new();
        Ok((
            Self {
                receiver,
                config_receiver,
                rules,
                windows: HashMap::new(),
                client,
            },
            config_sender,
        ))
    }

    /// 非同期タスクとしてエンジンを起動する
    pub fn spawn(self) {
        tokio::spawn(async move {
            self.run_loop().await;
        });
    }

    async fn run_loop(mut self) {
        loop {
            tokio::select! {
                result = self.receiver.recv() => {
                    match result {
                        Ok(event) => {
                            for i in 0..self.rules.len() {
                                if self.evaluate(i, &event) {
                                    self.execute_action(&self.rules[i], &event).await;
                                }
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(skipped = n, "アラートルールエンジン: イベント遅延");
                        }
                        Err(_) => break,
                    }
                }
                Ok(()) = self.config_receiver.changed() => {
                    let new_config = self.config_receiver.borrow_and_update().clone();
                    match Self::compile_rules(&new_config.rules) {
                        Ok(new_rules) => {
                            self.rules = new_rules;
                            self.windows.clear();
                            tracing::info!(
                                rule_count = self.rules.len(),
                                "アラートルールをリロード"
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                "アラートルールのコンパイル失敗。旧ルール継続"
                            );
                        }
                    }
                }
            }
        }
    }

    fn compile_rules(configs: &[AlertRuleConfig]) -> Result<Vec<CompiledAlertRule>, AppError> {
        configs.iter().map(Self::compile_rule).collect()
    }

    fn compile_rule(config: &AlertRuleConfig) -> Result<CompiledAlertRule, AppError> {
        let condition = Self::compile_condition(config)?;
        let action = Self::compile_action(config)?;
        Ok(CompiledAlertRule {
            name: config.name.clone(),
            description: config.description.clone().unwrap_or_default(),
            condition,
            action,
        })
    }

    fn compile_action(config: &AlertRuleConfig) -> Result<AlertActionType, AppError> {
        match config.action.as_str() {
            "log" => Ok(AlertActionType::Log),
            "command" => {
                let cmd = config.command.as_ref().ok_or_else(|| {
                    AppError::AlertRule(format!(
                        "ルール '{}': action が 'command' の場合 command は必須です",
                        config.name
                    ))
                })?;
                Ok(AlertActionType::Command {
                    command_template: cmd.clone(),
                    timeout: Duration::from_secs(config.timeout_secs),
                })
            }
            "webhook" => {
                let url = config.url.as_ref().ok_or_else(|| {
                    AppError::AlertRule(format!(
                        "ルール '{}': action が 'webhook' の場合 url は必須です",
                        config.name
                    ))
                })?;
                Ok(AlertActionType::Webhook {
                    url: url.clone(),
                    method: config.method.clone().unwrap_or_else(|| "POST".to_string()),
                    headers: config.headers.clone().unwrap_or_default(),
                    body_template: config.body_template.clone(),
                    max_retries: config.max_retries.unwrap_or(3),
                    timeout: Duration::from_secs(config.timeout_secs),
                })
            }
            other => Err(AppError::AlertRule(format!(
                "ルール '{}': 無効な action '{}'",
                config.name, other
            ))),
        }
    }

    fn compile_condition(config: &AlertRuleConfig) -> Result<CompiledCondition, AppError> {
        match config.condition_type.as_str() {
            "threshold" => {
                let count = config.threshold_count.ok_or_else(|| {
                    AppError::AlertRule(format!(
                        "ルール '{}': threshold には threshold_count が必須です",
                        config.name
                    ))
                })?;
                let window_secs = config.window_secs.ok_or_else(|| {
                    AppError::AlertRule(format!(
                        "ルール '{}': threshold には window_secs が必須です",
                        config.name
                    ))
                })?;
                let severity = Self::parse_severity_filter(config.severity_filter.as_deref())?;
                Ok(CompiledCondition::Threshold {
                    count,
                    window: Duration::from_secs(window_secs),
                    event_type: config.event_type.clone(),
                    severity,
                    module: config.module_filter.clone(),
                })
            }
            "field_match" => {
                let field_str = config.field.as_ref().ok_or_else(|| {
                    AppError::AlertRule(format!(
                        "ルール '{}': field_match には field が必須です",
                        config.name
                    ))
                })?;
                let pattern_str = config.pattern.as_ref().ok_or_else(|| {
                    AppError::AlertRule(format!(
                        "ルール '{}': field_match には pattern が必須です",
                        config.name
                    ))
                })?;
                let field = MatchField::parse(field_str)?;
                let pattern = Regex::new(pattern_str).map_err(|e| {
                    AppError::AlertRule(format!(
                        "ルール '{}': 正規表現のコンパイルに失敗: {}",
                        config.name, e
                    ))
                })?;
                let severity = Self::parse_severity_filter(config.severity_filter.as_deref())?;
                Ok(CompiledCondition::FieldMatch {
                    field,
                    pattern,
                    severity,
                    module: config.module_filter.clone(),
                    event_type: config.event_type.clone(),
                })
            }
            "compound" => {
                let op_str = config.operator.as_ref().ok_or_else(|| {
                    AppError::AlertRule(format!(
                        "ルール '{}': compound には operator が必須です",
                        config.name
                    ))
                })?;
                let operator = match op_str.as_str() {
                    "and" => LogicalOperator::And,
                    "or" => LogicalOperator::Or,
                    other => {
                        return Err(AppError::AlertRule(format!(
                            "ルール '{}': 無効な operator '{}'",
                            config.name, other
                        )));
                    }
                };
                if config.conditions.is_empty() {
                    return Err(AppError::AlertRule(format!(
                        "ルール '{}': compound には conditions が必須です",
                        config.name
                    )));
                }
                let conditions: Result<Vec<_>, _> = config
                    .conditions
                    .iter()
                    .map(|c| Self::compile_sub_condition(c, &config.name))
                    .collect();
                Ok(CompiledCondition::Compound {
                    operator,
                    conditions: conditions?,
                })
            }
            other => Err(AppError::AlertRule(format!(
                "ルール '{}': 無効な condition_type '{}'",
                config.name, other
            ))),
        }
    }

    fn compile_sub_condition(
        config: &AlertSubConditionConfig,
        rule_name: &str,
    ) -> Result<CompiledCondition, AppError> {
        match config.condition_type.as_str() {
            "threshold" => {
                let count = config.threshold_count.ok_or_else(|| {
                    AppError::AlertRule(format!(
                        "ルール '{}': サブ条件 threshold には threshold_count が必須です",
                        rule_name
                    ))
                })?;
                let window_secs = config.window_secs.ok_or_else(|| {
                    AppError::AlertRule(format!(
                        "ルール '{}': サブ条件 threshold には window_secs が必須です",
                        rule_name
                    ))
                })?;
                let severity = Self::parse_severity_filter(config.severity_filter.as_deref())?;
                Ok(CompiledCondition::Threshold {
                    count,
                    window: Duration::from_secs(window_secs),
                    event_type: config.event_type.clone(),
                    severity,
                    module: config.module_filter.clone(),
                })
            }
            "field_match" => {
                let field_str = config.field.as_ref().ok_or_else(|| {
                    AppError::AlertRule(format!(
                        "ルール '{}': サブ条件 field_match には field が必須です",
                        rule_name
                    ))
                })?;
                let pattern_str = config.pattern.as_ref().ok_or_else(|| {
                    AppError::AlertRule(format!(
                        "ルール '{}': サブ条件 field_match には pattern が必須です",
                        rule_name
                    ))
                })?;
                let field = MatchField::parse(field_str)?;
                let pattern = Regex::new(pattern_str).map_err(|e| {
                    AppError::AlertRule(format!(
                        "ルール '{}': サブ条件の正規表現コンパイルに失敗: {}",
                        rule_name, e
                    ))
                })?;
                let severity = Self::parse_severity_filter(config.severity_filter.as_deref())?;
                Ok(CompiledCondition::FieldMatch {
                    field,
                    pattern,
                    severity,
                    module: config.module_filter.clone(),
                    event_type: config.event_type.clone(),
                })
            }
            other => Err(AppError::AlertRule(format!(
                "ルール '{}': サブ条件の無効な condition_type '{}'",
                rule_name, other
            ))),
        }
    }

    fn parse_severity_filter(s: Option<&str>) -> Result<Option<Severity>, AppError> {
        match s {
            None => Ok(None),
            Some(s) => Severity::parse(s)
                .map(Some)
                .ok_or_else(|| AppError::AlertRule(format!("無効な severity: '{}'", s))),
        }
    }

    fn evaluate(&mut self, rule_index: usize, event: &SecurityEvent) -> bool {
        let rule_name = self.rules[rule_index].name.clone();
        let mut sub_index: usize = 0;
        Self::evaluate_condition(
            &self.rules[rule_index].condition,
            event,
            &rule_name,
            &mut sub_index,
            &mut self.windows,
        )
    }

    fn evaluate_condition(
        condition: &CompiledCondition,
        event: &SecurityEvent,
        rule_name: &str,
        sub_index: &mut usize,
        windows: &mut HashMap<WindowKey, SlidingWindow>,
    ) -> bool {
        match condition {
            CompiledCondition::Threshold {
                count,
                window,
                event_type,
                severity,
                module,
            } => {
                if !Self::event_matches_filters(event, event_type, severity, module) {
                    return false;
                }
                let key = WindowKey {
                    rule_name: rule_name.to_string(),
                    sub_condition_index: Some(*sub_index),
                };
                *sub_index += 1;
                let sliding = windows
                    .entry(key)
                    .or_insert_with(|| SlidingWindow::new(*window, *count));
                sliding.push_and_check(event.timestamp)
            }
            CompiledCondition::FieldMatch {
                field,
                pattern,
                severity,
                module,
                event_type,
            } => {
                if !Self::event_matches_filters(event, event_type, severity, module) {
                    return false;
                }
                let value = field.extract(event);
                pattern.is_match(&value)
            }
            CompiledCondition::Compound {
                operator,
                conditions,
            } => {
                // 短絡評価せず全サブ条件を評価し、threshold ウィンドウの更新漏れを防ぐ
                let results: Vec<bool> = conditions
                    .iter()
                    .map(|c| Self::evaluate_condition(c, event, rule_name, sub_index, windows))
                    .collect();
                match operator {
                    LogicalOperator::And => results.iter().all(|&r| r),
                    LogicalOperator::Or => results.iter().any(|&r| r),
                }
            }
        }
    }

    fn event_matches_filters(
        event: &SecurityEvent,
        event_type: &Option<String>,
        severity: &Option<Severity>,
        module: &Option<String>,
    ) -> bool {
        if let Some(et) = event_type
            && event.event_type != *et
        {
            return false;
        }
        if let Some(sev) = severity
            && event.severity != *sev
        {
            return false;
        }
        if let Some(m) = module
            && event.source_module != *m
        {
            return false;
        }
        true
    }

    async fn execute_action(&self, rule: &CompiledAlertRule, event: &SecurityEvent) {
        match &rule.action {
            AlertActionType::Log => {
                tracing::info!(
                    rule = %rule.name,
                    description = %rule.description,
                    event_type = %event.event_type,
                    source_module = %event.source_module,
                    severity = %event.severity,
                    "[AlertRule] {}",
                    event.message
                );
            }
            AlertActionType::Command {
                command_template,
                timeout,
            } => {
                let cmd = Self::expand_placeholders(command_template, event);
                match Self::run_command(&cmd, *timeout).await {
                    Ok(()) => {
                        tracing::info!(
                            rule = %rule.name,
                            command = %cmd,
                            "アラートルール: コマンドを実行しました"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            rule = %rule.name,
                            command = %cmd,
                            error = %e,
                            "アラートルール: コマンドの実行に失敗しました"
                        );
                    }
                }
            }
            AlertActionType::Webhook {
                url,
                method,
                headers,
                body_template,
                max_retries,
                timeout,
            } => {
                let body = match body_template {
                    Some(template) => Self::expand_placeholders(template, event),
                    None => Self::default_webhook_body(event),
                };
                let result = Self::send_webhook(
                    &self.client,
                    url,
                    method,
                    headers,
                    &body,
                    event,
                    *max_retries,
                    *timeout,
                )
                .await;
                match result {
                    Ok(()) => {
                        tracing::info!(
                            rule = %rule.name,
                            "アラートルール: Webhook を送信しました"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            rule = %rule.name,
                            error = %e,
                            "アラートルール: Webhook の送信に失敗しました"
                        );
                    }
                }
            }
        }
    }

    fn expand_placeholders(template: &str, event: &SecurityEvent) -> String {
        template
            .replace("{{source}}", &Self::shell_escape(&event.source_module))
            .replace("{{message}}", &Self::shell_escape(&event.message))
            .replace("{{severity}}", &event.severity.to_string())
            .replace("{{event_type}}", &Self::shell_escape(&event.event_type))
            .replace(
                "{{details}}",
                &Self::shell_escape(event.details.as_deref().unwrap_or("")),
            )
    }

    fn shell_escape(s: &str) -> String {
        s.replace('\'', "'\"'\"'")
    }

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
                    Err(AppError::AlertRule(format!(
                        "コマンドが終了コード {} で終了しました: {}",
                        output.status.code().unwrap_or(-1),
                        stderr.trim()
                    )))
                }
            }
            Ok(Err(e)) => Err(AppError::AlertRule(format!(
                "コマンドの起動に失敗しました: {}",
                e
            ))),
            Err(_) => Err(AppError::AlertRule(format!(
                "コマンドがタイムアウトしました（{}秒）",
                timeout.as_secs()
            ))),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_webhook(
        client: &reqwest::Client,
        url: &str,
        method: &str,
        headers: &HashMap<String, String>,
        body: &str,
        event: &SecurityEvent,
        max_retries: u32,
        timeout: Duration,
    ) -> Result<(), AppError> {
        for attempt in 0..=max_retries {
            if attempt > 0 {
                let delay = std::cmp::min(1u64 << (attempt - 1), 30);
                tokio::time::sleep(Duration::from_secs(delay)).await;
            }

            let mut request = match method.to_uppercase().as_str() {
                "GET" => client.get(url),
                _ => client.post(url),
            };

            for (key, value) in headers {
                request = request.header(key, &*Self::expand_placeholders(value, event));
            }

            let result = request.body(body.to_string()).timeout(timeout).send().await;

            match result {
                Ok(response) => {
                    let status = response.status();
                    if status.is_success() {
                        return Ok(());
                    } else if status.is_client_error() {
                        return Err(AppError::AlertRule(format!("HTTP {}", status)));
                    }
                }
                Err(e) if e.is_timeout() || e.is_connect() => {}
                Err(e) => {
                    return Err(AppError::AlertRule(e.to_string()));
                }
            }
        }

        Err(AppError::AlertRule(
            "最大リトライ回数に達しました".to_string(),
        ))
    }

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AlertRuleConfig, AlertSubConditionConfig};
    use std::time::{Duration, SystemTime};

    fn make_event(
        event_type: &str,
        severity: Severity,
        source_module: &str,
        message: &str,
    ) -> SecurityEvent {
        SecurityEvent {
            event_type: event_type.to_string(),
            severity,
            source_module: source_module.to_string(),
            timestamp: SystemTime::now(),
            message: message.to_string(),
            details: None,
        }
    }

    fn make_event_with_details(
        event_type: &str,
        severity: Severity,
        source_module: &str,
        message: &str,
        details: &str,
    ) -> SecurityEvent {
        SecurityEvent {
            event_type: event_type.to_string(),
            severity,
            source_module: source_module.to_string(),
            timestamp: SystemTime::now(),
            message: message.to_string(),
            details: Some(details.to_string()),
        }
    }

    #[test]
    fn test_sliding_window_basic() {
        let mut window = SlidingWindow::new(Duration::from_secs(60), 3);
        let now = SystemTime::now();
        assert!(!window.push_and_check(now));
        assert!(!window.push_and_check(now));
        assert!(window.push_and_check(now));
    }

    #[test]
    fn test_sliding_window_expiry() {
        let mut window = SlidingWindow::new(Duration::from_secs(10), 3);
        let past = SystemTime::now() - Duration::from_secs(20);
        window.timestamps.push_back(past);
        window.timestamps.push_back(past);

        let now = SystemTime::now();
        assert!(!window.push_and_check(now));
        assert_eq!(window.timestamps.len(), 1);
    }

    #[test]
    fn test_compile_threshold_rule() {
        let config = AlertRuleConfig {
            name: "test_threshold".to_string(),
            description: Some("test".to_string()),
            condition_type: "threshold".to_string(),
            threshold_count: Some(5),
            window_secs: Some(300),
            event_type: None,
            severity_filter: Some("Warning".to_string()),
            module_filter: Some("ssh_brute_force".to_string()),
            field: None,
            pattern: None,
            operator: None,
            conditions: vec![],
            action: "log".to_string(),
            command: None,
            timeout_secs: 30,
            url: None,
            method: None,
            headers: None,
            body_template: None,
            max_retries: None,
        };
        let result = AlertRuleEngine::compile_rule(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_compile_field_match_rule() {
        let config = AlertRuleConfig {
            name: "test_field_match".to_string(),
            description: None,
            condition_type: "field_match".to_string(),
            threshold_count: None,
            window_secs: None,
            event_type: None,
            severity_filter: None,
            module_filter: None,
            field: Some("details".to_string()),
            pattern: Some("/etc/(passwd|shadow)".to_string()),
            operator: None,
            conditions: vec![],
            action: "log".to_string(),
            command: None,
            timeout_secs: 30,
            url: None,
            method: None,
            headers: None,
            body_template: None,
            max_retries: None,
        };
        let result = AlertRuleEngine::compile_rule(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_compile_compound_rule() {
        let config = AlertRuleConfig {
            name: "test_compound".to_string(),
            description: None,
            condition_type: "compound".to_string(),
            threshold_count: None,
            window_secs: None,
            event_type: None,
            severity_filter: None,
            module_filter: None,
            field: None,
            pattern: None,
            operator: Some("and".to_string()),
            conditions: vec![
                AlertSubConditionConfig {
                    condition_type: "threshold".to_string(),
                    threshold_count: Some(5),
                    window_secs: Some(120),
                    event_type: None,
                    severity_filter: None,
                    module_filter: Some("ssh_brute_force".to_string()),
                    field: None,
                    pattern: None,
                },
                AlertSubConditionConfig {
                    condition_type: "field_match".to_string(),
                    threshold_count: None,
                    window_secs: None,
                    event_type: None,
                    severity_filter: None,
                    module_filter: None,
                    field: Some("source_module".to_string()),
                    pattern: Some("file_integrity".to_string()),
                },
            ],
            action: "log".to_string(),
            command: None,
            timeout_secs: 30,
            url: None,
            method: None,
            headers: None,
            body_template: None,
            max_retries: None,
        };
        let result = AlertRuleEngine::compile_rule(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_field_match_evaluation() {
        let config = AlertRuleConfig {
            name: "field_test".to_string(),
            description: None,
            condition_type: "field_match".to_string(),
            threshold_count: None,
            window_secs: None,
            event_type: None,
            severity_filter: None,
            module_filter: None,
            field: Some("details".to_string()),
            pattern: Some("/etc/(passwd|shadow)".to_string()),
            operator: None,
            conditions: vec![],
            action: "log".to_string(),
            command: None,
            timeout_secs: 30,
            url: None,
            method: None,
            headers: None,
            body_template: None,
            max_retries: None,
        };
        let rules = AlertRuleEngine::compile_rules(&[config]).unwrap();
        let mut windows: HashMap<WindowKey, SlidingWindow> = HashMap::new();

        let event_match = make_event_with_details(
            "file_modified",
            Severity::Warning,
            "file_integrity",
            "file changed",
            "/etc/passwd was modified",
        );
        let mut sub_index = 0;
        assert!(AlertRuleEngine::evaluate_condition(
            &rules[0].condition,
            &event_match,
            "field_test",
            &mut sub_index,
            &mut windows,
        ));

        let event_no_match = make_event_with_details(
            "file_modified",
            Severity::Warning,
            "file_integrity",
            "file changed",
            "/var/log/syslog was modified",
        );
        sub_index = 0;
        assert!(!AlertRuleEngine::evaluate_condition(
            &rules[0].condition,
            &event_no_match,
            "field_test",
            &mut sub_index,
            &mut windows,
        ));
    }

    #[test]
    fn test_threshold_evaluation() {
        let config = AlertRuleConfig {
            name: "threshold_test".to_string(),
            description: None,
            condition_type: "threshold".to_string(),
            threshold_count: Some(3),
            window_secs: Some(60),
            event_type: None,
            severity_filter: None,
            module_filter: Some("ssh_brute_force".to_string()),
            field: None,
            pattern: None,
            operator: None,
            conditions: vec![],
            action: "log".to_string(),
            command: None,
            timeout_secs: 30,
            url: None,
            method: None,
            headers: None,
            body_template: None,
            max_retries: None,
        };
        let rules = AlertRuleEngine::compile_rules(&[config]).unwrap();
        let mut windows: HashMap<WindowKey, SlidingWindow> = HashMap::new();

        let event = make_event(
            "brute_force_detected",
            Severity::Warning,
            "ssh_brute_force",
            "SSH brute force",
        );

        let mut sub_index = 0;
        assert!(!AlertRuleEngine::evaluate_condition(
            &rules[0].condition,
            &event,
            "threshold_test",
            &mut sub_index,
            &mut windows,
        ));

        sub_index = 0;
        assert!(!AlertRuleEngine::evaluate_condition(
            &rules[0].condition,
            &event,
            "threshold_test",
            &mut sub_index,
            &mut windows,
        ));

        sub_index = 0;
        assert!(AlertRuleEngine::evaluate_condition(
            &rules[0].condition,
            &event,
            "threshold_test",
            &mut sub_index,
            &mut windows,
        ));

        // Wrong module should not match
        let other_event = make_event(
            "brute_force_detected",
            Severity::Warning,
            "other_module",
            "something",
        );
        sub_index = 0;
        // does not increment window, threshold stays at 3, but we check the filter
        assert!(!AlertRuleEngine::evaluate_condition(
            &rules[0].condition,
            &other_event,
            "threshold_test",
            &mut sub_index,
            &mut windows,
        ));
    }

    #[test]
    fn test_compound_and_evaluation() {
        let config = AlertRuleConfig {
            name: "compound_and_test".to_string(),
            description: None,
            condition_type: "compound".to_string(),
            threshold_count: None,
            window_secs: None,
            event_type: None,
            severity_filter: None,
            module_filter: None,
            field: None,
            pattern: None,
            operator: Some("and".to_string()),
            conditions: vec![
                AlertSubConditionConfig {
                    condition_type: "field_match".to_string(),
                    threshold_count: None,
                    window_secs: None,
                    event_type: None,
                    severity_filter: None,
                    module_filter: None,
                    field: Some("source_module".to_string()),
                    pattern: Some("file_integrity".to_string()),
                },
                AlertSubConditionConfig {
                    condition_type: "field_match".to_string(),
                    threshold_count: None,
                    window_secs: None,
                    event_type: None,
                    severity_filter: Some("Critical".to_string()),
                    module_filter: None,
                    field: Some("message".to_string()),
                    pattern: Some("changed".to_string()),
                },
            ],
            action: "log".to_string(),
            command: None,
            timeout_secs: 30,
            url: None,
            method: None,
            headers: None,
            body_template: None,
            max_retries: None,
        };
        let rules = AlertRuleEngine::compile_rules(&[config]).unwrap();
        let mut windows: HashMap<WindowKey, SlidingWindow> = HashMap::new();

        // Both conditions match
        let event_both = make_event(
            "file_modified",
            Severity::Critical,
            "file_integrity",
            "file changed",
        );
        let mut sub_index = 0;
        assert!(AlertRuleEngine::evaluate_condition(
            &rules[0].condition,
            &event_both,
            "compound_and_test",
            &mut sub_index,
            &mut windows,
        ));

        // Only first condition matches (wrong severity)
        let event_partial = make_event(
            "file_modified",
            Severity::Info,
            "file_integrity",
            "file changed",
        );
        sub_index = 0;
        assert!(!AlertRuleEngine::evaluate_condition(
            &rules[0].condition,
            &event_partial,
            "compound_and_test",
            &mut sub_index,
            &mut windows,
        ));
    }

    #[test]
    fn test_compound_or_evaluation() {
        let config = AlertRuleConfig {
            name: "compound_or_test".to_string(),
            description: None,
            condition_type: "compound".to_string(),
            threshold_count: None,
            window_secs: None,
            event_type: None,
            severity_filter: None,
            module_filter: None,
            field: None,
            pattern: None,
            operator: Some("or".to_string()),
            conditions: vec![
                AlertSubConditionConfig {
                    condition_type: "field_match".to_string(),
                    threshold_count: None,
                    window_secs: None,
                    event_type: None,
                    severity_filter: None,
                    module_filter: Some("ssh_brute_force".to_string()),
                    field: Some("event_type".to_string()),
                    pattern: Some("brute_force".to_string()),
                },
                AlertSubConditionConfig {
                    condition_type: "field_match".to_string(),
                    threshold_count: None,
                    window_secs: None,
                    event_type: None,
                    severity_filter: None,
                    module_filter: Some("file_integrity".to_string()),
                    field: Some("event_type".to_string()),
                    pattern: Some("file_modified".to_string()),
                },
            ],
            action: "log".to_string(),
            command: None,
            timeout_secs: 30,
            url: None,
            method: None,
            headers: None,
            body_template: None,
            max_retries: None,
        };
        let rules = AlertRuleEngine::compile_rules(&[config]).unwrap();
        let mut windows: HashMap<WindowKey, SlidingWindow> = HashMap::new();

        // First condition matches
        let event1 = make_event(
            "brute_force_detected",
            Severity::Warning,
            "ssh_brute_force",
            "attack",
        );
        let mut sub_index = 0;
        assert!(AlertRuleEngine::evaluate_condition(
            &rules[0].condition,
            &event1,
            "compound_or_test",
            &mut sub_index,
            &mut windows,
        ));

        // Second condition matches
        let event2 = make_event(
            "file_modified",
            Severity::Warning,
            "file_integrity",
            "changed",
        );
        sub_index = 0;
        assert!(AlertRuleEngine::evaluate_condition(
            &rules[0].condition,
            &event2,
            "compound_or_test",
            &mut sub_index,
            &mut windows,
        ));

        // Neither matches
        let event3 = make_event(
            "process_anomaly",
            Severity::Warning,
            "process_monitor",
            "anomaly",
        );
        sub_index = 0;
        assert!(!AlertRuleEngine::evaluate_condition(
            &rules[0].condition,
            &event3,
            "compound_or_test",
            &mut sub_index,
            &mut windows,
        ));
    }

    #[test]
    fn test_event_matches_filters() {
        let event = make_event("file_modified", Severity::Warning, "file_integrity", "test");

        // All None filters match everything
        assert!(AlertRuleEngine::event_matches_filters(
            &event, &None, &None, &None
        ));

        // Matching event_type
        assert!(AlertRuleEngine::event_matches_filters(
            &event,
            &Some("file_modified".to_string()),
            &None,
            &None
        ));

        // Non-matching event_type
        assert!(!AlertRuleEngine::event_matches_filters(
            &event,
            &Some("process_anomaly".to_string()),
            &None,
            &None
        ));

        // Matching severity
        assert!(AlertRuleEngine::event_matches_filters(
            &event,
            &None,
            &Some(Severity::Warning),
            &None
        ));

        // Non-matching severity
        assert!(!AlertRuleEngine::event_matches_filters(
            &event,
            &None,
            &Some(Severity::Critical),
            &None
        ));

        // Matching module
        assert!(AlertRuleEngine::event_matches_filters(
            &event,
            &None,
            &None,
            &Some("file_integrity".to_string())
        ));

        // Non-matching module
        assert!(!AlertRuleEngine::event_matches_filters(
            &event,
            &None,
            &None,
            &Some("other_module".to_string())
        ));
    }

    #[test]
    fn test_config_validation() {
        // Valid threshold
        let valid_threshold = AlertRuleConfig {
            name: "valid".to_string(),
            description: None,
            condition_type: "threshold".to_string(),
            threshold_count: Some(5),
            window_secs: Some(60),
            event_type: None,
            severity_filter: None,
            module_filter: None,
            field: None,
            pattern: None,
            operator: None,
            conditions: vec![],
            action: "log".to_string(),
            command: None,
            timeout_secs: 30,
            url: None,
            method: None,
            headers: None,
            body_template: None,
            max_retries: None,
        };
        assert!(AlertRuleEngine::compile_rule(&valid_threshold).is_ok());

        // Missing threshold_count
        let invalid = AlertRuleConfig {
            name: "invalid".to_string(),
            description: None,
            condition_type: "threshold".to_string(),
            threshold_count: None,
            window_secs: Some(60),
            event_type: None,
            severity_filter: None,
            module_filter: None,
            field: None,
            pattern: None,
            operator: None,
            conditions: vec![],
            action: "log".to_string(),
            command: None,
            timeout_secs: 30,
            url: None,
            method: None,
            headers: None,
            body_template: None,
            max_retries: None,
        };
        assert!(AlertRuleEngine::compile_rule(&invalid).is_err());

        // Invalid condition_type
        let invalid2 = AlertRuleConfig {
            name: "bad_type".to_string(),
            description: None,
            condition_type: "invalid_type".to_string(),
            threshold_count: None,
            window_secs: None,
            event_type: None,
            severity_filter: None,
            module_filter: None,
            field: None,
            pattern: None,
            operator: None,
            conditions: vec![],
            action: "log".to_string(),
            command: None,
            timeout_secs: 30,
            url: None,
            method: None,
            headers: None,
            body_template: None,
            max_retries: None,
        };
        assert!(AlertRuleEngine::compile_rule(&invalid2).is_err());

        // Invalid regex pattern
        let invalid3 = AlertRuleConfig {
            name: "bad_regex".to_string(),
            description: None,
            condition_type: "field_match".to_string(),
            threshold_count: None,
            window_secs: None,
            event_type: None,
            severity_filter: None,
            module_filter: None,
            field: Some("message".to_string()),
            pattern: Some("[invalid".to_string()),
            operator: None,
            conditions: vec![],
            action: "log".to_string(),
            command: None,
            timeout_secs: 30,
            url: None,
            method: None,
            headers: None,
            body_template: None,
            max_retries: None,
        };
        assert!(AlertRuleEngine::compile_rule(&invalid3).is_err());
    }
}
