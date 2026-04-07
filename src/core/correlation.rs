//! イベント相関分析エンジン
//!
//! 複数のセキュリティイベントを時系列で相関分析し、
//! 多段階攻撃パターンを検知する。

use crate::config::CorrelationConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use regex::Regex;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, watch};

/// コンパイル済みルールステップ
#[derive(Debug)]
struct CompiledStep {
    /// ステップ名
    name: String,
    /// イベント種別の正規表現パターン
    event_type_pattern: Regex,
    /// ソースモジュールの正規表現パターン（オプション）
    source_module_pattern: Option<Regex>,
    /// 最小重要度（オプション）
    min_severity: Option<Severity>,
}

/// コンパイル済み相関ルール
#[derive(Debug)]
pub(crate) struct CompiledRule {
    /// ルール名
    name: String,
    /// ルールの説明
    description: String,
    /// ステップリスト
    steps: Vec<CompiledStep>,
    /// 時間窓
    within: Duration,
}

/// ホットリロード用のランタイム設定
pub struct CorrelationRuntimeConfig {
    /// イベントウィンドウの保持期間（秒）
    pub window_secs: u64,
    /// ウィンドウ内の最大イベント保持数
    pub max_events: usize,
    /// クリーンアップ間隔（秒）
    pub cleanup_interval_secs: u64,
    /// ルール設定（マージ済み、受信側でコンパイルする）
    pub rules: Vec<crate::config::CorrelationRuleConfig>,
    /// プリセットルールの有効/無効
    pub enable_presets: bool,
    /// 無効にするプリセットのリスト
    pub disabled_presets: Vec<String>,
}

/// 相関マッチ結果
struct CorrelationMatch {
    /// マッチしたルール名
    rule_name: String,
    /// ルールの説明
    rule_description: String,
    /// マッチしたイベントの情報リスト（ステップ名, イベント概要）
    matched_steps: Vec<(String, String)>,
}

/// スライディングウィンドウ
struct EventWindow {
    /// イベントキュー
    events: VecDeque<(Instant, SecurityEvent)>,
    /// 最大保持期間
    max_duration: Duration,
    /// 最大イベント数
    max_events: usize,
    /// ルールごとの最終マッチ時刻（連続発火防止）
    last_match: HashMap<String, Instant>,
}

impl EventWindow {
    /// 新しいイベントウィンドウを作成する
    fn new(max_duration: Duration, max_events: usize) -> Self {
        Self {
            events: VecDeque::new(),
            max_duration,
            max_events,
            last_match: HashMap::new(),
        }
    }

    /// イベントを追加する
    fn push(&mut self, event: SecurityEvent) {
        let now = Instant::now();
        self.events.push_back((now, event));

        // 最大数を超えたら古いイベントを削除
        while self.events.len() > self.max_events {
            self.events.pop_front();
        }
    }

    /// 期限切れイベントを削除し、削除件数を返す
    fn cleanup(&mut self) -> usize {
        let now = Instant::now();
        let before = self.events.len();

        while let Some((ts, _)) = self.events.front() {
            if now.duration_since(*ts) > self.max_duration {
                self.events.pop_front();
            } else {
                break;
            }
        }

        // last_match のクリーンアップ
        self.last_match
            .retain(|_, ts| now.duration_since(*ts) <= self.max_duration);

        before - self.events.len()
    }

    /// ルールにマッチするか判定する
    ///
    /// ステップは時系列順にマッチする必要がある。
    /// 全ステップがマッチし、最初から最後までの時間差が within 以内であれば成功。
    fn match_rule(&self, rule: &CompiledRule) -> Option<Vec<(String, &SecurityEvent)>> {
        if rule.steps.is_empty() {
            return None;
        }

        let mut step_idx = 0;
        let mut matched: Vec<(String, &SecurityEvent)> = Vec::new();

        for (_ts, event) in &self.events {
            if step_idx >= rule.steps.len() {
                break;
            }

            let step = &rule.steps[step_idx];

            if Self::event_matches_step(event, step) {
                matched.push((step.name.clone(), event));
                step_idx += 1;
            }
        }

        // 全ステップがマッチしたか
        if step_idx < rule.steps.len() {
            return None;
        }

        // 時間窓内か確認（最初のマッチから最後のマッチまで）
        if matched.len() >= 2 {
            let first_ts = matched
                .first()
                .and_then(|(_, e)| {
                    self.events
                        .iter()
                        .find(|(_, ev)| std::ptr::eq(ev, *e))
                        .map(|(ts, _)| ts)
                })
                .copied();
            let last_ts = matched
                .last()
                .and_then(|(_, e)| {
                    self.events
                        .iter()
                        .rev()
                        .find(|(_, ev)| std::ptr::eq(ev, *e))
                        .map(|(ts, _)| ts)
                })
                .copied();

            if let (Some(first), Some(last)) = (first_ts, last_ts)
                && last.duration_since(first) > rule.within
            {
                return None;
            }
        }

        Some(matched)
    }

    /// イベントがステップにマッチするか判定する
    fn event_matches_step(event: &SecurityEvent, step: &CompiledStep) -> bool {
        // event_type のマッチ
        if !step.event_type_pattern.is_match(&event.event_type) {
            return false;
        }

        // source_module のマッチ（設定されている場合）
        if let Some(ref pattern) = step.source_module_pattern
            && !pattern.is_match(&event.source_module)
        {
            return false;
        }

        // min_severity のマッチ（設定されている場合）
        if let Some(ref min_sev) = step.min_severity
            && event.severity < *min_sev
        {
            return false;
        }

        true
    }

    /// ルールの最終マッチ時刻を記録する
    fn record_match(&mut self, rule_name: &str) {
        self.last_match
            .insert(rule_name.to_string(), Instant::now());
    }

    /// 指定ルールが最近マッチ済みか判定する
    fn recently_matched(&self, rule_name: &str, cooldown: Duration) -> bool {
        if let Some(ts) = self.last_match.get(rule_name) {
            Instant::now().duration_since(*ts) <= cooldown
        } else {
            false
        }
    }

    /// ウィンドウ設定を更新する
    fn update_config(&mut self, max_duration: Duration, max_events: usize) {
        self.max_duration = max_duration;
        self.max_events = max_events;
    }
}

/// イベント相関分析エンジン
pub struct CorrelationEngine {
    receiver: broadcast::Receiver<SecurityEvent>,
    sender: broadcast::Sender<SecurityEvent>,
    config_receiver: watch::Receiver<CorrelationRuntimeConfig>,
    window: EventWindow,
    rules: Vec<CompiledRule>,
    cleanup_interval: Duration,
}

impl CorrelationEngine {
    /// 設定とイベントバスから CorrelationEngine を構築する
    pub fn new(
        config: &CorrelationConfig,
        event_bus: &EventBus,
    ) -> Result<(Self, watch::Sender<CorrelationRuntimeConfig>), AppError> {
        use crate::core::correlation_presets;

        let effective_rules = correlation_presets::merge_rules(
            &config.rules,
            config.enable_presets,
            &config.disabled_presets,
        );
        let rules = Self::compile_rules(&effective_rules, config.window_secs)?;

        let runtime_config = CorrelationRuntimeConfig {
            window_secs: config.window_secs,
            max_events: config.max_events,
            cleanup_interval_secs: config.cleanup_interval_secs,
            rules: effective_rules,
            enable_presets: config.enable_presets,
            disabled_presets: config.disabled_presets.clone(),
        };

        let (config_sender, config_receiver) = watch::channel(runtime_config);

        let window = EventWindow::new(Duration::from_secs(config.window_secs), config.max_events);

        Ok((
            Self {
                receiver: event_bus.subscribe(),
                sender: event_bus.sender(),
                config_receiver,
                window,
                rules,
                cleanup_interval: Duration::from_secs(config.cleanup_interval_secs),
            },
            config_sender,
        ))
    }

    /// 非同期タスクとして起動する
    pub fn spawn(self) {
        tokio::spawn(async move {
            Self::run_loop(
                self.receiver,
                self.sender,
                self.config_receiver,
                self.window,
                self.rules,
                self.cleanup_interval,
            )
            .await;
        });
    }

    /// ルール設定をコンパイルする
    pub(crate) fn compile_rules(
        rules: &[crate::config::CorrelationRuleConfig],
        default_window_secs: u64,
    ) -> Result<Vec<CompiledRule>, AppError> {
        let mut compiled = Vec::with_capacity(rules.len());

        for rule_config in rules {
            let mut steps = Vec::with_capacity(rule_config.steps.len());

            for step_config in &rule_config.steps {
                let event_type_pattern = Regex::new(&step_config.event_type).map_err(|e| {
                    AppError::CorrelationEngine {
                        message: format!(
                            "ルール '{}' ステップ '{}' の event_type 正規表現エラー: {}",
                            rule_config.name, step_config.name, e
                        ),
                    }
                })?;

                let source_module_pattern =
                    match &step_config.source_module {
                        Some(pattern) => Some(Regex::new(pattern).map_err(|e| {
                            AppError::CorrelationEngine {
                                message: format!(
                                    "ルール '{}' ステップ '{}' の source_module 正規表現エラー: {}",
                                    rule_config.name, step_config.name, e
                                ),
                            }
                        })?),
                        None => None,
                    };

                let min_severity = match &step_config.min_severity {
                    Some(s) => {
                        Some(
                            Severity::parse(s).ok_or_else(|| AppError::CorrelationEngine {
                                message: format!(
                                    "ルール '{}' ステップ '{}' の min_severity が無効です: {}",
                                    rule_config.name, step_config.name, s
                                ),
                            })?,
                        )
                    }
                    None => None,
                };

                steps.push(CompiledStep {
                    name: step_config.name.clone(),
                    event_type_pattern,
                    source_module_pattern,
                    min_severity,
                });
            }

            let within_secs = rule_config.within_secs.unwrap_or(default_window_secs);

            compiled.push(CompiledRule {
                name: rule_config.name.clone(),
                description: rule_config.description.clone(),
                steps,
                within: Duration::from_secs(within_secs),
            });
        }

        Ok(compiled)
    }

    /// メインループ
    async fn run_loop(
        mut receiver: broadcast::Receiver<SecurityEvent>,
        sender: broadcast::Sender<SecurityEvent>,
        mut config_receiver: watch::Receiver<CorrelationRuntimeConfig>,
        mut window: EventWindow,
        mut rules: Vec<CompiledRule>,
        mut cleanup_interval: Duration,
    ) {
        let mut cleanup_timer = tokio::time::interval(cleanup_interval);
        // 最初の tick はスキップ
        cleanup_timer.tick().await;

        loop {
            tokio::select! {
                result = receiver.recv() => {
                    match result {
                        Ok(event) => {
                            // 循環発火防止: 自身が発行したイベントは無視
                            if event.source_module == "correlation_engine" {
                                continue;
                            }

                            window.push(event);

                            // 全ルールを評価
                            let matches = Self::evaluate_rules(&rules, &window);
                            for matched in matches {
                                // 連続発火抑制: ルールの within 期間をクールダウンとして使用
                                let cooldown = rules
                                    .iter()
                                    .find(|r| r.name == matched.rule_name)
                                    .map(|r| r.within)
                                    .unwrap_or(Duration::from_secs(600));

                                if window.recently_matched(&matched.rule_name, cooldown) {
                                    tracing::debug!(
                                        rule = %matched.rule_name,
                                        "相関ルールのクールダウン中（連続発火抑制）"
                                    );
                                    continue;
                                }

                                Self::emit_correlation_event(&sender, &matched);
                                window.record_match(&matched.rule_name);
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(
                                lagged = n,
                                "相関分析エンジン: イベント受信が遅延しました"
                            );
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            tracing::info!("相関分析エンジン: イベントバスが閉じました");
                            break;
                        }
                    }
                }
                _ = cleanup_timer.tick() => {
                    let removed = window.cleanup();
                    if removed > 0 {
                        tracing::debug!(
                            removed = removed,
                            remaining = window.events.len(),
                            "相関分析エンジン: 期限切れイベントをクリーンアップ"
                        );
                    }
                }
                result = config_receiver.changed() => {
                    if result.is_err() {
                        tracing::info!("相関分析エンジン: 設定チャネルが閉じました");
                        break;
                    }

                    let (new_window_secs, new_max_events, new_cleanup_secs, new_rule_configs) = {
                        let new_config = config_receiver.borrow_and_update();
                        (
                            new_config.window_secs,
                            new_config.max_events,
                            new_config.cleanup_interval_secs,
                            new_config.rules.clone(),
                        )
                    };

                    window.update_config(
                        Duration::from_secs(new_window_secs),
                        new_max_events,
                    );
                    cleanup_interval = Duration::from_secs(new_cleanup_secs);

                    // タイマーをリセット
                    cleanup_timer = tokio::time::interval(cleanup_interval);
                    cleanup_timer.tick().await;

                    // ルールを再コンパイル
                    match CorrelationEngine::compile_rules(&new_rule_configs, new_window_secs) {
                        Ok(new_rules) => {
                            rules = new_rules;
                        }
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                "相関ルールの再コンパイルに失敗しました。既存のルールを維持します"
                            );
                        }
                    }

                    tracing::info!(
                        window_secs = new_window_secs,
                        cleanup_interval_secs = new_cleanup_secs,
                        rules = rules.len(),
                        "相関分析エンジンの設定をリロードしました"
                    );
                }
            }
        }
    }

    /// 全ルールに対してウィンドウ内のイベントを評価し、マッチしたルールのリストを返す
    fn evaluate_rules(rules: &[CompiledRule], window: &EventWindow) -> Vec<CorrelationMatch> {
        let mut matches = Vec::new();

        for rule in rules {
            if let Some(matched_events) = window.match_rule(rule) {
                let matched_steps: Vec<(String, String)> = matched_events
                    .into_iter()
                    .map(|(step_name, event)| {
                        (
                            step_name,
                            format!(
                                "[{}] {} ({})",
                                event.severity, event.event_type, event.source_module
                            ),
                        )
                    })
                    .collect();

                matches.push(CorrelationMatch {
                    rule_name: rule.name.clone(),
                    rule_description: rule.description.clone(),
                    matched_steps,
                });
            }
        }

        matches
    }

    /// マッチ結果から SecurityEvent を生成して発行する
    fn emit_correlation_event(
        sender: &broadcast::Sender<SecurityEvent>,
        matched: &CorrelationMatch,
    ) {
        let message = format!(
            "相関ルール「{}」が一致: {}",
            matched.rule_name, matched.rule_description
        );

        let details: Vec<String> = matched
            .matched_steps
            .iter()
            .map(|(step_name, summary)| format!("  - {}: {}", step_name, summary))
            .collect();

        let event = SecurityEvent::new(
            "correlation_detected",
            Severity::Critical,
            "correlation_engine",
            message,
        )
        .with_details(details.join("\n"));

        tracing::warn!(
            rule = %matched.rule_name,
            steps = matched.matched_steps.len(),
            "相関ルールが一致しました"
        );

        // サブスクライバーがいない場合もエラーにしない
        let _ = sender.send(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CorrelationRuleConfig, CorrelationStepConfig};

    fn make_step_config(
        name: &str,
        event_type: &str,
        source_module: Option<&str>,
        min_severity: Option<&str>,
    ) -> CorrelationStepConfig {
        CorrelationStepConfig {
            name: name.to_string(),
            event_type: event_type.to_string(),
            source_module: source_module.map(|s| s.to_string()),
            min_severity: min_severity.map(|s| s.to_string()),
        }
    }

    fn make_rule_config(
        name: &str,
        description: &str,
        steps: Vec<CorrelationStepConfig>,
        within_secs: Option<u64>,
    ) -> CorrelationRuleConfig {
        CorrelationRuleConfig {
            name: name.to_string(),
            description: description.to_string(),
            steps,
            within_secs,
        }
    }

    fn make_event(event_type: &str, severity: Severity, source_module: &str) -> SecurityEvent {
        SecurityEvent::new(event_type, severity, source_module, "テストイベント")
    }

    #[test]
    fn test_compile_rules_valid() {
        let rules = vec![make_rule_config(
            "test_rule",
            "テストルール",
            vec![
                make_step_config("step1", "ssh_brute_force", None, Some("warning")),
                make_step_config("step2", "user_added", Some("user_account"), None),
            ],
            Some(3600),
        )];

        let compiled = CorrelationEngine::compile_rules(&rules, 600).unwrap();
        assert_eq!(compiled.len(), 1);
        assert_eq!(compiled[0].name, "test_rule");
        assert_eq!(compiled[0].steps.len(), 2);
        assert_eq!(compiled[0].within, Duration::from_secs(3600));
    }

    #[test]
    fn test_compile_rules_invalid_regex() {
        let rules = vec![make_rule_config(
            "bad_rule",
            "不正なルール",
            vec![make_step_config("step1", "[invalid", None, None)],
            None,
        )];

        let result = CorrelationEngine::compile_rules(&rules, 600);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("正規表現エラー"));
    }

    #[test]
    fn test_event_window_push_and_cleanup() {
        let mut window = EventWindow::new(Duration::from_millis(50), 100);

        window.push(make_event("event1", Severity::Info, "mod1"));
        window.push(make_event("event2", Severity::Warning, "mod2"));
        assert_eq!(window.events.len(), 2);

        // 期限切れを待つ
        std::thread::sleep(Duration::from_millis(60));

        let removed = window.cleanup();
        assert_eq!(removed, 2);
        assert_eq!(window.events.len(), 0);
    }

    #[test]
    fn test_event_window_max_events() {
        let mut window = EventWindow::new(Duration::from_secs(600), 3);

        window.push(make_event("event1", Severity::Info, "mod1"));
        window.push(make_event("event2", Severity::Info, "mod1"));
        window.push(make_event("event3", Severity::Info, "mod1"));
        window.push(make_event("event4", Severity::Info, "mod1"));

        assert_eq!(window.events.len(), 3);
        // 最初のイベントが除去されている
        assert_eq!(window.events[0].1.event_type, "event2");
    }

    #[test]
    fn test_match_rule_full_match() {
        let rules = vec![make_rule_config(
            "test",
            "テスト",
            vec![
                make_step_config("step1", "ssh_brute_force", None, None),
                make_step_config("step2", "user_added", None, None),
                make_step_config("step3", "cron_modified", None, None),
            ],
            Some(3600),
        )];

        let compiled = CorrelationEngine::compile_rules(&rules, 600).unwrap();
        let mut window = EventWindow::new(Duration::from_secs(600), 100);

        window.push(make_event("ssh_brute_force", Severity::Warning, "ssh"));
        window.push(make_event("user_added", Severity::Warning, "user"));
        window.push(make_event("cron_modified", Severity::Warning, "cron"));

        let result = window.match_rule(&compiled[0]);
        assert!(result.is_some());
        let matched = result.unwrap();
        assert_eq!(matched.len(), 3);
        assert_eq!(matched[0].0, "step1");
        assert_eq!(matched[1].0, "step2");
        assert_eq!(matched[2].0, "step3");
    }

    #[test]
    fn test_match_rule_partial_match() {
        // 全ステップが揃っていない場合はマッチしない
        let rules = vec![make_rule_config(
            "test",
            "テスト",
            vec![
                make_step_config("step1", "ssh_brute_force", None, None),
                make_step_config("step2", "user_added", None, None),
                make_step_config("step3", "cron_modified", None, None),
            ],
            Some(3600),
        )];

        let compiled = CorrelationEngine::compile_rules(&rules, 600).unwrap();
        let mut window = EventWindow::new(Duration::from_secs(600), 100);

        window.push(make_event("ssh_brute_force", Severity::Warning, "ssh"));
        window.push(make_event("user_added", Severity::Warning, "user"));
        // step3 が欠けている

        let result = window.match_rule(&compiled[0]);
        assert!(result.is_none());
    }

    #[test]
    fn test_match_rule_no_match() {
        let rules = vec![make_rule_config(
            "test",
            "テスト",
            vec![make_step_config("step1", "ssh_brute_force", None, None)],
            Some(3600),
        )];

        let compiled = CorrelationEngine::compile_rules(&rules, 600).unwrap();
        let mut window = EventWindow::new(Duration::from_secs(600), 100);

        window.push(make_event("file_modified", Severity::Info, "file"));

        let result = window.match_rule(&compiled[0]);
        assert!(result.is_none());
    }

    #[test]
    fn test_match_rule_with_min_severity() {
        let rules = vec![make_rule_config(
            "test",
            "テスト",
            vec![make_step_config(
                "step1",
                "ssh_brute_force",
                None,
                Some("warning"),
            )],
            Some(3600),
        )];

        let compiled = CorrelationEngine::compile_rules(&rules, 600).unwrap();
        let mut window = EventWindow::new(Duration::from_secs(600), 100);

        // Info は Warning より低いのでマッチしない
        window.push(make_event("ssh_brute_force", Severity::Info, "ssh"));
        let result = window.match_rule(&compiled[0]);
        assert!(result.is_none());

        // Warning はマッチする
        window.push(make_event("ssh_brute_force", Severity::Warning, "ssh"));
        let result = window.match_rule(&compiled[0]);
        assert!(result.is_some());
    }

    #[test]
    fn test_match_rule_with_source_module_pattern() {
        let rules = vec![make_rule_config(
            "test",
            "テスト",
            vec![make_step_config(
                "step1",
                "brute_force",
                Some("ssh.*"),
                None,
            )],
            Some(3600),
        )];

        let compiled = CorrelationEngine::compile_rules(&rules, 600).unwrap();
        let mut window = EventWindow::new(Duration::from_secs(600), 100);

        // source_module が "ssh_monitor" なのでパターン "ssh.*" にマッチ
        window.push(make_event("brute_force", Severity::Warning, "ssh_monitor"));
        let result = window.match_rule(&compiled[0]);
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_correlation_engine_spawn() {
        let bus = EventBus::new(64);
        let config = CorrelationConfig {
            enabled: true,
            window_secs: 600,
            max_events: 100,
            cleanup_interval_secs: 30,
            enable_presets: false,
            disabled_presets: vec![],
            rules: vec![CorrelationRuleConfig {
                name: "test_rule".to_string(),
                description: "テストルール".to_string(),
                steps: vec![
                    CorrelationStepConfig {
                        name: "step1".to_string(),
                        event_type: "event_a".to_string(),
                        source_module: None,
                        min_severity: None,
                    },
                    CorrelationStepConfig {
                        name: "step2".to_string(),
                        event_type: "event_b".to_string(),
                        source_module: None,
                        min_severity: None,
                    },
                ],
                within_secs: Some(3600),
            }],
        };

        let (engine, _sender) = CorrelationEngine::new(&config, &bus).unwrap();
        let mut receiver = bus.subscribe();
        engine.spawn();

        // イベントを発行
        bus.publish(SecurityEvent::new(
            "event_a",
            Severity::Warning,
            "mod_a",
            "テストイベント A",
        ));

        // 少し待ってから2つ目のイベント
        tokio::time::sleep(Duration::from_millis(10)).await;

        bus.publish(SecurityEvent::new(
            "event_b",
            Severity::Warning,
            "mod_b",
            "テストイベント B",
        ));

        // 相関イベントの受信を待つ
        let mut found_correlation = false;
        let timeout = tokio::time::sleep(Duration::from_secs(2));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                result = receiver.recv() => {
                    match result {
                        Ok(event) if event.event_type == "correlation_detected" => {
                            assert_eq!(event.source_module, "correlation_engine");
                            assert_eq!(event.severity, Severity::Critical);
                            assert!(event.message.contains("test_rule"));
                            found_correlation = true;
                            break;
                        }
                        Ok(_) => continue,
                        Err(_) => break,
                    }
                }
                _ = &mut timeout => {
                    break;
                }
            }
        }

        assert!(found_correlation, "相関イベントが発行されませんでした");
    }

    #[tokio::test]
    async fn test_circular_prevention() {
        let bus = EventBus::new(64);
        let config = CorrelationConfig {
            enabled: true,
            window_secs: 600,
            max_events: 100,
            cleanup_interval_secs: 30,
            enable_presets: false,
            disabled_presets: vec![],
            rules: vec![CorrelationRuleConfig {
                name: "catch_all".to_string(),
                description: "全イベントにマッチ".to_string(),
                steps: vec![CorrelationStepConfig {
                    name: "any".to_string(),
                    event_type: ".*".to_string(),
                    source_module: None,
                    min_severity: None,
                }],
                within_secs: Some(3600),
            }],
        };

        let (engine, _sender) = CorrelationEngine::new(&config, &bus).unwrap();
        let mut receiver = bus.subscribe();
        engine.spawn();

        // 通常のイベントを発行
        bus.publish(SecurityEvent::new(
            "test_event",
            Severity::Warning,
            "test_module",
            "テスト",
        ));

        // 相関イベントが1つだけ発行されることを確認（循環しない）
        let mut correlation_count = 0;
        let timeout = tokio::time::sleep(Duration::from_millis(500));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                result = receiver.recv() => {
                    match result {
                        Ok(event) if event.event_type == "correlation_detected" => {
                            correlation_count += 1;
                        }
                        Ok(_) => continue,
                        Err(_) => break,
                    }
                }
                _ = &mut timeout => {
                    break;
                }
            }
        }

        // 循環発火しないので 1 回のみ（クールダウンで2回目は抑制される）
        assert_eq!(correlation_count, 1, "循環発火が発生しました");
    }

    #[tokio::test]
    async fn test_cooldown() {
        let bus = EventBus::new(64);
        let config = CorrelationConfig {
            enabled: true,
            window_secs: 600,
            max_events: 100,
            cleanup_interval_secs: 30,
            enable_presets: false,
            disabled_presets: vec![],
            rules: vec![CorrelationRuleConfig {
                name: "simple_rule".to_string(),
                description: "シンプルルール".to_string(),
                steps: vec![CorrelationStepConfig {
                    name: "step1".to_string(),
                    event_type: "target_event".to_string(),
                    source_module: None,
                    min_severity: None,
                }],
                within_secs: Some(3600),
            }],
        };

        let (engine, _sender) = CorrelationEngine::new(&config, &bus).unwrap();
        let mut receiver = bus.subscribe();
        engine.spawn();

        // 同じイベントを連続で発行
        for _ in 0..5 {
            bus.publish(SecurityEvent::new(
                "target_event",
                Severity::Warning,
                "test_module",
                "テスト",
            ));
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // クールダウンにより1回のみ発火するはず
        let mut correlation_count = 0;
        let timeout = tokio::time::sleep(Duration::from_secs(1));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                result = receiver.recv() => {
                    match result {
                        Ok(event) if event.event_type == "correlation_detected" => {
                            correlation_count += 1;
                        }
                        Ok(_) => continue,
                        Err(_) => break,
                    }
                }
                _ = &mut timeout => {
                    break;
                }
            }
        }

        assert_eq!(
            correlation_count, 1,
            "クールダウンが効いていません（{}回発火）",
            correlation_count
        );
    }

    #[test]
    fn test_match_rule_empty_window() {
        let rules = vec![make_rule_config(
            "test",
            "テスト",
            vec![make_step_config("step1", "ssh_brute_force", None, None)],
            Some(3600),
        )];

        let compiled = CorrelationEngine::compile_rules(&rules, 600).unwrap();
        let window = EventWindow::new(Duration::from_secs(600), 100);

        // ウィンドウが空の場合はマッチしない
        let result = window.match_rule(&compiled[0]);
        assert!(result.is_none());
    }

    #[test]
    fn test_match_rule_empty_steps() {
        // ステップが空のルール
        let rule = CompiledRule {
            name: "empty".to_string(),
            description: "空のルール".to_string(),
            steps: Vec::new(),
            within: Duration::from_secs(3600),
        };

        let mut window = EventWindow::new(Duration::from_secs(600), 100);
        window.push(make_event("some_event", Severity::Info, "mod1"));

        let result = window.match_rule(&rule);
        assert!(result.is_none());
    }

    #[test]
    fn test_compile_rules_invalid_severity() {
        let rules = vec![make_rule_config(
            "bad_severity",
            "不正な重要度",
            vec![make_step_config(
                "step1",
                "event",
                None,
                Some("nonexistent_severity"),
            )],
            None,
        )];

        let result = CorrelationEngine::compile_rules(&rules, 600);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("min_severity が無効です"));
    }

    #[test]
    fn test_compile_rules_invalid_source_module_regex() {
        let rules = vec![make_rule_config(
            "bad_source",
            "不正なソースモジュール正規表現",
            vec![make_step_config("step1", "event", Some("[invalid"), None)],
            None,
        )];

        let result = CorrelationEngine::compile_rules(&rules, 600);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("source_module 正規表現エラー"));
    }

    #[test]
    fn test_event_window_max_events_overflow_preserves_newest() {
        let mut window = EventWindow::new(Duration::from_secs(600), 2);

        window.push(make_event("old1", Severity::Info, "mod1"));
        window.push(make_event("old2", Severity::Info, "mod1"));
        window.push(make_event("new1", Severity::Info, "mod1"));
        window.push(make_event("new2", Severity::Info, "mod1"));

        assert_eq!(window.events.len(), 2);
        assert_eq!(window.events[0].1.event_type, "new1");
        assert_eq!(window.events[1].1.event_type, "new2");
    }

    #[test]
    fn test_event_window_update_config() {
        let mut window = EventWindow::new(Duration::from_secs(600), 100);

        window.push(make_event("event1", Severity::Info, "mod1"));
        window.push(make_event("event2", Severity::Info, "mod1"));
        window.push(make_event("event3", Severity::Info, "mod1"));

        // max_events を 2 に減らす
        window.update_config(Duration::from_secs(300), 2);
        assert_eq!(window.max_events, 2);
        assert_eq!(window.max_duration, Duration::from_secs(300));

        // 新規追加で max_events が適用される
        window.push(make_event("event4", Severity::Info, "mod1"));
        assert_eq!(window.events.len(), 2);
        assert_eq!(window.events[0].1.event_type, "event3");
        assert_eq!(window.events[1].1.event_type, "event4");
    }

    #[test]
    fn test_recently_matched_returns_false_when_no_prior_match() {
        let window = EventWindow::new(Duration::from_secs(600), 100);
        assert!(!window.recently_matched("nonexistent", Duration::from_secs(60)));
    }

    #[test]
    fn test_compile_rules_default_within() {
        // within_secs が None の場合、default_window_secs が使われる
        let rules = vec![make_rule_config(
            "test",
            "テスト",
            vec![make_step_config("step1", "event", None, None)],
            None,
        )];

        let compiled = CorrelationEngine::compile_rules(&rules, 900).unwrap();
        assert_eq!(compiled[0].within, Duration::from_secs(900));
    }

    #[tokio::test]
    async fn test_hot_reload() {
        let bus = EventBus::new(64);
        let config = CorrelationConfig {
            enabled: true,
            window_secs: 600,
            max_events: 100,
            cleanup_interval_secs: 30,
            enable_presets: false,
            disabled_presets: vec![],
            rules: vec![CorrelationRuleConfig {
                name: "original_rule".to_string(),
                description: "元のルール".to_string(),
                steps: vec![CorrelationStepConfig {
                    name: "step1".to_string(),
                    event_type: "event_x".to_string(),
                    source_module: None,
                    min_severity: None,
                }],
                within_secs: Some(3600),
            }],
        };

        let (engine, config_sender) = CorrelationEngine::new(&config, &bus).unwrap();
        let mut receiver = bus.subscribe();
        engine.spawn();

        // 新しいルールにリロード
        let new_rules = vec![crate::config::CorrelationRuleConfig {
            name: "new_rule".to_string(),
            description: "新しいルール".to_string(),
            steps: vec![crate::config::CorrelationStepConfig {
                name: "step1".to_string(),
                event_type: "event_y".to_string(),
                source_module: None,
                min_severity: None,
            }],
            within_secs: Some(3600),
        }];

        config_sender
            .send(CorrelationRuntimeConfig {
                window_secs: 300,
                max_events: 50,
                cleanup_interval_secs: 15,
                rules: new_rules,
                enable_presets: false,
                disabled_presets: vec![],
            })
            .unwrap();

        // リロードが反映されるのを待つ
        tokio::time::sleep(Duration::from_millis(50)).await;

        // 旧ルール（event_x）ではマッチしない
        bus.publish(SecurityEvent::new(
            "event_x",
            Severity::Warning,
            "mod_x",
            "旧ルール対象",
        ));

        // 新ルール（event_y）でマッチする
        tokio::time::sleep(Duration::from_millis(10)).await;
        bus.publish(SecurityEvent::new(
            "event_y",
            Severity::Warning,
            "mod_y",
            "新ルール対象",
        ));

        let mut found_new_rule = false;
        let mut found_old_rule = false;
        let timeout = tokio::time::sleep(Duration::from_secs(2));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                result = receiver.recv() => {
                    match result {
                        Ok(event) if event.event_type == "correlation_detected" => {
                            if event.message.contains("new_rule") {
                                found_new_rule = true;
                            }
                            if event.message.contains("original_rule") {
                                found_old_rule = true;
                            }
                        }
                        Ok(_) => continue,
                        Err(_) => break,
                    }
                }
                _ = &mut timeout => {
                    break;
                }
            }
        }

        assert!(
            found_new_rule,
            "新ルールの相関イベントが発行されませんでした"
        );
        assert!(
            !found_old_rule,
            "旧ルールが引き続きマッチしています（リロードが反映されていない）"
        );
    }
}
