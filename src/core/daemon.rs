use crate::config::AppConfig;
use crate::config::DigestConfig;
use crate::core::action::{ActionEngine, ActionEngineConfig, DigestCollector, InFlightTracker};
use crate::core::alert_rule::{AlertRuleEngine, AlertRuleEngineConfig};
use crate::core::api::{ApiServer, ModuleControlCommand, ModuleControlResult};
use crate::core::correlation::{CorrelationEngine, CorrelationRuntimeConfig};
use crate::core::event::{self, EventBus, SecurityEvent, Severity};
use crate::core::event_store::{EventStore, EventStoreRuntimeConfig};
use crate::core::event_stream::{EventStreamRuntimeConfig, EventStreamServer};
use crate::core::health::HealthChecker;
use crate::core::metrics::{MetricsCollector, SharedMetrics};
use crate::core::module_manager::ModuleManager;
use crate::core::module_stats::{self, ModuleStatsHandle};
use crate::core::prometheus::PrometheusExporter;
use crate::core::scan_state::{self, DiffKind};
use crate::core::scoring::{ScoringRuntimeConfig, SecurityScorer, SharedSecurityScore};
use crate::core::status::{DaemonState, StatusServer};
use crate::core::syslog::{SyslogForwarder, SyslogRuntimeConfig};
use crate::error::AppError;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

/// デーモンプロセスを管理する
pub struct Daemon {
    config: AppConfig,
    config_path: PathBuf,
}

impl Daemon {
    /// 新しいデーモンインスタンスを作成する
    pub fn new(config: AppConfig, config_path: PathBuf) -> Self {
        Self {
            config,
            config_path,
        }
    }

    /// デーモンを起動し、シグナルを受信するまでブロックする
    pub async fn run(&mut self) -> Result<(), AppError> {
        let mut sigterm = signal(SignalKind::terminate()).map_err(AppError::SignalHandler)?;
        let mut sighup = signal(SignalKind::hangup()).map_err(AppError::SignalHandler)?;

        let health_checker = HealthChecker::new();
        let health_enabled = self.config.health.enabled;
        let heartbeat_interval = Duration::from_secs(self.config.health.heartbeat_interval_secs);
        let mut heartbeat = tokio::time::interval(heartbeat_interval);
        // 最初の tick は即座に発火するのでスキップ
        heartbeat.tick().await;

        // ステータスサーバー用の共有状態
        let shared_module_names: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
        let mut shared_metrics: Option<Arc<StdMutex<SharedMetrics>>> = None;
        let module_stats_handle: Option<ModuleStatsHandle> = if self.config.module_stats.enabled {
            let handle = ModuleStatsHandle::new();
            handle.ensure_all(ModuleManager::known_module_names());
            Some(handle)
        } else {
            None
        };
        let mut shared_scoring: Option<Arc<StdMutex<SharedSecurityScore>>> = None;
        let mut scoring_config_sender: Option<watch::Sender<ScoringRuntimeConfig>> = None;
        let mut status_cancel_token: Option<CancellationToken> = None;
        let mut prometheus_cancel_token: Option<CancellationToken> = None;
        let mut api_cancel_token: Option<CancellationToken> = None;
        let mut api_shared_action_config: Option<Arc<StdMutex<crate::config::ActionConfig>>> = None;
        let prometheus_started_at = Instant::now();

        // API サーバー用リロードチャネル
        let (reload_sender, mut reload_receiver) = tokio::sync::mpsc::channel::<()>(1);

        // API サーバー用モジュール制御チャネル
        let (module_control_sender, mut module_control_receiver) = tokio::sync::mpsc::channel::<(
            ModuleControlCommand,
            tokio::sync::oneshot::Sender<ModuleControlResult>,
        )>(8);

        // イベントバスの初期化
        let mut action_config_sender: Option<watch::Sender<ActionEngineConfig>> = None;
        let mut inflight_tracker: Option<InFlightTracker> = None;
        let mut metrics_config_sender: Option<watch::Sender<u64>> = None;
        let mut digest_config_sender: Option<watch::Sender<DigestConfig>> = None;
        let mut event_store_config_sender: Option<watch::Sender<EventStoreRuntimeConfig>> = None;
        let mut event_stream_cancel_token: Option<CancellationToken> = None;
        let mut event_stream_config_sender: Option<watch::Sender<EventStreamRuntimeConfig>> = None;
        let mut correlation_config_sender: Option<watch::Sender<CorrelationRuntimeConfig>> = None;
        let mut syslog_config_sender: Option<watch::Sender<SyslogRuntimeConfig>> = None;
        let mut alert_rule_config_sender: Option<watch::Sender<AlertRuleEngineConfig>> = None;
        let event_bus = if self.config.event_bus.enabled {
            let bus = EventBus::with_filters(
                self.config.event_bus.channel_capacity,
                self.config.event_bus.debounce_secs,
                &self.config.event_bus.filters,
            )?;
            event::spawn_log_subscriber(&bus, &self.config.general.journald_field_prefix);
            event::spawn_debounce_cleanup(&bus);
            // アクションエンジンの起動
            if self.config.actions.enabled {
                match ActionEngine::new(&self.config.actions, &bus) {
                    Ok((engine, sender, tracker)) => {
                        action_config_sender = Some(sender);
                        inflight_tracker = Some(tracker);
                        engine.spawn();
                        tracing::info!("アクションエンジンを起動しました");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "アクションエンジンの初期化に失敗しました");
                    }
                }
            }

            // メトリクスコレクターの起動
            if self.config.metrics.enabled {
                let (collector, sender, metrics) =
                    MetricsCollector::new(&self.config.metrics, &bus);
                metrics_config_sender = Some(sender);
                shared_metrics = Some(metrics);
                collector.spawn();
                tracing::info!(
                    interval_secs = self.config.metrics.interval_secs,
                    "メトリクスコレクターを起動しました"
                );
            }

            // モジュール実行統計コレクターの起動
            if let Some(ref handle) = module_stats_handle {
                module_stats::spawn_event_subscriber(handle.clone(), &bus);
                module_stats::spawn_summary_logger(handle.clone(), &self.config.module_stats);
                tracing::info!(
                    log_interval_secs = self.config.module_stats.log_interval_secs,
                    "モジュール実行統計コレクターを起動しました"
                );
            }

            // セキュリティスコアラーの起動
            if self.config.scoring.enabled {
                let (scorer, sender, shared) = SecurityScorer::new(&self.config.scoring, &bus);
                scoring_config_sender = Some(sender);
                shared_scoring = Some(shared);
                scorer.spawn();
                tracing::info!("セキュリティスコアラーを起動しました");
            }

            // ダイジェストコレクターの起動
            if let Some(ref digest_cfg) = self.config.actions.digest
                && digest_cfg.enabled
            {
                let (collector, sender) = DigestCollector::new(digest_cfg, &bus);
                digest_config_sender = Some(sender);
                collector.spawn();
                tracing::info!(
                    interval_secs = digest_cfg.interval_secs,
                    min_events = digest_cfg.min_events,
                    "ダイジェストコレクターを起動しました"
                );
            }

            // イベントストアの起動
            if self.config.event_store.enabled {
                match EventStore::new(&self.config.event_store, &bus) {
                    Ok((store, sender)) => {
                        event_store_config_sender = Some(sender);
                        store.spawn();
                        tracing::info!(
                            database_path = %self.config.event_store.database_path,
                            retention_days = self.config.event_store.retention_days,
                            "イベントストアを起動しました"
                        );
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "イベントストアの初期化に失敗しました");
                    }
                }
            }

            // イベントストリームサーバーの起動
            if self.config.event_stream.enabled {
                let (server, sender) = EventStreamServer::new(&self.config.event_stream, &bus);
                event_stream_config_sender = Some(sender);
                event_stream_cancel_token = Some(server.cancel_token());
                match server.spawn() {
                    Ok(()) => {
                        tracing::info!(
                            socket_path = %self.config.event_stream.socket_path,
                            "イベントストリームサーバーを起動しました"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "イベントストリームサーバーの起動に失敗しました"
                        );
                    }
                }
            }

            // 相関分析エンジンの起動
            if self.config.correlation.enabled {
                match CorrelationEngine::new(&self.config.correlation, &bus) {
                    Ok((engine, sender)) => {
                        correlation_config_sender = Some(sender);
                        let effective_rules = crate::core::correlation_presets::merge_rules(
                            &self.config.correlation.rules,
                            self.config.correlation.enable_presets,
                            &self.config.correlation.disabled_presets,
                        );
                        engine.spawn();
                        tracing::info!(
                            total_rules = effective_rules.len(),
                            preset_rules = effective_rules
                                .iter()
                                .filter(|r| r.name.starts_with("preset:"))
                                .count(),
                            user_rules = self.config.correlation.rules.len(),
                            window_secs = self.config.correlation.window_secs,
                            "相関分析エンジンを起動しました"
                        );
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "相関分析エンジンの初期化に失敗しました");
                    }
                }
            }

            // Syslog フォワーダーの起動
            if self.config.syslog.enabled {
                let (forwarder, sender) = SyslogForwarder::new(&self.config.syslog, &bus);
                syslog_config_sender = Some(sender);
                forwarder.spawn();
                tracing::info!(
                    protocol = %self.config.syslog.protocol,
                    server = %self.config.syslog.server,
                    port = self.config.syslog.port,
                    facility = %self.config.syslog.facility,
                    "Syslog フォワーダーを起動しました"
                );
            }

            // アラートルールエンジンの起動
            if self.config.alert_rules.enabled {
                match AlertRuleEngine::new(&self.config.alert_rules, &bus) {
                    Ok((engine, sender)) => {
                        alert_rule_config_sender = Some(sender);
                        engine.spawn();
                        tracing::info!(
                            rule_count = self.config.alert_rules.rules.len(),
                            "アラートルールエンジンを起動しました"
                        );
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "アラートルールエンジンの初期化に失敗しました");
                    }
                }
            }

            tracing::info!(
                channel_capacity = self.config.event_bus.channel_capacity,
                "イベントバスを起動しました"
            );
            Some(bus)
        } else {
            None
        };

        if event_bus.is_none() && self.config.actions.enabled {
            tracing::warn!("アクションエンジンはイベントバスが無効のため起動できません");
        }

        if event_bus.is_none() && self.config.event_stream.enabled {
            tracing::warn!("イベントストリームはイベントバスが無効のため起動できません");
        }

        if event_bus.is_none() && self.config.syslog.enabled {
            tracing::warn!("Syslog フォワーダーはイベントバスが無効のため起動できません");
        }

        if event_bus.is_none() && self.config.alert_rules.enabled {
            tracing::warn!("アラートルールエンジンはイベントバスが無効のため起動できません");
        }

        // 前回のスキャン状態を読み込み
        let previous_scan_state =
            if self.config.startup_scan.enabled && self.config.startup_scan.persist_state {
                let state_path = Path::new(&self.config.startup_scan.state_file);
                scan_state::load_scan_state(state_path)
            } else {
                None
            };

        // モジュールマネージャーでモジュールを一括起動（起動時スキャン付き）
        let (mut module_manager, scan_report) = ModuleManager::start_modules(
            &self.config.modules,
            &event_bus,
            &module_stats_handle,
            self.config.startup_scan.enabled,
        )
        .await;

        // モジュール実行統計に起動時スキャン結果を記録
        if let Some(ref handle) = module_stats_handle {
            for (name, result) in &scan_report.results {
                handle.record_initial_scan(
                    name,
                    result.duration,
                    result.items_scanned,
                    result.issues_found,
                    &result.summary,
                );
            }
        }

        // 起動時スキャンのサマリーイベントを発行
        if self.config.startup_scan.enabled
            && let Some(ref bus) = event_bus
        {
            let total_items: usize = scan_report
                .results
                .iter()
                .map(|(_, r)| r.items_scanned)
                .sum();
            let total_issues: usize = scan_report
                .results
                .iter()
                .map(|(_, r)| r.issues_found)
                .sum();
            let summary = format!(
                "起動時スキャン完了: {}モジュール, {}アイテム, {}問題検知, {}エラー, {:.1}秒",
                scan_report.results.len(),
                total_items,
                total_issues,
                scan_report.errors.len(),
                scan_report.total_duration.as_secs_f64(),
            );
            let severity = if total_issues > 0 || !scan_report.errors.is_empty() {
                Severity::Warning
            } else {
                Severity::Info
            };
            bus.publish(SecurityEvent::new(
                "startup_scan_completed",
                severity,
                "daemon",
                summary,
            ));
        }

        // スキャン状態の差分検出と永続化
        if self.config.startup_scan.enabled && self.config.startup_scan.persist_state {
            // スナップショットデータを収集
            let snapshot_data: Vec<(String, std::collections::BTreeMap<String, String>)> =
                scan_report
                    .results
                    .iter()
                    .filter(|(_, r)| !r.snapshot.is_empty())
                    .map(|(name, r)| (name.clone(), r.snapshot.clone()))
                    .collect();

            // 前回の状態との差分検出
            if let Some(ref prev_state) = previous_scan_state {
                let diffs = scan_state::detect_diffs(prev_state, &snapshot_data);
                if !diffs.is_empty() {
                    let total_changes: usize = diffs.iter().map(|d| d.entries.len()).sum();
                    tracing::warn!(
                        modules = diffs.len(),
                        total_changes = total_changes,
                        "前回起動時からの変更を検出しました"
                    );

                    if let Some(ref bus) = event_bus {
                        for diff in &diffs {
                            for entry in &diff.entries {
                                let (event_type, message) = match entry.kind {
                                    DiffKind::Added => (
                                        "scan_state_added",
                                        format!("[{}] 新規追加: {}", diff.module_name, entry.key),
                                    ),
                                    DiffKind::Removed => (
                                        "scan_state_removed",
                                        format!("[{}] 削除: {}", diff.module_name, entry.key),
                                    ),
                                    DiffKind::Modified => (
                                        "scan_state_modified",
                                        format!("[{}] 変更: {}", diff.module_name, entry.key),
                                    ),
                                };
                                bus.publish(SecurityEvent::new(
                                    event_type,
                                    Severity::Warning,
                                    "daemon",
                                    message,
                                ));
                            }
                        }
                    }
                } else {
                    tracing::info!("前回起動時からの変更はありません");
                }
            }

            // 現在のスナップショットを保存
            let state_path = Path::new(&self.config.startup_scan.state_file);
            scan_state::save_scan_state(state_path, &snapshot_data);
        }

        // モジュール名を共有状態に反映
        {
            // unwrap safety: Mutex が poisoned になるのはパニック時のみ
            let mut names = shared_module_names.lock().unwrap();
            *names = module_manager.running_module_names();
        }

        // ステータス用: モジュール再起動回数の共有状態
        let shared_module_restarts: Arc<StdMutex<std::collections::HashMap<String, u32>>> =
            Arc::new(StdMutex::new(std::collections::HashMap::new()));

        // ステータスサーバーの起動
        if self.config.status.enabled {
            let state = DaemonState::new(
                Arc::clone(&shared_module_names),
                shared_metrics.clone(),
                Arc::clone(&shared_module_restarts),
            );
            let server = StatusServer::new(&self.config.status.socket_path, state);
            status_cancel_token = Some(server.cancel_token());
            match server.spawn() {
                Ok(()) => {}
                Err(e) => {
                    tracing::error!(error = %e, "ステータスサーバーの起動に失敗しました");
                }
            }
        }

        // Prometheus エクスポーターの起動
        if self.config.prometheus.enabled {
            if let Some(ref metrics) = shared_metrics {
                let exporter = PrometheusExporter::new(
                    &self.config.prometheus,
                    Arc::clone(metrics),
                    prometheus_started_at,
                )
                .with_scoring(shared_scoring.clone())
                .with_module_stats(module_stats_handle.clone());
                prometheus_cancel_token = Some(exporter.cancel_token());
                match exporter.spawn() {
                    Ok(()) => {}
                    Err(e) => {
                        tracing::error!(error = %e, "Prometheus エクスポーターの起動に失敗しました");
                    }
                }
            } else {
                tracing::warn!(
                    "Prometheus エクスポーターはメトリクス収集が無効のため起動できません。metrics.enabled = true を設定してください"
                );
            }
        }

        // REST API サーバーの起動
        if self.config.api.enabled {
            let event_store_db_path = if self.config.event_store.enabled {
                Some(self.config.event_store.database_path.clone())
            } else {
                None
            };
            let event_store_cfg = if self.config.event_store.enabled {
                Some(&self.config.event_store)
            } else {
                None
            };
            let api_server = ApiServer::new(
                &self.config.api,
                Arc::clone(&shared_module_names),
                shared_metrics.clone(),
                Arc::clone(&shared_module_restarts),
                prometheus_started_at,
                event_store_db_path,
                Some(self.config_path.to_string_lossy().to_string()),
                reload_sender.clone(),
                module_control_sender.clone(),
                event_bus.as_ref().map(|b| b.sender()),
                shared_scoring.clone(),
                event_store_cfg,
                &self.config.actions,
                module_stats_handle.clone(),
            );
            api_cancel_token = Some(api_server.cancel_token());
            api_shared_action_config = Some(api_server.shared_action_config());
            match api_server.spawn() {
                Ok(()) => {}
                Err(e) => {
                    tracing::error!(error = %e, "REST API サーバーの起動に失敗しました");
                }
            }
        }

        // モジュールウォッチドッグの初期化
        let watchdog_enabled = self.config.module_watchdog.enabled;
        let watchdog_interval_duration =
            Duration::from_secs(self.config.module_watchdog.check_interval_secs);
        let mut watchdog_interval = tokio::time::interval(watchdog_interval_duration);
        // 最初の tick は即座に発火するのでスキップ
        watchdog_interval.tick().await;

        tracing::info!("デーモンを起動しました");

        if health_enabled {
            tracing::info!(
                interval_secs = self.config.health.heartbeat_interval_secs,
                "ハートビートを有効化しました"
            );
        }

        if watchdog_enabled {
            tracing::info!(
                check_interval_secs = self.config.module_watchdog.check_interval_secs,
                auto_restart = self.config.module_watchdog.auto_restart,
                max_restarts = self.config.module_watchdog.max_restarts,
                "モジュールウォッチドッグを有効化しました"
            );
        }

        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("SIGINT を受信しました。シャットダウンします...");
                    break;
                }
                _ = sigterm.recv() => {
                    tracing::info!("SIGTERM を受信しました。シャットダウンします...");
                    break;
                }
                _ = sighup.recv() => {
                    tracing::info!("SIGHUP を受信しました。設定をリロードします...");
                    match AppConfig::load(&self.config_path) {
                        Ok(new_config) => {
                            let result = module_manager.reload(
                                &self.config.modules,
                                &new_config.modules,
                                &event_bus,
                                &module_stats_handle,
                            ).await;

                            let summary = format!(
                                "起動: {}, 停止: {}, 再起動: {}, エラー: {}",
                                result.started.len(),
                                result.stopped.len(),
                                result.restarted.len(),
                                result.errors.len(),
                            );
                            tracing::info!(summary = %summary, "設定リロード完了");

                            if let Some(ref bus) = event_bus {
                                let event = SecurityEvent::new(
                                    "config_reloaded",
                                    Severity::Info,
                                    "daemon",
                                    format!("設定ファイルをリロードしました ({})", summary),
                                );
                                bus.publish(event);
                            }

                            // モジュール名を共有状態に反映
                            {
                                // unwrap safety: Mutex が poisoned になるのはパニック時のみ
                                let mut names = shared_module_names.lock().unwrap();
                                *names = module_manager.running_module_names();
                            }

                            // デバウンス間隔の更新
                            if let Some(ref bus) = event_bus {
                                bus.update_debounce_secs(new_config.event_bus.debounce_secs);
                            }

                            // イベントフィルターの更新
                            if let Some(ref bus) = event_bus
                                && let Err(e) =
                                    bus.update_filters(&new_config.event_bus.filters)
                            {
                                tracing::error!(error = %e, "イベントフィルターの更新に失敗しました");
                            }

                            // アクションエンジンのルール・レートリミットリロード
                            if let Some(ref sender) = action_config_sender {
                                match ActionEngine::parse_config(&new_config.actions) {
                                    Ok(engine_config) => {
                                        let rule_count = engine_config.rules.len();
                                        if sender.send(engine_config).is_ok() {
                                            tracing::info!(
                                                rules = rule_count,
                                                "アクションエンジンの設定をリロードしました"
                                            );
                                        } else {
                                            tracing::warn!(
                                                "アクションエンジンの設定リロードに失敗しました（受信側が閉じています）"
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        tracing::error!(
                                            error = %e,
                                            "アクション設定のパースに失敗しました。既存の設定を維持します"
                                        );
                                    }
                                }
                            }

                            // メトリクスのインターバルリロード
                            if self.config.metrics.interval_secs != new_config.metrics.interval_secs
                                && let Some(ref sender) = metrics_config_sender
                            {
                                if sender.send(new_config.metrics.interval_secs).is_ok() {
                                    tracing::info!(
                                        old = self.config.metrics.interval_secs,
                                        new = new_config.metrics.interval_secs,
                                        "メトリクスのインターバルをリロードしました"
                                    );
                                } else {
                                    tracing::warn!(
                                        "メトリクスのインターバルリロードに失敗しました（受信側が閉じています）"
                                    );
                                }
                            }

                            // スコアラーのリロード
                            if let Some(ref sender) = scoring_config_sender {
                                let new_runtime = ScoringRuntimeConfig {
                                    interval_secs: new_config.scoring.interval_secs,
                                    category_weights: new_config.scoring.category_weights.clone(),
                                };
                                if sender.send(new_runtime).is_ok() {
                                    tracing::info!(
                                        "スコアラーの設定をリロードしました"
                                    );
                                } else {
                                    tracing::warn!(
                                        "スコアラーの設定リロードに失敗しました（受信側が閉じています）"
                                    );
                                }
                            }

                            // ダイジェストコレクターのリロード
                            if let Some(ref sender) = digest_config_sender
                                && let Some(ref new_digest) = new_config.actions.digest
                            {
                                if sender.send(new_digest.clone()).is_ok() {
                                    tracing::info!(
                                        "ダイジェストコレクターの設定をリロードしました"
                                    );
                                } else {
                                    tracing::warn!(
                                        "ダイジェストコレクターの設定リロードに失敗しました（受信側が閉じています）"
                                    );
                                }
                            }

                            // イベントストアのリロード
                            if let Some(ref sender) = event_store_config_sender {
                                if new_config.event_store.database_path
                                    != self.config.event_store.database_path
                                {
                                    tracing::warn!(
                                        "event_store.database_path の変更はホットリロードに対応していません。デーモンを再起動してください"
                                    );
                                }
                                if new_config.event_store.archive_enabled
                                    && new_config.event_store.archive_after_days
                                        >= new_config.event_store.retention_days
                                {
                                    tracing::warn!(
                                        archive_after_days = new_config.event_store.archive_after_days,
                                        retention_days = new_config.event_store.retention_days,
                                        "archive_after_days が retention_days 以上です。アーカイブ前にイベントが削除される可能性があります"
                                    );
                                }
                                let new_runtime = EventStoreRuntimeConfig::from(&new_config.event_store);
                                if sender.send(new_runtime).is_ok() {
                                    tracing::info!(
                                        "イベントストアの設定をリロードしました"
                                    );
                                } else {
                                    tracing::warn!(
                                        "イベントストアの設定リロードに失敗しました（受信側が閉じています）"
                                    );
                                }
                            }

                            // イベントストリームのリロード
                            if let Some(ref sender) = event_stream_config_sender {
                                if new_config.event_stream.socket_path
                                    != self.config.event_stream.socket_path
                                {
                                    tracing::warn!(
                                        "event_stream.socket_path の変更はホットリロードに対応していません。デーモンを再起動してください"
                                    );
                                }
                                let new_runtime = EventStreamRuntimeConfig {
                                    buffer_size: new_config.event_stream.buffer_size,
                                };
                                if sender.send(new_runtime).is_ok() {
                                    tracing::info!(
                                        "イベントストリームの設定をリロードしました"
                                    );
                                } else {
                                    tracing::warn!(
                                        "イベントストリームの設定リロードに失敗しました（受信側が閉じています）"
                                    );
                                }
                            }

                            // 相関分析エンジンのリロード
                            if let Some(ref sender) = correlation_config_sender {
                                let effective_rules =
                                    crate::core::correlation_presets::merge_rules(
                                        &new_config.correlation.rules,
                                        new_config.correlation.enable_presets,
                                        &new_config.correlation.disabled_presets,
                                    );
                                let runtime_config = CorrelationRuntimeConfig {
                                    window_secs: new_config.correlation.window_secs,
                                    max_events: new_config.correlation.max_events,
                                    cleanup_interval_secs: new_config
                                        .correlation
                                        .cleanup_interval_secs,
                                    rules: effective_rules.clone(),
                                    enable_presets: new_config.correlation.enable_presets,
                                    disabled_presets: new_config
                                        .correlation
                                        .disabled_presets
                                        .clone(),
                                };
                                if sender.send(runtime_config).is_ok() {
                                    tracing::info!(
                                        total_rules = effective_rules.len(),
                                        preset_rules = effective_rules.iter().filter(|r| r.name.starts_with("preset:")).count(),
                                        user_rules = new_config.correlation.rules.len(),
                                        "相関分析エンジンの設定をリロードしました"
                                    );
                                } else {
                                    tracing::warn!(
                                        "相関分析エンジンの設定リロードに失敗しました（受信側が閉じています）"
                                    );
                                }
                            }

                            // Syslog フォワーダーのリロード
                            if let Some(ref sender) = syslog_config_sender {
                                let new_runtime = SyslogRuntimeConfig::from(&new_config.syslog);
                                if sender.send(new_runtime).is_ok() {
                                    tracing::info!(
                                        "Syslog フォワーダーの設定をリロードしました"
                                    );
                                } else {
                                    tracing::warn!(
                                        "Syslog フォワーダーの設定リロードに失敗しました（受信側が閉じています）"
                                    );
                                }
                            }

                            // アラートルールエンジンのリロード
                            if let Some(ref sender) = alert_rule_config_sender {
                                let new_runtime = AlertRuleEngineConfig {
                                    rules: new_config.alert_rules.rules.clone(),
                                };
                                if sender.send(new_runtime).is_ok() {
                                    tracing::info!(
                                        rule_count = new_config.alert_rules.rules.len(),
                                        "アラートルールエンジンの設定をリロードしました"
                                    );
                                } else {
                                    tracing::warn!(
                                        "アラートルールエンジンの設定リロードに失敗しました（受信側が閉じています）"
                                    );
                                }
                            }

                            // Prometheus エクスポーターのホットリロード
                            if self.config.prometheus != new_config.prometheus {
                                let was_enabled = self.config.prometheus.enabled;
                                let now_enabled = new_config.prometheus.enabled;

                                if was_enabled && !now_enabled {
                                    // パターン A: 停止のみ
                                    if let Some(token) = prometheus_cancel_token.take() {
                                        token.cancel();
                                        tracing::info!("Prometheus エクスポーターを停止しました");
                                    }
                                } else if !was_enabled && now_enabled {
                                    // パターン B: 新規起動
                                    if let Some(ref metrics) = shared_metrics {
                                        let exporter = PrometheusExporter::new(
                                            &new_config.prometheus,
                                            Arc::clone(metrics),
                                            prometheus_started_at,
                                        )
                                        .with_scoring(shared_scoring.clone())
                                        .with_module_stats(module_stats_handle.clone());
                                        prometheus_cancel_token = Some(exporter.cancel_token());
                                        match exporter.spawn() {
                                            Ok(()) => tracing::info!(
                                                "Prometheus エクスポーターを起動しました（ホットリロード）"
                                            ),
                                            Err(e) => tracing::error!(
                                                error = %e,
                                                "Prometheus エクスポーターの起動に失敗しました"
                                            ),
                                        }
                                    }
                                } else {
                                    // パターン C: bind_address/port 変更（停止→再起動）
                                    if let Some(token) = prometheus_cancel_token.take() {
                                        token.cancel();
                                    }
                                    tokio::time::sleep(Duration::from_millis(100)).await;
                                    if let Some(ref metrics) = shared_metrics {
                                        let exporter = PrometheusExporter::new(
                                            &new_config.prometheus,
                                            Arc::clone(metrics),
                                            prometheus_started_at,
                                        )
                                        .with_scoring(shared_scoring.clone())
                                        .with_module_stats(module_stats_handle.clone());
                                        prometheus_cancel_token = Some(exporter.cancel_token());
                                        match exporter.spawn() {
                                            Ok(()) => tracing::info!(
                                                bind_address = %new_config.prometheus.bind_address,
                                                port = new_config.prometheus.port,
                                                "Prometheus エクスポーターをリロードしました"
                                            ),
                                            Err(e) => {
                                                tracing::error!(
                                                    error = %e,
                                                    "新設定での Prometheus エクスポーターの起動に失敗。旧設定で復旧を試みます"
                                                );
                                                let fallback = PrometheusExporter::new(
                                                    &self.config.prometheus,
                                                    Arc::clone(metrics),
                                                    prometheus_started_at,
                                                )
                                                .with_scoring(shared_scoring.clone())
                                                .with_module_stats(module_stats_handle.clone());
                                                prometheus_cancel_token =
                                                    Some(fallback.cancel_token());
                                                match fallback.spawn() {
                                                    Ok(()) => tracing::info!(
                                                        "旧設定で Prometheus エクスポーターを復旧しました"
                                                    ),
                                                    Err(e2) => tracing::error!(
                                                        error = %e2,
                                                        "旧設定での Prometheus エクスポーターの復旧にも失敗しました"
                                                    ),
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            // REST API サーバーのホットリロード
                            if self.config.api != new_config.api {
                                let was_enabled = self.config.api.enabled;
                                let now_enabled = new_config.api.enabled;

                                if was_enabled && !now_enabled {
                                    // パターン A: 停止のみ
                                    if let Some(token) = api_cancel_token.take() {
                                        token.cancel();
                                        tracing::info!("REST API サーバーを停止しました");
                                    }
                                } else if !was_enabled && now_enabled {
                                    // パターン B: 新規起動
                                    let event_store_db_path = if new_config.event_store.enabled {
                                        Some(new_config.event_store.database_path.clone())
                                    } else {
                                        None
                                    };
                                    let es_cfg_b = if new_config.event_store.enabled {
                                        Some(&new_config.event_store)
                                    } else {
                                        None
                                    };
                                    let api_server = ApiServer::new(
                                        &new_config.api,
                                        Arc::clone(&shared_module_names),
                                        shared_metrics.clone(),
                                        Arc::clone(&shared_module_restarts),
                                        prometheus_started_at,
                                        event_store_db_path,
                                        Some(self.config_path.to_string_lossy().to_string()),
                                        reload_sender.clone(),
                                        module_control_sender.clone(),
                                        event_bus.as_ref().map(|b| b.sender()),
                                        shared_scoring.clone(),
                                        es_cfg_b,
                                        &new_config.actions,
                                        module_stats_handle.clone(),
                                    );
                                    api_cancel_token = Some(api_server.cancel_token());
                                    api_shared_action_config =
                                        Some(api_server.shared_action_config());
                                    match api_server.spawn() {
                                        Ok(()) => tracing::info!(
                                            "REST API サーバーを起動しました（ホットリロード）"
                                        ),
                                        Err(e) => tracing::error!(
                                            error = %e,
                                            "REST API サーバーの起動に失敗しました"
                                        ),
                                    }
                                } else {
                                    // パターン C: bind_address/port 変更（停止→再起動）
                                    if let Some(token) = api_cancel_token.take() {
                                        token.cancel();
                                    }
                                    tokio::time::sleep(Duration::from_millis(100)).await;
                                    let event_store_db_path = if new_config.event_store.enabled {
                                        Some(new_config.event_store.database_path.clone())
                                    } else {
                                        None
                                    };
                                    let es_cfg_c = if new_config.event_store.enabled {
                                        Some(&new_config.event_store)
                                    } else {
                                        None
                                    };
                                    let api_server = ApiServer::new(
                                        &new_config.api,
                                        Arc::clone(&shared_module_names),
                                        shared_metrics.clone(),
                                        Arc::clone(&shared_module_restarts),
                                        prometheus_started_at,
                                        event_store_db_path,
                                        Some(self.config_path.to_string_lossy().to_string()),
                                        reload_sender.clone(),
                                        module_control_sender.clone(),
                                        event_bus.as_ref().map(|b| b.sender()),
                                        shared_scoring.clone(),
                                        es_cfg_c,
                                        &new_config.actions,
                                        module_stats_handle.clone(),
                                    );
                                    api_cancel_token = Some(api_server.cancel_token());
                                    api_shared_action_config =
                                        Some(api_server.shared_action_config());
                                    match api_server.spawn() {
                                        Ok(()) => tracing::info!(
                                            bind_address = %new_config.api.bind_address,
                                            port = new_config.api.port,
                                            "REST API サーバーをリロードしました"
                                        ),
                                        Err(e) => {
                                            tracing::error!(
                                                error = %e,
                                                "新設定での REST API サーバーの起動に失敗。旧設定で復旧を試みます"
                                            );
                                            let fallback_db_path = if self.config.event_store.enabled {
                                                Some(self.config.event_store.database_path.clone())
                                            } else {
                                                None
                                            };
                                            let es_cfg_fb = if self.config.event_store.enabled {
                                                Some(&self.config.event_store)
                                            } else {
                                                None
                                            };
                                            let fallback = ApiServer::new(
                                                &self.config.api,
                                                Arc::clone(&shared_module_names),
                                                shared_metrics.clone(),
                                                Arc::clone(&shared_module_restarts),
                                                prometheus_started_at,
                                                fallback_db_path,
                                                Some(self.config_path.to_string_lossy().to_string()),
                                                reload_sender.clone(),
                                                module_control_sender.clone(),
                                                event_bus.as_ref().map(|b| b.sender()),
                                                shared_scoring.clone(),
                                                es_cfg_fb,
                                                &self.config.actions,
                                                module_stats_handle.clone(),
                                            );
                                            api_cancel_token =
                                                Some(fallback.cancel_token());
                                            api_shared_action_config =
                                                Some(fallback.shared_action_config());
                                            match fallback.spawn() {
                                                Ok(()) => tracing::info!(
                                                    "旧設定で REST API サーバーを復旧しました"
                                                ),
                                                Err(e2) => tracing::error!(
                                                    error = %e2,
                                                    "旧設定での REST API サーバーの復旧にも失敗しました"
                                                ),
                                            }
                                        }
                                    }
                                }
                            }

                            // API Webhook 設定のリロード
                            if let Some(ref cfg) = api_shared_action_config {
                                // unwrap safety: Mutex が poisoned になるのはパニック時のみ
                                *cfg.lock().unwrap() = new_config.actions.clone();
                                tracing::info!("API Webhook 設定をリロードしました");
                            }

                            self.config = new_config;
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "設定ファイルのリロードに失敗しました");
                            if let Some(ref bus) = event_bus {
                                let event = SecurityEvent::new(
                                    "config_reload_failed",
                                    Severity::Warning,
                                    "daemon",
                                    format!("設定ファイルのリロードに失敗: {}", e),
                                );
                                bus.publish(event);
                            }
                        }
                    }
                }
                _ = reload_receiver.recv() => {
                    tracing::info!("API 経由で設定リロードがトリガーされました");
                    // SAFETY: 自プロセスに SIGHUP を送信してリロードをトリガー
                    // libc::kill は POSIX 標準の安全な関数だが、Rust の FFI 経由なので unsafe が必要
                    unsafe { libc::kill(std::process::id() as libc::pid_t, libc::SIGHUP); }
                }
                Some((cmd, reply)) = module_control_receiver.recv() => {
                    let result = match cmd {
                        ModuleControlCommand::Start(ref name) => {
                            if !ModuleManager::is_known_module(name) {
                                ModuleControlResult::NotFound(format!("モジュール '{}' は存在しません", name))
                            } else if module_manager.is_module_running(name) {
                                ModuleControlResult::Conflict(format!("モジュール '{}' は既に起動中です", name))
                            } else {
                                match module_manager.start_module_by_name(name, &self.config.modules, &event_bus).await {
                                    Ok(()) => {
                                        {
                                            let mut names = shared_module_names.lock().unwrap();
                                            *names = module_manager.running_module_names();
                                        }
                                        if let Some(ref bus) = event_bus {
                                            bus.publish(SecurityEvent::new(
                                                "module_started_api",
                                                Severity::Info,
                                                "api",
                                                format!("API 経由でモジュールを起動しました: {}", name),
                                            ));
                                        }
                                        ModuleControlResult::Ok(format!("モジュール '{}' を起動しました", name))
                                    }
                                    Err(e) => ModuleControlResult::Error(e),
                                }
                            }
                        }
                        ModuleControlCommand::Stop(ref name) => {
                            if !ModuleManager::is_known_module(name) {
                                ModuleControlResult::NotFound(format!("モジュール '{}' は存在しません", name))
                            } else if !module_manager.is_module_running(name) {
                                ModuleControlResult::Conflict(format!("モジュール '{}' は起動していません", name))
                            } else {
                                module_manager.stop_module_by_name(name);
                                {
                                    let mut names = shared_module_names.lock().unwrap();
                                    *names = module_manager.running_module_names();
                                }
                                if let Some(ref bus) = event_bus {
                                    bus.publish(SecurityEvent::new(
                                        "module_stopped_api",
                                        Severity::Info,
                                        "api",
                                        format!("API 経由でモジュールを停止しました: {}", name),
                                    ));
                                }
                                ModuleControlResult::Ok(format!("モジュール '{}' を停止しました", name))
                            }
                        }
                        ModuleControlCommand::Restart(ref name) => {
                            if !ModuleManager::is_known_module(name) {
                                ModuleControlResult::NotFound(format!("モジュール '{}' は存在しません", name))
                            } else {
                                let was_running = module_manager.is_module_running(name);
                                if was_running {
                                    module_manager.stop_module_by_name(name);
                                }
                                match module_manager.start_module_by_name(name, &self.config.modules, &event_bus).await {
                                    Ok(()) => {
                                        {
                                            let mut names = shared_module_names.lock().unwrap();
                                            *names = module_manager.running_module_names();
                                        }
                                        if let Some(ref bus) = event_bus {
                                            bus.publish(SecurityEvent::new(
                                                "module_restarted_api",
                                                Severity::Info,
                                                "api",
                                                format!("API 経由でモジュールを再起動しました: {}", name),
                                            ));
                                        }
                                        ModuleControlResult::Ok(format!("モジュール '{}' を再起動しました", name))
                                    }
                                    Err(e) => ModuleControlResult::Error(e),
                                }
                            }
                        }
                    };
                    let _ = reply.send(result);
                }
                _ = heartbeat.tick(), if health_enabled => {
                    let status = health_checker.status();
                    match status.memory_rss_kb {
                        Some(rss_kb) => {
                            let rss_mb = rss_kb as f64 / 1024.0;
                            tracing::info!(
                                uptime_secs = status.uptime_secs,
                                memory_rss_mb = format!("{rss_mb:.1}"),
                                "ハートビート"
                            );
                        }
                        None => {
                            tracing::info!(
                                uptime_secs = status.uptime_secs,
                                "ハートビート（メモリ情報取得不可）"
                            );
                        }
                    }
                }
                _ = watchdog_interval.tick(), if watchdog_enabled => {
                    let report = module_manager.check_health(
                        &self.config.module_watchdog,
                        &self.config.modules,
                        &event_bus,
                    ).await;
                    if !report.crashed.is_empty() {
                        tracing::warn!(
                            crashed = ?report.crashed,
                            restarted = ?report.restarted,
                            restart_limit_reached = ?report.restart_limit_reached,
                            cooldown_skipped = ?report.cooldown_skipped,
                            "ウォッチドッグ: モジュールの異常停止を検知"
                        );
                    }
                    // ステータス用モジュール名リストと再起動回数を更新
                    if !report.restarted.is_empty() || !report.crashed.is_empty() {
                        {
                            // unwrap safety: Mutex が poisoned になるのはパニック時のみ
                            let mut names = shared_module_names.lock().unwrap();
                            *names = module_manager.running_module_names();
                        }
                        {
                            // unwrap safety: Mutex が poisoned になるのはパニック時のみ
                            let mut restarts = shared_module_restarts.lock().unwrap();
                            *restarts = module_manager.module_restart_counts();
                        }
                    }
                }
            }
        }

        // ステータスサーバーの停止
        if let Some(token) = status_cancel_token {
            token.cancel();
        }

        // Prometheus エクスポーターの停止
        if let Some(token) = prometheus_cancel_token {
            token.cancel();
        }

        // REST API サーバーの停止
        if let Some(token) = api_cancel_token {
            token.cancel();
        }

        // イベントストリームサーバーの停止
        if let Some(token) = event_stream_cancel_token {
            token.cancel();
        }

        // インフライトトラッカーのシャットダウン開始
        if let Some(ref tracker) = inflight_tracker {
            tracker.begin_shutdown();
            let in_flight = tracker.in_flight_count();
            if in_flight > 0 {
                let timeout = Duration::from_secs(self.config.daemon.shutdown_timeout_secs);
                tracing::info!(
                    in_flight = in_flight,
                    timeout_secs = timeout.as_secs(),
                    "実行中のアクション完了を待機します..."
                );
                if tracker.wait_for_completion(timeout).await {
                    tracing::info!("全アクションが完了しました");
                } else {
                    tracing::warn!(
                        remaining = tracker.in_flight_count(),
                        "タイムアウト: 一部のアクションが完了していません"
                    );
                }
            }
        }

        // モジュールの一括停止
        module_manager.stop_all();

        tracing::info!("シャットダウン完了");
        Ok(())
    }
}
