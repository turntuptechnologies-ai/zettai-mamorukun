use crate::config::AppConfig;
use crate::core::action::{ActionEngine, ActionEngineConfig, InFlightTracker};
use crate::core::event::{self, EventBus, SecurityEvent, Severity};
use crate::core::health::HealthChecker;
use crate::core::metrics::{MetricsCollector, SharedMetrics};
use crate::core::module_manager::ModuleManager;
use crate::core::status::{DaemonState, StatusServer};
use crate::error::AppError;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
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
        let mut status_cancel_token: Option<CancellationToken> = None;

        // イベントバスの初期化
        let mut action_config_sender: Option<watch::Sender<ActionEngineConfig>> = None;
        let mut inflight_tracker: Option<InFlightTracker> = None;
        let mut metrics_config_sender: Option<watch::Sender<u64>> = None;
        let event_bus = if self.config.event_bus.enabled {
            let bus = EventBus::with_filters(
                self.config.event_bus.channel_capacity,
                self.config.event_bus.debounce_secs,
                &self.config.event_bus.filters,
            )?;
            event::spawn_log_subscriber(&bus);
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

        // モジュールマネージャーでモジュールを一括起動（起動時スキャン付き）
        let (mut module_manager, scan_report) = ModuleManager::start_modules(
            &self.config.modules,
            &event_bus,
            self.config.startup_scan.enabled,
        )
        .await;

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

        // モジュール名を共有状態に反映
        {
            // unwrap safety: Mutex が poisoned になるのはパニック時のみ
            let mut names = shared_module_names.lock().unwrap();
            *names = module_manager.running_module_names();
        }

        // ステータスサーバーの起動
        if self.config.status.enabled {
            let state = DaemonState::new(Arc::clone(&shared_module_names), shared_metrics.clone());
            let server = StatusServer::new(&self.config.status.socket_path, state);
            status_cancel_token = Some(server.cancel_token());
            match server.spawn() {
                Ok(()) => {}
                Err(e) => {
                    tracing::error!(error = %e, "ステータスサーバーの起動に失敗しました");
                }
            }
        }

        tracing::info!("デーモンを起動しました");

        if health_enabled {
            tracing::info!(
                interval_secs = self.config.health.heartbeat_interval_secs,
                "ハートビートを有効化しました"
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
            }
        }

        // ステータスサーバーの停止
        if let Some(token) = status_cancel_token {
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
