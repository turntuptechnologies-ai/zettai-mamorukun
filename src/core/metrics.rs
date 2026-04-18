//! イベント統計・メトリクス収集

use crate::config::MetricsConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, watch};

/// 外部から参照可能なメトリクスデータ
#[derive(Debug, Clone, Default, Serialize)]
pub struct SharedMetrics {
    /// 合計イベント数
    pub total_events: u64,
    /// INFO レベルのイベント数
    pub info_count: u64,
    /// WARNING レベルのイベント数
    pub warning_count: u64,
    /// CRITICAL レベルのイベント数
    pub critical_count: u64,
    /// モジュール別イベント数
    pub module_counts: HashMap<String, u64>,
}

/// イベント統計・メトリクス収集
pub struct MetricsCollector {
    receiver: broadcast::Receiver<SecurityEvent>,
    interval: Duration,
    config_receiver: watch::Receiver<u64>,
    shared_metrics: Arc<StdMutex<SharedMetrics>>,
}

impl MetricsCollector {
    /// 設定とイベントバスから MetricsCollector を構築する
    pub fn new(
        config: &MetricsConfig,
        event_bus: &EventBus,
    ) -> (Self, watch::Sender<u64>, Arc<StdMutex<SharedMetrics>>) {
        let interval_secs = config.interval_secs;
        let (config_sender, config_receiver) = watch::channel(interval_secs);
        let shared_metrics = Arc::new(StdMutex::new(SharedMetrics::default()));
        (
            Self {
                receiver: event_bus.subscribe(),
                interval: Duration::from_secs(interval_secs),
                config_receiver,
                shared_metrics: Arc::clone(&shared_metrics),
            },
            config_sender,
            shared_metrics,
        )
    }

    /// 非同期タスクとしてメトリクスコレクターを起動する
    pub fn spawn(self) {
        let shared_metrics = self.shared_metrics;
        tokio::spawn(async move {
            Self::run_loop(
                self.receiver,
                self.interval,
                self.config_receiver,
                shared_metrics,
            )
            .await;
        });
    }

    async fn run_loop(
        mut receiver: broadcast::Receiver<SecurityEvent>,
        interval: Duration,
        mut config_receiver: watch::Receiver<u64>,
        shared_metrics: Arc<StdMutex<SharedMetrics>>,
    ) {
        let started_at = Instant::now();
        let mut total_events: u64 = 0;
        let mut info_count: u64 = 0;
        let mut warning_count: u64 = 0;
        let mut critical_count: u64 = 0;
        let mut module_counts: HashMap<String, u64> = HashMap::new();
        let mut interval_events: u64 = 0;

        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // 最初の tick をスキップ

        loop {
            tokio::select! {
                result = receiver.recv() => {
                    match result {
                        Ok(event) => {
                            total_events += 1;
                            interval_events += 1;
                            match event.severity {
                                Severity::Info => info_count += 1,
                                Severity::Warning => warning_count += 1,
                                Severity::Critical => critical_count += 1,
                            }
                            *module_counts
                                .entry(event.source_module.clone())
                                .or_insert(0) += 1;

                            // SharedMetrics を更新
                            // unwrap safety: Mutex が poisoned になるのはパニック時のみ
                            if let Ok(mut m) = shared_metrics.lock() {
                                m.total_events = total_events;
                                m.info_count = info_count;
                                m.warning_count = warning_count;
                                m.critical_count = critical_count;
                                m.module_counts = module_counts.clone();
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(
                                skipped = n,
                                "メトリクス: {} 件のイベントをスキップ（遅延）",
                                n
                            );
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            Self::emit_summary(
                                total_events,
                                interval_events,
                                info_count,
                                warning_count,
                                critical_count,
                                &module_counts,
                                &started_at,
                            );
                            tracing::info!("イベントバスが閉じられました。メトリクスコレクターを終了します");
                            break;
                        }
                    }
                }
                _ = ticker.tick() => {
                    Self::emit_summary(
                        total_events,
                        interval_events,
                        info_count,
                        warning_count,
                        critical_count,
                        &module_counts,
                        &started_at,
                    );
                    interval_events = 0;
                }
                result = config_receiver.changed() => {
                    match result {
                        Ok(()) => {
                            let new_interval_secs = *config_receiver.borrow_and_update();
                            let new_interval = Duration::from_secs(new_interval_secs);
                            tracing::info!(
                                old_interval_secs = interval.as_secs(),
                                new_interval_secs = new_interval_secs,
                                "メトリクスコレクター: インターバルをリロードしました"
                            );
                            ticker = tokio::time::interval(new_interval);
                            ticker.tick().await;
                        }
                        Err(_) => {
                            tracing::info!("設定チャネルが閉じられました。メトリクスコレクターを終了します");
                            break;
                        }
                    }
                }
            }
        }
    }

    fn emit_summary(
        total_events: u64,
        interval_events: u64,
        info_count: u64,
        warning_count: u64,
        critical_count: u64,
        module_counts: &HashMap<String, u64>,
        started_at: &Instant,
    ) {
        let uptime_secs = started_at.elapsed().as_secs();
        tracing::info!(
            total_events = total_events,
            interval_events = interval_events,
            info_count = info_count,
            warning_count = warning_count,
            critical_count = critical_count,
            uptime_secs = uptime_secs,
            "[MetricsSummary] 合計: {}, 直近: {}, INFO: {}, WARNING: {}, CRITICAL: {}",
            total_events,
            interval_events,
            info_count,
            warning_count,
            critical_count
        );

        if !module_counts.is_empty() {
            let module_summary: Vec<String> = module_counts
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();
            tracing::info!(
                modules = %module_summary.join(", "),
                "[MetricsSummary] モジュール別カウント"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collector_new() {
        let config = MetricsConfig {
            enabled: true,
            interval_secs: 120,
        };
        let bus = EventBus::new(16);
        let (collector, _sender, _shared) = MetricsCollector::new(&config, &bus);
        assert_eq!(collector.interval, Duration::from_secs(120));
    }

    #[tokio::test]
    async fn test_emit_summary_does_not_panic() {
        let module_counts = HashMap::new();
        let started_at = Instant::now();
        // パニックしないことを確認
        MetricsCollector::emit_summary(0, 0, 0, 0, 0, &module_counts, &started_at);
    }

    #[tokio::test]
    async fn test_emit_summary_with_module_counts() {
        let mut module_counts = HashMap::new();
        module_counts.insert("file_integrity".to_string(), 5);
        module_counts.insert("process_monitor".to_string(), 3);
        let started_at = Instant::now();
        // パニックしないことを確認
        MetricsCollector::emit_summary(8, 2, 4, 3, 1, &module_counts, &started_at);
    }

    #[tokio::test]
    async fn test_metrics_collector_receives_events() {
        let bus = EventBus::new(16);
        let config = MetricsConfig {
            enabled: true,
            interval_secs: 1,
        };
        let (collector, _sender, _shared) = MetricsCollector::new(&config, &bus);
        collector.spawn();

        // イベントを発行
        bus.publish(SecurityEvent::new(
            "test_event",
            Severity::Info,
            "test_module",
            "テストイベント",
        ));
        bus.publish(SecurityEvent::new(
            "test_event",
            Severity::Warning,
            "test_module",
            "テストイベント",
        ));
        bus.publish(SecurityEvent::new(
            "test_event",
            Severity::Critical,
            "another_module",
            "テストイベント",
        ));

        // メトリクスコレクターがイベントを処理する時間を与える
        tokio::time::sleep(Duration::from_millis(100)).await;

        // サマリー出力まで待つ（1秒インターバル）
        tokio::time::sleep(Duration::from_secs(1)).await;

        // パニックせずに動作することを確認（ログ出力は tracing で検証）
    }

    #[tokio::test]
    async fn test_metrics_collector_interval_reload() {
        let config = MetricsConfig {
            enabled: true,
            interval_secs: 60,
        };
        let bus = EventBus::new(16);
        let (collector, sender, _shared) = MetricsCollector::new(&config, &bus);

        // 初期値の確認
        assert_eq!(collector.interval, Duration::from_secs(60));

        collector.spawn();

        // インターバル変更を送信
        sender.send(30).unwrap();

        // 変更が処理される時間を与える
        tokio::time::sleep(Duration::from_millis(100)).await;

        // パニックせずに動作することを確認
    }

    #[tokio::test]
    async fn test_metrics_collector_config_channel_closed() {
        let config = MetricsConfig {
            enabled: true,
            interval_secs: 60,
        };
        let bus = EventBus::new(16);
        let (collector, sender, _shared) = MetricsCollector::new(&config, &bus);
        collector.spawn();

        // sender をドロップしてチャネルを閉じる
        drop(sender);

        // メトリクスコレクターが正常に終了することを確認
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    #[test]
    fn test_shared_metrics_default() {
        let metrics = SharedMetrics::default();
        assert_eq!(metrics.total_events, 0);
        assert_eq!(metrics.info_count, 0);
        assert_eq!(metrics.warning_count, 0);
        assert_eq!(metrics.critical_count, 0);
        assert!(metrics.module_counts.is_empty());
    }

    #[test]
    fn test_shared_metrics_serialize() {
        let mut metrics = SharedMetrics {
            total_events: 10,
            info_count: 5,
            warning_count: 3,
            critical_count: 2,
            ..Default::default()
        };
        metrics.module_counts.insert("test_module".to_string(), 10);

        let json = serde_json::to_string(&metrics).unwrap();
        assert!(json.contains("\"total_events\":10"));
        assert!(json.contains("\"test_module\":10"));
    }

    #[tokio::test]
    async fn test_shared_metrics_updated_by_collector() {
        let bus = EventBus::new(16);
        let config = MetricsConfig {
            enabled: true,
            interval_secs: 60,
        };
        let (collector, _sender, shared) = MetricsCollector::new(&config, &bus);
        collector.spawn();

        // イベントを発行
        bus.publish(SecurityEvent::new(
            "test_event",
            Severity::Info,
            "test_module",
            "テストイベント",
        ));
        bus.publish(SecurityEvent::new(
            "test_event",
            Severity::Critical,
            "another_module",
            "テストイベント",
        ));

        // メトリクスコレクターがイベントを処理する時間を与える
        tokio::time::sleep(Duration::from_millis(200)).await;

        // unwrap safety: テストコード
        let m = shared.lock().unwrap();
        assert_eq!(m.total_events, 2);
        assert_eq!(m.info_count, 1);
        assert_eq!(m.critical_count, 1);
        assert_eq!(m.module_counts.get("test_module"), Some(&1));
        assert_eq!(m.module_counts.get("another_module"), Some(&1));
    }
}
