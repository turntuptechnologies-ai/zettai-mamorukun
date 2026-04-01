//! イベント統計・メトリクス収集

use crate::config::MetricsConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

/// イベント統計・メトリクス収集
pub struct MetricsCollector {
    receiver: broadcast::Receiver<SecurityEvent>,
    interval: Duration,
}

impl MetricsCollector {
    /// 設定とイベントバスから MetricsCollector を構築する
    pub fn new(config: &MetricsConfig, event_bus: &EventBus) -> Self {
        Self {
            receiver: event_bus.subscribe(),
            interval: Duration::from_secs(config.interval_secs),
        }
    }

    /// 非同期タスクとしてメトリクスコレクターを起動する
    pub fn spawn(self) {
        tokio::spawn(async move {
            Self::run_loop(self.receiver, self.interval).await;
        });
    }

    async fn run_loop(mut receiver: broadcast::Receiver<SecurityEvent>, interval: Duration) {
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
        let collector = MetricsCollector::new(&config, &bus);
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
        let collector = MetricsCollector::new(&config, &bus);
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
}
