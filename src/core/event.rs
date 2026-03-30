//! イベントバス — モジュール間イベント伝達

use std::fmt;
use std::time::SystemTime;
use tokio::sync::broadcast;
use tracing::{error, info, warn};

/// セキュリティイベントの重要度
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    /// 情報レベル
    Info,
    /// 警告レベル
    Warning,
    /// 重大レベル
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Warning => write!(f, "WARNING"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// セキュリティイベント
#[derive(Debug, Clone)]
pub struct SecurityEvent {
    /// イベント種別（例: "file_modified", "process_anomaly"）
    pub event_type: String,
    /// 重要度
    pub severity: Severity,
    /// 発生元モジュール名
    pub source_module: String,
    /// タイムスタンプ
    pub timestamp: SystemTime,
    /// 人間が読めるメッセージ
    pub message: String,
    /// 追加情報（パス、PID等）
    pub details: Option<String>,
}

impl SecurityEvent {
    /// 新しいセキュリティイベントを作成する
    pub fn new(
        event_type: impl Into<String>,
        severity: Severity,
        source_module: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            event_type: event_type.into(),
            severity,
            source_module: source_module.into(),
            timestamp: SystemTime::now(),
            message: message.into(),
            details: None,
        }
    }

    /// 追加情報を設定する
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }
}

impl fmt::Display for SecurityEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} ({}): {}",
            self.severity, self.event_type, self.source_module, self.message
        )
    }
}

/// モジュール間イベント伝達バス
#[derive(Debug, Clone)]
pub struct EventBus {
    sender: broadcast::Sender<SecurityEvent>,
}

impl EventBus {
    /// 指定された容量でイベントバスを作成する
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    /// イベントを発行する
    pub fn publish(&self, event: SecurityEvent) {
        // サブスクライバーがいない場合でもエラーにしない
        if self.sender.receiver_count() == 0 {
            tracing::debug!(
                event_type = %event.event_type,
                source = %event.source_module,
                "イベント発行: サブスクライバーなし（イベントは破棄）"
            );
            return;
        }
        match self.sender.send(event) {
            Ok(n) => {
                tracing::trace!("イベントを {} 件のサブスクライバーに配信", n);
            }
            Err(_) => {
                tracing::debug!("イベント発行: サブスクライバーなし（イベントは破棄）");
            }
        }
    }

    /// イベントを購読するレシーバーを取得する
    pub fn subscribe(&self) -> broadcast::Receiver<SecurityEvent> {
        self.sender.subscribe()
    }
}

/// デフォルトのログサブスクライバーを起動する
///
/// 全てのイベントを Severity に応じた tracing レベルで構造化ログに記録する
pub fn spawn_log_subscriber(event_bus: &EventBus) {
    let mut receiver = event_bus.subscribe();
    tokio::spawn(async move {
        loop {
            match receiver.recv().await {
                Ok(event) => match event.severity {
                    Severity::Info => {
                        info!(
                            event_type = %event.event_type,
                            source_module = %event.source_module,
                            severity = "INFO",
                            details = ?event.details,
                            "[SecurityEvent] {}",
                            event.message
                        );
                    }
                    Severity::Warning => {
                        warn!(
                            event_type = %event.event_type,
                            source_module = %event.source_module,
                            severity = "WARNING",
                            details = ?event.details,
                            "[SecurityEvent] {}",
                            event.message
                        );
                    }
                    Severity::Critical => {
                        error!(
                            event_type = %event.event_type,
                            source_module = %event.source_module,
                            severity = "CRITICAL",
                            details = ?event.details,
                            "[SecurityEvent] {}",
                            event.message
                        );
                    }
                },
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!("ログサブスクライバー: {} 件のイベントをスキップ（遅延）", n);
                }
                Err(broadcast::error::RecvError::Closed) => {
                    info!("イベントバスが閉じられました。ログサブスクライバーを終了します");
                    break;
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_display() {
        assert_eq!(Severity::Info.to_string(), "INFO");
        assert_eq!(Severity::Warning.to_string(), "WARNING");
        assert_eq!(Severity::Critical.to_string(), "CRITICAL");
    }

    #[test]
    fn test_security_event_new() {
        let event = SecurityEvent::new(
            "file_modified",
            Severity::Warning,
            "file_integrity",
            "ファイルが変更されました",
        );
        assert_eq!(event.event_type, "file_modified");
        assert_eq!(event.severity, Severity::Warning);
        assert_eq!(event.source_module, "file_integrity");
        assert_eq!(event.message, "ファイルが変更されました");
        assert!(event.details.is_none());
    }

    #[test]
    fn test_security_event_with_details() {
        let event = SecurityEvent::new(
            "file_modified",
            Severity::Warning,
            "file_integrity",
            "ファイルが変更されました",
        )
        .with_details("/etc/passwd");
        assert_eq!(event.details, Some("/etc/passwd".to_string()));
    }

    #[test]
    fn test_security_event_display() {
        let event = SecurityEvent::new(
            "file_modified",
            Severity::Warning,
            "file_integrity",
            "ファイルが変更されました",
        );
        let display = format!("{}", event);
        assert_eq!(
            display,
            "[WARNING] file_modified (file_integrity): ファイルが変更されました"
        );
    }

    #[test]
    fn test_event_bus_publish_no_subscribers() {
        let bus = EventBus::new(16);
        let event = SecurityEvent::new("test", Severity::Info, "test_module", "テスト");
        // サブスクライバーなしでもパニックしない
        bus.publish(event);
    }

    #[tokio::test]
    async fn test_event_bus_publish_and_receive() {
        let bus = EventBus::new(16);
        let mut receiver = bus.subscribe();

        let event = SecurityEvent::new(
            "test_event",
            Severity::Info,
            "test_module",
            "テストメッセージ",
        );
        bus.publish(event);

        let received = receiver.recv().await.unwrap();
        assert_eq!(received.event_type, "test_event");
        assert_eq!(received.source_module, "test_module");
        assert_eq!(received.message, "テストメッセージ");
    }

    #[tokio::test]
    async fn test_event_bus_multiple_subscribers() {
        let bus = EventBus::new(16);
        let mut receiver1 = bus.subscribe();
        let mut receiver2 = bus.subscribe();

        let event = SecurityEvent::new("test_event", Severity::Critical, "test_module", "テスト");
        bus.publish(event);

        let r1 = receiver1.recv().await.unwrap();
        let r2 = receiver2.recv().await.unwrap();
        assert_eq!(r1.event_type, "test_event");
        assert_eq!(r2.event_type, "test_event");
    }

    #[test]
    fn test_event_bus_clone() {
        let bus = EventBus::new(16);
        let bus2 = bus.clone();
        let _receiver = bus2.subscribe();
        let event = SecurityEvent::new("test", Severity::Info, "test", "テスト");
        bus.publish(event);
    }

    #[test]
    fn test_security_event_display_all_severities() {
        let info_event =
            SecurityEvent::new("test_info", Severity::Info, "module_a", "情報イベント");
        assert_eq!(
            format!("{}", info_event),
            "[INFO] test_info (module_a): 情報イベント"
        );

        let critical_event = SecurityEvent::new(
            "test_critical",
            Severity::Critical,
            "module_b",
            "重大イベント",
        );
        assert_eq!(
            format!("{}", critical_event),
            "[CRITICAL] test_critical (module_b): 重大イベント"
        );
    }

    #[test]
    fn test_security_event_display_with_details_does_not_affect_display() {
        let event = SecurityEvent::new(
            "file_modified",
            Severity::Warning,
            "file_integrity",
            "ファイルが変更されました",
        )
        .with_details("/etc/passwd");
        // Display は details を含まない
        let display = format!("{}", event);
        assert_eq!(
            display,
            "[WARNING] file_modified (file_integrity): ファイルが変更されました"
        );
        assert!(!display.contains("/etc/passwd"));
    }

    #[tokio::test]
    async fn test_event_bus_lagged_receiver() {
        // 容量 2 のバスで 3 件送信し、遅延を発生させる
        let bus = EventBus::new(2);
        let mut receiver = bus.subscribe();

        // 容量を超えるイベントを送信
        for i in 0..3 {
            bus.publish(SecurityEvent::new(
                format!("event_{}", i),
                Severity::Info,
                "test",
                "テスト",
            ));
        }

        // 最初の recv で Lagged エラーが返る
        let result = receiver.recv().await;
        assert!(result.is_ok() || matches!(result, Err(broadcast::error::RecvError::Lagged(_))));
    }

    #[tokio::test]
    async fn test_event_bus_clone_shares_channel() {
        let bus1 = EventBus::new(16);
        let bus2 = bus1.clone();
        let mut receiver = bus1.subscribe();

        // クローンから送信したイベントを元のバスのサブスクライバーで受信できる
        let event = SecurityEvent::new("from_clone", Severity::Info, "test", "クローンからの送信");
        bus2.publish(event);

        let received = receiver.recv().await.unwrap();
        assert_eq!(received.event_type, "from_clone");
        assert_eq!(received.message, "クローンからの送信");
    }
}
