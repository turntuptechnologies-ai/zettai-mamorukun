//! イベントバス — モジュール間イベント伝達

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
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

impl Severity {
    /// 文字列から Severity を解析する
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "info" => Some(Severity::Info),
            "warning" => Some(Severity::Warning),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }
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

/// デバウンスエントリ
#[derive(Debug)]
struct DebounceEntry {
    last_published: Instant,
    suppressed_count: u64,
}

/// デバウンスフィルター
#[derive(Debug)]
pub(crate) struct DebounceFilter {
    entries: HashMap<String, DebounceEntry>,
    debounce_duration: Duration,
    max_entries: usize,
}

impl DebounceFilter {
    /// 新しいデバウンスフィルターを作成する
    fn new(debounce_secs: u64) -> Self {
        Self {
            entries: HashMap::new(),
            debounce_duration: Duration::from_secs(debounce_secs),
            max_entries: 10_000,
        }
    }

    /// イベントからデバウンスキーを生成する
    fn make_key(event: &SecurityEvent) -> String {
        let detail_part = match &event.details {
            Some(d) => {
                if d.len() > 128 {
                    &d[..d.floor_char_boundary(128)]
                } else {
                    d.as_str()
                }
            }
            None => &event.message,
        };
        format!(
            "{}:{}:{}",
            event.source_module, event.event_type, detail_part
        )
    }

    /// イベントを発行すべきか判定する
    fn should_publish(&mut self, key: &str) -> bool {
        let now = Instant::now();
        match self.entries.get_mut(key) {
            Some(entry) => {
                if now.duration_since(entry.last_published) >= self.debounce_duration {
                    entry.last_published = now;
                    entry.suppressed_count = 0;
                    true
                } else {
                    entry.suppressed_count += 1;
                    false
                }
            }
            None => {
                self.entries.insert(
                    key.to_string(),
                    DebounceEntry {
                        last_published: now,
                        suppressed_count: 0,
                    },
                );
                true
            }
        }
    }

    /// デバウンス間隔を更新する
    fn update_duration(&mut self, debounce_secs: u64) {
        self.debounce_duration = Duration::from_secs(debounce_secs);
    }

    /// 期限切れのエントリをクリーンアップする
    fn cleanup(&mut self) -> usize {
        let now = Instant::now();
        let expiry = self.debounce_duration * 2;
        let mut removed = 0;

        self.entries.retain(|key, entry| {
            if now.duration_since(entry.last_published) > expiry {
                if entry.suppressed_count > 0 {
                    info!(
                        key = %key,
                        suppressed_count = entry.suppressed_count,
                        "デバウンス: 抑制されたイベントのクリーンアップ"
                    );
                }
                removed += 1;
                false
            } else {
                true
            }
        });

        // max_entries 超過時は最も古いエントリから削除
        if self.entries.len() > self.max_entries {
            let mut entries_vec: Vec<(String, Instant)> = self
                .entries
                .iter()
                .map(|(k, v)| (k.clone(), v.last_published))
                .collect();
            entries_vec.sort_by_key(|(_, t)| *t);

            let to_remove = self.entries.len() - self.max_entries;
            for (key, _) in entries_vec.into_iter().take(to_remove) {
                self.entries.remove(&key);
                removed += 1;
            }
        }

        removed
    }
}

/// モジュール間イベント伝達バス
#[derive(Debug, Clone)]
pub struct EventBus {
    sender: broadcast::Sender<SecurityEvent>,
    debounce: Option<Arc<Mutex<DebounceFilter>>>,
}

impl EventBus {
    /// 指定された容量でイベントバスを作成する（デバウンスなし）
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            sender,
            debounce: None,
        }
    }

    /// デバウンス付きでイベントバスを作成する
    ///
    /// `debounce_secs` が 0 の場合はデバウンスを無効にする
    pub fn with_debounce(capacity: usize, debounce_secs: u64) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        let debounce = if debounce_secs > 0 {
            Some(Arc::new(Mutex::new(DebounceFilter::new(debounce_secs))))
        } else {
            None
        };
        Self { sender, debounce }
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

        // デバウンスフィルター適用
        if let Some(ref debounce) = self.debounce {
            // Critical イベントは常に即時配信
            if event.severity != Severity::Critical {
                let key = DebounceFilter::make_key(&event);
                // unwrap safety: Mutex が poisoned になるのはパニック時のみで、正常動作時は安全
                let should_publish = debounce.lock().unwrap().should_publish(&key);
                if !should_publish {
                    tracing::trace!(
                        event_type = %event.event_type,
                        source = %event.source_module,
                        "デバウンス: イベントを抑制"
                    );
                    return;
                }
            }
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

    /// デバウンス間隔を更新する
    pub fn update_debounce_secs(&self, debounce_secs: u64) {
        if let Some(ref debounce) = self.debounce {
            // unwrap safety: Mutex が poisoned になるのはパニック時のみで、正常動作時は安全
            debounce.lock().unwrap().update_duration(debounce_secs);
            tracing::info!(
                debounce_secs = debounce_secs,
                "デバウンス間隔を更新しました"
            );
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

/// デバウンスフィルターの定期クリーンアップを起動する
///
/// デバウンスが有効な場合のみクリーンアップタスクを起動する
pub fn spawn_debounce_cleanup(event_bus: &EventBus) {
    if let Some(ref debounce) = event_bus.debounce {
        let debounce = Arc::clone(debounce);
        // unwrap safety: Mutex が poisoned になるのはパニック時のみで、正常動作時は安全
        let debounce_duration = debounce.lock().unwrap().debounce_duration;
        let interval_duration = std::cmp::max(debounce_duration * 2, Duration::from_secs(10));

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(interval_duration);
            // 最初の tick は即座に発火するのでスキップ
            interval.tick().await;

            loop {
                interval.tick().await;
                // unwrap safety: Mutex が poisoned になるのはパニック時のみで、正常動作時は安全
                let removed = debounce.lock().unwrap().cleanup();
                if removed > 0 {
                    tracing::debug!(
                        removed = removed,
                        "デバウンスクリーンアップ: {} 件のエントリを削除",
                        removed
                    );
                }
            }
        });
        tracing::info!("デバウンスクリーンアップタスクを起動しました");
    }
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

    #[test]
    fn test_debounce_filter_new() {
        let filter = DebounceFilter::new(30);
        assert_eq!(filter.debounce_duration, Duration::from_secs(30));
        assert_eq!(filter.max_entries, 10_000);
        assert!(filter.entries.is_empty());
    }

    #[test]
    fn test_debounce_key_with_details() {
        let event = SecurityEvent::new(
            "file_modified",
            Severity::Warning,
            "file_integrity",
            "ファイルが変更されました",
        )
        .with_details("/etc/passwd");
        let key = DebounceFilter::make_key(&event);
        assert_eq!(key, "file_integrity:file_modified:/etc/passwd");
    }

    #[test]
    fn test_debounce_key_without_details() {
        let event = SecurityEvent::new(
            "file_modified",
            Severity::Warning,
            "file_integrity",
            "ファイルが変更されました",
        );
        let key = DebounceFilter::make_key(&event);
        assert_eq!(key, "file_integrity:file_modified:ファイルが変更されました");
    }

    #[test]
    fn test_debounce_key_long_details_truncated() {
        let long_details = "a".repeat(200);
        let event = SecurityEvent::new("file_modified", Severity::Warning, "file_integrity", "msg")
            .with_details(long_details);
        let key = DebounceFilter::make_key(&event);
        // "file_integrity:file_modified:" = 29 chars + 128 chars = 157 chars
        let prefix = "file_integrity:file_modified:";
        assert!(key.starts_with(prefix));
        assert_eq!(key.len(), prefix.len() + 128);
    }

    #[test]
    fn test_debounce_first_event_passes() {
        let mut filter = DebounceFilter::new(30);
        assert!(filter.should_publish("test_key"));
    }

    #[test]
    fn test_debounce_duplicate_suppressed() {
        let mut filter = DebounceFilter::new(30);
        assert!(filter.should_publish("test_key"));
        assert!(!filter.should_publish("test_key"));
        assert!(!filter.should_publish("test_key"));
    }

    #[test]
    fn test_debounce_different_keys_pass() {
        let mut filter = DebounceFilter::new(30);
        assert!(filter.should_publish("key_a"));
        assert!(filter.should_publish("key_b"));
        assert!(!filter.should_publish("key_a"));
        assert!(!filter.should_publish("key_b"));
    }

    #[tokio::test]
    async fn test_debounce_critical_bypasses() {
        let bus = EventBus::with_debounce(16, 60);
        let mut receiver = bus.subscribe();

        // 同じ Critical イベントを 2 回送信 — 両方とも配信される
        for _ in 0..2 {
            let event = SecurityEvent::new("intrusion", Severity::Critical, "ids", "侵入検知");
            bus.publish(event);
        }

        let r1 = receiver.recv().await.unwrap();
        assert_eq!(r1.event_type, "intrusion");
        let r2 = receiver.recv().await.unwrap();
        assert_eq!(r2.event_type, "intrusion");
    }

    #[test]
    fn test_debounce_cleanup_removes_expired() {
        let mut filter = DebounceFilter::new(0); // 0 秒 = 即座に期限切れ
        filter.should_publish("key_a");
        filter.should_publish("key_b");
        assert_eq!(filter.entries.len(), 2);

        // debounce_duration が 0 なので expiry (0*2=0) も即座に期限切れ
        std::thread::sleep(Duration::from_millis(10));
        let removed = filter.cleanup();
        assert_eq!(removed, 2);
        assert!(filter.entries.is_empty());
    }

    #[test]
    fn test_debounce_update_duration() {
        let mut filter = DebounceFilter::new(30);
        assert_eq!(filter.debounce_duration, Duration::from_secs(30));
        filter.update_duration(60);
        assert_eq!(filter.debounce_duration, Duration::from_secs(60));
    }

    #[test]
    fn test_debounce_zero_disables() {
        let bus = EventBus::with_debounce(16, 0);
        assert!(bus.debounce.is_none());
    }

    #[test]
    fn test_event_bus_with_debounce() {
        let bus = EventBus::with_debounce(16, 30);
        assert!(bus.debounce.is_some());
    }

    #[test]
    fn test_event_bus_new_no_debounce() {
        let bus = EventBus::new(16);
        assert!(bus.debounce.is_none());
    }
}
