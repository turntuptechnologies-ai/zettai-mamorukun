//! イベントストア — SecurityEvent の SQLite 永続化

use crate::config::EventStoreConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use rusqlite::{Connection, params};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, watch};

/// ホットリロード対象のランタイム設定
#[derive(Debug, Clone, PartialEq)]
pub struct EventStoreRuntimeConfig {
    /// イベント保持期間（日数）
    pub retention_days: u64,
    /// バッチ挿入サイズ
    pub batch_size: usize,
    /// バッチフラッシュ間隔（秒）
    pub batch_interval_secs: u64,
    /// クリーンアップ実行間隔（時間）
    pub cleanup_interval_hours: u64,
}

impl From<&EventStoreConfig> for EventStoreRuntimeConfig {
    fn from(config: &EventStoreConfig) -> Self {
        Self {
            retention_days: config.retention_days,
            batch_size: config.batch_size,
            batch_interval_secs: config.batch_interval_secs,
            cleanup_interval_hours: config.cleanup_interval_hours,
        }
    }
}

/// イベントストア — イベントバスのサブスクライバーとして動作し、
/// SecurityEvent を SQLite に永続保存する
pub struct EventStore {
    receiver: broadcast::Receiver<SecurityEvent>,
    config_receiver: watch::Receiver<EventStoreRuntimeConfig>,
    conn: Arc<StdMutex<Connection>>,
    batch_size: usize,
    batch_interval: Duration,
    cleanup_interval: Duration,
}

/// SQLite データベースを初期化する（テーブル作成・PRAGMA 設定）
fn init_database(conn: &Connection) -> Result<(), AppError> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA busy_timeout = 5000;",
    )
    .map_err(|e| AppError::EventStore {
        message: format!("PRAGMA 設定に失敗: {}", e),
    })?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS security_events (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp     INTEGER NOT NULL,
            severity      TEXT    NOT NULL,
            source_module TEXT    NOT NULL,
            event_type    TEXT    NOT NULL,
            message       TEXT    NOT NULL,
            details       TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_security_events_timestamp
            ON security_events (timestamp);
        CREATE INDEX IF NOT EXISTS idx_security_events_module_severity
            ON security_events (source_module, severity);",
    )
    .map_err(|e| AppError::EventStore {
        message: format!("テーブル作成に失敗: {}", e),
    })?;

    Ok(())
}

impl EventStore {
    /// 設定とイベントバスから EventStore を構築する
    pub fn new(
        config: &EventStoreConfig,
        event_bus: &EventBus,
    ) -> Result<(Self, watch::Sender<EventStoreRuntimeConfig>), AppError> {
        let conn = Connection::open(&config.database_path).map_err(|e| AppError::EventStore {
            message: format!("データベースを開けません ({}): {}", config.database_path, e),
        })?;

        init_database(&conn)?;

        let runtime_config = EventStoreRuntimeConfig::from(config);
        let (config_sender, config_receiver) = watch::channel(runtime_config.clone());

        Ok((
            Self {
                receiver: event_bus.subscribe(),
                config_receiver,
                conn: Arc::new(StdMutex::new(conn)),
                batch_size: runtime_config.batch_size,
                batch_interval: Duration::from_secs(runtime_config.batch_interval_secs),
                cleanup_interval: Duration::from_secs(runtime_config.cleanup_interval_hours * 3600),
            },
            config_sender,
        ))
    }

    /// インメモリデータベースで EventStore を構築する（テスト用）
    #[cfg(test)]
    pub fn new_in_memory(
        event_bus: &EventBus,
        config: &EventStoreConfig,
    ) -> Result<(Self, watch::Sender<EventStoreRuntimeConfig>), AppError> {
        let conn = Connection::open_in_memory().map_err(|e| AppError::EventStore {
            message: format!("インメモリデータベースの作成に失敗: {}", e),
        })?;

        init_database(&conn)?;

        let runtime_config = EventStoreRuntimeConfig::from(config);
        let (config_sender, config_receiver) = watch::channel(runtime_config.clone());

        Ok((
            Self {
                receiver: event_bus.subscribe(),
                config_receiver,
                conn: Arc::new(StdMutex::new(conn)),
                batch_size: runtime_config.batch_size,
                batch_interval: Duration::from_secs(runtime_config.batch_interval_secs),
                cleanup_interval: Duration::from_secs(runtime_config.cleanup_interval_hours * 3600),
            },
            config_sender,
        ))
    }

    /// 非同期タスクとしてイベントストアを起動する
    pub fn spawn(self) {
        tokio::spawn(async move {
            Self::run_loop(
                self.receiver,
                self.config_receiver,
                self.conn,
                self.batch_size,
                self.batch_interval,
                self.cleanup_interval,
            )
            .await;
        });
    }

    async fn run_loop(
        mut receiver: broadcast::Receiver<SecurityEvent>,
        mut config_receiver: watch::Receiver<EventStoreRuntimeConfig>,
        conn: Arc<StdMutex<Connection>>,
        mut batch_size: usize,
        batch_interval: Duration,
        cleanup_interval: Duration,
    ) {
        let mut buffer: Vec<SecurityEvent> = Vec::new();
        let mut batch_ticker = tokio::time::interval(batch_interval);
        batch_ticker.tick().await; // 最初の tick をスキップ

        let mut cleanup_ticker = tokio::time::interval(cleanup_interval);
        cleanup_ticker.tick().await; // 最初の tick をスキップ

        let mut retention_days: u64 = {
            let cfg = config_receiver.borrow();
            cfg.retention_days
        };

        loop {
            tokio::select! {
                result = receiver.recv() => {
                    match result {
                        Ok(event) => {
                            buffer.push(event);
                            if buffer.len() >= batch_size {
                                let events = std::mem::take(&mut buffer);
                                Self::flush_batch(&conn, events).await;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(
                                skipped = n,
                                "イベントストア: {} 件のイベントをスキップ（遅延）",
                                n
                            );
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            if !buffer.is_empty() {
                                let events = std::mem::take(&mut buffer);
                                Self::flush_batch(&conn, events).await;
                            }
                            tracing::info!("イベントバスが閉じられました。イベントストアを終了します");
                            break;
                        }
                    }
                }
                _ = batch_ticker.tick() => {
                    if !buffer.is_empty() {
                        let events = std::mem::take(&mut buffer);
                        Self::flush_batch(&conn, events).await;
                    }
                }
                _ = cleanup_ticker.tick() => {
                    Self::cleanup_old_events(&conn, retention_days).await;
                }
                result = config_receiver.changed() => {
                    match result {
                        Ok(()) => {
                            let new_config = config_receiver.borrow_and_update().clone();
                            tracing::info!(
                                retention_days = new_config.retention_days,
                                batch_size = new_config.batch_size,
                                batch_interval_secs = new_config.batch_interval_secs,
                                cleanup_interval_hours = new_config.cleanup_interval_hours,
                                "イベントストア: 設定をリロードしました"
                            );
                            batch_size = new_config.batch_size;
                            retention_days = new_config.retention_days;

                            let new_batch_interval = Duration::from_secs(new_config.batch_interval_secs);
                            batch_ticker = tokio::time::interval(new_batch_interval);
                            batch_ticker.tick().await;

                            let new_cleanup_interval = Duration::from_secs(new_config.cleanup_interval_hours * 3600);
                            cleanup_ticker = tokio::time::interval(new_cleanup_interval);
                            cleanup_ticker.tick().await;
                        }
                        Err(_) => {
                            tracing::info!("設定チャネルが閉じられました。イベントストアを終了します");
                            break;
                        }
                    }
                }
            }
        }
    }

    async fn flush_batch(conn: &Arc<StdMutex<Connection>>, events: Vec<SecurityEvent>) {
        let count = events.len();
        let conn = Arc::clone(conn);
        let result = tokio::task::spawn_blocking(move || {
            // unwrap safety: Mutex が poisoned になるのはパニック時のみ
            let mut conn = conn.lock().unwrap();
            Self::insert_events(&mut conn, &events)
        })
        .await;

        match result {
            Ok(Ok(())) => {
                tracing::debug!(
                    count = count,
                    "イベントストア: {} 件のイベントを保存しました",
                    count
                );
            }
            Ok(Err(e)) => {
                tracing::error!(error = %e, count = count, "イベントストア: バッチ挿入に失敗");
            }
            Err(e) => {
                tracing::error!(error = %e, "イベントストア: spawn_blocking タスクがパニックしました");
            }
        }
    }

    fn insert_events(conn: &mut Connection, events: &[SecurityEvent]) -> Result<(), AppError> {
        let tx = conn.transaction().map_err(|e| AppError::EventStore {
            message: format!("トランザクション開始に失敗: {}", e),
        })?;

        {
            let mut stmt = tx
                .prepare_cached(
                    "INSERT INTO security_events (timestamp, severity, source_module, event_type, message, details)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                )
                .map_err(|e| AppError::EventStore {
                    message: format!("プリペアドステートメントの作成に失敗: {}", e),
                })?;

            for event in events {
                let timestamp = event
                    .timestamp
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                let severity = match event.severity {
                    Severity::Info => "INFO",
                    Severity::Warning => "WARNING",
                    Severity::Critical => "CRITICAL",
                };

                stmt.execute(params![
                    timestamp,
                    severity,
                    event.source_module,
                    event.event_type,
                    event.message,
                    event.details,
                ])
                .map_err(|e| AppError::EventStore {
                    message: format!("イベント挿入に失敗: {}", e),
                })?;
            }
        }

        tx.commit().map_err(|e| AppError::EventStore {
            message: format!("コミットに失敗: {}", e),
        })?;

        Ok(())
    }

    async fn cleanup_old_events(conn: &Arc<StdMutex<Connection>>, retention_days: u64) {
        let conn = Arc::clone(conn);
        let result = tokio::task::spawn_blocking(move || {
            let cutoff = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .saturating_sub(retention_days * 86400) as i64;

            // unwrap safety: Mutex が poisoned になるのはパニック時のみ
            let conn = conn.lock().unwrap();
            conn.execute(
                "DELETE FROM security_events WHERE timestamp < ?1",
                params![cutoff],
            )
        })
        .await;

        match result {
            Ok(Ok(deleted)) => {
                if deleted > 0 {
                    tracing::info!(
                        deleted = deleted,
                        retention_days = retention_days,
                        "イベントストア: {} 件の古いイベントを削除しました",
                        deleted
                    );
                }
            }
            Ok(Err(e)) => {
                tracing::error!(error = %e, "イベントストア: クリーンアップに失敗");
            }
            Err(e) => {
                tracing::error!(error = %e, "イベントストア: spawn_blocking タスクがパニックしました");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::EventBus;

    fn test_config() -> EventStoreConfig {
        EventStoreConfig {
            enabled: true,
            database_path: String::new(),
            retention_days: 90,
            batch_size: 10,
            batch_interval_secs: 1,
            cleanup_interval_hours: 24,
        }
    }

    #[test]
    fn test_init_database() {
        let conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();

        // テーブルが作成されていることを確認
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='security_events'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_init_database_indexes() {
        let conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name LIKE 'idx_security_events_%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_insert_events() {
        let mut conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();

        let events = vec![
            SecurityEvent::new(
                "test_event",
                Severity::Info,
                "test_module",
                "テストイベント1",
            ),
            SecurityEvent::new(
                "test_event",
                Severity::Warning,
                "test_module",
                "テストイベント2",
            ),
            SecurityEvent::new(
                "critical_event",
                Severity::Critical,
                "another_module",
                "重大イベント",
            )
            .with_details("詳細情報"),
        ];

        EventStore::insert_events(&mut conn, &events).unwrap();

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM security_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 3);

        // details が正しく保存されていることを確認
        let details: Option<String> = conn
            .query_row(
                "SELECT details FROM security_events WHERE event_type = 'critical_event'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(details.as_deref(), Some("詳細情報"));
    }

    #[test]
    fn test_insert_events_empty() {
        let mut conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();

        EventStore::insert_events(&mut conn, &[]).unwrap();

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM security_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_event_store_new_in_memory() {
        let bus = EventBus::new(16);
        let config = test_config();
        let result = EventStore::new_in_memory(&bus, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_runtime_config_from_event_store_config() {
        let config = EventStoreConfig {
            enabled: true,
            database_path: "/tmp/test.db".to_string(),
            retention_days: 30,
            batch_size: 50,
            batch_interval_secs: 10,
            cleanup_interval_hours: 12,
        };
        let runtime = EventStoreRuntimeConfig::from(&config);
        assert_eq!(runtime.retention_days, 30);
        assert_eq!(runtime.batch_size, 50);
        assert_eq!(runtime.batch_interval_secs, 10);
        assert_eq!(runtime.cleanup_interval_hours, 12);
    }

    #[tokio::test]
    async fn test_event_store_receives_and_stores_events() {
        let bus = EventBus::new(16);
        let config = EventStoreConfig {
            enabled: true,
            database_path: String::new(),
            retention_days: 90,
            batch_size: 2,
            batch_interval_secs: 60,
            cleanup_interval_hours: 24,
        };
        let (store, _sender) = EventStore::new_in_memory(&bus, &config).unwrap();
        let conn = Arc::clone(&store.conn);
        store.spawn();

        // イベントを発行（batch_size=2 なので2件でフラッシュされる）
        bus.publish(SecurityEvent::new(
            "test_event",
            Severity::Info,
            "test_module",
            "テストイベント1",
        ));
        bus.publish(SecurityEvent::new(
            "test_event",
            Severity::Warning,
            "test_module",
            "テストイベント2",
        ));

        // イベントストアが処理する時間を与える
        tokio::time::sleep(Duration::from_millis(200)).await;

        let count: i64 = {
            let conn = conn.lock().unwrap();
            conn.query_row("SELECT COUNT(*) FROM security_events", [], |row| row.get(0))
                .unwrap()
        };
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn test_event_store_batch_timer_flush() {
        let bus = EventBus::new(16);
        let config = EventStoreConfig {
            enabled: true,
            database_path: String::new(),
            retention_days: 90,
            batch_size: 100, // 大きいバッチサイズ
            batch_interval_secs: 1,
            cleanup_interval_hours: 24,
        };
        let (store, _sender) = EventStore::new_in_memory(&bus, &config).unwrap();
        let conn = Arc::clone(&store.conn);
        store.spawn();

        // 1件だけ発行（batch_size に達しない）
        bus.publish(SecurityEvent::new(
            "test_event",
            Severity::Info,
            "test_module",
            "テストイベント",
        ));

        // バッチタイマー（1秒）でフラッシュされるのを待つ
        tokio::time::sleep(Duration::from_secs(2)).await;

        let count: i64 = {
            let conn = conn.lock().unwrap();
            conn.query_row("SELECT COUNT(*) FROM security_events", [], |row| row.get(0))
                .unwrap()
        };
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_event_store_config_reload() {
        let bus = EventBus::new(16);
        let config = test_config();
        let (store, sender) = EventStore::new_in_memory(&bus, &config).unwrap();
        store.spawn();

        // 設定変更を送信
        let new_config = EventStoreRuntimeConfig {
            retention_days: 30,
            batch_size: 50,
            batch_interval_secs: 10,
            cleanup_interval_hours: 12,
        };
        sender.send(new_config).unwrap();

        // 変更が処理される時間を与える
        tokio::time::sleep(Duration::from_millis(100)).await;
        // パニックせずに動作することを確認
    }

    #[tokio::test]
    async fn test_event_store_config_channel_closed() {
        let bus = EventBus::new(16);
        let config = test_config();
        let (store, sender) = EventStore::new_in_memory(&bus, &config).unwrap();
        store.spawn();

        // sender をドロップしてチャネルを閉じる
        drop(sender);

        // イベントストアが正常に終了することを確認
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    #[test]
    fn test_event_store_config_default() {
        let config = EventStoreConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.database_path, "/var/lib/zettai-mamorukun/events.db");
        assert_eq!(config.retention_days, 90);
        assert_eq!(config.batch_size, 100);
        assert_eq!(config.batch_interval_secs, 5);
        assert_eq!(config.cleanup_interval_hours, 24);
    }
}
