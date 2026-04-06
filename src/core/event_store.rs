//! イベントストア — SecurityEvent の SQLite 永続化

use crate::config::EventStoreConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use rusqlite::{Connection, OpenFlags, params};
use serde::Serialize;
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

/// イベント検索クエリ条件
pub struct EventQuery {
    /// ソースモジュール名フィルタ
    pub module: Option<String>,
    /// 重要度フィルタ（"INFO", "WARNING", "CRITICAL"）
    pub severity: Option<String>,
    /// 開始タイムスタンプ（UNIX 秒、以上）
    pub since: Option<i64>,
    /// 終了タイムスタンプ（UNIX 秒、以下）
    pub until: Option<i64>,
    /// イベント種別フィルタ
    pub event_type: Option<String>,
    /// 表示件数上限
    pub limit: u32,
}

/// 検索結果のイベントレコード
#[derive(Debug, Serialize)]
pub struct EventRecord {
    /// レコード ID
    pub id: i64,
    /// タイムスタンプ（UNIX 秒）
    pub timestamp: i64,
    /// 重要度
    pub severity: String,
    /// ソースモジュール名
    pub source_module: String,
    /// イベント種別
    pub event_type: String,
    /// メッセージ
    pub message: String,
    /// 追加情報
    pub details: Option<String>,
}

/// イベント統計結果
#[derive(Debug, Serialize)]
pub struct EventStats {
    /// 期間別イベント件数
    pub period_counts: PeriodCounts,
    /// 重要度別件数
    pub severity_counts: SeverityCounts,
    /// モジュール別 TOP 10
    pub top_modules: Vec<ModuleCount>,
    /// 日次推移
    pub daily_trend: Vec<DailyCount>,
}

/// 期間別イベント件数
#[derive(Debug, Serialize)]
pub struct PeriodCounts {
    /// 直近 24 時間
    pub last_24h: u64,
    /// 直近 7 日間
    pub last_7d: u64,
    /// 直近 30 日間
    pub last_30d: u64,
}

/// 重要度別件数
#[derive(Debug, Serialize)]
pub struct SeverityCounts {
    /// CRITICAL
    pub critical: u64,
    /// WARNING
    pub warning: u64,
    /// INFO
    pub info: u64,
}

/// モジュール別件数
#[derive(Debug, Serialize)]
pub struct ModuleCount {
    /// モジュール名
    pub module: String,
    /// 件数
    pub count: u64,
}

/// 日次件数
#[derive(Debug, Serialize)]
pub struct DailyCount {
    /// 日付（YYYY-MM-DD）
    pub date: String,
    /// 件数
    pub count: u64,
}

/// イベント統計を集計する
pub fn query_event_stats(conn: &Connection, days: u32) -> Result<EventStats, AppError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let cutoff_24h = now - 86400;
    let cutoff_7d = now - 7 * 86400;
    let cutoff_30d = now - 30 * 86400;

    // 期間別イベント件数
    let period_counts: PeriodCounts = conn
        .query_row(
            "SELECT \
                COALESCE(SUM(CASE WHEN timestamp >= ?1 THEN 1 ELSE 0 END), 0) AS last_24h, \
                COALESCE(SUM(CASE WHEN timestamp >= ?2 THEN 1 ELSE 0 END), 0) AS last_7d, \
                COALESCE(SUM(CASE WHEN timestamp >= ?3 THEN 1 ELSE 0 END), 0) AS last_30d \
             FROM security_events",
            params![cutoff_24h, cutoff_7d, cutoff_30d],
            |row| {
                Ok(PeriodCounts {
                    last_24h: row.get::<_, i64>(0).map(|v| v as u64)?,
                    last_7d: row.get::<_, i64>(1).map(|v| v as u64)?,
                    last_30d: row.get::<_, i64>(2).map(|v| v as u64)?,
                })
            },
        )
        .map_err(|e| AppError::EventStore {
            message: format!("期間別集計に失敗: {}", e),
        })?;

    // Severity 別集計（days 期間内）
    let cutoff_days = now - i64::from(days) * 86400;
    let mut severity_counts = SeverityCounts {
        critical: 0,
        warning: 0,
        info: 0,
    };
    {
        let mut stmt = conn
            .prepare(
                "SELECT severity, COUNT(*) AS count \
                 FROM security_events \
                 WHERE timestamp >= ?1 \
                 GROUP BY severity",
            )
            .map_err(|e| AppError::EventStore {
                message: format!("重要度別集計の準備に失敗: {}", e),
            })?;

        let rows = stmt
            .query_map(params![cutoff_days], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(|e| AppError::EventStore {
                message: format!("重要度別集計の実行に失敗: {}", e),
            })?;

        for row in rows {
            let (severity, count) = row.map_err(|e| AppError::EventStore {
                message: format!("重要度別集計の行読み取りに失敗: {}", e),
            })?;
            let count = count as u64;
            match severity.as_str() {
                "CRITICAL" => severity_counts.critical = count,
                "WARNING" => severity_counts.warning = count,
                "INFO" => severity_counts.info = count,
                _ => {}
            }
        }
    }

    // モジュール別集計（上位10件）
    let top_modules: Vec<ModuleCount> = {
        let mut stmt = conn
            .prepare(
                "SELECT source_module, COUNT(*) AS count \
                 FROM security_events \
                 WHERE timestamp >= ?1 \
                 GROUP BY source_module \
                 ORDER BY count DESC \
                 LIMIT 10",
            )
            .map_err(|e| AppError::EventStore {
                message: format!("モジュール別集計の準備に失敗: {}", e),
            })?;

        let rows = stmt
            .query_map(params![cutoff_days], |row| {
                Ok(ModuleCount {
                    module: row.get(0)?,
                    count: row.get::<_, i64>(1).map(|v| v as u64)?,
                })
            })
            .map_err(|e| AppError::EventStore {
                message: format!("モジュール別集計の実行に失敗: {}", e),
            })?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(|e| AppError::EventStore {
                message: format!("モジュール別集計の行読み取りに失敗: {}", e),
            })?);
        }
        result
    };

    // 日次推移（days 日間）
    let daily_trend: Vec<DailyCount> = {
        let mut stmt = conn
            .prepare(
                "SELECT (timestamp / 86400) AS day, COUNT(*) AS count \
                 FROM security_events \
                 WHERE timestamp >= ?1 \
                 GROUP BY day \
                 ORDER BY day ASC",
            )
            .map_err(|e| AppError::EventStore {
                message: format!("日次推移集計の準備に失敗: {}", e),
            })?;

        let rows = stmt
            .query_map(params![cutoff_days], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(|e| AppError::EventStore {
                message: format!("日次推移集計の実行に失敗: {}", e),
            })?;

        let mut day_map = std::collections::HashMap::new();
        for row in rows {
            let (day, count) = row.map_err(|e| AppError::EventStore {
                message: format!("日次推移集計の行読み取りに失敗: {}", e),
            })?;
            day_map.insert(day, count as u64);
        }

        // 欠損日を 0 で補完
        let start_day = cutoff_days / 86400;
        let end_day = now / 86400;
        let mut result = Vec::new();
        for d in start_day..=end_day {
            let (year, month, day) = days_to_ymd(d);
            let date = format!("{:04}-{:02}-{:02}", year, month, day);
            let count = day_map.get(&d).copied().unwrap_or(0);
            result.push(DailyCount { date, count });
        }
        result
    };

    Ok(EventStats {
        period_counts,
        severity_counts,
        top_modules,
        daily_trend,
    })
}

/// 読み取り専用で SQLite データベースを開く（CLI 検索用）
pub fn open_readonly(db_path: &str) -> Result<Connection, AppError> {
    Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| AppError::EventStore {
        message: format!("データベースを開けません ({}): {}", db_path, e),
    })
}

/// 指定された条件でイベントを検索する
pub fn query_events(conn: &Connection, query: &EventQuery) -> Result<Vec<EventRecord>, AppError> {
    let mut sql = String::from(
        "SELECT id, timestamp, severity, source_module, event_type, message, details \
         FROM security_events WHERE 1=1",
    );
    let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    let mut idx = 1;

    if let Some(module) = &query.module {
        sql.push_str(&format!(" AND source_module = ?{}", idx));
        param_values.push(Box::new(module.clone()));
        idx += 1;
    }
    if let Some(severity) = &query.severity {
        sql.push_str(&format!(" AND severity = ?{}", idx));
        param_values.push(Box::new(severity.to_uppercase()));
        idx += 1;
    }
    if let Some(since) = query.since {
        sql.push_str(&format!(" AND timestamp >= ?{}", idx));
        param_values.push(Box::new(since));
        idx += 1;
    }
    if let Some(until) = query.until {
        sql.push_str(&format!(" AND timestamp <= ?{}", idx));
        param_values.push(Box::new(until));
        idx += 1;
    }
    if let Some(event_type) = &query.event_type {
        sql.push_str(&format!(" AND event_type = ?{}", idx));
        param_values.push(Box::new(event_type.clone()));
        idx += 1;
    }

    sql.push_str(&format!(" ORDER BY timestamp DESC LIMIT ?{}", idx));
    param_values.push(Box::new(query.limit));

    let param_refs: Vec<&dyn rusqlite::types::ToSql> =
        param_values.iter().map(|p| p.as_ref()).collect();

    let mut stmt = conn.prepare(&sql).map_err(|e| AppError::EventStore {
        message: format!("クエリの準備に失敗: {}", e),
    })?;

    let rows = stmt
        .query_map(param_refs.as_slice(), |row| {
            Ok(EventRecord {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                severity: row.get(2)?,
                source_module: row.get(3)?,
                event_type: row.get(4)?,
                message: row.get(5)?,
                details: row.get(6)?,
            })
        })
        .map_err(|e| AppError::EventStore {
            message: format!("クエリの実行に失敗: {}", e),
        })?;

    let mut records = Vec::new();
    for row in rows {
        records.push(row.map_err(|e| AppError::EventStore {
            message: format!("行の読み取りに失敗: {}", e),
        })?);
    }

    Ok(records)
}

/// UNIX タイムスタンプを "YYYY-MM-DD HH:MM:SS" (UTC) 形式に変換する
pub fn format_timestamp(ts: i64) -> String {
    let secs_per_day: i64 = 86400;
    let secs_per_hour: i64 = 3600;
    let secs_per_min: i64 = 60;

    let days = ts / secs_per_day;
    let remaining = ts % secs_per_day;
    let hour = remaining / secs_per_hour;
    let min = (remaining % secs_per_hour) / secs_per_min;
    let sec = remaining % secs_per_min;

    // 1970-01-01 からの日数を年月日に変換
    let (year, month, day) = days_to_ymd(days);

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year, month, day, hour, min, sec
    )
}

/// UNIX タイムスタンプを ISO 8601 形式に変換する（JSON 出力用）
pub fn format_timestamp_iso(ts: i64) -> String {
    let secs_per_day: i64 = 86400;
    let secs_per_hour: i64 = 3600;
    let secs_per_min: i64 = 60;

    let days = ts / secs_per_day;
    let remaining = ts % secs_per_day;
    let hour = remaining / secs_per_hour;
    let min = (remaining % secs_per_hour) / secs_per_min;
    let sec = remaining % secs_per_min;

    let (year, month, day) = days_to_ymd(days);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, min, sec
    )
}

/// 1970-01-01 からの日数を (year, month, day) に変換する
fn days_to_ymd(mut days: i64) -> (i64, u32, u32) {
    // 1970-01-01 = day 0
    let mut year = 1970;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    let leap = is_leap_year(year);
    let months_days = if leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 0;
    for (i, &d) in months_days.iter().enumerate() {
        if days < d as i64 {
            month = i as u32 + 1;
            break;
        }
        days -= d as i64;
    }

    (year, month, days as u32 + 1)
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// 日時文字列を UNIX タイムスタンプ（秒）に変換する
///
/// サポート形式:
/// - `YYYY-MM-DD` → その日の 00:00:00 UTC
/// - `YYYY-MM-DD HH:MM:SS` → UTC
pub fn parse_datetime(s: &str) -> Result<i64, String> {
    let parts: Vec<&str> = s.split(' ').collect();
    let (date_str, time_str) = match parts.len() {
        1 => (parts[0], "00:00:00"),
        2 => (parts[0], parts[1]),
        _ => return Err(format!("不正な日時形式です: {}", s)),
    };

    let date_parts: Vec<&str> = date_str.split('-').collect();
    if date_parts.len() != 3 {
        return Err(format!("不正な日付形式です (YYYY-MM-DD): {}", date_str));
    }

    let year: i64 = date_parts[0]
        .parse()
        .map_err(|_| format!("不正な年: {}", date_parts[0]))?;
    let month: u32 = date_parts[1]
        .parse()
        .map_err(|_| format!("不正な月: {}", date_parts[1]))?;
    let day: u32 = date_parts[2]
        .parse()
        .map_err(|_| format!("不正な日: {}", date_parts[2]))?;

    if !(1..=12).contains(&month) {
        return Err(format!("月は 1-12 の範囲で指定してください: {}", month));
    }
    if !(1..=31).contains(&day) {
        return Err(format!("日は 1-31 の範囲で指定してください: {}", day));
    }

    let time_parts: Vec<&str> = time_str.split(':').collect();
    if time_parts.len() != 3 {
        return Err(format!("不正な時刻形式です (HH:MM:SS): {}", time_str));
    }

    let hour: u32 = time_parts[0]
        .parse()
        .map_err(|_| format!("不正な時: {}", time_parts[0]))?;
    let min: u32 = time_parts[1]
        .parse()
        .map_err(|_| format!("不正な分: {}", time_parts[1]))?;
    let sec: u32 = time_parts[2]
        .parse()
        .map_err(|_| format!("不正な秒: {}", time_parts[2]))?;

    if hour >= 24 || min >= 60 || sec >= 60 {
        return Err(format!("不正な時刻です: {}", time_str));
    }

    // 1970-01-01 からの日数を計算
    let mut total_days: i64 = 0;
    for y in 1970..year {
        total_days += if is_leap_year(y) { 366 } else { 365 };
    }

    let leap = is_leap_year(year);
    let months_days = if leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    for &d in months_days.iter().take(month as usize - 1) {
        total_days += d as i64;
    }
    total_days += (day as i64) - 1;

    let timestamp = total_days * 86400 + (hour as i64) * 3600 + (min as i64) * 60 + (sec as i64);

    Ok(timestamp)
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

    #[test]
    fn test_parse_datetime_date_only() {
        let ts = parse_datetime("2026-04-05").unwrap();
        // 2026-04-05 00:00:00 UTC
        assert_eq!(format_timestamp(ts), "2026-04-05 00:00:00");
    }

    #[test]
    fn test_parse_datetime_full() {
        let ts = parse_datetime("2026-04-05 12:34:56").unwrap();
        assert_eq!(format_timestamp(ts), "2026-04-05 12:34:56");
    }

    #[test]
    fn test_parse_datetime_epoch() {
        let ts = parse_datetime("1970-01-01").unwrap();
        assert_eq!(ts, 0);
    }

    #[test]
    fn test_parse_datetime_invalid() {
        assert!(parse_datetime("not-a-date").is_err());
        assert!(parse_datetime("2026-13-01").is_err());
        assert!(parse_datetime("2026-04-05 25:00:00").is_err());
    }

    #[test]
    fn test_format_timestamp_roundtrip() {
        let original = "2026-01-15 08:30:45";
        let ts = parse_datetime(original).unwrap();
        assert_eq!(format_timestamp(ts), original);
    }

    #[test]
    fn test_format_timestamp_iso() {
        let ts = parse_datetime("2026-04-05 12:34:56").unwrap();
        assert_eq!(format_timestamp_iso(ts), "2026-04-05T12:34:56Z");
    }

    #[test]
    fn test_query_events_empty() {
        let conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();

        let query = EventQuery {
            module: None,
            severity: None,
            since: None,
            until: None,
            event_type: None,
            limit: 100,
        };
        let results = query_events(&conn, &query).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_query_events_with_data() {
        let mut conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();

        let events = vec![
            SecurityEvent::new(
                "file_modified",
                Severity::Warning,
                "file_integrity",
                "ファイル変更",
            ),
            SecurityEvent::new(
                "brute_force",
                Severity::Critical,
                "ssh_brute_force",
                "SSH攻撃",
            ),
            SecurityEvent::new(
                "process_anomaly",
                Severity::Info,
                "process_monitor",
                "異常プロセス",
            ),
        ];
        EventStore::insert_events(&mut conn, &events).unwrap();

        // 全件取得
        let query = EventQuery {
            module: None,
            severity: None,
            since: None,
            until: None,
            event_type: None,
            limit: 100,
        };
        let results = query_events(&conn, &query).unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_query_events_filter_module() {
        let mut conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();

        let events = vec![
            SecurityEvent::new(
                "file_modified",
                Severity::Warning,
                "file_integrity",
                "ファイル変更",
            ),
            SecurityEvent::new(
                "brute_force",
                Severity::Critical,
                "ssh_brute_force",
                "SSH攻撃",
            ),
        ];
        EventStore::insert_events(&mut conn, &events).unwrap();

        let query = EventQuery {
            module: Some("ssh_brute_force".to_string()),
            severity: None,
            since: None,
            until: None,
            event_type: None,
            limit: 100,
        };
        let results = query_events(&conn, &query).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].source_module, "ssh_brute_force");
    }

    #[test]
    fn test_query_events_filter_severity() {
        let mut conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();

        let events = vec![
            SecurityEvent::new("ev1", Severity::Info, "mod1", "情報"),
            SecurityEvent::new("ev2", Severity::Critical, "mod2", "重大"),
        ];
        EventStore::insert_events(&mut conn, &events).unwrap();

        let query = EventQuery {
            module: None,
            severity: Some("CRITICAL".to_string()),
            since: None,
            until: None,
            event_type: None,
            limit: 100,
        };
        let results = query_events(&conn, &query).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, "CRITICAL");
    }

    #[test]
    fn test_query_events_limit() {
        let mut conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();

        let events: Vec<SecurityEvent> = (0..10)
            .map(|i| SecurityEvent::new("ev", Severity::Info, "mod", &format!("イベント{}", i)))
            .collect();
        EventStore::insert_events(&mut conn, &events).unwrap();

        let query = EventQuery {
            module: None,
            severity: None,
            since: None,
            until: None,
            event_type: None,
            limit: 3,
        };
        let results = query_events(&conn, &query).unwrap();
        assert_eq!(results.len(), 3);
    }

    fn insert_event_at(conn: &Connection, timestamp: i64, severity: &str, module: &str) {
        conn.execute(
            "INSERT INTO security_events (timestamp, severity, source_module, event_type, message) \
             VALUES (?1, ?2, ?3, 'test_event', 'テスト')",
            params![timestamp, severity, module],
        )
        .unwrap();
    }

    #[test]
    fn test_query_event_stats_empty() {
        let conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();

        let stats = query_event_stats(&conn, 7).unwrap();
        assert_eq!(stats.period_counts.last_24h, 0);
        assert_eq!(stats.period_counts.last_7d, 0);
        assert_eq!(stats.period_counts.last_30d, 0);
        assert_eq!(stats.severity_counts.critical, 0);
        assert_eq!(stats.severity_counts.warning, 0);
        assert_eq!(stats.severity_counts.info, 0);
        assert!(stats.top_modules.is_empty());
        // daily_trend は days 分の 0 件エントリがある
        assert!(!stats.daily_trend.is_empty());
        for dc in &stats.daily_trend {
            assert_eq!(dc.count, 0);
        }
    }

    #[test]
    fn test_query_event_stats_with_data() {
        let conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // 直近 1 時間以内のイベント
        insert_event_at(&conn, now - 3600, "INFO", "mod_a");
        insert_event_at(&conn, now - 7200, "WARNING", "mod_b");
        insert_event_at(&conn, now - 100, "CRITICAL", "mod_a");

        let stats = query_event_stats(&conn, 7).unwrap();
        assert_eq!(stats.period_counts.last_24h, 3);
        assert_eq!(stats.period_counts.last_7d, 3);
        assert_eq!(stats.period_counts.last_30d, 3);
    }

    #[test]
    fn test_query_event_stats_daily_trend_fills_gaps() {
        let conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // 2日前にだけイベントを入れる
        let two_days_ago = now - 2 * 86400;
        insert_event_at(&conn, two_days_ago, "INFO", "mod_a");

        let stats = query_event_stats(&conn, 7).unwrap();
        // 7 日分 + 今日 = 8 エントリ（start_day から end_day まで）
        assert!(stats.daily_trend.len() >= 7);

        // データがある日は count > 0、それ以外は 0
        let non_zero: Vec<&DailyCount> = stats.daily_trend.iter().filter(|d| d.count > 0).collect();
        assert_eq!(non_zero.len(), 1);
        assert_eq!(non_zero[0].count, 1);
    }

    #[test]
    fn test_query_event_stats_severity_counts() {
        let conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        insert_event_at(&conn, now - 100, "CRITICAL", "mod_a");
        insert_event_at(&conn, now - 200, "CRITICAL", "mod_a");
        insert_event_at(&conn, now - 300, "WARNING", "mod_b");
        insert_event_at(&conn, now - 400, "INFO", "mod_c");
        insert_event_at(&conn, now - 500, "INFO", "mod_c");
        insert_event_at(&conn, now - 600, "INFO", "mod_c");

        let stats = query_event_stats(&conn, 7).unwrap();
        assert_eq!(stats.severity_counts.critical, 2);
        assert_eq!(stats.severity_counts.warning, 1);
        assert_eq!(stats.severity_counts.info, 3);
    }

    #[test]
    fn test_query_event_stats_top_modules() {
        let conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // mod_a: 3件, mod_b: 2件, mod_c: 1件
        for _ in 0..3 {
            insert_event_at(&conn, now - 100, "INFO", "mod_a");
        }
        for _ in 0..2 {
            insert_event_at(&conn, now - 100, "WARNING", "mod_b");
        }
        insert_event_at(&conn, now - 100, "CRITICAL", "mod_c");

        let stats = query_event_stats(&conn, 7).unwrap();
        assert_eq!(stats.top_modules.len(), 3);
        assert_eq!(stats.top_modules[0].module, "mod_a");
        assert_eq!(stats.top_modules[0].count, 3);
        assert_eq!(stats.top_modules[1].module, "mod_b");
        assert_eq!(stats.top_modules[1].count, 2);
        assert_eq!(stats.top_modules[2].module, "mod_c");
        assert_eq!(stats.top_modules[2].count, 1);
    }

    #[test]
    fn test_days_to_ymd() {
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
        assert_eq!(days_to_ymd(365), (1971, 1, 1));
        // 2000-03-01 (leap year)
        assert_eq!(days_to_ymd(11017), (2000, 3, 1));
    }

    #[test]
    fn test_leap_year() {
        assert!(is_leap_year(2000));
        assert!(is_leap_year(2024));
        assert!(!is_leap_year(1900));
        assert!(!is_leap_year(2023));
    }
}
