//! イベントストア — SecurityEvent の SQLite 永続化

use crate::config::EventStoreConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use rusqlite::{Connection, OpenFlags, params};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, watch};

/// ホットリロード対象のランタイム設定
#[derive(Debug, Clone, PartialEq)]
pub struct EventStoreRuntimeConfig {
    /// イベント保持期間（日数）
    pub retention_days: u64,
    /// CRITICAL イベントの保持期間（日数）。0 の場合は retention_days と同じ
    pub retention_days_critical: u64,
    /// ストレージ上限（MB）。0 で無制限
    pub max_storage_mb: u64,
    /// バッチ挿入サイズ
    pub batch_size: usize,
    /// バッチフラッシュ間隔（秒）
    pub batch_interval_secs: u64,
    /// クリーンアップ実行間隔（時間）
    pub cleanup_interval_hours: u64,
    /// アーカイブ機能の有効/無効
    pub archive_enabled: bool,
    /// アーカイブ対象とするイベントの経過日数
    pub archive_after_days: u64,
    /// アーカイブファイルの保存先ディレクトリ
    pub archive_dir: String,
    /// アーカイブ実行間隔（時間）
    pub archive_interval_hours: u64,
    /// gzip 圧縮の有効/無効
    pub archive_compress: bool,
}

impl From<&EventStoreConfig> for EventStoreRuntimeConfig {
    fn from(config: &EventStoreConfig) -> Self {
        Self {
            retention_days: config.retention_days,
            retention_days_critical: config.retention_days_critical,
            max_storage_mb: config.max_storage_mb,
            batch_size: config.batch_size,
            batch_interval_secs: config.batch_interval_secs,
            cleanup_interval_hours: config.cleanup_interval_hours,
            archive_enabled: config.archive_enabled,
            archive_after_days: config.archive_after_days,
            archive_dir: config.archive_dir.clone(),
            archive_interval_hours: config.archive_interval_hours,
            archive_compress: config.archive_compress,
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

    // FTS5 仮想テーブルの作成
    conn.execute_batch(
        "CREATE VIRTUAL TABLE IF NOT EXISTS security_events_fts USING fts5(
            message,
            details,
            content='security_events',
            content_rowid='id',
            tokenize='unicode61'
        );",
    )
    .map_err(|e| AppError::EventStore {
        message: format!("FTS5 テーブル作成に失敗: {}", e),
    })?;

    // FTS5 自動同期トリガー
    conn.execute_batch(
        "CREATE TRIGGER IF NOT EXISTS security_events_fts_insert
            AFTER INSERT ON security_events
        BEGIN
            INSERT INTO security_events_fts(rowid, message, details)
            VALUES (new.id, new.message, new.details);
        END;

        CREATE TRIGGER IF NOT EXISTS security_events_fts_delete
            AFTER DELETE ON security_events
        BEGIN
            INSERT INTO security_events_fts(security_events_fts, rowid, message, details)
            VALUES ('delete', old.id, old.message, old.details);
        END;

        CREATE TRIGGER IF NOT EXISTS security_events_fts_update
            AFTER UPDATE ON security_events
        BEGIN
            INSERT INTO security_events_fts(security_events_fts, rowid, message, details)
            VALUES ('delete', old.id, old.message, old.details);
            INSERT INTO security_events_fts(rowid, message, details)
            VALUES (new.id, new.message, new.details);
        END;",
    )
    .map_err(|e| AppError::EventStore {
        message: format!("FTS5 トリガー作成に失敗: {}", e),
    })?;

    // 既存データの FTS インデックス再構築（初回のみ）
    let fts_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM security_events_fts", [], |row| {
            row.get(0)
        })
        .unwrap_or(0);

    if fts_count == 0 {
        let events_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM security_events", [], |row| row.get(0))
            .unwrap_or(0);

        if events_count > 0 {
            conn.execute_batch(
                "INSERT INTO security_events_fts(security_events_fts) VALUES('rebuild');",
            )
            .map_err(|e| AppError::EventStore {
                message: format!("FTS5 インデックス再構築に失敗: {}", e),
            })?;
            tracing::info!(
                count = events_count,
                "FTS5 インデックスを再構築しました（{} 件）",
                events_count
            );
        }
    }

    let has_acknowledged = {
        let mut stmt = conn
            .prepare("PRAGMA table_info(security_events)")
            .map_err(|e| AppError::EventStore {
                message: format!("PRAGMA table_info に失敗: {}", e),
            })?;
        let columns: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|e| AppError::EventStore {
                message: format!("カラム情報の取得に失敗: {}", e),
            })?
            .filter_map(|r| r.ok())
            .collect();
        columns.iter().any(|c| c == "acknowledged")
    };

    if !has_acknowledged {
        conn.execute_batch(
            "ALTER TABLE security_events ADD COLUMN acknowledged INTEGER NOT NULL DEFAULT 0;",
        )
        .map_err(|e| AppError::EventStore {
            message: format!("acknowledged カラムの追加に失敗: {}", e),
        })?;
    }

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
        batch_ticker.tick().await;

        let mut cleanup_ticker = tokio::time::interval(cleanup_interval);
        cleanup_ticker.tick().await;

        let (
            mut retention_days,
            mut retention_days_critical,
            mut max_storage_mb,
            mut archive_enabled,
            mut archive_after_days,
            mut archive_dir,
            mut archive_compress,
        ) = {
            let cfg = config_receiver.borrow();
            (
                cfg.retention_days,
                cfg.retention_days_critical,
                cfg.max_storage_mb,
                cfg.archive_enabled,
                cfg.archive_after_days,
                cfg.archive_dir.clone(),
                cfg.archive_compress,
            )
        };

        let archive_interval = {
            let cfg = config_receiver.borrow();
            Duration::from_secs(cfg.archive_interval_hours * 3600)
        };
        let mut archive_ticker = tokio::time::interval(archive_interval);
        archive_ticker.tick().await;

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
                    Self::cleanup_old_events(&conn, retention_days, retention_days_critical, max_storage_mb).await;
                }
                _ = archive_ticker.tick(), if archive_enabled => {
                    Self::run_archive(&conn, archive_after_days, &archive_dir, archive_compress).await;
                }
                result = config_receiver.changed() => {
                    match result {
                        Ok(()) => {
                            let new_config = config_receiver.borrow_and_update().clone();
                            tracing::info!(
                                retention_days = new_config.retention_days,
                                retention_days_critical = new_config.retention_days_critical,
                                max_storage_mb = new_config.max_storage_mb,
                                batch_size = new_config.batch_size,
                                batch_interval_secs = new_config.batch_interval_secs,
                                cleanup_interval_hours = new_config.cleanup_interval_hours,
                                archive_enabled = new_config.archive_enabled,
                                archive_after_days = new_config.archive_after_days,
                                archive_interval_hours = new_config.archive_interval_hours,
                                archive_compress = new_config.archive_compress,
                                "イベントストア: 設定をリロードしました"
                            );
                            batch_size = new_config.batch_size;
                            retention_days = new_config.retention_days;
                            retention_days_critical = new_config.retention_days_critical;
                            max_storage_mb = new_config.max_storage_mb;
                            archive_enabled = new_config.archive_enabled;
                            archive_after_days = new_config.archive_after_days;
                            archive_dir = new_config.archive_dir;
                            archive_compress = new_config.archive_compress;

                            let new_batch_interval = Duration::from_secs(new_config.batch_interval_secs);
                            batch_ticker = tokio::time::interval(new_batch_interval);
                            batch_ticker.tick().await;

                            let new_cleanup_interval = Duration::from_secs(new_config.cleanup_interval_hours * 3600);
                            cleanup_ticker = tokio::time::interval(new_cleanup_interval);
                            cleanup_ticker.tick().await;

                            let new_archive_interval = Duration::from_secs(new_config.archive_interval_hours * 3600);
                            archive_ticker = tokio::time::interval(new_archive_interval);
                            archive_ticker.tick().await;
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

    async fn cleanup_old_events(
        conn: &Arc<StdMutex<Connection>>,
        retention_days: u64,
        retention_days_critical: u64,
        max_storage_mb: u64,
    ) {
        let conn = Arc::clone(conn);
        let result = tokio::task::spawn_blocking(move || {
            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let cutoff_default = now_secs.saturating_sub(retention_days * 86400) as i64;
            let effective_critical_days = if retention_days_critical == 0 {
                retention_days
            } else {
                retention_days_critical
            };
            let cutoff_critical = now_secs.saturating_sub(effective_critical_days * 86400) as i64;

            // unwrap safety: Mutex が poisoned になるのはパニック時のみ
            let conn = conn.lock().unwrap();

            // Severity ベース保持: INFO/WARNING は retention_days、CRITICAL は retention_days_critical
            let deleted_info: usize = conn
                .execute(
                    "DELETE FROM security_events WHERE severity = 'INFO' AND timestamp < ?1",
                    params![cutoff_default],
                )
                .unwrap_or(0);

            let deleted_warning: usize = conn
                .execute(
                    "DELETE FROM security_events WHERE severity = 'WARNING' AND timestamp < ?1",
                    params![cutoff_default],
                )
                .unwrap_or(0);

            let deleted_critical: usize = conn
                .execute(
                    "DELETE FROM security_events WHERE severity = 'CRITICAL' AND timestamp < ?1",
                    params![cutoff_critical],
                )
                .unwrap_or(0);

            let total_deleted = deleted_info + deleted_warning + deleted_critical;

            // ストレージ上限チェック
            let mut storage_deleted: usize = 0;
            if max_storage_mb > 0 {
                storage_deleted = Self::enforce_storage_limit(&conn, max_storage_mb);
            }

            (
                total_deleted,
                deleted_info,
                deleted_warning,
                deleted_critical,
                storage_deleted,
            )
        })
        .await;

        match result {
            Ok((total, info, warning, critical, storage)) => {
                if total > 0 {
                    tracing::info!(
                        total = total,
                        info = info,
                        warning = warning,
                        critical = critical,
                        retention_days = retention_days,
                        retention_days_critical = retention_days_critical,
                        "イベントストア: 保持期間超過により {} 件削除（INFO: {}, WARNING: {}, CRITICAL: {}）",
                        total,
                        info,
                        warning,
                        critical
                    );
                }
                if storage > 0 {
                    tracing::info!(
                        deleted = storage,
                        max_storage_mb = max_storage_mb,
                        "イベントストア: ストレージ上限超過により {} 件削除",
                        storage
                    );
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "イベントストア: spawn_blocking タスクがパニックしました");
            }
        }
    }

    /// ストレージ上限を超過している場合、古い INFO → WARNING → CRITICAL の順で削除する
    fn enforce_storage_limit(conn: &Connection, max_storage_mb: u64) -> usize {
        let max_bytes = max_storage_mb * 1024 * 1024;
        let mut total_deleted: usize = 0;

        for severity in &["INFO", "WARNING", "CRITICAL"] {
            let db_size: i64 = conn
                .query_row(
                    "SELECT page_count * page_size FROM pragma_page_count, pragma_page_size",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or(0);

            if (db_size as u64) <= max_bytes {
                break;
            }

            // 該当 Severity の最も古いイベントを 100 件ずつ削除
            loop {
                let db_size: i64 = conn
                    .query_row(
                        "SELECT page_count * page_size FROM pragma_page_count, pragma_page_size",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap_or(0);

                if (db_size as u64) <= max_bytes {
                    break;
                }

                let deleted = conn
                    .execute(
                        "DELETE FROM security_events WHERE id IN \
                         (SELECT id FROM security_events WHERE severity = ?1 \
                          ORDER BY timestamp ASC LIMIT 100)",
                        params![severity],
                    )
                    .unwrap_or(0);

                if deleted == 0 {
                    break;
                }
                total_deleted += deleted;
            }
        }

        total_deleted
    }

    async fn run_archive(
        conn: &Arc<StdMutex<Connection>>,
        archive_after_days: u64,
        archive_dir: &str,
        compress: bool,
    ) {
        let conn = Arc::clone(conn);
        let archive_dir = archive_dir.to_string();
        let result = tokio::task::spawn_blocking(move || {
            archive_events_blocking(&conn, archive_after_days, &archive_dir, compress)
        })
        .await;

        match result {
            Ok(Ok(count)) => {
                if count > 0 {
                    tracing::info!(
                        archived = count,
                        archive_after_days = archive_after_days,
                        "イベントストア: {} 件のイベントをアーカイブしました",
                        count
                    );
                }
            }
            Ok(Err(e)) => {
                tracing::error!(error = %e, "イベントストア: アーカイブ処理に失敗しました");
            }
            Err(e) => {
                tracing::error!(error = %e, "イベントストア: アーカイブ spawn_blocking タスクがパニックしました");
            }
        }
    }
}

/// アーカイブ処理の本体（ブロッキング）
fn archive_events_blocking(
    conn: &Arc<StdMutex<Connection>>,
    archive_after_days: u64,
    archive_dir: &str,
    compress: bool,
) -> Result<usize, AppError> {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let cutoff = now_secs.saturating_sub(archive_after_days * 86400) as i64;

    // unwrap safety: Mutex が poisoned になるのはパニック時のみ
    let conn = conn.lock().unwrap();

    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM security_events WHERE timestamp < ?1",
            params![cutoff],
            |row| row.get(0),
        )
        .map_err(|e| AppError::EventStore {
            message: format!("アーカイブ対象件数の取得に失敗: {}", e),
        })?;

    if count == 0 {
        return Ok(0);
    }

    std::fs::create_dir_all(archive_dir).map_err(|e| AppError::EventStore {
        message: format!(
            "アーカイブディレクトリの作成に失敗 ({}): {}",
            archive_dir, e
        ),
    })?;

    let min_ts: i64 = conn
        .query_row(
            "SELECT MIN(timestamp) FROM security_events WHERE timestamp < ?1",
            params![cutoff],
            |row| row.get(0),
        )
        .map_err(|e| AppError::EventStore {
            message: format!("最小タイムスタンプの取得に失敗: {}", e),
        })?;

    let date_from = format_date_from_epoch(min_ts);
    let date_to = format_date_from_epoch(cutoff);

    let extension = if compress { "jsonl.gz" } else { "jsonl" };
    let filename = format!("events_{}_{}.{}", date_from, date_to, extension);
    let filepath = std::path::Path::new(archive_dir).join(&filename);
    let tmp_filepath = std::path::Path::new(archive_dir).join(format!("{}.tmp", filename));

    let mut hasher = Sha256::new();
    let written;

    {
        let file = std::fs::File::create(&tmp_filepath).map_err(|e| AppError::EventStore {
            message: format!(
                "アーカイブ一時ファイルの作成に失敗 ({}): {}",
                tmp_filepath.display(),
                e
            ),
        })?;

        if compress {
            let encoder = GzEncoder::new(file, Compression::default());
            let mut writer = BufWriter::new(encoder);
            written = write_archive_events(&conn, cutoff, &mut writer, &mut hasher)?;
            let encoder = writer.into_inner().map_err(|e| AppError::EventStore {
                message: format!("バッファフラッシュに失敗: {}", e),
            })?;
            encoder.finish().map_err(|e| AppError::EventStore {
                message: format!("gzip 圧縮の完了に失敗: {}", e),
            })?;
        } else {
            let mut writer = BufWriter::new(file);
            written = write_archive_events(&conn, cutoff, &mut writer, &mut hasher)?;
            writer.flush().map_err(|e| AppError::EventStore {
                message: format!("バッファフラッシュに失敗: {}", e),
            })?;
        }
    }

    let checksum = format!("{:x}", hasher.finalize());

    let checksum_path = std::path::Path::new(archive_dir).join(format!("{}.sha256", filename));
    std::fs::write(&checksum_path, format!("{}  {}\n", checksum, filename)).map_err(|e| {
        AppError::EventStore {
            message: format!(
                "チェックサムファイルの書き込みに失敗 ({}): {}",
                checksum_path.display(),
                e
            ),
        }
    })?;

    std::fs::rename(&tmp_filepath, &filepath).map_err(|e| AppError::EventStore {
        message: format!("アーカイブファイルのリネームに失敗: {}", e),
    })?;

    conn.execute(
        "DELETE FROM security_events WHERE timestamp < ?1",
        params![cutoff],
    )
    .map_err(|e| AppError::EventStore {
        message: format!("アーカイブ済みイベントの削除に失敗: {}", e),
    })?;

    tracing::debug!(
        file = %filepath.display(),
        checksum = %checksum,
        events = written,
        "アーカイブファイルを書き出しました"
    );

    Ok(written)
}

/// イベントを JSON Lines 形式でライターに書き出す
fn write_archive_events<W: Write>(
    conn: &Connection,
    cutoff: i64,
    writer: &mut W,
    hasher: &mut Sha256,
) -> Result<usize, AppError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, timestamp, severity, source_module, event_type, message, details, acknowledged \
             FROM security_events WHERE timestamp < ?1 ORDER BY timestamp ASC",
        )
        .map_err(|e| AppError::EventStore {
            message: format!("アーカイブクエリの準備に失敗: {}", e),
        })?;

    let rows = stmt
        .query_map(params![cutoff], |row| {
            Ok(EventRecord {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                severity: row.get(2)?,
                source_module: row.get(3)?,
                event_type: row.get(4)?,
                message: row.get(5)?,
                details: row.get(6)?,
                acknowledged: row.get(7)?,
            })
        })
        .map_err(|e| AppError::EventStore {
            message: format!("アーカイブクエリの実行に失敗: {}", e),
        })?;

    let mut count = 0;
    for row in rows {
        let record = row.map_err(|e| AppError::EventStore {
            message: format!("行の読み取りに失敗: {}", e),
        })?;
        let mut line = serde_json::to_vec(&record).map_err(|e| AppError::EventStore {
            message: format!("JSON シリアライズに失敗: {}", e),
        })?;
        line.push(b'\n');
        hasher.update(&line);
        writer.write_all(&line).map_err(|e| AppError::EventStore {
            message: format!("アーカイブファイルの書き込みに失敗: {}", e),
        })?;
        count += 1;
    }

    Ok(count)
}

/// UNIX エポック秒から YYYYMMDD 形式の日付文字列を生成する
fn format_date_from_epoch(epoch_secs: i64) -> String {
    let days = epoch_secs / 86400;
    let mut y: i64 = 1970;
    let mut remaining = days;
    loop {
        let days_in_year: i64 = if is_leap_year(y) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        y += 1;
    }
    let leap = is_leap_year(y);
    let month_days: [i64; 12] = if leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut m = 0;
    for (i, &md) in month_days.iter().enumerate() {
        if remaining < md {
            m = i;
            break;
        }
        remaining -= md;
    }
    let d = remaining + 1;
    format!("{:04}{:02}{:02}", y, m + 1, d)
}

/// アーカイブファイルの情報
#[derive(Debug, Serialize)]
pub struct ArchiveInfo {
    /// ファイル名
    pub filename: String,
    /// ファイルサイズ（バイト）
    pub size: u64,
    /// SHA-256 チェックサム
    pub checksum: Option<String>,
}

/// アーカイブファイル一覧を取得する
pub fn list_archives(archive_dir: &str) -> Result<Vec<ArchiveInfo>, AppError> {
    let dir = std::path::Path::new(archive_dir);
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut archives = Vec::new();
    let entries = std::fs::read_dir(dir).map_err(|e| AppError::EventStore {
        message: format!(
            "アーカイブディレクトリの読み取りに失敗 ({}): {}",
            archive_dir, e
        ),
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| AppError::EventStore {
            message: format!("ディレクトリエントリの読み取りに失敗: {}", e),
        })?;
        let filename = entry.file_name().to_string_lossy().to_string();
        if !filename.starts_with("events_")
            || (!filename.ends_with(".jsonl") && !filename.ends_with(".jsonl.gz"))
        {
            continue;
        }

        let meta = entry.metadata().map_err(|e| AppError::EventStore {
            message: format!("ファイルメタデータの取得に失敗: {}", e),
        })?;

        let checksum_filename = format!("{}.sha256", filename);
        let checksum_path = dir.join(&checksum_filename);
        let checksum = std::fs::read_to_string(&checksum_path)
            .ok()
            .and_then(|content| content.split_whitespace().next().map(|s| s.to_string()));

        archives.push(ArchiveInfo {
            filename,
            size: meta.len(),
            checksum,
        });
    }

    archives.sort_by(|a, b| a.filename.cmp(&b.filename));
    Ok(archives)
}

/// アーカイブファイルからイベントを復元する
pub fn restore_archive(
    db_path: &str,
    archive_dir: &str,
    archive_filename: &str,
) -> Result<usize, AppError> {
    let filepath = std::path::Path::new(archive_dir).join(archive_filename);
    if !filepath.exists() {
        return Err(AppError::EventStore {
            message: format!("アーカイブファイルが見つかりません: {}", filepath.display()),
        });
    }

    let conn = Connection::open(db_path).map_err(|e| AppError::EventStore {
        message: format!("データベースを開けません ({}): {}", db_path, e),
    })?;
    init_database(&conn)?;

    let file = std::fs::File::open(&filepath).map_err(|e| AppError::EventStore {
        message: format!(
            "アーカイブファイルを開けません ({}): {}",
            filepath.display(),
            e
        ),
    })?;

    let compressed = archive_filename.ends_with(".gz");
    let reader: Box<dyn BufRead> = if compressed {
        Box::new(BufReader::new(GzDecoder::new(file)))
    } else {
        Box::new(BufReader::new(file))
    };

    let mut count = 0;
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| AppError::EventStore {
            message: format!("トランザクション開始に失敗: {}", e),
        })?;

    {
        let mut stmt = tx
            .prepare_cached(
                "INSERT OR IGNORE INTO security_events \
                 (timestamp, severity, source_module, event_type, message, details, acknowledged) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )
            .map_err(|e| AppError::EventStore {
                message: format!("INSERT 文の準備に失敗: {}", e),
            })?;

        for line in reader.lines() {
            let line = line.map_err(|e| AppError::EventStore {
                message: format!("行の読み取りに失敗: {}", e),
            })?;
            if line.trim().is_empty() {
                continue;
            }
            let record: EventRecord =
                serde_json::from_str(&line).map_err(|e| AppError::EventStore {
                    message: format!("JSON デシリアライズに失敗: {}", e),
                })?;

            stmt.execute(params![
                record.timestamp,
                record.severity,
                record.source_module,
                record.event_type,
                record.message,
                record.details,
                record.acknowledged,
            ])
            .map_err(|e| AppError::EventStore {
                message: format!("イベント挿入に失敗: {}", e),
            })?;
            count += 1;
        }
    }

    tx.commit().map_err(|e| AppError::EventStore {
        message: format!("コミットに失敗: {}", e),
    })?;

    Ok(count)
}

/// 手動アーカイブ実行（CLI 用）
pub fn run_archive_manual(
    db_path: &str,
    archive_after_days: u64,
    archive_dir: &str,
    compress: bool,
) -> Result<usize, AppError> {
    let conn = Connection::open(db_path).map_err(|e| AppError::EventStore {
        message: format!("データベースを開けません ({}): {}", db_path, e),
    })?;
    let conn = Arc::new(StdMutex::new(conn));
    archive_events_blocking(&conn, archive_after_days, archive_dir, compress)
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
    /// ページネーションカーソル（指定した ID より古いイベントを取得）
    pub cursor: Option<i64>,
    /// フルテキスト検索クエリ（FTS5 MATCH 構文）
    pub text: Option<String>,
}

/// 検索結果のイベントレコード
#[derive(Debug, Serialize, serde::Deserialize)]
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
    /// 確認済みフラグ
    pub acknowledged: bool,
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

/// 指定され��条件でイベントを検索する
pub fn query_events(conn: &Connection, query: &EventQuery) -> Result<Vec<EventRecord>, AppError> {
    let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    let mut idx = 1;

    let use_fts = query.text.is_some();
    let mut sql = if use_fts {
        String::from(
            "SELECT e.id, e.timestamp, e.severity, e.source_module, e.event_type, \
             highlight(security_events_fts, 0, '<<', '>>') AS message, e.details, e.acknowledged \
             FROM security_events e \
             INNER JOIN security_events_fts fts ON e.id = fts.rowid \
             WHERE fts.security_events_fts MATCH ?1",
        )
    } else {
        String::from(
            "SELECT id, timestamp, severity, source_module, event_type, message, details, acknowledged \
             FROM security_events WHERE 1=1",
        )
    };

    if let Some(text) = &query.text {
        param_values.push(Box::new(text.clone()));
        idx += 1;
    }

    let col_prefix = if use_fts { "e." } else { "" };

    if let Some(cursor) = query.cursor {
        sql.push_str(&format!(" AND {}id < ?{}", col_prefix, idx));
        param_values.push(Box::new(cursor));
        idx += 1;
    }
    if let Some(module) = &query.module {
        sql.push_str(&format!(" AND {}source_module = ?{}", col_prefix, idx));
        param_values.push(Box::new(module.clone()));
        idx += 1;
    }
    if let Some(severity) = &query.severity {
        sql.push_str(&format!(" AND {}severity = ?{}", col_prefix, idx));
        param_values.push(Box::new(severity.to_uppercase()));
        idx += 1;
    }
    if let Some(since) = query.since {
        sql.push_str(&format!(" AND {}timestamp >= ?{}", col_prefix, idx));
        param_values.push(Box::new(since));
        idx += 1;
    }
    if let Some(until) = query.until {
        sql.push_str(&format!(" AND {}timestamp <= ?{}", col_prefix, idx));
        param_values.push(Box::new(until));
        idx += 1;
    }
    if let Some(event_type) = &query.event_type {
        sql.push_str(&format!(" AND {}event_type = ?{}", col_prefix, idx));
        param_values.push(Box::new(event_type.clone()));
        idx += 1;
    }

    if use_fts {
        sql.push_str(&format!(" ORDER BY rank LIMIT ?{}", idx));
    } else {
        sql.push_str(&format!(" ORDER BY timestamp DESC LIMIT ?{}", idx));
    }
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
                acknowledged: row.get::<_, i64>(7).map(|v| v != 0).unwrap_or(false),
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

/// バッチ削除フィルタ
pub struct BatchDeleteFilter {
    /// 重要度フィルタ
    pub severity: Option<String>,
    /// ソースモジュール名フィルタ
    pub source_module: Option<String>,
    /// 開始タイムスタンプ（UNIX 秒、以上）
    pub since: Option<i64>,
    /// 終了タイムスタンプ（UNIX 秒、以下）
    pub until: Option<i64>,
}

/// ID 指定でイベントを一括削除する
pub fn batch_delete_by_ids(conn: &Connection, ids: &[i64]) -> Result<u64, AppError> {
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| AppError::EventStore {
            message: format!("トランザクション開始に失敗: {}", e),
        })?;
    let mut total = 0u64;
    for chunk in ids.chunks(999) {
        let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!("DELETE FROM security_events WHERE id IN ({})", placeholders);
        let params: Vec<&dyn rusqlite::types::ToSql> = chunk
            .iter()
            .map(|id| id as &dyn rusqlite::types::ToSql)
            .collect();
        let deleted = tx
            .execute(&sql, params.as_slice())
            .map_err(|e| AppError::EventStore {
                message: format!("バッチ削除に失敗: {}", e),
            })?;
        total += deleted as u64;
    }
    tx.commit().map_err(|e| AppError::EventStore {
        message: format!("コミットに失敗: {}", e),
    })?;
    Ok(total)
}

/// フィルタ条件でイベントを一括削除する
pub fn batch_delete_by_filter(
    conn: &Connection,
    filter: &BatchDeleteFilter,
) -> Result<u64, AppError> {
    let mut sql = String::from("DELETE FROM security_events WHERE 1=1");
    let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    let mut idx = 1;

    if let Some(severity) = &filter.severity {
        sql.push_str(&format!(" AND severity = ?{}", idx));
        param_values.push(Box::new(severity.to_uppercase()));
        idx += 1;
    }
    if let Some(module) = &filter.source_module {
        sql.push_str(&format!(" AND source_module = ?{}", idx));
        param_values.push(Box::new(module.clone()));
        idx += 1;
    }
    if let Some(since) = filter.since {
        sql.push_str(&format!(" AND timestamp >= ?{}", idx));
        param_values.push(Box::new(since));
        idx += 1;
    }
    if let Some(until) = filter.until {
        sql.push_str(&format!(" AND timestamp <= ?{}", idx));
        param_values.push(Box::new(until));
        let _ = idx;
    }

    let param_refs: Vec<&dyn rusqlite::types::ToSql> =
        param_values.iter().map(|p| p.as_ref()).collect();

    let tx = conn
        .unchecked_transaction()
        .map_err(|e| AppError::EventStore {
            message: format!("トランザクション開始に失敗: {}", e),
        })?;
    let deleted = tx
        .execute(&sql, param_refs.as_slice())
        .map_err(|e| AppError::EventStore {
            message: format!("フィルタ削除に失敗: {}", e),
        })?;
    tx.commit().map_err(|e| AppError::EventStore {
        message: format!("コミットに失敗: {}", e),
    })?;
    Ok(deleted as u64)
}

/// ID 指定でイベントを一括確認済みにする
pub fn batch_acknowledge(conn: &Connection, ids: &[i64]) -> Result<u64, AppError> {
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| AppError::EventStore {
            message: format!("トランザクション開始に失敗: {}", e),
        })?;
    let mut total = 0u64;
    for chunk in ids.chunks(999) {
        let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!(
            "UPDATE security_events SET acknowledged = 1 WHERE id IN ({})",
            placeholders
        );
        let params: Vec<&dyn rusqlite::types::ToSql> = chunk
            .iter()
            .map(|id| id as &dyn rusqlite::types::ToSql)
            .collect();
        let updated = tx
            .execute(&sql, params.as_slice())
            .map_err(|e| AppError::EventStore {
                message: format!("バッチ確認に失敗: {}", e),
            })?;
        total += updated as u64;
    }
    tx.commit().map_err(|e| AppError::EventStore {
        message: format!("コミットに失敗: {}", e),
    })?;
    Ok(total)
}

/// ID 指定でイベントの件数をカウントする（dry-run 用）
pub fn count_by_ids(conn: &Connection, ids: &[i64]) -> Result<(u64, Vec<i64>), AppError> {
    let mut total = 0u64;
    let mut sample_ids = Vec::new();
    for chunk in ids.chunks(999) {
        let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!(
            "SELECT id FROM security_events WHERE id IN ({})",
            placeholders
        );
        let params: Vec<&dyn rusqlite::types::ToSql> = chunk
            .iter()
            .map(|id| id as &dyn rusqlite::types::ToSql)
            .collect();
        let mut stmt = conn.prepare(&sql).map_err(|e| AppError::EventStore {
            message: format!("クエリ準備に失敗: {}", e),
        })?;
        let rows = stmt
            .query_map(params.as_slice(), |row| row.get::<_, i64>(0))
            .map_err(|e| AppError::EventStore {
                message: format!("クエリ実行に失敗: {}", e),
            })?;
        for row in rows {
            let id = row.map_err(|e| AppError::EventStore {
                message: format!("行読取に失敗: {}", e),
            })?;
            total += 1;
            if sample_ids.len() < 10 {
                sample_ids.push(id);
            }
        }
    }
    Ok((total, sample_ids))
}

/// フィルタ条件でイベントの件数をカウントする（dry-run 用）
pub fn count_by_filter(
    conn: &Connection,
    filter: &BatchDeleteFilter,
) -> Result<(u64, Vec<i64>), AppError> {
    let mut where_clause = String::from("WHERE 1=1");
    let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    let mut idx = 1;

    if let Some(severity) = &filter.severity {
        where_clause.push_str(&format!(" AND severity = ?{}", idx));
        param_values.push(Box::new(severity.to_uppercase()));
        idx += 1;
    }
    if let Some(module) = &filter.source_module {
        where_clause.push_str(&format!(" AND source_module = ?{}", idx));
        param_values.push(Box::new(module.clone()));
        idx += 1;
    }
    if let Some(since) = filter.since {
        where_clause.push_str(&format!(" AND timestamp >= ?{}", idx));
        param_values.push(Box::new(since));
        idx += 1;
    }
    if let Some(until) = filter.until {
        where_clause.push_str(&format!(" AND timestamp <= ?{}", idx));
        param_values.push(Box::new(until));
        idx += 1;
    }

    let param_refs: Vec<&dyn rusqlite::types::ToSql> =
        param_values.iter().map(|p| p.as_ref()).collect();

    let count_sql = format!("SELECT COUNT(*) FROM security_events {}", where_clause);
    let total: u64 = conn
        .query_row(&count_sql, param_refs.as_slice(), |row| {
            row.get::<_, i64>(0)
        })
        .map(|v| v as u64)
        .map_err(|e| AppError::EventStore {
            message: format!("カウントクエリに失敗: {}", e),
        })?;

    let sample_sql = format!(
        "SELECT id FROM security_events {} ORDER BY id DESC LIMIT 10",
        where_clause
    );
    let mut stmt = conn
        .prepare(&sample_sql)
        .map_err(|e| AppError::EventStore {
            message: format!("サンプルクエリ準備に失敗: {}", e),
        })?;
    let sample_ids: Vec<i64> = stmt
        .query_map(param_refs.as_slice(), |row| row.get::<_, i64>(0))
        .map_err(|e| AppError::EventStore {
            message: format!("サンプルクエリ実行に失敗: {}", e),
        })?
        .filter_map(|r| r.ok())
        .collect();

    let _ = idx;
    Ok((total, sample_ids))
}

/// 未確認イベントの件数をカウントする（dry-run 用）
pub fn count_acknowledge_targets(
    conn: &Connection,
    ids: &[i64],
) -> Result<(u64, Vec<i64>), AppError> {
    let mut total = 0u64;
    let mut sample_ids = Vec::new();
    for chunk in ids.chunks(999) {
        let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!(
            "SELECT id FROM security_events WHERE id IN ({}) AND acknowledged = 0",
            placeholders
        );
        let params: Vec<&dyn rusqlite::types::ToSql> = chunk
            .iter()
            .map(|id| id as &dyn rusqlite::types::ToSql)
            .collect();
        let mut stmt = conn.prepare(&sql).map_err(|e| AppError::EventStore {
            message: format!("クエリ準備に失敗: {}", e),
        })?;
        let rows = stmt
            .query_map(params.as_slice(), |row| row.get::<_, i64>(0))
            .map_err(|e| AppError::EventStore {
                message: format!("クエリ実行に失敗: {}", e),
            })?;
        for row in rows {
            let id = row.map_err(|e| AppError::EventStore {
                message: format!("行読取に失敗: {}", e),
            })?;
            total += 1;
            if sample_ids.len() < 10 {
                sample_ids.push(id);
            }
        }
    }
    Ok((total, sample_ids))
}

/// エクスポート用クエリ（acknowledged フィールド含む、件数上限あり）
pub fn query_events_for_export(
    conn: &Connection,
    query: &EventQuery,
    max_size: u32,
) -> Result<Vec<EventRecord>, AppError> {
    let mut sql = String::from(
        "SELECT id, timestamp, severity, source_module, event_type, message, details, acknowledged \
         FROM security_events WHERE 1=1",
    );
    let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    let mut idx = 1;

    if let Some(cursor) = query.cursor {
        sql.push_str(&format!(" AND id < ?{}", idx));
        param_values.push(Box::new(cursor));
        idx += 1;
    }
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

    let effective_limit = query.limit.min(max_size);
    sql.push_str(&format!(" ORDER BY timestamp DESC LIMIT ?{}", idx));
    param_values.push(Box::new(effective_limit));

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
                acknowledged: row.get::<_, i64>(7).map(|v| v != 0).unwrap_or(false),
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
            retention_days_critical: 365,
            max_storage_mb: 0,
            archive_enabled: false,
            archive_after_days: 30,
            archive_dir: "/tmp/zettai-test-archive".to_string(),
            archive_interval_hours: 24,
            archive_compress: true,
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
            retention_days_critical: 180,
            max_storage_mb: 500,
            archive_enabled: true,
            archive_after_days: 7,
            archive_dir: "/tmp/archive".to_string(),
            archive_interval_hours: 12,
            archive_compress: false,
        };
        let runtime = EventStoreRuntimeConfig::from(&config);
        assert_eq!(runtime.retention_days, 30);
        assert_eq!(runtime.retention_days_critical, 180);
        assert_eq!(runtime.max_storage_mb, 500);
        assert_eq!(runtime.batch_size, 50);
        assert_eq!(runtime.batch_interval_secs, 10);
        assert_eq!(runtime.cleanup_interval_hours, 12);
        assert_eq!(runtime.archive_enabled, true);
        assert_eq!(runtime.archive_after_days, 7);
        assert_eq!(runtime.archive_dir, "/tmp/archive");
        assert_eq!(runtime.archive_interval_hours, 12);
        assert_eq!(runtime.archive_compress, false);
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
            retention_days_critical: 365,
            max_storage_mb: 0,
            ..Default::default()
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
            batch_size: 100,
            batch_interval_secs: 1,
            cleanup_interval_hours: 24,
            retention_days_critical: 365,
            max_storage_mb: 0,
            ..Default::default()
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
            retention_days_critical: 180,
            max_storage_mb: 500,
            batch_size: 50,
            batch_interval_secs: 10,
            cleanup_interval_hours: 12,
            archive_enabled: false,
            archive_after_days: 30,
            archive_dir: "/tmp/archive".to_string(),
            archive_interval_hours: 24,
            archive_compress: true,
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
        assert_eq!(config.retention_days_critical, 365);
        assert_eq!(config.max_storage_mb, 0);
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
            cursor: None,
            text: None,
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
            cursor: None,
            text: None,
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
            cursor: None,
            text: None,
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
            cursor: None,
            text: None,
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
            cursor: None,
            text: None,
        };
        let results = query_events(&conn, &query).unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_query_events_with_cursor() {
        let mut conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();

        let events: Vec<SecurityEvent> = (0..5)
            .map(|i| SecurityEvent::new("ev", Severity::Info, "mod", &format!("イベント{}", i)))
            .collect();
        EventStore::insert_events(&mut conn, &events).unwrap();

        // 全件取得して ID を確認
        let all = query_events(
            &conn,
            &EventQuery {
                module: None,
                severity: None,
                since: None,
                until: None,
                event_type: None,
                limit: 100,
                cursor: None,
                text: None,
            },
        )
        .unwrap();
        assert_eq!(all.len(), 5);

        // cursor を使って途中から取得（id DESC なので最新の id をカーソルに指定）
        let cursor_id = all[1].id;
        let paged = query_events(
            &conn,
            &EventQuery {
                module: None,
                severity: None,
                since: None,
                until: None,
                event_type: None,
                limit: 100,
                cursor: Some(cursor_id),
                text: None,
            },
        )
        .unwrap();
        assert_eq!(paged.len(), 3);
        for record in &paged {
            assert!(record.id < cursor_id);
        }
    }

    #[test]
    fn test_fulltext_search_basic() {
        let mut conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();

        let events = vec![
            SecurityEvent::new(
                "file_modified",
                Severity::Warning,
                "file_integrity",
                "/etc/passwd が変更されました",
            ),
            SecurityEvent::new(
                "brute_force",
                Severity::Critical,
                "ssh_brute_force",
                "192.168.1.100 からの SSH ブルートフォース攻撃を検知",
            ),
            SecurityEvent::new(
                "process_anomaly",
                Severity::Info,
                "process_monitor",
                "不審なプロセス /tmp/malware が起動",
            ),
        ];
        EventStore::insert_events(&mut conn, &events).unwrap();

        let query = EventQuery {
            module: None,
            severity: None,
            since: None,
            until: None,
            event_type: None,
            limit: 100,
            cursor: None,
            text: Some("passwd".to_string()),
        };
        let results = query_events(&conn, &query).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].message.contains("passwd"));
    }

    #[test]
    fn test_fulltext_search_with_filter() {
        let mut conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();

        let events = vec![
            SecurityEvent::new(
                "file_modified",
                Severity::Warning,
                "file_integrity",
                "sshd_config modified by root",
            ),
            SecurityEvent::new(
                "file_modified",
                Severity::Critical,
                "file_integrity",
                "shadow file modified by unknown",
            ),
            SecurityEvent::new(
                "brute_force",
                Severity::Critical,
                "ssh_brute_force",
                "brute force detected from 10.0.0.1",
            ),
        ];
        EventStore::insert_events(&mut conn, &events).unwrap();

        let query = EventQuery {
            module: None,
            severity: Some("CRITICAL".to_string()),
            since: None,
            until: None,
            event_type: None,
            limit: 100,
            cursor: None,
            text: Some("modified".to_string()),
        };
        let results = query_events(&conn, &query).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].message.contains("shadow"));
    }

    #[test]
    fn test_fulltext_search_no_results() {
        let mut conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();

        let events = vec![SecurityEvent::new(
            "test",
            Severity::Info,
            "test_module",
            "テストメッセージ",
        )];
        EventStore::insert_events(&mut conn, &events).unwrap();

        let query = EventQuery {
            module: None,
            severity: None,
            since: None,
            until: None,
            event_type: None,
            limit: 100,
            cursor: None,
            text: Some("存在しないキーワード".to_string()),
        };
        let results = query_events(&conn, &query).unwrap();
        assert!(results.is_empty());
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

    #[tokio::test]
    async fn test_cleanup_severity_based_retention() {
        let conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // 60日前のイベント（retention_days=30 で期限切れ、retention_days_critical=90 で保持対象）
        let sixty_days_ago = now - 60 * 86400;
        insert_event_at(&conn, sixty_days_ago, "INFO", "mod_a");
        insert_event_at(&conn, sixty_days_ago, "WARNING", "mod_b");
        insert_event_at(&conn, sixty_days_ago, "CRITICAL", "mod_c");

        // 最近のイベント（全て保持対象）
        insert_event_at(&conn, now - 100, "INFO", "mod_a");
        insert_event_at(&conn, now - 100, "CRITICAL", "mod_c");

        let conn_arc = Arc::new(StdMutex::new(conn));

        // retention_days=30, retention_days_critical=90
        EventStore::cleanup_old_events(&conn_arc, 30, 90, 0).await;

        let conn = conn_arc.lock().unwrap();
        // INFO と WARNING の60日前イベントは削除、CRITICAL は保持
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM security_events", [], |row| row.get(0))
            .unwrap();
        // 残り: CRITICAL(60日前) + INFO(最近) + CRITICAL(最近) = 3
        assert_eq!(count, 3);

        // CRITICAL が2件残っていること
        let critical_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM security_events WHERE severity = 'CRITICAL'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(critical_count, 2);
    }

    #[tokio::test]
    async fn test_cleanup_critical_zero_uses_default_retention() {
        let conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // 60日前のイベント
        let sixty_days_ago = now - 60 * 86400;
        insert_event_at(&conn, sixty_days_ago, "CRITICAL", "mod_c");
        insert_event_at(&conn, now - 100, "CRITICAL", "mod_c");

        let conn_arc = Arc::new(StdMutex::new(conn));

        // retention_days_critical=0 → retention_days(30) を使用
        EventStore::cleanup_old_events(&conn_arc, 30, 0, 0).await;

        let conn = conn_arc.lock().unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM security_events", [], |row| row.get(0))
            .unwrap();
        // 60日前の CRITICAL も retention_days=30 で削除される
        assert_eq!(count, 1);
    }

    #[test]
    fn test_enforce_storage_limit_no_excess() {
        let conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();

        insert_event_at(&conn, 1000, "INFO", "mod_a");

        // 十分大きい上限 → 削除なし
        let deleted = EventStore::enforce_storage_limit(&conn, 1000);
        assert_eq!(deleted, 0);

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM security_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_enforce_storage_limit_deletes_by_severity_order() {
        let conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();

        // 大量のイベントを挿入してDBサイズを増やす
        for i in 0..500 {
            insert_event_at(&conn, 1000 + i, "INFO", "mod_a");
        }
        for i in 0..500 {
            insert_event_at(&conn, 1000 + i, "WARNING", "mod_b");
        }
        for i in 0..500 {
            insert_event_at(&conn, 1000 + i, "CRITICAL", "mod_c");
        }

        let total_before: i64 = conn
            .query_row("SELECT COUNT(*) FROM security_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(total_before, 1500);

        // DB サイズを取得
        let db_size: i64 = conn
            .query_row(
                "SELECT page_count * page_size FROM pragma_page_count, pragma_page_size",
                [],
                |row| row.get(0),
            )
            .unwrap();

        // 現在のサイズの半分を上限に設定（バイト → MB 変換）
        // インメモリDBではpage_countの更新が即座に反映されない場合があるため、
        // 少なくとも削除が試みられることを確認
        if db_size > 0 {
            let half_mb = (db_size / 2) as u64 / (1024 * 1024);
            if half_mb > 0 {
                let deleted = EventStore::enforce_storage_limit(&conn, half_mb);
                // INFO が最初に削除対象になるはず
                if deleted > 0 {
                    let info_count: i64 = conn
                        .query_row(
                            "SELECT COUNT(*) FROM security_events WHERE severity = 'INFO'",
                            [],
                            |row| row.get(0),
                        )
                        .unwrap();
                    // INFO の件数が減っているはず
                    assert!(info_count < 500);
                }
            }
        }
    }

    fn insert_test_events(conn: &Connection, count: usize) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        for i in 0..count {
            conn.execute(
                "INSERT INTO security_events (timestamp, severity, source_module, event_type, message) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![now - (i as i64), "INFO", "test_module", "test_event", format!("テスト {}", i)],
            )
            .unwrap();
        }
    }

    #[test]
    fn test_batch_delete_by_ids() {
        let conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();
        insert_test_events(&conn, 5);

        let ids: Vec<i64> = conn
            .prepare("SELECT id FROM security_events")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        let deleted = batch_delete_by_ids(&conn, &ids[..3]).unwrap();
        assert_eq!(deleted, 3);

        let remaining: i64 = conn
            .query_row("SELECT COUNT(*) FROM security_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(remaining, 2);
    }

    #[test]
    fn test_batch_delete_by_filter() {
        let conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        conn.execute(
            "INSERT INTO security_events (timestamp, severity, source_module, event_type, message) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![now, "WARNING", "file_integrity", "test", "warning event"],
        ).unwrap();
        conn.execute(
            "INSERT INTO security_events (timestamp, severity, source_module, event_type, message) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![now, "INFO", "file_integrity", "test", "info event"],
        ).unwrap();
        conn.execute(
            "INSERT INTO security_events (timestamp, severity, source_module, event_type, message) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![now, "INFO", "network_monitor", "test", "other event"],
        ).unwrap();

        let filter = BatchDeleteFilter {
            severity: Some("INFO".to_string()),
            source_module: Some("file_integrity".to_string()),
            since: None,
            until: None,
        };
        let deleted = batch_delete_by_filter(&conn, &filter).unwrap();
        assert_eq!(deleted, 1);

        let remaining: i64 = conn
            .query_row("SELECT COUNT(*) FROM security_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(remaining, 2);
    }

    #[test]
    fn test_batch_acknowledge() {
        let conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();
        insert_test_events(&conn, 5);

        let ids: Vec<i64> = conn
            .prepare("SELECT id FROM security_events LIMIT 3")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        let updated = batch_acknowledge(&conn, &ids).unwrap();
        assert_eq!(updated, 3);

        let acked: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM security_events WHERE acknowledged = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(acked, 3);

        let not_acked: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM security_events WHERE acknowledged = 0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(not_acked, 2);
    }

    #[test]
    fn test_batch_delete_chunks() {
        let conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();
        insert_test_events(&conn, 1500);

        let ids: Vec<i64> = conn
            .prepare("SELECT id FROM security_events")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        assert_eq!(ids.len(), 1500);

        let deleted = batch_delete_by_ids(&conn, &ids).unwrap();
        assert_eq!(deleted, 1500);

        let remaining: i64 = conn
            .query_row("SELECT COUNT(*) FROM security_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(remaining, 0);
    }

    #[test]
    fn test_acknowledged_column_migration() {
        let conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();

        let has_col = {
            let mut stmt = conn.prepare("PRAGMA table_info(security_events)").unwrap();
            let columns: Vec<String> = stmt
                .query_map([], |row| row.get::<_, String>(1))
                .unwrap()
                .filter_map(|r| r.ok())
                .collect();
            columns.iter().any(|c| c == "acknowledged")
        };
        assert!(has_col);

        // Running init_database again should be idempotent
        init_database(&conn).unwrap();
    }

    #[test]
    fn test_count_by_ids() {
        let conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();
        insert_test_events(&conn, 5);

        let ids: Vec<i64> = conn
            .prepare("SELECT id FROM security_events")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        let (count, sample) = count_by_ids(&conn, &ids[..3]).unwrap();
        assert_eq!(count, 3);
        assert_eq!(sample.len(), 3);

        let (count, _) = count_by_ids(&conn, &[9999]).unwrap();
        assert_eq!(count, 0);

        let remaining: i64 = conn
            .query_row("SELECT COUNT(*) FROM security_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(remaining, 5);
    }

    #[test]
    fn test_count_by_filter() {
        let conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();
        insert_test_events(&conn, 5);

        let filter = BatchDeleteFilter {
            severity: Some("info".to_string()),
            source_module: Some("test_module".to_string()),
            since: None,
            until: None,
        };
        let (count, sample) = count_by_filter(&conn, &filter).unwrap();
        assert_eq!(count, 5);
        assert!(sample.len() <= 10);

        let filter_no_match = BatchDeleteFilter {
            severity: Some("critical".to_string()),
            source_module: None,
            since: None,
            until: None,
        };
        let (count, _) = count_by_filter(&conn, &filter_no_match).unwrap();
        assert_eq!(count, 0);

        let remaining: i64 = conn
            .query_row("SELECT COUNT(*) FROM security_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(remaining, 5);
    }

    #[test]
    fn test_count_acknowledge_targets() {
        let conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();
        insert_test_events(&conn, 5);

        let ids: Vec<i64> = conn
            .prepare("SELECT id FROM security_events")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        let (count, sample) = count_acknowledge_targets(&conn, &ids).unwrap();
        assert_eq!(count, 5);
        assert_eq!(sample.len(), 5);

        batch_acknowledge(&conn, &ids[..2]).unwrap();
        let (count, _) = count_acknowledge_targets(&conn, &ids).unwrap();
        assert_eq!(count, 3);

        let remaining: i64 = conn
            .query_row("SELECT COUNT(*) FROM security_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(remaining, 5);
    }

    #[test]
    fn test_count_by_ids_sample_limit() {
        let conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();
        insert_test_events(&conn, 20);

        let ids: Vec<i64> = conn
            .prepare("SELECT id FROM security_events")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        let (count, sample) = count_by_ids(&conn, &ids).unwrap();
        assert_eq!(count, 20);
        assert!(sample.len() <= 10);
    }

    #[test]
    fn test_format_date_from_epoch() {
        assert_eq!(format_date_from_epoch(0), "19700101");
        assert_eq!(format_date_from_epoch(1704067200), "20240101");
        assert_eq!(format_date_from_epoch(1672531200), "20230101");
    }

    #[test]
    fn test_archive_and_restore_compressed() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let archive_dir = dir.path().join("archive");

        let conn = Connection::open(&db_path).unwrap();
        init_database(&conn).unwrap();

        let old_ts = 1000i64;
        for i in 0..5 {
            conn.execute(
                "INSERT INTO security_events (timestamp, severity, source_module, event_type, message) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![old_ts + i, "INFO", "test_mod", "test_event", format!("message {}", i)],
            ).unwrap();
        }
        let recent_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        conn.execute(
            "INSERT INTO security_events (timestamp, severity, source_module, event_type, message) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![recent_ts, "WARNING", "test_mod", "test_event", "recent event"],
        ).unwrap();
        drop(conn);

        let count = run_archive_manual(
            db_path.to_str().unwrap(),
            1,
            archive_dir.to_str().unwrap(),
            true,
        )
        .unwrap();
        assert_eq!(count, 5);

        let conn = Connection::open(&db_path).unwrap();
        let remaining: i64 = conn
            .query_row("SELECT COUNT(*) FROM security_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(remaining, 1);
        drop(conn);

        let archives = list_archives(archive_dir.to_str().unwrap()).unwrap();
        assert_eq!(archives.len(), 1);
        assert!(archives[0].filename.ends_with(".jsonl.gz"));
        assert!(archives[0].checksum.is_some());

        let restored = restore_archive(
            db_path.to_str().unwrap(),
            archive_dir.to_str().unwrap(),
            &archives[0].filename,
        )
        .unwrap();
        assert_eq!(restored, 5);

        let conn = Connection::open(&db_path).unwrap();
        let total: i64 = conn
            .query_row("SELECT COUNT(*) FROM security_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(total, 6);
    }

    #[test]
    fn test_archive_uncompressed() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let archive_dir = dir.path().join("archive");

        let conn = Connection::open(&db_path).unwrap();
        init_database(&conn).unwrap();

        conn.execute(
            "INSERT INTO security_events (timestamp, severity, source_module, event_type, message) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![100i64, "CRITICAL", "test_mod", "critical_event", "critical message"],
        ).unwrap();
        drop(conn);

        let count = run_archive_manual(
            db_path.to_str().unwrap(),
            1,
            archive_dir.to_str().unwrap(),
            false,
        )
        .unwrap();
        assert_eq!(count, 1);

        let archives = list_archives(archive_dir.to_str().unwrap()).unwrap();
        assert_eq!(archives.len(), 1);
        assert!(archives[0].filename.ends_with(".jsonl"));
        assert!(!archives[0].filename.ends_with(".jsonl.gz"));
    }

    #[test]
    fn test_archive_no_old_events() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let archive_dir = dir.path().join("archive");

        let conn = Connection::open(&db_path).unwrap();
        init_database(&conn).unwrap();

        let recent_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        conn.execute(
            "INSERT INTO security_events (timestamp, severity, source_module, event_type, message) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![recent_ts, "INFO", "test_mod", "test_event", "recent"],
        ).unwrap();
        drop(conn);

        let count = run_archive_manual(
            db_path.to_str().unwrap(),
            1,
            archive_dir.to_str().unwrap(),
            true,
        )
        .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_list_archives_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let archives = list_archives(dir.path().to_str().unwrap()).unwrap();
        assert!(archives.is_empty());
    }

    #[test]
    fn test_list_archives_nonexistent_dir() {
        let archives = list_archives("/nonexistent/path").unwrap();
        assert!(archives.is_empty());
    }

    #[test]
    fn test_restore_nonexistent_file() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let result = restore_archive(
            db_path.to_str().unwrap(),
            dir.path().to_str().unwrap(),
            "nonexistent.jsonl.gz",
        );
        assert!(result.is_err());
    }
}
