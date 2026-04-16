//! REST API サーバー
//!
//! HTTP REST API でデーモンのステータス確認、イベント検索、モジュール一覧、
//! 設定リロードをリモートから操作可能にする。
//! JSON レスポンス形式で `/api/v1/` プレフィックスのエンドポイントを提供する。

use crate::config::{
    ActionConfig, ApiConfig, ApiRateLimitConfig, ApiRole, ApiTokenConfig, CorsConfig,
    WebSocketConfig,
};
use crate::core::event::{SecurityEvent, Severity};
use crate::core::metrics::SharedMetrics;
use crate::core::openapi;
use crate::core::scoring::SharedSecurityScore;
use crate::core::status::{MetricsSummary, StatusResponse};
use futures_util::{SinkExt, StreamExt};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;

/// TLS/非 TLS 両対応のストリームラッパー
///
/// TLS が有効な場合は `TlsStream<TcpStream>`、無効な場合は `TcpStream` を透過的に扱う。
pub enum MaybeTlsStream {
    /// 平文 TCP ストリーム
    Plain(tokio::net::TcpStream),
    /// TLS 暗号化ストリーム
    Tls(Box<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>),
}

impl AsyncRead for MaybeTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_flush(cx),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// HTTP メソッド
enum HttpMethod {
    Get,
    Post,
    Delete,
    Options,
    Other,
}

/// 認証結果
enum AuthResult {
    /// 認証不要（トークン未設定）
    NoAuthRequired,
    /// 認証成功（ロール付き）
    Authenticated(ApiRole),
    /// 認証失敗
    Unauthorized,
}

/// トークンバケット（IP アドレスごとのレート管理）
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

/// レートリミット判定結果
struct RateLimitResult {
    allowed: bool,
    limit: u32,
    remaining: u32,
    reset_secs: u64,
    retry_after: Option<f64>,
}

const MAX_RATE_LIMIT_ENTRIES: usize = 10000;

const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(BASE64_CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(BASE64_CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(BASE64_CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(BASE64_CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

/// トークンバケット方式のレートリミッター
struct RateLimiter {
    buckets: HashMap<IpAddr, TokenBucket>,
    max_tokens: f64,
    refill_rate: f64,
    last_cleanup: Instant,
    cleanup_interval: std::time::Duration,
    max_entries: usize,
}

impl RateLimiter {
    fn new(config: &ApiRateLimitConfig) -> Self {
        Self {
            buckets: HashMap::new(),
            max_tokens: f64::from(config.burst_size),
            refill_rate: config.max_requests_per_second,
            last_cleanup: Instant::now(),
            cleanup_interval: std::time::Duration::from_secs(config.cleanup_interval_secs),
            max_entries: MAX_RATE_LIMIT_ENTRIES,
        }
    }

    fn check_rate_limit(&mut self, ip: IpAddr) -> RateLimitResult {
        let now = Instant::now();

        if !self.buckets.contains_key(&ip) && self.buckets.len() >= self.max_entries {
            self.cleanup();
            if self.buckets.len() >= self.max_entries {
                return RateLimitResult {
                    allowed: false,
                    limit: self.max_tokens as u32,
                    remaining: 0,
                    reset_secs: (self.max_tokens / self.refill_rate).ceil() as u64,
                    retry_after: Some(1.0),
                };
            }
        }

        let bucket = self.buckets.entry(ip).or_insert_with(|| TokenBucket {
            tokens: self.max_tokens,
            last_refill: now,
        });

        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            let remaining = bucket.tokens as u32;
            let reset_secs = if remaining < self.max_tokens as u32 {
                ((self.max_tokens - bucket.tokens) / self.refill_rate).ceil() as u64
            } else {
                0
            };
            RateLimitResult {
                allowed: true,
                limit: self.max_tokens as u32,
                remaining,
                reset_secs,
                retry_after: None,
            }
        } else {
            let deficit = 1.0 - bucket.tokens;
            let retry_after = deficit / self.refill_rate;
            let reset_secs = (self.max_tokens / self.refill_rate).ceil() as u64;
            RateLimitResult {
                allowed: false,
                limit: self.max_tokens as u32,
                remaining: 0,
                reset_secs,
                retry_after: Some(retry_after),
            }
        }
    }

    fn cleanup(&mut self) {
        let now = Instant::now();
        let threshold = self.cleanup_interval * 2;
        self.buckets
            .retain(|_, bucket| now.duration_since(bucket.last_refill) < threshold);
        self.last_cleanup = now;
    }
}

/// REST API サーバー
pub struct ApiServer {
    bind_address: String,
    port: u16,
    shared_module_names: Arc<StdMutex<Vec<String>>>,
    shared_metrics: Option<Arc<StdMutex<SharedMetrics>>>,
    shared_module_restarts: Arc<StdMutex<HashMap<String, u32>>>,
    started_at: Instant,
    event_store_db_path: Option<String>,
    config_path: Option<String>,
    reload_sender: mpsc::Sender<()>,
    module_control_sender: mpsc::Sender<(
        ModuleControlCommand,
        tokio::sync::oneshot::Sender<ModuleControlResult>,
    )>,
    cancel_token: CancellationToken,
    tokens: Arc<StdMutex<Vec<ApiTokenConfig>>>,
    rate_limiter: Arc<StdMutex<Option<RateLimiter>>>,
    rate_limit_config: ApiRateLimitConfig,
    event_bus: Option<broadcast::Sender<SecurityEvent>>,
    ws_config: WebSocketConfig,
    ws_connections: Arc<AtomicUsize>,
    cors_config: Arc<CorsConfig>,
    openapi_enabled: bool,
    default_page_size: u32,
    max_page_size: u32,
    batch_max_size: u32,
    max_request_body_size: usize,
    shared_scoring: Option<Arc<StdMutex<SharedSecurityScore>>>,
    access_log: Arc<AtomicBool>,
    tls_acceptor: Option<Arc<tokio_rustls::TlsAcceptor>>,
    mtls_status: String,
    archive_dir: Option<String>,
    archive_config: ArchiveApiConfig,
    shared_action_config: Arc<StdMutex<ActionConfig>>,
}

/// アーカイブ API 用の設定
#[derive(Clone)]
struct ArchiveApiConfig {
    archive_after_days: u64,
    compress: bool,
    max_age_days: u64,
    max_total_mb: u64,
    max_files: u64,
}

/// TLS アクセプターを構築する
fn build_tls_acceptor(
    tls_config: &crate::config::ApiTlsConfig,
) -> Result<tokio_rustls::TlsAcceptor, io::Error> {
    use rustls::ServerConfig;
    use rustls_pemfile::{certs, private_key};
    use std::fs::File;
    use std::io::BufReader;

    let cert_file = File::open(&tls_config.cert_file).map_err(|e| {
        io::Error::other(format!(
            "証明書ファイルを開けません: {}: {}",
            tls_config.cert_file, e
        ))
    })?;
    let key_file = File::open(&tls_config.key_file).map_err(|e| {
        io::Error::other(format!(
            "秘密鍵ファイルを開けません: {}: {}",
            tls_config.key_file, e
        ))
    })?;

    let server_certs: Vec<rustls_pki_types::CertificateDer<'static>> =
        certs(&mut BufReader::new(cert_file))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("証明書の読み込みに失敗: {}", e),
                )
            })?;

    let key = private_key(&mut BufReader::new(key_file))
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("秘密鍵の読み込みに失敗: {}", e),
            )
        })?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "秘密鍵が見つかりません"))?;

    let builder =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("TLS プロトコルバージョンの設定に失敗: {}", e),
                )
            })?;

    let config = if tls_config.mtls.enabled {
        use rustls::server::WebPkiClientVerifier;

        let ca_file = File::open(&tls_config.mtls.client_ca_file).map_err(|e| {
            io::Error::other(format!(
                "クライアント CA 証明書ファイルを開けません: {}: {}",
                tls_config.mtls.client_ca_file, e
            ))
        })?;
        let ca_certs: Vec<rustls_pki_types::CertificateDer<'static>> =
            certs(&mut BufReader::new(ca_file))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("クライアント CA 証明書の読み込みに失敗: {}", e),
                    )
                })?;

        let mut client_root_store = rustls::RootCertStore::empty();
        for cert in ca_certs {
            client_root_store.add(cert).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("クライアント CA 証明書の追加に失敗: {}", e),
                )
            })?;
        }

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = if tls_config.mtls.client_auth_mode == "optional" {
            WebPkiClientVerifier::builder_with_provider(
                Arc::new(client_root_store),
                provider.clone(),
            )
            .allow_unauthenticated()
            .build()
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("mTLS クライアント検証の構築に失敗: {}", e),
                )
            })?
        } else {
            WebPkiClientVerifier::builder_with_provider(
                Arc::new(client_root_store),
                provider.clone(),
            )
            .build()
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("mTLS クライアント検証の構築に失敗: {}", e),
                )
            })?
        };

        tracing::info!(
            client_ca_file = %tls_config.mtls.client_ca_file,
            client_auth_mode = %tls_config.mtls.client_auth_mode,
            "REST API mTLS: 有効"
        );

        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(server_certs, key)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("TLS 設定の構築に失敗: {}", e),
                )
            })?
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(server_certs, key)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("TLS 設定の構築に失敗: {}", e),
                )
            })?
    };

    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

/// モジュール制御コマンド
#[derive(Debug)]
pub enum ModuleControlCommand {
    /// モジュールを起動する
    Start(String),
    /// モジュールを停止する
    Stop(String),
    /// モジュールを再起動する
    Restart(String),
}

/// モジュール制御の結果
#[derive(Debug)]
pub enum ModuleControlResult {
    /// 操作成功
    Ok(String),
    /// モジュールが見つからない
    NotFound(String),
    /// 状態の競合（既に起動中/停止中）
    Conflict(String),
    /// 操作失敗
    Error(String),
}

fn is_dry_run(query_params: &HashMap<String, String>) -> bool {
    query_params
        .get("dry_run")
        .map(|v| v == "true")
        .unwrap_or(false)
}

impl ApiServer {
    /// 新しい ApiServer を作成する
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: &ApiConfig,
        shared_module_names: Arc<StdMutex<Vec<String>>>,
        shared_metrics: Option<Arc<StdMutex<SharedMetrics>>>,
        shared_module_restarts: Arc<StdMutex<HashMap<String, u32>>>,
        started_at: Instant,
        event_store_db_path: Option<String>,
        config_path: Option<String>,
        reload_sender: mpsc::Sender<()>,
        module_control_sender: mpsc::Sender<(
            ModuleControlCommand,
            tokio::sync::oneshot::Sender<ModuleControlResult>,
        )>,
        event_bus: Option<broadcast::Sender<SecurityEvent>>,
        shared_scoring: Option<Arc<StdMutex<SharedSecurityScore>>>,
        event_store_config: Option<&crate::config::EventStoreConfig>,
        action_config: &ActionConfig,
    ) -> Self {
        let rate_limiter = if config.rate_limit.enabled {
            Some(RateLimiter::new(&config.rate_limit))
        } else {
            None
        };

        if config.tls.mtls.enabled && !config.tls.enabled {
            tracing::warn!(
                "mTLS が有効ですが TLS が無効です。mTLS を機能させるには tls.enabled = true が必要です"
            );
        }

        let tls_acceptor = if config.tls.enabled {
            match build_tls_acceptor(&config.tls) {
                Ok(acceptor) => {
                    tracing::info!(
                        cert_file = %config.tls.cert_file,
                        key_file = %config.tls.key_file,
                        "REST API TLS: 有効"
                    );
                    Some(Arc::new(acceptor))
                }
                Err(e) => {
                    tracing::error!(error = %e, "TLS アクセプターの構築に失敗。TLS なしで起動します");
                    None
                }
            }
        } else {
            None
        };

        Self {
            bind_address: config.bind_address.clone(),
            port: config.port,
            shared_module_names,
            shared_metrics,
            shared_module_restarts,
            started_at,
            event_store_db_path,
            config_path,
            reload_sender,
            module_control_sender,
            cancel_token: CancellationToken::new(),
            tokens: Arc::new(StdMutex::new(config.tokens.clone())),
            rate_limiter: Arc::new(StdMutex::new(rate_limiter)),
            rate_limit_config: config.rate_limit.clone(),
            event_bus,
            ws_config: config.websocket.clone(),
            ws_connections: Arc::new(AtomicUsize::new(0)),
            cors_config: Arc::new(config.cors.clone()),
            openapi_enabled: config.openapi_enabled,
            default_page_size: config.default_page_size,
            max_page_size: config.max_page_size,
            batch_max_size: config.batch_max_size,
            max_request_body_size: config.max_request_body_size,
            shared_scoring,
            access_log: Arc::new(AtomicBool::new(config.access_log)),
            tls_acceptor,
            mtls_status: if config.tls.enabled && config.tls.mtls.enabled {
                config.tls.mtls.client_auth_mode.clone()
            } else {
                "無効".to_string()
            },
            archive_dir: event_store_config
                .filter(|c| c.archive_enabled)
                .map(|c| c.archive_dir.clone()),
            archive_config: event_store_config
                .map(|c| ArchiveApiConfig {
                    archive_after_days: c.archive_after_days,
                    compress: c.archive_compress,
                    max_age_days: c.archive_max_age_days,
                    max_total_mb: c.archive_max_total_mb,
                    max_files: c.archive_max_files,
                })
                .unwrap_or(ArchiveApiConfig {
                    archive_after_days: 30,
                    compress: true,
                    max_age_days: 365,
                    max_total_mb: 0,
                    max_files: 0,
                }),
            shared_action_config: Arc::new(StdMutex::new(action_config.clone())),
        }
    }

    /// キャンセルトークンを取得する
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    /// アクセスログフラグの共有参照を取得する（ホットリロード用）
    pub fn access_log_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.access_log)
    }

    /// アクション設定の共有参照を取得する（ホットリロード用）
    pub fn shared_action_config(&self) -> Arc<StdMutex<ActionConfig>> {
        Arc::clone(&self.shared_action_config)
    }

    /// API サーバーを非同期タスクとして起動する
    pub fn spawn(self) -> Result<(), std::io::Error> {
        let addr = format!("{}:{}", self.bind_address, self.port);
        let listener = std::net::TcpListener::bind(&addr)?;
        listener.set_nonblocking(true)?;
        let listener = TcpListener::from_std(listener)?;

        let shared_module_names = self.shared_module_names;
        let shared_metrics = self.shared_metrics;
        let shared_module_restarts = self.shared_module_restarts;
        let started_at = self.started_at;
        let event_store_db_path = self.event_store_db_path;
        let config_path = self.config_path;
        let reload_sender = self.reload_sender;
        let module_control_sender = self.module_control_sender;
        let cancel_token = self.cancel_token;
        let tokens = self.tokens;
        let rate_limiter = self.rate_limiter;
        let event_bus = self.event_bus;
        let ws_config = Arc::new(self.ws_config);
        let ws_connections = self.ws_connections;
        let cors_config = self.cors_config;
        let openapi_enabled = self.openapi_enabled;
        let default_page_size = self.default_page_size;
        let max_page_size = self.max_page_size;
        let batch_max_size = self.batch_max_size;
        let max_request_body_size = self.max_request_body_size;
        let shared_scoring = self.shared_scoring;
        let access_log = self.access_log;
        let tls_acceptor = self.tls_acceptor;
        let mtls_status = self.mtls_status;
        let archive_dir = self.archive_dir;
        let archive_config = self.archive_config;
        let shared_action_config = self.shared_action_config;

        // クリーンアップタスク
        if self.rate_limit_config.enabled {
            let rl_cleanup = Arc::clone(&rate_limiter);
            let cleanup_interval =
                std::time::Duration::from_secs(self.rate_limit_config.cleanup_interval_secs);
            let cancel_cleanup = cancel_token.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(cleanup_interval);
                interval.tick().await;
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            // unwrap safety: Mutex が poisoned になるのはパニック時のみ
                            if let Some(ref mut rl) = *rl_cleanup.lock().unwrap() {
                                rl.cleanup();
                            }
                        }
                        _ = cancel_cleanup.cancelled() => {
                            break;
                        }
                    }
                }
            });
        }

        let tls_enabled = tls_acceptor.is_some();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, addr)) => {
                                let names = Arc::clone(&shared_module_names);
                                let metrics = shared_metrics.clone();
                                let restarts = Arc::clone(&shared_module_restarts);
                                let db_path = event_store_db_path.clone();
                                let cfg_path = config_path.clone();
                                let sender = reload_sender.clone();
                                let mc_sender = module_control_sender.clone();
                                let started = started_at;
                                let toks = Arc::clone(&tokens);
                                let rl = Arc::clone(&rate_limiter);
                                let client_ip = addr.ip();
                                let eb = event_bus.clone();
                                let wsc = Arc::clone(&ws_config);
                                let wsc_count = Arc::clone(&ws_connections);
                                let cors = Arc::clone(&cors_config);
                                let oa_enabled = openapi_enabled;
                                let dps = default_page_size;
                                let mps = max_page_size;
                                let bms = batch_max_size;
                                let mrbs = max_request_body_size;
                                let scoring = shared_scoring.clone();
                                let al = Arc::clone(&access_log);
                                let arch_dir = archive_dir.clone();
                                let arch_cfg = archive_config.clone();
                                let act_cfg = Arc::clone(&shared_action_config);
                                let tls_acc = tls_acceptor.clone();
                                tokio::spawn(async move {
                                    let maybe_stream = if let Some(ref acceptor) = tls_acc {
                                        match acceptor.accept(stream).await {
                                            Ok(tls_stream) => MaybeTlsStream::Tls(Box::new(tls_stream)),
                                            Err(e) => {
                                                tracing::debug!(error = %e, "TLS ハンドシェイクに失敗");
                                                return;
                                            }
                                        }
                                    } else {
                                        MaybeTlsStream::Plain(stream)
                                    };
                                    if let Err(e) = Self::handle_connection(
                                        maybe_stream, &names, &metrics, &restarts,
                                        started, &db_path, &cfg_path, &sender, &mc_sender, &toks,
                                        client_ip, &rl, &eb, &wsc, &wsc_count, &cors,
                                        oa_enabled, dps, mps, bms, mrbs, &scoring, &al,
                                        &arch_dir, &arch_cfg, &act_cfg,
                                    ).await {
                                        tracing::debug!(error = %e, "API 接続の処理に失敗");
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::debug!(error = %e, "API リスナーの accept に失敗");
                            }
                        }
                    }
                    _ = cancel_token.cancelled() => {
                        tracing::info!("REST API サーバーを停止します");
                        break;
                    }
                }
            }
        });

        tracing::info!(
            bind_address = %addr,
            tls = tls_enabled,
            mtls = %mtls_status,
            "REST API サーバーを起動しました"
        );
        Ok(())
    }

    fn authenticate(raw: &str, tokens: &[ApiTokenConfig]) -> AuthResult {
        if tokens.is_empty() {
            return AuthResult::NoAuthRequired;
        }

        let bearer = raw.lines().find_map(|line| {
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("authorization:") {
                let value = line["authorization:".len()..].trim();
                if value.len() > 7 && value[..7].eq_ignore_ascii_case("bearer ") {
                    Some(value[7..].trim().to_string())
                } else {
                    None
                }
            } else {
                None
            }
        });

        let Some(token) = bearer else {
            return AuthResult::Unauthorized;
        };

        let hash = Self::hash_token(&token);

        for tc in tokens {
            if tc.token_hash == hash {
                tracing::debug!(token_name = %tc.name, "API 認証成功");
                return AuthResult::Authenticated(tc.role.clone());
            }
        }

        tracing::warn!("API 認証失敗: 不明なトークン");
        AuthResult::Unauthorized
    }

    /// トークン文字列から `sha256:<hex>` 形式のハッシュを生成する
    pub fn hash_token(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let result = hasher.finalize();
        format!("sha256:{:x}", result)
    }

    fn required_role(method: &HttpMethod, path: &str) -> Option<ApiRole> {
        match (method, path) {
            (HttpMethod::Get, "/api/v1/health") => None,
            (HttpMethod::Get, "/api/v1/status")
            | (HttpMethod::Get, "/api/v1/modules")
            | (HttpMethod::Get, "/api/v1/events")
            | (HttpMethod::Get, "/api/v1/events/summary")
            | (HttpMethod::Get, "/api/v1/events/summary/timeline")
            | (HttpMethod::Get, "/api/v1/events/summary/modules")
            | (HttpMethod::Get, "/api/v1/events/summary/severity")
            | (HttpMethod::Get, "/api/v1/events/stream")
            | (HttpMethod::Get, "/api/v1/score")
            | (HttpMethod::Get, "/api/v1/archives")
            | (HttpMethod::Get, "/api/v1/webhooks") => Some(ApiRole::ReadOnly),
            (HttpMethod::Post, "/api/v1/reload") => Some(ApiRole::Admin),
            (HttpMethod::Post, "/api/v1/events/batch/delete") => Some(ApiRole::Admin),
            (HttpMethod::Post, "/api/v1/events/batch/export") => Some(ApiRole::ReadOnly),
            (HttpMethod::Post, "/api/v1/events/batch/acknowledge") => Some(ApiRole::Admin),
            (HttpMethod::Post, "/api/v1/archives") => Some(ApiRole::Admin),
            (HttpMethod::Post, "/api/v1/archives/restore") => Some(ApiRole::Admin),
            (HttpMethod::Post, "/api/v1/archives/rotate") => Some(ApiRole::Admin),
            (HttpMethod::Post, "/api/v1/webhooks/test") => Some(ApiRole::Admin),
            _ if matches!(method, HttpMethod::Post)
                && path.starts_with("/api/v1/modules/")
                && (path.ends_with("/start")
                    || path.ends_with("/stop")
                    || path.ends_with("/restart")) =>
            {
                Some(ApiRole::Admin)
            }
            _ if matches!(method, HttpMethod::Delete) && path.starts_with("/api/v1/archives/") => {
                Some(ApiRole::Admin)
            }
            _ => None,
        }
    }

    fn extract_header<'a>(raw: &'a str, name: &str) -> Option<&'a str> {
        let name_with_colon = format!("{}:", name.to_ascii_lowercase());
        for line in raw.lines() {
            let line_lower = line.to_ascii_lowercase();
            if line_lower.starts_with(&name_with_colon) {
                let colon_pos = line.find(':').unwrap_or(0);
                return Some(line[colon_pos + 1..].trim());
            }
        }
        None
    }

    fn build_cors_headers(cors: &CorsConfig, origin: Option<&str>, is_preflight: bool) -> String {
        if !cors.enabled {
            return String::new();
        }

        let origin_value = match origin {
            Some("null") => return String::new(),
            Some(o) => {
                if cors.allowed_origins.is_empty() {
                    if cors.allow_credentials {
                        o.to_string()
                    } else {
                        "*".to_string()
                    }
                } else if cors.allowed_origins.iter().any(|allowed| allowed == o) {
                    o.to_string()
                } else {
                    return String::new();
                }
            }
            None => return String::new(),
        };

        let mut headers = format!(
            "Access-Control-Allow-Origin: {}\r\nVary: Origin",
            origin_value
        );

        if cors.allow_credentials {
            headers.push_str("\r\nAccess-Control-Allow-Credentials: true");
        }

        if is_preflight {
            let methods = cors.allowed_methods.join(", ");
            let hdrs = cors.allowed_headers.join(", ");
            headers.push_str(&format!(
                "\r\nAccess-Control-Allow-Methods: {}\r\nAccess-Control-Allow-Headers: {}\r\nAccess-Control-Max-Age: {}",
                methods, hdrs, cors.max_age
            ));
        }

        headers
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_connection(
        mut stream: MaybeTlsStream,
        shared_module_names: &Arc<StdMutex<Vec<String>>>,
        shared_metrics: &Option<Arc<StdMutex<SharedMetrics>>>,
        shared_module_restarts: &Arc<StdMutex<HashMap<String, u32>>>,
        started_at: Instant,
        event_store_db_path: &Option<String>,
        config_path: &Option<String>,
        reload_sender: &mpsc::Sender<()>,
        module_control_sender: &mpsc::Sender<(
            ModuleControlCommand,
            tokio::sync::oneshot::Sender<ModuleControlResult>,
        )>,
        tokens: &Arc<StdMutex<Vec<ApiTokenConfig>>>,
        client_ip: IpAddr,
        rate_limiter: &Arc<StdMutex<Option<RateLimiter>>>,
        event_bus: &Option<broadcast::Sender<SecurityEvent>>,
        ws_config: &Arc<WebSocketConfig>,
        ws_connections: &Arc<AtomicUsize>,
        cors_config: &Arc<CorsConfig>,
        openapi_enabled: bool,
        default_page_size: u32,
        max_page_size: u32,
        batch_max_size: u32,
        max_request_body_size: usize,
        shared_scoring: &Option<Arc<StdMutex<SharedSecurityScore>>>,
        access_log: &Arc<AtomicBool>,
        archive_dir: &Option<String>,
        archive_config: &ArchiveApiConfig,
        shared_action_config: &Arc<StdMutex<ActionConfig>>,
    ) -> Result<(), io::Error> {
        let request_start = Instant::now();

        // 接続タイムアウト（スローロリス対策）
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            Self::read_request(&mut stream),
        )
        .await;

        let raw = match result {
            Ok(Ok(line)) => line,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "接続タイムアウト"));
            }
        };

        let (method, path, query_params) = Self::parse_request(&raw);

        let access_log_enabled = access_log.load(Ordering::Relaxed);
        let method_str = match &method {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Options => "OPTIONS",
            HttpMethod::Other => "OTHER",
        };
        let user_agent = Self::extract_header(&raw, "user-agent").unwrap_or_default();
        let request_size: u64 = Self::extract_header(&raw, "content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        // CORS ヘッダーの構築（全レスポンスに付与するため先に計算）
        let origin = Self::extract_header(&raw, "origin");
        let is_preflight = matches!(method, HttpMethod::Options);
        let cors_headers = Self::build_cors_headers(cors_config, origin, is_preflight);
        let cors_headers_for_health = cors_headers.clone();

        // レートリミットチェック（/api/v1/health, /api/v1/openapi.json はスキップ）
        let rate_limit_check = if path != "/api/v1/health" && path != "/api/v1/openapi.json" {
            // unwrap safety: Mutex が poisoned になるのはパニック時のみ
            let mut rl_guard = rate_limiter.lock().unwrap();
            (*rl_guard)
                .as_mut()
                .map(|rl| rl.check_rate_limit(client_ip))
        } else {
            None
        };

        if let Some(ref result) = rate_limit_check
            && !result.allowed
        {
            let retry_after = result.retry_after.unwrap_or(1.0).ceil() as u64;
            let retry_after = if retry_after == 0 { 1 } else { retry_after };
            let body =
                r#"{"error":"リクエスト数が上限を超えました。しばらくしてから再試行してください"}"#;
            let cors_extra = if cors_headers.is_empty() {
                String::new()
            } else {
                format!("{}\r\n", cors_headers)
            };
            let response = format!(
                "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nRetry-After: {}\r\nX-RateLimit-Limit: {}\r\nX-RateLimit-Remaining: 0\r\nX-RateLimit-Reset: {}\r\n{}\r\n{}",
                body.len(),
                retry_after,
                result.limit,
                result.reset_secs,
                cors_extra,
                body
            );
            stream.write_all(response.as_bytes()).await?;
            if access_log_enabled {
                Self::log_access(
                    method_str,
                    &path,
                    429,
                    request_start,
                    client_ip,
                    user_agent,
                    request_size,
                    body.len() as u64,
                );
            }
            stream.shutdown().await?;
            return Ok(());
        }

        let rate_limit_headers = rate_limit_check.as_ref().and_then(|result| {
            if result.allowed {
                Some(format!(
                    "X-RateLimit-Limit: {}\r\nX-RateLimit-Remaining: {}\r\nX-RateLimit-Reset: {}",
                    result.limit, result.remaining, result.reset_secs
                ))
            } else {
                None
            }
        });

        let combined_extra = match (&rate_limit_headers, cors_headers.is_empty()) {
            (Some(rl), false) => Some(format!("{}\r\n{}", rl, cors_headers)),
            (Some(rl), true) => Some(rl.clone()),
            (None, false) => Some(cors_headers),
            (None, true) => None,
        };

        // CORS プリフライトリクエスト処理
        if is_preflight && cors_config.enabled {
            let extra = combined_extra.as_deref().unwrap_or("");
            let extra_fmt = if extra.is_empty() {
                String::new()
            } else {
                format!("{}\r\n", extra)
            };
            let response = format!(
                "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n{}\r\n",
                extra_fmt
            );
            stream.write_all(response.as_bytes()).await?;
            if access_log_enabled {
                Self::log_access(
                    method_str,
                    &path,
                    204,
                    request_start,
                    client_ip,
                    user_agent,
                    request_size,
                    0,
                );
            }
            stream.shutdown().await?;
            return Ok(());
        }

        // 認証チェック
        // unwrap safety: Mutex が poisoned になるのはパニック時のみ
        let token_list = tokens.lock().unwrap().clone();
        let auth = Self::authenticate(&raw, &token_list);

        if let Some(required) = Self::required_role(&method, &path) {
            match &auth {
                AuthResult::NoAuthRequired => {}
                AuthResult::Authenticated(role) => {
                    if !role.has_permission(&required) {
                        tracing::warn!(
                            path = %path,
                            "API 認可失敗: 権限不足"
                        );
                        let err_body = r#"{"error":"権限が不足しています"}"#;
                        Self::send_error_with_headers(
                            &mut stream,
                            403,
                            "Forbidden",
                            "権限が不足しています",
                            combined_extra.as_deref(),
                        )
                        .await?;
                        if access_log_enabled {
                            Self::log_access(
                                method_str,
                                &path,
                                403,
                                request_start,
                                client_ip,
                                user_agent,
                                request_size,
                                err_body.len() as u64,
                            );
                        }
                        stream.shutdown().await?;
                        return Ok(());
                    }
                }
                AuthResult::Unauthorized => {
                    let err_body = r#"{"error":"認証が必要です"}"#;
                    Self::send_error_with_headers(
                        &mut stream,
                        401,
                        "Unauthorized",
                        "認証が必要です",
                        combined_extra.as_deref(),
                    )
                    .await?;
                    if access_log_enabled {
                        Self::log_access(
                            method_str,
                            &path,
                            401,
                            request_start,
                            client_ip,
                            user_agent,
                            request_size,
                            err_body.len() as u64,
                        );
                    }
                    stream.shutdown().await?;
                    return Ok(());
                }
            }
        }

        // WebSocket イベントストリーミング
        if path == "/api/v1/events/stream" {
            return Self::handle_websocket(
                stream,
                &raw,
                &query_params,
                tokens,
                event_bus,
                ws_config,
                ws_connections,
            )
            .await;
        }

        let extra = combined_extra.as_deref();
        #[allow(unused_assignments)]
        let mut resp_status: u16 = 200;
        #[allow(unused_assignments)]
        let mut resp_size: u64 = 0;
        match (&method, path.as_str()) {
            (HttpMethod::Get, "/api/v1/health") => {
                let cors_only = if cors_headers_for_health.is_empty() {
                    None
                } else {
                    Some(cors_headers_for_health.as_str())
                };
                resp_status = 200;
                resp_size = r#"{"status":"ok"}"#.len() as u64;
                Self::send_json_response_with_headers(
                    &mut stream,
                    200,
                    "OK",
                    r#"{"status":"ok"}"#,
                    cors_only,
                )
                .await?;
            }
            (HttpMethod::Get, "/api/v1/status") => {
                let body = Self::build_status_response(
                    shared_module_names,
                    shared_metrics,
                    shared_module_restarts,
                    started_at,
                );
                resp_status = 200;
                resp_size = body.len() as u64;
                Self::send_json_response_with_headers(&mut stream, 200, "OK", &body, extra).await?;
            }
            (HttpMethod::Get, "/api/v1/modules") => {
                let body =
                    Self::build_modules_response(shared_module_names, shared_module_restarts);
                resp_status = 200;
                resp_size = body.len() as u64;
                Self::send_json_response_with_headers(&mut stream, 200, "OK", &body, extra).await?;
            }
            (HttpMethod::Get, path_str) if path_str.starts_with("/api/v1/events/summary") => {
                match event_store_db_path {
                    Some(db_path) => {
                        let sub_path = &path_str["/api/v1/events/summary".len()..];
                        match Self::handle_events_summary(db_path, sub_path, &query_params) {
                            Ok(body) => {
                                resp_status = 200;
                                resp_size = body.len() as u64;
                                Self::send_json_response_with_headers(
                                    &mut stream,
                                    200,
                                    "OK",
                                    &body,
                                    extra,
                                )
                                .await?;
                            }
                            Err((status, msg)) => {
                                let err_body =
                                    format!(r#"{{"error":"{}"}}"#, Self::escape_json_string(&msg));
                                resp_status = status;
                                resp_size = err_body.len() as u64;
                                Self::send_error_with_headers(
                                    &mut stream,
                                    status,
                                    "Error",
                                    &err_body,
                                    extra,
                                )
                                .await?;
                            }
                        }
                    }
                    None => {
                        let err_body = r#"{"error":"イベントストアが無効です"}"#;
                        resp_status = 503;
                        resp_size = err_body.len() as u64;
                        Self::send_error_with_headers(
                            &mut stream,
                            503,
                            "Service Unavailable",
                            err_body,
                            extra,
                        )
                        .await?;
                    }
                }
            }
            (HttpMethod::Get, "/api/v1/events") => match event_store_db_path {
                Some(db_path) => match Self::build_events_response(
                    db_path,
                    &query_params,
                    default_page_size,
                    max_page_size,
                ) {
                    Ok(body) => {
                        resp_status = 200;
                        resp_size = body.len() as u64;
                        Self::send_json_response_with_headers(&mut stream, 200, "OK", &body, extra)
                            .await?;
                    }
                    Err(e) => {
                        let err_body = format!(r#"{{"error":"{}"}}"#, Self::escape_json_string(&e));
                        resp_status = 500;
                        resp_size = err_body.len() as u64;
                        Self::send_error_with_headers(
                            &mut stream,
                            500,
                            "Internal Server Error",
                            &e,
                            extra,
                        )
                        .await?;
                    }
                },
                None => {
                    let err_body = format!(
                        r#"{{"error":"{}"}}"#,
                        Self::escape_json_string("イベントストアが無効です")
                    );
                    resp_status = 503;
                    resp_size = err_body.len() as u64;
                    Self::send_error_with_headers(
                        &mut stream,
                        503,
                        "Service Unavailable",
                        "イベントストアが無効です",
                        extra,
                    )
                    .await?;
                }
            },
            (HttpMethod::Get, "/api/v1/score") => match shared_scoring {
                Some(scoring) => {
                    let body = if let Ok(s) = scoring.lock() {
                        serde_json::to_string(&*s)
                            .unwrap_or_else(|_| r#"{"error":"serialize failed"}"#.to_string())
                    } else {
                        r#"{"error":"lock failed"}"#.to_string()
                    };
                    resp_status = 200;
                    resp_size = body.len() as u64;
                    Self::send_json_response_with_headers(&mut stream, 200, "OK", &body, extra)
                        .await?;
                }
                None => {
                    let err_body = format!(
                        r#"{{"error":"{}"}}"#,
                        Self::escape_json_string("スコアリングが無効です")
                    );
                    resp_status = 503;
                    resp_size = err_body.len() as u64;
                    Self::send_error_with_headers(
                        &mut stream,
                        503,
                        "Service Unavailable",
                        "スコアリングが無効です",
                        extra,
                    )
                    .await?;
                }
            },
            (HttpMethod::Post, "/api/v1/reload") => {
                if is_dry_run(&query_params) {
                    let result = match config_path {
                        Some(path) => {
                            let p = std::path::Path::new(path);
                            match crate::config::AppConfig::load(p) {
                                Ok(config) => match config.validate() {
                                    Ok(()) => {
                                        r#"{"dry_run":true,"message":"設定ファイルは有効です","details":{"config_valid":true,"errors":[]}}"#.to_string()
                                    }
                                    Err(e) => {
                                        format!(
                                            r#"{{"dry_run":true,"message":"設定ファイルにエラーがあります","details":{{"config_valid":false,"errors":["{}"]}}}}"#,
                                            Self::escape_json_string(&e.to_string())
                                        )
                                    }
                                },
                                Err(e) => {
                                    format!(
                                        r#"{{"dry_run":true,"message":"設定ファイルの読み込みに失敗","details":{{"config_valid":false,"errors":["{}"]}}}}"#,
                                        Self::escape_json_string(&e.to_string())
                                    )
                                }
                            }
                        }
                        None => {
                            r#"{"dry_run":true,"message":"設定ファイルパスが不明です","details":{"config_valid":false,"errors":["設定ファイルパスが指定されていません"]}}"#.to_string()
                        }
                    };
                    resp_status = 200;
                    resp_size = result.len() as u64;
                    Self::send_json_response_with_headers(&mut stream, 200, "OK", &result, extra)
                        .await?;
                } else {
                    match reload_sender.try_send(()) {
                        Ok(()) => {
                            let reload_body = r#"{"message":"リロードをトリガーしました"}"#;
                            resp_status = 200;
                            resp_size = reload_body.len() as u64;
                            Self::send_json_response_with_headers(
                                &mut stream,
                                200,
                                "OK",
                                reload_body,
                                extra,
                            )
                            .await?;
                        }
                        Err(e) => {
                            let msg = format!("リロードのトリガーに失敗しました: {}", e);
                            let err_body =
                                format!(r#"{{"error":"{}"}}"#, Self::escape_json_string(&msg));
                            resp_status = 500;
                            resp_size = err_body.len() as u64;
                            Self::send_error_with_headers(
                                &mut stream,
                                500,
                                "Internal Server Error",
                                &msg,
                                extra,
                            )
                            .await?;
                        }
                    }
                }
            }
            (HttpMethod::Post, "/api/v1/events/batch/delete") => match event_store_db_path {
                Some(db_path) => {
                    let body_result = tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        Self::read_request_with_body(&mut stream, max_request_body_size),
                    )
                    .await;
                    let full = match body_result {
                        Ok(Ok(s)) => s,
                        Ok(Err(e)) => {
                            let msg = format!("リクエストの読み取りに失敗: {}", e);
                            let err_body =
                                format!(r#"{{"error":"{}"}}"#, Self::escape_json_string(&msg));
                            Self::send_error_with_headers(
                                &mut stream,
                                400,
                                "Bad Request",
                                &msg,
                                extra,
                            )
                            .await?;
                            if access_log_enabled {
                                Self::log_access(
                                    method_str,
                                    &path,
                                    400,
                                    request_start,
                                    client_ip,
                                    user_agent,
                                    request_size,
                                    err_body.len() as u64,
                                );
                            }
                            stream.shutdown().await?;
                            return Ok(());
                        }
                        Err(_) => {
                            let err_body = format!(
                                r#"{{"error":"{}"}}"#,
                                Self::escape_json_string("リクエストタイムアウト")
                            );
                            Self::send_error_with_headers(
                                &mut stream,
                                408,
                                "Request Timeout",
                                "リクエストタイムアウト",
                                extra,
                            )
                            .await?;
                            if access_log_enabled {
                                Self::log_access(
                                    method_str,
                                    &path,
                                    408,
                                    request_start,
                                    client_ip,
                                    user_agent,
                                    request_size,
                                    err_body.len() as u64,
                                );
                            }
                            stream.shutdown().await?;
                            return Ok(());
                        }
                    };
                    let body = full.split("\r\n\r\n").nth(1).unwrap_or("");
                    match Self::handle_batch_delete(
                        db_path,
                        body,
                        batch_max_size,
                        is_dry_run(&query_params),
                    ) {
                        Ok(resp) => {
                            resp_status = 200;
                            resp_size = resp.len() as u64;
                            Self::send_json_response_with_headers(
                                &mut stream,
                                200,
                                "OK",
                                &resp,
                                extra,
                            )
                            .await?;
                        }
                        Err((status, msg)) => {
                            let status_text = match status {
                                400 => "Bad Request",
                                500 => "Internal Server Error",
                                _ => "Error",
                            };
                            let err_body =
                                format!(r#"{{"error":"{}"}}"#, Self::escape_json_string(&msg));
                            resp_status = status;
                            resp_size = err_body.len() as u64;
                            Self::send_error_with_headers(
                                &mut stream,
                                status,
                                status_text,
                                &msg,
                                extra,
                            )
                            .await?;
                        }
                    }
                }
                None => {
                    let err_body = format!(
                        r#"{{"error":"{}"}}"#,
                        Self::escape_json_string("イベントストアが無効です")
                    );
                    resp_status = 503;
                    resp_size = err_body.len() as u64;
                    Self::send_error_with_headers(
                        &mut stream,
                        503,
                        "Service Unavailable",
                        "イベントストアが無効です",
                        extra,
                    )
                    .await?;
                }
            },
            (HttpMethod::Post, "/api/v1/events/batch/export") => match event_store_db_path {
                Some(db_path) => {
                    let body_result = tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        Self::read_request_with_body(&mut stream, max_request_body_size),
                    )
                    .await;
                    let full = match body_result {
                        Ok(Ok(s)) => s,
                        Ok(Err(e)) => {
                            let msg = format!("リクエストの読み取りに失敗: {}", e);
                            let err_body =
                                format!(r#"{{"error":"{}"}}"#, Self::escape_json_string(&msg));
                            Self::send_error_with_headers(
                                &mut stream,
                                400,
                                "Bad Request",
                                &msg,
                                extra,
                            )
                            .await?;
                            if access_log_enabled {
                                Self::log_access(
                                    method_str,
                                    &path,
                                    400,
                                    request_start,
                                    client_ip,
                                    user_agent,
                                    request_size,
                                    err_body.len() as u64,
                                );
                            }
                            stream.shutdown().await?;
                            return Ok(());
                        }
                        Err(_) => {
                            let err_body = format!(
                                r#"{{"error":"{}"}}"#,
                                Self::escape_json_string("リクエストタイムアウト")
                            );
                            Self::send_error_with_headers(
                                &mut stream,
                                408,
                                "Request Timeout",
                                "リクエストタイムアウト",
                                extra,
                            )
                            .await?;
                            if access_log_enabled {
                                Self::log_access(
                                    method_str,
                                    &path,
                                    408,
                                    request_start,
                                    client_ip,
                                    user_agent,
                                    request_size,
                                    err_body.len() as u64,
                                );
                            }
                            stream.shutdown().await?;
                            return Ok(());
                        }
                    };
                    let body = full.split("\r\n\r\n").nth(1).unwrap_or("");
                    match Self::handle_batch_export(db_path, body, batch_max_size) {
                        Ok(resp) => {
                            resp_status = 200;
                            resp_size = resp.len() as u64;
                            Self::send_json_response_with_headers(
                                &mut stream,
                                200,
                                "OK",
                                &resp,
                                extra,
                            )
                            .await?;
                        }
                        Err((status, msg)) => {
                            let status_text = match status {
                                400 => "Bad Request",
                                500 => "Internal Server Error",
                                _ => "Error",
                            };
                            let err_body =
                                format!(r#"{{"error":"{}"}}"#, Self::escape_json_string(&msg));
                            resp_status = status;
                            resp_size = err_body.len() as u64;
                            Self::send_error_with_headers(
                                &mut stream,
                                status,
                                status_text,
                                &msg,
                                extra,
                            )
                            .await?;
                        }
                    }
                }
                None => {
                    let err_body = format!(
                        r#"{{"error":"{}"}}"#,
                        Self::escape_json_string("イベントストアが無効です")
                    );
                    resp_status = 503;
                    resp_size = err_body.len() as u64;
                    Self::send_error_with_headers(
                        &mut stream,
                        503,
                        "Service Unavailable",
                        "イベントストアが無効です",
                        extra,
                    )
                    .await?;
                }
            },
            (HttpMethod::Post, "/api/v1/events/batch/acknowledge") => match event_store_db_path {
                Some(db_path) => {
                    let body_result = tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        Self::read_request_with_body(&mut stream, max_request_body_size),
                    )
                    .await;
                    let full = match body_result {
                        Ok(Ok(s)) => s,
                        Ok(Err(e)) => {
                            let msg = format!("リクエストの読み取りに失敗: {}", e);
                            let err_body =
                                format!(r#"{{"error":"{}"}}"#, Self::escape_json_string(&msg));
                            Self::send_error_with_headers(
                                &mut stream,
                                400,
                                "Bad Request",
                                &msg,
                                extra,
                            )
                            .await?;
                            if access_log_enabled {
                                Self::log_access(
                                    method_str,
                                    &path,
                                    400,
                                    request_start,
                                    client_ip,
                                    user_agent,
                                    request_size,
                                    err_body.len() as u64,
                                );
                            }
                            stream.shutdown().await?;
                            return Ok(());
                        }
                        Err(_) => {
                            let err_body = format!(
                                r#"{{"error":"{}"}}"#,
                                Self::escape_json_string("リクエストタイムアウト")
                            );
                            Self::send_error_with_headers(
                                &mut stream,
                                408,
                                "Request Timeout",
                                "リクエストタイムアウト",
                                extra,
                            )
                            .await?;
                            if access_log_enabled {
                                Self::log_access(
                                    method_str,
                                    &path,
                                    408,
                                    request_start,
                                    client_ip,
                                    user_agent,
                                    request_size,
                                    err_body.len() as u64,
                                );
                            }
                            stream.shutdown().await?;
                            return Ok(());
                        }
                    };
                    let body = full.split("\r\n\r\n").nth(1).unwrap_or("");
                    match Self::handle_batch_acknowledge(
                        db_path,
                        body,
                        batch_max_size,
                        is_dry_run(&query_params),
                    ) {
                        Ok(resp) => {
                            resp_status = 200;
                            resp_size = resp.len() as u64;
                            Self::send_json_response_with_headers(
                                &mut stream,
                                200,
                                "OK",
                                &resp,
                                extra,
                            )
                            .await?;
                        }
                        Err((status, msg)) => {
                            let status_text = match status {
                                400 => "Bad Request",
                                500 => "Internal Server Error",
                                _ => "Error",
                            };
                            let err_body =
                                format!(r#"{{"error":"{}"}}"#, Self::escape_json_string(&msg));
                            resp_status = status;
                            resp_size = err_body.len() as u64;
                            Self::send_error_with_headers(
                                &mut stream,
                                status,
                                status_text,
                                &msg,
                                extra,
                            )
                            .await?;
                        }
                    }
                }
                None => {
                    let err_body = format!(
                        r#"{{"error":"{}"}}"#,
                        Self::escape_json_string("イベントストアが無効です")
                    );
                    resp_status = 503;
                    resp_size = err_body.len() as u64;
                    Self::send_error_with_headers(
                        &mut stream,
                        503,
                        "Service Unavailable",
                        "イベントストアが無効です",
                        extra,
                    )
                    .await?;
                }
            },
            (HttpMethod::Get, "/api/v1/archives") => match archive_dir {
                Some(dir) => match Self::handle_archives_list(dir) {
                    Ok(body) => {
                        resp_status = 200;
                        resp_size = body.len() as u64;
                        Self::send_json_response_with_headers(&mut stream, 200, "OK", &body, extra)
                            .await?;
                    }
                    Err(msg) => {
                        let err_body =
                            format!(r#"{{"error":"{}"}}"#, Self::escape_json_string(&msg));
                        resp_status = 500;
                        resp_size = err_body.len() as u64;
                        Self::send_error_with_headers(
                            &mut stream,
                            500,
                            "Internal Server Error",
                            &msg,
                            extra,
                        )
                        .await?;
                    }
                },
                None => {
                    resp_status = 503;
                    let err_body = format!(
                        r#"{{"error":"{}"}}"#,
                        Self::escape_json_string("アーカイブ機能が無効です")
                    );
                    resp_size = err_body.len() as u64;
                    Self::send_error_with_headers(
                        &mut stream,
                        503,
                        "Service Unavailable",
                        "アーカイブ機能が無効です",
                        extra,
                    )
                    .await?;
                }
            },
            (HttpMethod::Post, "/api/v1/archives") => match archive_dir {
                Some(dir) => match event_store_db_path {
                    Some(db_path) => {
                        let body_result = tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            Self::read_request_with_body(&mut stream, max_request_body_size),
                        )
                        .await;
                        let full = match body_result {
                            Ok(Ok(s)) => s,
                            Ok(Err(e)) => {
                                let msg = format!("リクエストの読み取りに失敗: {}", e);
                                Self::send_error_with_headers(
                                    &mut stream,
                                    400,
                                    "Bad Request",
                                    &msg,
                                    extra,
                                )
                                .await?;
                                let err_body =
                                    format!(r#"{{"error":"{}"}}"#, Self::escape_json_string(&msg));
                                if access_log_enabled {
                                    Self::log_access(
                                        method_str,
                                        &path,
                                        400,
                                        request_start,
                                        client_ip,
                                        user_agent,
                                        request_size,
                                        err_body.len() as u64,
                                    );
                                }
                                stream.shutdown().await?;
                                return Ok(());
                            }
                            Err(_) => {
                                Self::send_error_with_headers(
                                    &mut stream,
                                    408,
                                    "Request Timeout",
                                    "リクエストタイムアウト",
                                    extra,
                                )
                                .await?;
                                let err_body = format!(
                                    r#"{{"error":"{}"}}"#,
                                    Self::escape_json_string("リクエストタイムアウト")
                                );
                                if access_log_enabled {
                                    Self::log_access(
                                        method_str,
                                        &path,
                                        408,
                                        request_start,
                                        client_ip,
                                        user_agent,
                                        request_size,
                                        err_body.len() as u64,
                                    );
                                }
                                stream.shutdown().await?;
                                return Ok(());
                            }
                        };
                        let body = full.split("\r\n\r\n").nth(1).unwrap_or("");
                        match Self::handle_archives_create(
                            db_path,
                            dir,
                            body,
                            archive_config,
                            is_dry_run(&query_params),
                        ) {
                            Ok(resp) => {
                                resp_status = 200;
                                resp_size = resp.len() as u64;
                                Self::send_json_response_with_headers(
                                    &mut stream,
                                    200,
                                    "OK",
                                    &resp,
                                    extra,
                                )
                                .await?;
                            }
                            Err((status, msg)) => {
                                let status_text = match status {
                                    400 => "Bad Request",
                                    500 => "Internal Server Error",
                                    _ => "Error",
                                };
                                let err_body =
                                    format!(r#"{{"error":"{}"}}"#, Self::escape_json_string(&msg));
                                resp_status = status;
                                resp_size = err_body.len() as u64;
                                Self::send_error_with_headers(
                                    &mut stream,
                                    status,
                                    status_text,
                                    &msg,
                                    extra,
                                )
                                .await?;
                            }
                        }
                    }
                    None => {
                        resp_status = 503;
                        let err_body = format!(
                            r#"{{"error":"{}"}}"#,
                            Self::escape_json_string("イベントストアが無効です")
                        );
                        resp_size = err_body.len() as u64;
                        Self::send_error_with_headers(
                            &mut stream,
                            503,
                            "Service Unavailable",
                            "イベントストアが無効です",
                            extra,
                        )
                        .await?;
                    }
                },
                None => {
                    resp_status = 503;
                    let err_body = format!(
                        r#"{{"error":"{}"}}"#,
                        Self::escape_json_string("アーカイブ機能が無効です")
                    );
                    resp_size = err_body.len() as u64;
                    Self::send_error_with_headers(
                        &mut stream,
                        503,
                        "Service Unavailable",
                        "アーカイブ機能が無効です",
                        extra,
                    )
                    .await?;
                }
            },
            (HttpMethod::Post, "/api/v1/archives/restore") => match archive_dir {
                Some(dir) => match event_store_db_path {
                    Some(db_path) => {
                        let body_result = tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            Self::read_request_with_body(&mut stream, max_request_body_size),
                        )
                        .await;
                        let full = match body_result {
                            Ok(Ok(s)) => s,
                            Ok(Err(e)) => {
                                let msg = format!("リクエストの読み取りに失敗: {}", e);
                                Self::send_error_with_headers(
                                    &mut stream,
                                    400,
                                    "Bad Request",
                                    &msg,
                                    extra,
                                )
                                .await?;
                                let err_body =
                                    format!(r#"{{"error":"{}"}}"#, Self::escape_json_string(&msg));
                                if access_log_enabled {
                                    Self::log_access(
                                        method_str,
                                        &path,
                                        400,
                                        request_start,
                                        client_ip,
                                        user_agent,
                                        request_size,
                                        err_body.len() as u64,
                                    );
                                }
                                stream.shutdown().await?;
                                return Ok(());
                            }
                            Err(_) => {
                                Self::send_error_with_headers(
                                    &mut stream,
                                    408,
                                    "Request Timeout",
                                    "リクエストタイムアウト",
                                    extra,
                                )
                                .await?;
                                let err_body = format!(
                                    r#"{{"error":"{}"}}"#,
                                    Self::escape_json_string("リクエストタイムアウト")
                                );
                                if access_log_enabled {
                                    Self::log_access(
                                        method_str,
                                        &path,
                                        408,
                                        request_start,
                                        client_ip,
                                        user_agent,
                                        request_size,
                                        err_body.len() as u64,
                                    );
                                }
                                stream.shutdown().await?;
                                return Ok(());
                            }
                        };
                        let body = full.split("\r\n\r\n").nth(1).unwrap_or("");
                        match Self::handle_archives_restore(
                            db_path,
                            dir,
                            body,
                            is_dry_run(&query_params),
                        ) {
                            Ok(resp) => {
                                resp_status = 200;
                                resp_size = resp.len() as u64;
                                Self::send_json_response_with_headers(
                                    &mut stream,
                                    200,
                                    "OK",
                                    &resp,
                                    extra,
                                )
                                .await?;
                            }
                            Err((status, msg)) => {
                                let status_text = match status {
                                    400 => "Bad Request",
                                    500 => "Internal Server Error",
                                    _ => "Error",
                                };
                                let err_body =
                                    format!(r#"{{"error":"{}"}}"#, Self::escape_json_string(&msg));
                                resp_status = status;
                                resp_size = err_body.len() as u64;
                                Self::send_error_with_headers(
                                    &mut stream,
                                    status,
                                    status_text,
                                    &msg,
                                    extra,
                                )
                                .await?;
                            }
                        }
                    }
                    None => {
                        resp_status = 503;
                        let err_body = format!(
                            r#"{{"error":"{}"}}"#,
                            Self::escape_json_string("イベントストアが無効です")
                        );
                        resp_size = err_body.len() as u64;
                        Self::send_error_with_headers(
                            &mut stream,
                            503,
                            "Service Unavailable",
                            "イベントストアが無効です",
                            extra,
                        )
                        .await?;
                    }
                },
                None => {
                    resp_status = 503;
                    let err_body = format!(
                        r#"{{"error":"{}"}}"#,
                        Self::escape_json_string("アーカイブ機能が無効です")
                    );
                    resp_size = err_body.len() as u64;
                    Self::send_error_with_headers(
                        &mut stream,
                        503,
                        "Service Unavailable",
                        "アーカイブ機能が無効です",
                        extra,
                    )
                    .await?;
                }
            },
            (HttpMethod::Post, "/api/v1/archives/rotate") => match archive_dir {
                Some(dir) => {
                    let body_result = tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        Self::read_request_with_body(&mut stream, max_request_body_size),
                    )
                    .await;
                    let full = match body_result {
                        Ok(Ok(s)) => s,
                        Ok(Err(e)) => {
                            let msg = format!("リクエストの読み取りに失敗: {}", e);
                            Self::send_error_with_headers(
                                &mut stream,
                                400,
                                "Bad Request",
                                &msg,
                                extra,
                            )
                            .await?;
                            let err_body =
                                format!(r#"{{"error":"{}"}}"#, Self::escape_json_string(&msg));
                            if access_log_enabled {
                                Self::log_access(
                                    method_str,
                                    &path,
                                    400,
                                    request_start,
                                    client_ip,
                                    user_agent,
                                    request_size,
                                    err_body.len() as u64,
                                );
                            }
                            stream.shutdown().await?;
                            return Ok(());
                        }
                        Err(_) => {
                            Self::send_error_with_headers(
                                &mut stream,
                                408,
                                "Request Timeout",
                                "リクエストタイムアウト",
                                extra,
                            )
                            .await?;
                            let err_body = format!(
                                r#"{{"error":"{}"}}"#,
                                Self::escape_json_string("リクエストタイムアウト")
                            );
                            if access_log_enabled {
                                Self::log_access(
                                    method_str,
                                    &path,
                                    408,
                                    request_start,
                                    client_ip,
                                    user_agent,
                                    request_size,
                                    err_body.len() as u64,
                                );
                            }
                            stream.shutdown().await?;
                            return Ok(());
                        }
                    };
                    let body = full.split("\r\n\r\n").nth(1).unwrap_or("");
                    match Self::handle_archives_rotate(
                        dir,
                        body,
                        archive_config,
                        is_dry_run(&query_params),
                    ) {
                        Ok(resp) => {
                            resp_status = 200;
                            resp_size = resp.len() as u64;
                            Self::send_json_response_with_headers(
                                &mut stream,
                                200,
                                "OK",
                                &resp,
                                extra,
                            )
                            .await?;
                        }
                        Err((status, msg)) => {
                            let status_text = match status {
                                400 => "Bad Request",
                                500 => "Internal Server Error",
                                _ => "Error",
                            };
                            let err_body =
                                format!(r#"{{"error":"{}"}}"#, Self::escape_json_string(&msg));
                            resp_status = status;
                            resp_size = err_body.len() as u64;
                            Self::send_error_with_headers(
                                &mut stream,
                                status,
                                status_text,
                                &msg,
                                extra,
                            )
                            .await?;
                        }
                    }
                }
                None => {
                    resp_status = 503;
                    let err_body = format!(
                        r#"{{"error":"{}"}}"#,
                        Self::escape_json_string("アーカイブ機能が無効です")
                    );
                    resp_size = err_body.len() as u64;
                    Self::send_error_with_headers(
                        &mut stream,
                        503,
                        "Service Unavailable",
                        "アーカイブ機能が無効です",
                        extra,
                    )
                    .await?;
                }
            },
            (HttpMethod::Delete, p) if p.starts_with("/api/v1/archives/") => match archive_dir {
                Some(dir) => {
                    let filename = &p["/api/v1/archives/".len()..];
                    match Self::handle_archive_delete(dir, filename, is_dry_run(&query_params)) {
                        Ok(resp) => {
                            resp_status = 200;
                            resp_size = resp.len() as u64;
                            Self::send_json_response_with_headers(
                                &mut stream,
                                200,
                                "OK",
                                &resp,
                                extra,
                            )
                            .await?;
                        }
                        Err((status, msg)) => {
                            let status_text = match status {
                                400 => "Bad Request",
                                404 => "Not Found",
                                500 => "Internal Server Error",
                                _ => "Error",
                            };
                            let err_body =
                                format!(r#"{{"error":"{}"}}"#, Self::escape_json_string(&msg));
                            resp_status = status;
                            resp_size = err_body.len() as u64;
                            Self::send_error_with_headers(
                                &mut stream,
                                status,
                                status_text,
                                &msg,
                                extra,
                            )
                            .await?;
                        }
                    }
                }
                None => {
                    resp_status = 503;
                    let err_body = format!(
                        r#"{{"error":"{}"}}"#,
                        Self::escape_json_string("アーカイブ機能が無効です")
                    );
                    resp_size = err_body.len() as u64;
                    Self::send_error_with_headers(
                        &mut stream,
                        503,
                        "Service Unavailable",
                        "アーカイブ機能が無効です",
                        extra,
                    )
                    .await?;
                }
            },
            (HttpMethod::Get, "/api/v1/openapi.json") => {
                if openapi_enabled {
                    let schema = openapi::generate_openapi_schema();
                    let body = serde_json::to_string(&schema).unwrap_or_else(|_| {
                        r#"{"error":"OpenAPI スキーマの生成に失敗しました"}"#.to_string()
                    });
                    let cors_only = if cors_headers_for_health.is_empty() {
                        None
                    } else {
                        Some(cors_headers_for_health.as_str())
                    };
                    resp_status = 200;
                    resp_size = body.len() as u64;
                    Self::send_json_response_with_headers(&mut stream, 200, "OK", &body, cors_only)
                        .await?;
                } else {
                    let err_body = format!(
                        r#"{{"error":"{}"}}"#,
                        Self::escape_json_string("OpenAPI スキーマが無効です")
                    );
                    resp_status = 404;
                    resp_size = err_body.len() as u64;
                    Self::send_error_with_headers(
                        &mut stream,
                        404,
                        "Not Found",
                        "OpenAPI スキーマが無効です",
                        extra,
                    )
                    .await?;
                }
            }
            (HttpMethod::Get, "/api/v1/webhooks") => {
                let body = Self::build_webhooks_response(shared_action_config);
                resp_status = 200;
                resp_size = body.len() as u64;
                Self::send_json_response_with_headers(&mut stream, 200, "OK", &body, extra).await?;
            }
            (HttpMethod::Post, "/api/v1/webhooks/test") => {
                let body_result = tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    Self::read_request_with_body(&mut stream, max_request_body_size),
                )
                .await;
                let full = match body_result {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        let msg = format!("リクエストの読み取りに失敗: {}", e);
                        Self::send_error_with_headers(&mut stream, 400, "Bad Request", &msg, extra)
                            .await?;
                        let err_body =
                            format!(r#"{{"error":"{}"}}"#, Self::escape_json_string(&msg));
                        if access_log_enabled {
                            Self::log_access(
                                method_str,
                                &path,
                                400,
                                request_start,
                                client_ip,
                                user_agent,
                                request_size,
                                err_body.len() as u64,
                            );
                        }
                        stream.shutdown().await?;
                        return Ok(());
                    }
                    Err(_) => {
                        Self::send_error_with_headers(
                            &mut stream,
                            408,
                            "Request Timeout",
                            "リクエストタイムアウト",
                            extra,
                        )
                        .await?;
                        let err_body = format!(
                            r#"{{"error":"{}"}}"#,
                            Self::escape_json_string("リクエストタイムアウト")
                        );
                        if access_log_enabled {
                            Self::log_access(
                                method_str,
                                &path,
                                408,
                                request_start,
                                client_ip,
                                user_agent,
                                request_size,
                                err_body.len() as u64,
                            );
                        }
                        stream.shutdown().await?;
                        return Ok(());
                    }
                };
                let req_body = full.split("\r\n\r\n").nth(1).unwrap_or("");
                if req_body.is_empty() {
                    resp_status = 400;
                    let err_body = r#"{"error":"リクエストボディが必要です"}"#;
                    resp_size = err_body.len() as u64;
                    Self::send_error_with_headers(
                        &mut stream,
                        400,
                        "Bad Request",
                        "リクエストボディが必要です",
                        extra,
                    )
                    .await?;
                } else {
                    let body = Self::handle_webhook_test(shared_action_config, req_body).await;
                    let status = if body.contains(r#""success":true"#) {
                        200
                    } else if body.contains("が見つかりません") {
                        404
                    } else {
                        502
                    };
                    resp_status = status;
                    resp_size = body.len() as u64;
                    let status_text = match status {
                        200 => "OK",
                        404 => "Not Found",
                        _ => "Bad Gateway",
                    };
                    Self::send_json_response_with_headers(
                        &mut stream,
                        status,
                        status_text,
                        &body,
                        extra,
                    )
                    .await?;
                }
            }
            (HttpMethod::Post, _)
                if path.starts_with("/api/v1/modules/")
                    && (path.ends_with("/start")
                        || path.ends_with("/stop")
                        || path.ends_with("/restart")) =>
            {
                let parts: Vec<&str> = path.split('/').collect();
                // /api/v1/modules/{name}/{action} => ["", "api", "v1", "modules", "{name}", "{action}"]
                if parts.len() == 6 {
                    let module_name = parts[4];
                    let action = parts[5];
                    let dry_run = is_dry_run(&query_params);

                    if dry_run {
                        // dry_run: 実際には操作せず、バリデーションのみ
                        let names = shared_module_names.lock().unwrap().clone();
                        let is_running = names.iter().any(|n| n == module_name);

                        let (valid, message) = match action {
                            "start" if is_running => (false, "モジュールは既に起動中です"),
                            "stop" if !is_running => (false, "モジュールは起動していません"),
                            _ => (true, "操作を実行可能です"),
                        };

                        let body = format!(
                            r#"{{"dry_run":true,"valid":{},"module":"{}","action":"{}","message":"{}"}}"#,
                            valid,
                            Self::escape_json_string(module_name),
                            Self::escape_json_string(action),
                            Self::escape_json_string(message),
                        );
                        resp_status = 200;
                        resp_size = body.len() as u64;
                        Self::send_json_response_with_headers(&mut stream, 200, "OK", &body, extra)
                            .await?;
                    } else {
                        let cmd = match action {
                            "start" => ModuleControlCommand::Start(module_name.to_string()),
                            "stop" => ModuleControlCommand::Stop(module_name.to_string()),
                            "restart" => ModuleControlCommand::Restart(module_name.to_string()),
                            _ => unreachable!(),
                        };

                        let (tx, rx) = tokio::sync::oneshot::channel();
                        if module_control_sender.send((cmd, tx)).await.is_ok() {
                            match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await
                            {
                                Ok(Ok(result)) => {
                                    let (status, body) = match result {
                                        ModuleControlResult::Ok(msg) => (
                                            200u16,
                                            format!(
                                                r#"{{"success":true,"module":"{}","action":"{}","message":"{}"}}"#,
                                                Self::escape_json_string(module_name),
                                                Self::escape_json_string(action),
                                                Self::escape_json_string(&msg),
                                            ),
                                        ),
                                        ModuleControlResult::NotFound(msg) => (
                                            404,
                                            format!(
                                                r#"{{"error":"{}"}}"#,
                                                Self::escape_json_string(&msg),
                                            ),
                                        ),
                                        ModuleControlResult::Conflict(msg) => (
                                            409,
                                            format!(
                                                r#"{{"error":"{}"}}"#,
                                                Self::escape_json_string(&msg),
                                            ),
                                        ),
                                        ModuleControlResult::Error(msg) => (
                                            500,
                                            format!(
                                                r#"{{"error":"{}"}}"#,
                                                Self::escape_json_string(&msg),
                                            ),
                                        ),
                                    };
                                    let status_text = match status {
                                        200 => "OK",
                                        404 => "Not Found",
                                        409 => "Conflict",
                                        _ => "Internal Server Error",
                                    };
                                    resp_status = status;
                                    resp_size = body.len() as u64;
                                    Self::send_json_response_with_headers(
                                        &mut stream,
                                        status,
                                        status_text,
                                        &body,
                                        extra,
                                    )
                                    .await?;
                                }
                                Ok(Err(_)) => {
                                    resp_status = 500;
                                    let err_msg = "モジュール制御の応答が取得できません";
                                    let err_body = format!(
                                        r#"{{"error":"{}"}}"#,
                                        Self::escape_json_string(err_msg),
                                    );
                                    resp_size = err_body.len() as u64;
                                    Self::send_error_with_headers(
                                        &mut stream,
                                        500,
                                        "Internal Server Error",
                                        err_msg,
                                        extra,
                                    )
                                    .await?;
                                }
                                Err(_) => {
                                    resp_status = 504;
                                    let err_msg = "モジュール制御がタイムアウトしました";
                                    let err_body = format!(
                                        r#"{{"error":"{}"}}"#,
                                        Self::escape_json_string(err_msg),
                                    );
                                    resp_size = err_body.len() as u64;
                                    Self::send_error_with_headers(
                                        &mut stream,
                                        504,
                                        "Gateway Timeout",
                                        err_msg,
                                        extra,
                                    )
                                    .await?;
                                }
                            }
                        } else {
                            resp_status = 503;
                            let err_msg = "モジュール制御チャネルが利用できません";
                            let err_body =
                                format!(r#"{{"error":"{}"}}"#, Self::escape_json_string(err_msg),);
                            resp_size = err_body.len() as u64;
                            Self::send_error_with_headers(
                                &mut stream,
                                503,
                                "Service Unavailable",
                                err_msg,
                                extra,
                            )
                            .await?;
                        }
                    }
                } else {
                    resp_status = 400;
                    let err_msg = "不正なモジュール制御パスです";
                    let err_body =
                        format!(r#"{{"error":"{}"}}"#, Self::escape_json_string(err_msg),);
                    resp_size = err_body.len() as u64;
                    Self::send_error_with_headers(&mut stream, 400, "Bad Request", err_msg, extra)
                        .await?;
                }
            }
            (HttpMethod::Get, _)
            | (HttpMethod::Options, _)
            | (HttpMethod::Delete, _)
            | (HttpMethod::Other, _) => {
                if matches!(
                    path.as_str(),
                    "/api/v1/health"
                        | "/api/v1/status"
                        | "/api/v1/modules"
                        | "/api/v1/events"
                        | "/api/v1/reload"
                        | "/api/v1/openapi.json"
                        | "/api/v1/events/batch/delete"
                        | "/api/v1/events/batch/export"
                        | "/api/v1/events/batch/acknowledge"
                        | "/api/v1/archives"
                        | "/api/v1/archives/restore"
                        | "/api/v1/archives/rotate"
                        | "/api/v1/webhooks"
                        | "/api/v1/webhooks/test"
                ) || path.starts_with("/api/v1/archives/")
                    || path.starts_with("/api/v1/modules/")
                {
                    let err_body = format!(
                        r#"{{"error":"{}"}}"#,
                        Self::escape_json_string("許可されていないメソッドです")
                    );
                    resp_status = 405;
                    resp_size = err_body.len() as u64;
                    Self::send_error_with_headers(
                        &mut stream,
                        405,
                        "Method Not Allowed",
                        "許可されていないメソッドです",
                        extra,
                    )
                    .await?;
                } else {
                    let err_body = format!(
                        r#"{{"error":"{}"}}"#,
                        Self::escape_json_string("エンドポイントが見つかりません")
                    );
                    resp_status = 404;
                    resp_size = err_body.len() as u64;
                    Self::send_error_with_headers(
                        &mut stream,
                        404,
                        "Not Found",
                        "エンドポイントが見つかりません",
                        extra,
                    )
                    .await?;
                }
            }
            (HttpMethod::Post, _) => {
                let is_known_non_post = matches!(
                    path.as_str(),
                    "/api/v1/health"
                        | "/api/v1/status"
                        | "/api/v1/modules"
                        | "/api/v1/events"
                        | "/api/v1/openapi.json"
                        | "/api/v1/webhooks"
                ) || (path.starts_with("/api/v1/archives/")
                    && !matches!(
                        path.as_str(),
                        "/api/v1/archives/restore" | "/api/v1/archives/rotate"
                    ));
                if is_known_non_post {
                    let err_body = format!(
                        r#"{{"error":"{}"}}"#,
                        Self::escape_json_string("許可されていないメソッドです")
                    );
                    resp_status = 405;
                    resp_size = err_body.len() as u64;
                    Self::send_error_with_headers(
                        &mut stream,
                        405,
                        "Method Not Allowed",
                        "許可されていないメソッドです",
                        extra,
                    )
                    .await?;
                } else {
                    let err_body = format!(
                        r#"{{"error":"{}"}}"#,
                        Self::escape_json_string("エンドポイントが見つかりません")
                    );
                    resp_status = 404;
                    resp_size = err_body.len() as u64;
                    Self::send_error_with_headers(
                        &mut stream,
                        404,
                        "Not Found",
                        "エンドポイントが見つかりません",
                        extra,
                    )
                    .await?;
                }
            }
        }

        if access_log_enabled {
            Self::log_access(
                method_str,
                &path,
                resp_status,
                request_start,
                client_ip,
                user_agent,
                request_size,
                resp_size,
            );
        }

        stream.shutdown().await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn log_access(
        method_str: &str,
        path: &str,
        status_code: u16,
        request_start: Instant,
        client_ip: IpAddr,
        user_agent: &str,
        request_size: u64,
        response_size: u64,
    ) {
        let response_time_ms = request_start.elapsed().as_secs_f64() * 1000.0;
        let response_time_str = format!("{:.2}", response_time_ms);
        let client_ip_str = client_ip.to_string();
        if status_code >= 500 {
            tracing::error!(
                target: "api::access",
                http_method = %method_str,
                http_path = %path,
                http_status_code = status_code,
                http_response_time_ms = %response_time_str,
                http_client_ip = %client_ip_str,
                http_user_agent = %user_agent,
                http_request_size = request_size,
                http_response_size = response_size,
                "API リクエスト"
            );
        } else if status_code >= 400 {
            tracing::warn!(
                target: "api::access",
                http_method = %method_str,
                http_path = %path,
                http_status_code = status_code,
                http_response_time_ms = %response_time_str,
                http_client_ip = %client_ip_str,
                http_user_agent = %user_agent,
                http_request_size = request_size,
                http_response_size = response_size,
                "API リクエスト"
            );
        } else {
            tracing::info!(
                target: "api::access",
                http_method = %method_str,
                http_path = %path,
                http_status_code = status_code,
                http_response_time_ms = %response_time_str,
                http_client_ip = %client_ip_str,
                http_user_agent = %user_agent,
                http_request_size = request_size,
                http_response_size = response_size,
                "API リクエスト"
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_websocket(
        mut stream: MaybeTlsStream,
        raw: &str,
        query_params: &HashMap<String, String>,
        tokens: &Arc<StdMutex<Vec<ApiTokenConfig>>>,
        event_bus: &Option<broadcast::Sender<SecurityEvent>>,
        ws_config: &Arc<WebSocketConfig>,
        ws_connections: &Arc<AtomicUsize>,
    ) -> Result<(), io::Error> {
        if !ws_config.enabled {
            Self::send_error_with_headers(
                &mut stream,
                503,
                "Service Unavailable",
                "WebSocket ストリーミングが無効です",
                None,
            )
            .await?;
            stream.shutdown().await?;
            return Ok(());
        }

        // Upgrade ヘッダーの確認
        let has_upgrade = raw.lines().any(|line| {
            line.to_ascii_lowercase().starts_with("upgrade:")
                && line.to_ascii_lowercase().contains("websocket")
        });
        if !has_upgrade {
            let body = r#"{"error":"WebSocket Upgrade が必要です"}"#;
            let response = format!(
                "HTTP/1.1 426 Upgrade Required\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nUpgrade: websocket\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await?;
            stream.shutdown().await?;
            return Ok(());
        }

        // 認証チェック（Authorization ヘッダーまたは token クエリパラメータ）
        // unwrap safety: Mutex が poisoned になるのはパニック時のみ
        let token_list = tokens.lock().unwrap().clone();
        if !token_list.is_empty() {
            let auth_from_header = Self::authenticate(raw, &token_list);
            let authenticated = match auth_from_header {
                AuthResult::Authenticated(ref role) => role.has_permission(&ApiRole::ReadOnly),
                AuthResult::NoAuthRequired => true,
                AuthResult::Unauthorized => {
                    // Authorization ヘッダーがない場合、クエリパラメータを試す
                    if let Some(token_value) = query_params.get("token") {
                        let hash = Self::hash_token(token_value);
                        token_list.iter().any(|tc| {
                            tc.token_hash == hash && tc.role.has_permission(&ApiRole::ReadOnly)
                        })
                    } else {
                        false
                    }
                }
            };

            if !authenticated {
                Self::send_error_with_headers(
                    &mut stream,
                    401,
                    "Unauthorized",
                    "認証が必要です",
                    None,
                )
                .await?;
                stream.shutdown().await?;
                return Ok(());
            }
        }

        // 同時接続数チェック
        let current = ws_connections.fetch_add(1, Ordering::SeqCst);
        if current >= ws_config.max_connections {
            ws_connections.fetch_sub(1, Ordering::SeqCst);
            Self::send_error_with_headers(
                &mut stream,
                503,
                "Service Unavailable",
                "WebSocket 接続数が上限に達しています",
                None,
            )
            .await?;
            stream.shutdown().await?;
            return Ok(());
        }

        let event_sender = match event_bus {
            Some(sender) => sender.clone(),
            None => {
                ws_connections.fetch_sub(1, Ordering::SeqCst);
                Self::send_error_with_headers(
                    &mut stream,
                    503,
                    "Service Unavailable",
                    "イベントバスが無効です",
                    None,
                )
                .await?;
                stream.shutdown().await?;
                return Ok(());
            }
        };

        // フィルタ条件のパース
        let filter_modules: Option<Vec<String>> = query_params.get("module").map(|m| {
            m.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        });
        let filter_severity: Option<Severity> = query_params
            .get("severity")
            .and_then(|s| Severity::parse(s));

        // Sec-WebSocket-Key の取得
        let ws_key = raw.lines().find_map(|line| {
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("sec-websocket-key:") {
                Some(line["sec-websocket-key:".len()..].trim().to_string())
            } else {
                None
            }
        });
        let ws_key = match ws_key {
            Some(k) => k,
            None => {
                ws_connections.fetch_sub(1, Ordering::SeqCst);
                Self::send_error_with_headers(
                    &mut stream,
                    400,
                    "Bad Request",
                    "Sec-WebSocket-Key が見つかりません",
                    None,
                )
                .await?;
                stream.shutdown().await?;
                return Ok(());
            }
        };

        // WebSocket ハンドシェイク応答を生成
        let accept_key = Self::compute_ws_accept_key(&ws_key);
        let handshake_response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
            accept_key
        );
        stream.write_all(handshake_response.as_bytes()).await?;

        tracing::info!("WebSocket 接続を確立しました");

        // tokio-tungstenite で WebSocket ストリームに変換
        let ws_stream = tokio_tungstenite::WebSocketStream::from_raw_socket(
            stream,
            tokio_tungstenite::tungstenite::protocol::Role::Server,
            None,
        )
        .await;

        let ws_conns = Arc::clone(ws_connections);
        let ping_interval_secs = ws_config.ping_interval_secs;
        let idle_timeout_secs = ws_config.idle_timeout_secs;
        let buffer_size = ws_config.buffer_size;

        tokio::spawn(async move {
            Self::run_websocket_session(
                ws_stream,
                event_sender,
                filter_modules,
                filter_severity,
                ping_interval_secs,
                idle_timeout_secs,
                buffer_size,
            )
            .await;
            ws_conns.fetch_sub(1, Ordering::SeqCst);
            tracing::info!("WebSocket 接続を切断しました");
        });

        Ok(())
    }

    async fn run_websocket_session(
        ws_stream: tokio_tungstenite::WebSocketStream<MaybeTlsStream>,
        event_sender: broadcast::Sender<SecurityEvent>,
        filter_modules: Option<Vec<String>>,
        filter_severity: Option<Severity>,
        ping_interval_secs: u64,
        idle_timeout_secs: u64,
        buffer_size: usize,
    ) {
        use tokio_tungstenite::tungstenite::Message;

        let mut event_rx = event_sender.subscribe();
        let (mut ws_tx, mut ws_rx) = ws_stream.split();
        let mut ping_interval =
            tokio::time::interval(std::time::Duration::from_secs(ping_interval_secs));
        ping_interval.tick().await;
        let mut last_activity = Instant::now();

        // 送信バッファ
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Message>(buffer_size);

        // 送信タスク
        let send_task = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if ws_tx.send(msg).await.is_err() {
                    break;
                }
            }
        });

        loop {
            tokio::select! {
                result = event_rx.recv() => {
                    match result {
                        Ok(event) => {
                            if let Some(ref modules) = filter_modules
                                && !modules.iter().any(|m| m == &event.source_module)
                            {
                                continue;
                            }
                            if let Some(ref sev) = filter_severity
                                && event.severity < *sev
                            {
                                continue;
                            }
                            let json = Self::event_to_json(&event);
                            if tx.try_send(Message::Text(json.into())).is_err() {
                                tracing::debug!("WebSocket 送信バッファが満杯です");
                                break;
                            }
                            last_activity = Instant::now();
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(lagged = n, "WebSocket イベント受信が遅延しています");
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }
                msg = ws_rx.next() => {
                    match msg {
                        Some(Ok(Message::Pong(_))) => {
                            last_activity = Instant::now();
                        }
                        Some(Ok(Message::Close(_))) | None => {
                            break;
                        }
                        Some(Ok(_)) => {
                            last_activity = Instant::now();
                        }
                        Some(Err(_)) => {
                            break;
                        }
                    }
                }
                _ = ping_interval.tick() => {
                    if last_activity.elapsed() > std::time::Duration::from_secs(idle_timeout_secs) {
                        tracing::info!("WebSocket アイドルタイムアウト");
                        let _ = tx.send(Message::Close(None)).await;
                        break;
                    }
                    if tx.try_send(Message::Ping(Vec::new().into())).is_err() {
                        break;
                    }
                }
            }
        }

        send_task.abort();
    }

    fn event_to_json(event: &SecurityEvent) -> String {
        let timestamp = event
            .timestamp
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let details_part = match &event.details {
            Some(d) => format!(r#","details":"{}""#, Self::escape_json_string(d)),
            None => String::new(),
        };
        format!(
            r#"{{"event_type":"{}","severity":"{}","source_module":"{}","timestamp":{},"message":"{}"{}}}"#,
            Self::escape_json_string(&event.event_type),
            event.severity,
            Self::escape_json_string(&event.source_module),
            timestamp,
            Self::escape_json_string(&event.message),
            details_part
        )
    }

    fn compute_ws_accept_key(key: &str) -> String {
        use sha1::{Digest as Sha1Digest, Sha1};

        let mut hasher = Sha1::new();
        hasher.update(key.as_bytes());
        hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        let result = hasher.finalize();
        base64_encode(&result)
    }

    async fn read_request(stream: &mut MaybeTlsStream) -> Result<String, io::Error> {
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "空のリクエスト",
            ));
        }
        Ok(String::from_utf8_lossy(&buf[..n]).to_string())
    }

    async fn read_request_with_body(
        stream: &mut MaybeTlsStream,
        max_body_size: usize,
    ) -> Result<String, io::Error> {
        let mut buf = Vec::with_capacity(4096);
        let mut tmp = [0u8; 4096];
        let header_end;

        loop {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "空のリクエスト",
                ));
            }
            buf.extend_from_slice(&tmp[..n]);

            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                header_end = pos + 4;
                break;
            }

            if buf.len() > 16384 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ヘッダーが大きすぎます",
                ));
            }
        }

        let header_str = String::from_utf8_lossy(&buf[..header_end]);
        let content_length: usize = header_str
            .lines()
            .find_map(|line| {
                let lower = line.to_ascii_lowercase();
                if lower.starts_with("content-length:") {
                    line["content-length:".len()..].trim().parse().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0);

        if content_length > max_body_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "リクエストボディが大きすぎます",
            ));
        }

        let total_needed = header_end + content_length;
        while buf.len() < total_needed {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
        }

        Ok(String::from_utf8_lossy(&buf[..buf.len().min(total_needed)]).to_string())
    }

    fn parse_request(raw: &str) -> (HttpMethod, String, HashMap<String, String>) {
        let first_line = raw.lines().next().unwrap_or("");
        let parts: Vec<&str> = first_line.split_whitespace().collect();

        let method = if !parts.is_empty() {
            match parts[0] {
                "GET" => HttpMethod::Get,
                "POST" => HttpMethod::Post,
                "DELETE" => HttpMethod::Delete,
                "OPTIONS" => HttpMethod::Options,
                _ => HttpMethod::Other,
            }
        } else {
            HttpMethod::Other
        };

        let (path, query_params) = if parts.len() >= 2 {
            let full_path = parts[1];
            if let Some(idx) = full_path.find('?') {
                let path = full_path[..idx].to_string();
                let query_str = &full_path[idx + 1..];
                let params = Self::parse_query_string(query_str);
                (path, params)
            } else {
                (full_path.to_string(), HashMap::new())
            }
        } else {
            ("/".to_string(), HashMap::new())
        };

        (method, path, query_params)
    }

    fn parse_query_string(query: &str) -> HashMap<String, String> {
        let mut params = HashMap::new();
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            if let Some(idx) = pair.find('=') {
                let key = pair[..idx].to_string();
                let value = pair[idx + 1..].to_string();
                params.insert(key, value);
            } else {
                params.insert(pair.to_string(), String::new());
            }
        }
        params
    }

    fn build_status_response(
        shared_module_names: &Arc<StdMutex<Vec<String>>>,
        shared_metrics: &Option<Arc<StdMutex<SharedMetrics>>>,
        shared_module_restarts: &Arc<StdMutex<HashMap<String, u32>>>,
        started_at: Instant,
    ) -> String {
        // unwrap safety: Mutex が poisoned になるのはパニック時のみ
        let modules = shared_module_names.lock().unwrap().clone();
        let metrics = shared_metrics.as_ref().map(|m| {
            // unwrap safety: Mutex が poisoned になるのはパニック時のみ
            let m = m.lock().unwrap();
            MetricsSummary {
                total_events: m.total_events,
                info_count: m.info_count,
                warning_count: m.warning_count,
                critical_count: m.critical_count,
                module_counts: m.module_counts.clone(),
            }
        });
        // unwrap safety: Mutex が poisoned になるのはパニック時のみ
        let module_restarts = shared_module_restarts.lock().unwrap().clone();

        let response = StatusResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs: started_at.elapsed().as_secs(),
            modules,
            metrics,
            module_restarts,
        };

        // unwrap safety: StatusResponse は Serialize を実装しており、シリアライズ失敗は起こらない
        serde_json::to_string(&response)
            .unwrap_or_else(|e| format!(r#"{{"error":"シリアライズに失敗: {}"}}"#, e))
    }

    fn build_modules_response(
        shared_module_names: &Arc<StdMutex<Vec<String>>>,
        shared_module_restarts: &Arc<StdMutex<HashMap<String, u32>>>,
    ) -> String {
        // unwrap safety: Mutex が poisoned になるのはパニック時のみ
        let names = shared_module_names.lock().unwrap().clone();
        // unwrap safety: Mutex が poisoned になるのはパニック時のみ
        let restarts = shared_module_restarts.lock().unwrap().clone();

        let mut modules_json = Vec::new();
        for name in &names {
            let restart_count = restarts.get(name).copied().unwrap_or(0);
            modules_json.push(format!(
                r#"{{"name":"{}","restarts":{}}}"#,
                Self::escape_json_string(name),
                restart_count
            ));
        }

        format!(r#"{{"modules":[{}]}}"#, modules_json.join(","))
    }

    fn handle_events_summary(
        db_path: &str,
        sub_path: &str,
        query_params: &HashMap<String, String>,
    ) -> Result<String, (u16, String)> {
        use crate::core::event_store::{self, SummaryQuery, TimelineInterval};

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // since: デフォルト 7 日前
        let since = match query_params.get("since") {
            Some(s) => Self::parse_iso8601_to_timestamp(s)
                .ok_or_else(|| (400u16, format!("無効な日時形式です: {}", s)))?,
            None => now - 7 * 86400,
        };

        // until: デフォルト 現在
        let until = match query_params.get("until") {
            Some(s) => Self::parse_iso8601_to_timestamp(s)
                .ok_or_else(|| (400u16, format!("無効な日時形式です: {}", s)))?,
            None => now,
        };

        if since > until {
            return Err((
                400,
                "since は until より前の日時を指定してください".to_string(),
            ));
        }

        // 期間上限: 90 日
        if until - since > 90 * 86400 {
            return Err((400, "期間は最大 90 日までです".to_string()));
        }

        let severity = query_params.get("severity").map(|s| s.to_uppercase());
        if let Some(ref sev) = severity
            && !["INFO", "WARNING", "CRITICAL"].contains(&sev.as_str())
        {
            return Err((400, format!("無効な severity です: {}", sev)));
        }

        let module = query_params.get("module").cloned();

        let summary_query = SummaryQuery {
            since,
            until,
            module,
            severity,
        };

        let conn = event_store::open_readonly(db_path)
            .map_err(|e| (500u16, format!("データベース接続に失敗: {}", e)))?;

        match sub_path {
            "" => {
                let result = event_store::query_event_summary(&conn, &summary_query)
                    .map_err(|e| (500u16, format!("集計クエリの実行に失敗: {}", e)))?;
                serde_json::to_string(&result)
                    .map_err(|e| (500u16, format!("JSON シリアライズに失敗: {}", e)))
            }
            "/timeline" => {
                let interval_str = query_params
                    .get("interval")
                    .map(|s| s.as_str())
                    .unwrap_or("day");
                let interval = TimelineInterval::parse(interval_str).ok_or_else(|| {
                    (
                        400u16,
                        "無効な interval です（hour, day, week のいずれかを指定）".to_string(),
                    )
                })?;
                let buckets = event_store::query_event_timeline(&conn, &summary_query, interval)
                    .map_err(|e| (500u16, format!("集計クエリの実行に失敗: {}", e)))?;
                let json = serde_json::json!({
                    "interval": interval_str,
                    "since": since,
                    "until": until,
                    "buckets": buckets,
                });
                serde_json::to_string(&json)
                    .map_err(|e| (500u16, format!("JSON シリアライズに失敗: {}", e)))
            }
            "/modules" => {
                let limit = query_params
                    .get("limit")
                    .and_then(|v| v.parse::<u32>().ok())
                    .unwrap_or(20)
                    .min(200);
                if limit == 0 {
                    return Err((400, "limit は 1〜200 の範囲で指定してください".to_string()));
                }
                let modules = event_store::query_module_summary(&conn, &summary_query, limit)
                    .map_err(|e| (500u16, format!("集計クエリの実行に失敗: {}", e)))?;
                let json = serde_json::json!({
                    "since": since,
                    "until": until,
                    "modules": modules,
                });
                serde_json::to_string(&json)
                    .map_err(|e| (500u16, format!("JSON シリアライズに失敗: {}", e)))
            }
            "/severity" => {
                let (total, severities) =
                    event_store::query_severity_summary(&conn, &summary_query)
                        .map_err(|e| (500u16, format!("集計クエリの実行に失敗: {}", e)))?;
                let json = serde_json::json!({
                    "since": since,
                    "until": until,
                    "total": total,
                    "severities": severities,
                });
                serde_json::to_string(&json)
                    .map_err(|e| (500u16, format!("JSON シリアライズに失敗: {}", e)))
            }
            _ => Err((404, "エンドポイントが見つかりません".to_string())),
        }
    }

    fn build_events_response(
        db_path: &str,
        query_params: &HashMap<String, String>,
        default_page_size: u32,
        max_page_size: u32,
    ) -> Result<String, String> {
        let conn = rusqlite::Connection::open_with_flags(
            db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .map_err(|e| format!("データベースのオープンに失敗: {}", e))?;

        let mut params_vec: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        let use_fts = query_params.contains_key("q");

        let mut sql = if use_fts {
            "SELECT e.id, e.timestamp, e.severity, e.source_module, e.event_type, \
             highlight(security_events_fts, 0, '<<', '>>') AS message, e.details \
             FROM security_events e \
             INNER JOIN security_events_fts fts ON e.id = fts.rowid \
             WHERE fts.security_events_fts MATCH ?"
                .to_string()
        } else {
            "SELECT id, timestamp, severity, source_module, event_type, message, details FROM security_events WHERE 1=1"
                .to_string()
        };

        if let Some(q) = query_params.get("q") {
            params_vec.push(Box::new(q.clone()));
        }

        let col_prefix = if use_fts { "e." } else { "" };

        let cursor = query_params
            .get("cursor")
            .and_then(|v| v.parse::<i64>().ok());

        if let Some(cursor_val) = cursor {
            sql.push_str(&format!(" AND {}id < ?", col_prefix));
            params_vec.push(Box::new(cursor_val));
        }

        if let Some(severity) = query_params.get("severity") {
            sql.push_str(&format!(" AND {}severity = ?", col_prefix));
            params_vec.push(Box::new(severity.clone()));
        }

        if let Some(module) = query_params.get("module") {
            sql.push_str(&format!(" AND {}source_module = ?", col_prefix));
            params_vec.push(Box::new(module.clone()));
        }

        if let Some(since) = query_params.get("since")
            && let Some(ts) = Self::parse_iso8601(since)
        {
            sql.push_str(&format!(" AND {}timestamp >= ?", col_prefix));
            params_vec.push(Box::new(ts));
        }

        if let Some(until) = query_params.get("until")
            && let Some(ts) = Self::parse_iso8601(until)
        {
            sql.push_str(&format!(" AND {}timestamp <= ?", col_prefix));
            params_vec.push(Box::new(ts));
        }

        let limit = query_params
            .get("limit")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(default_page_size)
            .min(max_page_size);

        if use_fts {
            sql.push_str(" ORDER BY rank LIMIT ?");
        } else {
            sql.push_str(" ORDER BY id DESC LIMIT ?");
        }
        params_vec.push(Box::new(limit + 1));

        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            params_vec.iter().map(|p| p.as_ref()).collect();

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| format!("クエリの準備に失敗: {}", e))?;

        let rows = stmt
            .query_map(params_refs.as_slice(), |row| {
                let id: i64 = row.get(0)?;
                let timestamp: String = row.get(1)?;
                let severity: String = row.get(2)?;
                let source_module: String = row.get(3)?;
                let event_type: String = row.get(4)?;
                let message: String = row.get(5)?;
                let details: Option<String> = row.get(6)?;
                Ok((
                    id,
                    timestamp,
                    severity,
                    source_module,
                    event_type,
                    message,
                    details,
                ))
            })
            .map_err(|e| format!("クエリの実行に失敗: {}", e))?;

        let mut events_data: Vec<(i64, String)> = Vec::new();
        for row in rows {
            match row {
                Ok((id, timestamp, severity, source_module, event_type, message, details)) => {
                    let details_part = match details {
                        Some(ref d) => format!(r#","details":"{}""#, Self::escape_json_string(d)),
                        None => String::new(),
                    };
                    let json = format!(
                        r#"{{"id":{},"timestamp":"{}","severity":"{}","source_module":"{}","event_type":"{}","message":"{}"{}}}"#,
                        id,
                        Self::escape_json_string(&timestamp),
                        Self::escape_json_string(&severity),
                        Self::escape_json_string(&source_module),
                        Self::escape_json_string(&event_type),
                        Self::escape_json_string(&message),
                        details_part
                    );
                    events_data.push((id, json));
                }
                Err(e) => {
                    tracing::debug!(error = %e, "イベント行の読み取りに失敗");
                }
            }
        }

        let has_more = events_data.len() > limit as usize;
        if has_more {
            events_data.pop();
        }
        let count = events_data.len();
        let next_cursor = if has_more {
            events_data
                .last()
                .map(|(id, _)| id.to_string())
                .unwrap_or_else(|| "null".to_string())
        } else {
            "null".to_string()
        };

        let events_json: Vec<&str> = events_data.iter().map(|(_, json)| json.as_str()).collect();
        Ok(format!(
            r#"{{"items":[{}],"next_cursor":{},"has_more":{},"count":{}}}"#,
            events_json.join(","),
            next_cursor,
            has_more,
            count
        ))
    }

    /// ISO 8601 簡易パーサー
    ///
    /// `YYYY-MM-DDTHH:MM:SSZ` または `YYYY-MM-DD` 形式のみサポート。
    fn parse_iso8601(s: &str) -> Option<String> {
        let s = s.trim();
        // YYYY-MM-DDTHH:MM:SSZ
        if s.len() == 20 && s.ends_with('Z') {
            let parts: Vec<&str> = s[..19].split('T').collect();
            if parts.len() == 2 && Self::is_valid_date(parts[0]) && Self::is_valid_time(parts[1]) {
                return Some(s[..19].to_string());
            }
        }
        // YYYY-MM-DD
        if s.len() == 10 && Self::is_valid_date(s) {
            return Some(format!("{}T00:00:00", s));
        }
        None
    }

    fn is_valid_date(s: &str) -> bool {
        if s.len() != 10 {
            return false;
        }
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 3 {
            return false;
        }
        parts[0].len() == 4
            && parts[1].len() == 2
            && parts[2].len() == 2
            && parts[0].chars().all(|c| c.is_ascii_digit())
            && parts[1].chars().all(|c| c.is_ascii_digit())
            && parts[2].chars().all(|c| c.is_ascii_digit())
    }

    fn is_valid_time(s: &str) -> bool {
        if s.len() != 8 {
            return false;
        }
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 3 {
            return false;
        }
        parts[0].len() == 2
            && parts[1].len() == 2
            && parts[2].len() == 2
            && parts[0].chars().all(|c| c.is_ascii_digit())
            && parts[1].chars().all(|c| c.is_ascii_digit())
            && parts[2].chars().all(|c| c.is_ascii_digit())
    }

    fn escape_json_string(s: &str) -> String {
        let mut result = String::with_capacity(s.len());
        for c in s.chars() {
            match c {
                '"' => result.push_str("\\\""),
                '\\' => result.push_str("\\\\"),
                '\n' => result.push_str("\\n"),
                '\r' => result.push_str("\\r"),
                '\t' => result.push_str("\\t"),
                c if (c as u32) < 0x20 => {
                    result.push_str(&format!("\\u{:04x}", c as u32));
                }
                c => result.push(c),
            }
        }
        result
    }

    fn parse_iso8601_to_timestamp(s: &str) -> Option<i64> {
        let s = s.trim().trim_matches('"');
        if s.len() == 20 && s.ends_with('Z') {
            let inner = &s[..19];
            let parts: Vec<&str> = inner.split('T').collect();
            if parts.len() == 2 {
                let datetime_str = format!("{} {}", parts[0], parts[1]);
                return crate::core::event_store::parse_datetime(&datetime_str).ok();
            }
        }
        if s.len() == 10 {
            let datetime_str = format!("{} 00:00:00", s);
            return crate::core::event_store::parse_datetime(&datetime_str).ok();
        }
        None
    }

    fn format_ids_json(ids: &[i64]) -> String {
        let inner: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
        format!("[{}]", inner.join(","))
    }

    fn handle_batch_delete(
        db_path: &str,
        body: &str,
        batch_max_size: u32,
        dry_run: bool,
    ) -> Result<String, (u16, String)> {
        let json: serde_json::Value = serde_json::from_str(body)
            .map_err(|e| (400u16, format!("JSON パースに失敗: {}", e)))?;

        let has_ids = json.get("ids").is_some();
        let has_filter = json.get("filter").is_some();

        if has_ids && has_filter {
            return Err((400, "ids と filter は同時に指定できません".to_string()));
        }
        if !has_ids && !has_filter {
            return Err((400, "ids または filter を指定してください".to_string()));
        }

        let flags = if dry_run {
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
        } else {
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
        };
        let conn = rusqlite::Connection::open_with_flags(db_path, flags)
            .map_err(|e| (500u16, format!("データベースのオープンに失敗: {}", e)))?;

        if has_ids {
            let ids = json["ids"]
                .as_array()
                .ok_or_else(|| (400u16, "ids は配列で指定してください".to_string()))?;
            if ids.len() > batch_max_size as usize {
                return Err((
                    400,
                    format!("ids の件数が上限 {} を超えています", batch_max_size),
                ));
            }
            let id_values: Vec<i64> = ids.iter().filter_map(|v| v.as_i64()).collect();
            if id_values.len() != ids.len() {
                return Err((400, "ids に不正な値が含まれています".to_string()));
            }
            if dry_run {
                let (count, sample_ids) = crate::core::event_store::count_by_ids(&conn, &id_values)
                    .map_err(|e| (500u16, format!("{}", e)))?;
                return Ok(format!(
                    r#"{{"dry_run":true,"affected_count":{},"details":{{"sample_ids":{}}}}}"#,
                    count,
                    Self::format_ids_json(&sample_ids)
                ));
            }
            let deleted = crate::core::event_store::batch_delete_by_ids(&conn, &id_values)
                .map_err(|e| (500u16, format!("{}", e)))?;
            Ok(format!(r#"{{"deleted":{}}}"#, deleted))
        } else {
            let filter_obj = &json["filter"];
            let filter = crate::core::event_store::BatchDeleteFilter {
                severity: filter_obj
                    .get("severity")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                source_module: filter_obj
                    .get("module")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                since: filter_obj
                    .get("since")
                    .and_then(|v| v.as_str())
                    .and_then(Self::parse_iso8601_to_timestamp),
                until: filter_obj
                    .get("until")
                    .and_then(|v| v.as_str())
                    .and_then(Self::parse_iso8601_to_timestamp),
            };
            if dry_run {
                let (count, sample_ids) = crate::core::event_store::count_by_filter(&conn, &filter)
                    .map_err(|e| (500u16, format!("{}", e)))?;
                return Ok(format!(
                    r#"{{"dry_run":true,"affected_count":{},"details":{{"sample_ids":{}}}}}"#,
                    count,
                    Self::format_ids_json(&sample_ids)
                ));
            }
            let deleted = crate::core::event_store::batch_delete_by_filter(&conn, &filter)
                .map_err(|e| (500u16, format!("{}", e)))?;
            Ok(format!(r#"{{"deleted":{}}}"#, deleted))
        }
    }

    fn handle_batch_export(
        db_path: &str,
        body: &str,
        batch_max_size: u32,
    ) -> Result<String, (u16, String)> {
        let json: serde_json::Value = serde_json::from_str(body)
            .map_err(|e| (400u16, format!("JSON パースに失敗: {}", e)))?;

        let filter = json.get("filter");
        let limit = json
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
            .unwrap_or(batch_max_size)
            .min(batch_max_size);

        let query = crate::core::event_store::EventQuery {
            module: filter
                .and_then(|f| f.get("module"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            severity: filter
                .and_then(|f| f.get("severity"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            since: filter
                .and_then(|f| f.get("since"))
                .and_then(|v| v.as_str())
                .and_then(Self::parse_iso8601_to_timestamp),
            until: filter
                .and_then(|f| f.get("until"))
                .and_then(|v| v.as_str())
                .and_then(Self::parse_iso8601_to_timestamp),
            event_type: filter
                .and_then(|f| f.get("event_type"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            limit,
            cursor: None,
            text: None,
        };

        let conn = rusqlite::Connection::open_with_flags(
            db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .map_err(|e| (500u16, format!("データベースのオープンに失敗: {}", e)))?;

        let records =
            crate::core::event_store::query_events_for_export(&conn, &query, batch_max_size)
                .map_err(|e| (500u16, format!("{}", e)))?;

        let count = records.len();
        let items: Vec<String> = records
            .iter()
            .map(|r| {
                let details_part = match &r.details {
                    Some(d) => format!(r#","details":"{}""#, Self::escape_json_string(d)),
                    None => String::new(),
                };
                let ts = crate::core::event_store::format_timestamp_iso(r.timestamp);
                format!(
                    r#"{{"id":{},"timestamp":"{}","severity":"{}","source_module":"{}","event_type":"{}","message":"{}","acknowledged":{}{}}}"#,
                    r.id,
                    Self::escape_json_string(&ts),
                    Self::escape_json_string(&r.severity),
                    Self::escape_json_string(&r.source_module),
                    Self::escape_json_string(&r.event_type),
                    Self::escape_json_string(&r.message),
                    r.acknowledged,
                    details_part,
                )
            })
            .collect();

        Ok(format!(
            r#"{{"items":[{}],"count":{}}}"#,
            items.join(","),
            count
        ))
    }

    fn handle_batch_acknowledge(
        db_path: &str,
        body: &str,
        batch_max_size: u32,
        dry_run: bool,
    ) -> Result<String, (u16, String)> {
        let json: serde_json::Value = serde_json::from_str(body)
            .map_err(|e| (400u16, format!("JSON パースに失敗: {}", e)))?;

        let ids = json
            .get("ids")
            .and_then(|v| v.as_array())
            .ok_or_else(|| (400u16, "ids を配列で指定してください".to_string()))?;

        if ids.len() > batch_max_size as usize {
            return Err((
                400,
                format!("ids の件数が上限 {} を超えています", batch_max_size),
            ));
        }

        let id_values: Vec<i64> = ids.iter().filter_map(|v| v.as_i64()).collect();
        if id_values.len() != ids.len() {
            return Err((400, "ids に不正な値が含まれています".to_string()));
        }

        let flags = if dry_run {
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
        } else {
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
        };
        let conn = rusqlite::Connection::open_with_flags(db_path, flags)
            .map_err(|e| (500u16, format!("データベースのオープンに失敗: {}", e)))?;

        if dry_run {
            let (count, sample_ids) =
                crate::core::event_store::count_acknowledge_targets(&conn, &id_values)
                    .map_err(|e| (500u16, format!("{}", e)))?;
            return Ok(format!(
                r#"{{"dry_run":true,"affected_count":{},"details":{{"sample_ids":{}}}}}"#,
                count,
                Self::format_ids_json(&sample_ids)
            ));
        }

        let acknowledged = crate::core::event_store::batch_acknowledge(&conn, &id_values)
            .map_err(|e| (500u16, format!("{}", e)))?;

        Ok(format!(r#"{{"acknowledged":{}}}"#, acknowledged))
    }

    fn handle_archives_list(archive_dir: &str) -> Result<String, String> {
        let archives =
            crate::core::event_store::list_archives(archive_dir).map_err(|e| format!("{}", e))?;

        let items: Vec<String> = archives
            .iter()
            .map(|a| {
                let checksum_part = match &a.checksum {
                    Some(c) => format!(r#","checksum":"{}""#, Self::escape_json_string(c)),
                    None => String::new(),
                };
                let created_at_part = match a.created_at {
                    Some(ts) => format!(r#","created_at":{}"#, ts),
                    None => String::new(),
                };
                format!(
                    r#"{{"filename":"{}","size":{}{}{}}}"#,
                    Self::escape_json_string(&a.filename),
                    a.size,
                    checksum_part,
                    created_at_part,
                )
            })
            .collect();

        Ok(format!(
            r#"{{"archives":[{}],"count":{}}}"#,
            items.join(","),
            archives.len()
        ))
    }

    fn handle_archives_create(
        db_path: &str,
        archive_dir: &str,
        body: &str,
        config: &ArchiveApiConfig,
        dry_run: bool,
    ) -> Result<String, (u16, String)> {
        let (after_days, compress) = if body.trim().is_empty() || body.trim() == "{}" {
            (config.archive_after_days, config.compress)
        } else {
            let json: serde_json::Value = serde_json::from_str(body)
                .map_err(|e| (400u16, format!("JSON パースに失敗: {}", e)))?;
            let after_days = json
                .get("archive_after_days")
                .and_then(|v| v.as_u64())
                .unwrap_or(config.archive_after_days);
            let compress = json
                .get("compress")
                .and_then(|v| v.as_bool())
                .unwrap_or(config.compress);
            (after_days, compress)
        };

        if dry_run {
            return Ok(format!(
                r#"{{"dry_run":true,"message":"手動アーカイブをプレビューします","details":{{"archive_after_days":{},"compress":{},"archive_dir":"{}"}}}}"#,
                after_days,
                compress,
                Self::escape_json_string(archive_dir),
            ));
        }

        let archived = crate::core::event_store::run_archive_manual(
            db_path,
            after_days,
            archive_dir,
            compress,
        )
        .map_err(|e| (500u16, format!("{}", e)))?;

        Ok(format!(
            r#"{{"message":"アーカイブが完了しました","archived":{}}}"#,
            archived
        ))
    }

    fn handle_archives_restore(
        db_path: &str,
        archive_dir: &str,
        body: &str,
        dry_run: bool,
    ) -> Result<String, (u16, String)> {
        let json: serde_json::Value = serde_json::from_str(body)
            .map_err(|e| (400u16, format!("JSON パースに失敗: {}", e)))?;

        let filename = json
            .get("filename")
            .and_then(|v| v.as_str())
            .ok_or_else(|| (400u16, "filename を指定してください".to_string()))?;

        if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
            return Err((400, "不正なファイル名です".to_string()));
        }

        if dry_run {
            let filepath = std::path::Path::new(archive_dir).join(filename);
            let exists = filepath.exists();
            return Ok(format!(
                r#"{{"dry_run":true,"message":"復元をプレビューします","details":{{"filename":"{}","file_exists":{}}}}}"#,
                Self::escape_json_string(filename),
                exists,
            ));
        }

        let restored = crate::core::event_store::restore_archive(db_path, archive_dir, filename)
            .map_err(|e| (500u16, format!("{}", e)))?;

        Ok(format!(
            r#"{{"message":"復元が完了しました","restored":{}}}"#,
            restored
        ))
    }

    fn handle_archives_rotate(
        archive_dir: &str,
        body: &str,
        config: &ArchiveApiConfig,
        dry_run: bool,
    ) -> Result<String, (u16, String)> {
        let (max_age_days, max_total_mb, max_files) =
            if body.trim().is_empty() || body.trim() == "{}" {
                (config.max_age_days, config.max_total_mb, config.max_files)
            } else {
                let json: serde_json::Value = serde_json::from_str(body)
                    .map_err(|e| (400u16, format!("JSON パースに失敗: {}", e)))?;
                let max_age = json
                    .get("max_age_days")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(config.max_age_days);
                let max_mb = json
                    .get("max_total_mb")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(config.max_total_mb);
                let max_f = json
                    .get("max_files")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(config.max_files);
                (max_age, max_mb, max_f)
            };

        if dry_run {
            let archives = crate::core::event_store::list_archives(archive_dir)
                .map_err(|e| (500u16, format!("{}", e)))?;
            return Ok(format!(
                r#"{{"dry_run":true,"message":"ローテーションをプレビューします","details":{{"current_files":{},"max_age_days":{},"max_total_mb":{},"max_files":{}}}}}"#,
                archives.len(),
                max_age_days,
                max_total_mb,
                max_files,
            ));
        }

        let deleted = crate::core::event_store::rotate_archives(
            archive_dir,
            max_age_days,
            max_total_mb,
            max_files,
        )
        .map_err(|e| (500u16, format!("{}", e)))?;

        Ok(format!(
            r#"{{"message":"ローテーションが完了しました","deleted":{}}}"#,
            deleted
        ))
    }

    fn handle_archive_delete(
        archive_dir: &str,
        filename: &str,
        dry_run: bool,
    ) -> Result<String, (u16, String)> {
        if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
            return Err((400, "不正なファイル名です".to_string()));
        }

        if filename.is_empty() {
            return Err((400, "ファイル名を指定してください".to_string()));
        }

        if dry_run {
            let filepath = std::path::Path::new(archive_dir).join(filename);
            let exists = filepath.exists();
            return Ok(format!(
                r#"{{"dry_run":true,"message":"削除をプレビューします","details":{{"filename":"{}","file_exists":{}}}}}"#,
                Self::escape_json_string(filename),
                exists,
            ));
        }

        crate::core::event_store::delete_archive(archive_dir, filename).map_err(|e| {
            let msg = format!("{}", e);
            if msg.contains("見つかりません") {
                (404u16, msg)
            } else {
                (500u16, msg)
            }
        })?;

        Ok(format!(
            r#"{{"message":"アーカイブファイルを削除しました","filename":"{}"}}"#,
            Self::escape_json_string(filename)
        ))
    }

    async fn send_json_response_with_headers(
        stream: &mut MaybeTlsStream,
        status: u16,
        status_text: &str,
        body: &str,
        extra_headers: Option<&str>,
    ) -> Result<(), io::Error> {
        let extra = match extra_headers {
            Some(h) => format!("{}\r\n", h),
            None => String::new(),
        };
        let response = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n{}\r\n{}",
            status,
            status_text,
            body.len(),
            extra,
            body
        );
        stream.write_all(response.as_bytes()).await
    }

    async fn send_error_with_headers(
        stream: &mut MaybeTlsStream,
        status: u16,
        status_text: &str,
        message: &str,
        extra_headers: Option<&str>,
    ) -> Result<(), io::Error> {
        let body = format!(r#"{{"error":"{}"}}"#, Self::escape_json_string(message));
        Self::send_json_response_with_headers(stream, status, status_text, &body, extra_headers)
            .await
    }

    /// Webhook 一覧レスポンスを構築する
    fn build_webhooks_response(shared_action_config: &Arc<StdMutex<ActionConfig>>) -> String {
        use crate::core::action::ActionEngine;

        // unwrap safety: Mutex が poisoned になるのはパニック時のみ
        let config = shared_action_config.lock().unwrap();
        let mut webhooks = Vec::new();

        // アクションルールの Webhook を収集
        for rule in &config.rules {
            if rule.action == "webhook"
                && let Some(ref url) = rule.url
            {
                let entry = format!(
                    r#"{{"name":"{}","action_type":"rule","severity_filter":{},"module_filter":{},"url_masked":"{}","method":"{}","has_headers":{},"has_body_template":{},"max_retries":{},"timeout_secs":{}}}"#,
                    Self::escape_json_string(&rule.name),
                    match &rule.severity {
                        Some(s) => format!(r#""{}""#, Self::escape_json_string(s)),
                        None => "null".to_string(),
                    },
                    match &rule.module {
                        Some(m) => format!(r#""{}""#, Self::escape_json_string(m)),
                        None => "null".to_string(),
                    },
                    Self::escape_json_string(&ActionEngine::mask_url(url)),
                    Self::escape_json_string(rule.method.as_deref().unwrap_or("POST")),
                    rule.headers.as_ref().is_some_and(|h| !h.is_empty()),
                    rule.body_template.is_some(),
                    rule.max_retries.unwrap_or(3),
                    rule.timeout_secs,
                );
                webhooks.push(entry);
            }
        }

        // ダイジェスト Webhook を収集
        if let Some(ref digest) = config.digest
            && digest.enabled
            && let Some(ref url) = digest.webhook_url
        {
            let entry = format!(
                r#"{{"name":"digest_notification","action_type":"digest","severity_filter":null,"module_filter":null,"url_masked":"{}","method":"{}","has_headers":{},"has_body_template":{},"max_retries":{},"timeout_secs":null}}"#,
                Self::escape_json_string(&ActionEngine::mask_url(url)),
                Self::escape_json_string(&digest.method),
                !digest.headers.is_empty(),
                digest.body_template.is_some(),
                digest.max_retries,
            );
            webhooks.push(entry);
        }

        let total = webhooks.len();
        format!(
            r#"{{"webhooks":[{}],"total":{}}}"#,
            webhooks.join(","),
            total
        )
    }

    /// Webhook テスト送信を処理する
    async fn handle_webhook_test(
        shared_action_config: &Arc<StdMutex<ActionConfig>>,
        body: &str,
    ) -> String {
        use crate::core::action::ActionEngine;

        // リクエストボディの解析
        let name = match Self::extract_json_string(body, "name") {
            Some(n) => n,
            None => {
                return r#"{"error":"'name' フィールドが必要です"}"#.to_string();
            }
        };

        // 設定から Webhook を検索
        let (url, method, headers, body_template, timeout_secs) = {
            // unwrap safety: Mutex が poisoned になるのはパニック時のみ
            let config = shared_action_config.lock().unwrap();

            // まずルール Webhook を検索
            let rule_match = config
                .rules
                .iter()
                .find(|r| r.action == "webhook" && r.name == name);
            if let Some(rule) = rule_match {
                let url = match &rule.url {
                    Some(u) => u.clone(),
                    None => {
                        return format!(
                            r#"{{"error":"Webhook '{}' に URL が設定されていません"}}"#,
                            Self::escape_json_string(&name)
                        );
                    }
                };
                (
                    url,
                    rule.method.clone().unwrap_or_else(|| "POST".to_string()),
                    rule.headers.clone().unwrap_or_default(),
                    rule.body_template.clone(),
                    rule.timeout_secs,
                )
            } else if name == "digest_notification" {
                // ダイジェスト Webhook を検索
                match &config.digest {
                    Some(digest) if digest.enabled && digest.webhook_url.is_some() => (
                        digest.webhook_url.clone().unwrap_or_default(),
                        digest.method.clone(),
                        digest.headers.clone(),
                        digest.body_template.clone(),
                        30,
                    ),
                    _ => {
                        return format!(
                            r#"{{"error":"Webhook '{}' が見つかりません"}}"#,
                            Self::escape_json_string(&name)
                        );
                    }
                }
            } else {
                return format!(
                    r#"{{"error":"Webhook '{}' が見つかりません"}}"#,
                    Self::escape_json_string(&name)
                );
            }
        };

        let masked_url = ActionEngine::mask_url(&url);

        // テスト用 SecurityEvent を作成
        let test_event = crate::core::event::SecurityEvent::new(
            "webhook_test",
            crate::core::event::Severity::Info,
            "api_server",
            "Webhook テスト送信",
        );

        // ボディの構築
        let request_body = match &body_template {
            Some(tmpl) => ActionEngine::expand_placeholders(tmpl, &test_event),
            None => {
                let ts_secs = test_event
                    .timestamp
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                format!(
                    r#"{{"source":"{}","message":"{}","severity":"{}","event_type":"{}","timestamp":{}}}"#,
                    test_event.source_module,
                    Self::escape_json_string(&test_event.message),
                    test_event.severity,
                    test_event.event_type,
                    ts_secs,
                )
            }
        };

        // HTTP リクエストを送信
        let start = std::time::Instant::now();
        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                return format!(
                    r#"{{"success":false,"name":"{}","url_masked":"{}","error":"HTTP クライアントの構築に失敗: {}"}}"#,
                    Self::escape_json_string(&name),
                    Self::escape_json_string(&masked_url),
                    Self::escape_json_string(&e.to_string()),
                );
            }
        };

        let mut req = match method.to_uppercase().as_str() {
            "GET" => client.get(&url),
            "PUT" => client.put(&url).body(request_body),
            "PATCH" => client.patch(&url).body(request_body),
            _ => client.post(&url).body(request_body),
        };

        req = req.header("Content-Type", "application/json");
        for (key, value) in &headers {
            req = req.header(key.as_str(), value.as_str());
        }

        match req.send().await {
            Ok(response) => {
                let status_code = response.status().as_u16();
                let elapsed_ms = start.elapsed().as_millis();
                format!(
                    r#"{{"success":true,"name":"{}","url_masked":"{}","status_code":{},"response_time_ms":{}}}"#,
                    Self::escape_json_string(&name),
                    Self::escape_json_string(&masked_url),
                    status_code,
                    elapsed_ms,
                )
            }
            Err(e) => {
                let elapsed_ms = start.elapsed().as_millis();
                format!(
                    r#"{{"success":false,"name":"{}","url_masked":"{}","error":"{}","response_time_ms":{}}}"#,
                    Self::escape_json_string(&name),
                    Self::escape_json_string(&masked_url),
                    Self::escape_json_string(&e.to_string()),
                    elapsed_ms,
                )
            }
        }
    }

    /// JSON 文字列からフィールドを抽出する簡易パーサー
    fn extract_json_string(json: &str, field: &str) -> Option<String> {
        let pattern = format!(r#""{}""#, field);
        let pos = json.find(&pattern)?;
        let after_key = &json[pos + pattern.len()..];
        let colon_pos = after_key.find(':')?;
        let after_colon = after_key[colon_pos + 1..].trim_start();
        if !after_colon.starts_with('"') {
            return None;
        }
        let value_start = 1;
        let mut chars = after_colon[value_start..].chars();
        let mut value = String::new();
        loop {
            match chars.next() {
                Some('\\') => {
                    if let Some(c) = chars.next() {
                        value.push(c);
                    }
                }
                Some('"') => break,
                Some(c) => value.push(c),
                None => return None,
            }
        }
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ActionRuleConfig, DigestConfig};
    use std::collections::HashMap;

    #[test]
    fn test_parse_request_get() {
        let (method, path, params) =
            ApiServer::parse_request("GET /api/v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(matches!(method, HttpMethod::Get));
        assert_eq!(path, "/api/v1/health");
        assert!(params.is_empty());
    }

    #[test]
    fn test_parse_request_post() {
        let (method, path, params) =
            ApiServer::parse_request("POST /api/v1/reload HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(matches!(method, HttpMethod::Post));
        assert_eq!(path, "/api/v1/reload");
        assert!(params.is_empty());
    }

    #[test]
    fn test_parse_request_with_query_params() {
        let (method, path, params) = ApiServer::parse_request(
            "GET /api/v1/events?severity=critical&limit=50 HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        assert!(matches!(method, HttpMethod::Get));
        assert_eq!(path, "/api/v1/events");
        assert_eq!(params.get("severity"), Some(&"critical".to_string()));
        assert_eq!(params.get("limit"), Some(&"50".to_string()));
    }

    #[test]
    fn test_parse_iso8601_full() {
        let result = ApiServer::parse_iso8601("2024-01-15T10:30:00Z");
        assert_eq!(result, Some("2024-01-15T10:30:00".to_string()));
    }

    #[test]
    fn test_parse_iso8601_date_only() {
        let result = ApiServer::parse_iso8601("2024-01-15");
        assert_eq!(result, Some("2024-01-15T00:00:00".to_string()));
    }

    #[test]
    fn test_parse_iso8601_invalid() {
        assert_eq!(ApiServer::parse_iso8601("not-a-date"), None);
        assert_eq!(ApiServer::parse_iso8601("2024/01/15"), None);
        assert_eq!(ApiServer::parse_iso8601(""), None);
    }

    #[tokio::test]
    async fn test_api_server_health_endpoint() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let (reload_tx, _reload_rx) = mpsc::channel::<()>(1);
        let config = ApiConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port,
            tokens: Vec::new(),
            rate_limit: ApiRateLimitConfig::default(),
            websocket: WebSocketConfig::default(),
            cors: CorsConfig::default(),
            openapi_enabled: true,
            default_page_size: 50,
            max_page_size: 200,
            batch_max_size: 1000,
            max_request_body_size: 1_048_576,
            access_log: true,
            tls: crate::config::ApiTlsConfig::default(),
        };
        let server = ApiServer::new(
            &config,
            Arc::new(StdMutex::new(Vec::new())),
            None,
            Arc::new(StdMutex::new(HashMap::new())),
            Instant::now(),
            None,
            None,
            reload_tx,
            mpsc::channel(8).0,
            None,
            None,
            None,
            &ActionConfig::default(),
        );
        let cancel = server.cancel_token();
        server.spawn().unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        stream
            .write_all(b"GET /api/v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);

        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains(r#"{"status":"ok"}"#));

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_api_server_status_endpoint() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let (reload_tx, _reload_rx) = mpsc::channel::<()>(1);
        let config = ApiConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port,
            tokens: Vec::new(),
            rate_limit: ApiRateLimitConfig::default(),
            websocket: WebSocketConfig::default(),
            cors: CorsConfig::default(),
            openapi_enabled: true,
            default_page_size: 50,
            max_page_size: 200,
            batch_max_size: 1000,
            max_request_body_size: 1_048_576,
            access_log: true,
            tls: crate::config::ApiTlsConfig::default(),
        };
        let modules = Arc::new(StdMutex::new(vec!["test_module".to_string()]));
        let metrics = Arc::new(StdMutex::new(SharedMetrics {
            total_events: 10,
            info_count: 5,
            warning_count: 3,
            critical_count: 2,
            module_counts: HashMap::new(),
        }));
        let server = ApiServer::new(
            &config,
            modules,
            Some(metrics),
            Arc::new(StdMutex::new(HashMap::new())),
            Instant::now(),
            None,
            None,
            reload_tx,
            mpsc::channel(8).0,
            None,
            None,
            None,
            &ActionConfig::default(),
        );
        let cancel = server.cancel_token();
        server.spawn().unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        stream
            .write_all(b"GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);

        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("application/json"));
        assert!(response.contains("test_module"));
        assert!(response.contains(r#""total_events":10"#));

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_api_server_modules_endpoint() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let (reload_tx, _reload_rx) = mpsc::channel::<()>(1);
        let config = ApiConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port,
            tokens: Vec::new(),
            rate_limit: ApiRateLimitConfig::default(),
            websocket: WebSocketConfig::default(),
            cors: CorsConfig::default(),
            openapi_enabled: true,
            default_page_size: 50,
            max_page_size: 200,
            batch_max_size: 1000,
            max_request_body_size: 1_048_576,
            access_log: true,
            tls: crate::config::ApiTlsConfig::default(),
        };
        let modules = Arc::new(StdMutex::new(vec![
            "mod_a".to_string(),
            "mod_b".to_string(),
        ]));
        let mut restarts = HashMap::new();
        restarts.insert("mod_b".to_string(), 2);
        let server = ApiServer::new(
            &config,
            modules,
            None,
            Arc::new(StdMutex::new(restarts)),
            Instant::now(),
            None,
            None,
            reload_tx,
            mpsc::channel(8).0,
            None,
            None,
            None,
            &ActionConfig::default(),
        );
        let cancel = server.cancel_token();
        server.spawn().unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        stream
            .write_all(b"GET /api/v1/modules HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);

        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains(r#""name":"mod_a""#));
        assert!(response.contains(r#""name":"mod_b""#));
        assert!(response.contains(r#""restarts":2"#));
        assert!(response.contains(r#""restarts":0"#));

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_api_server_reload_endpoint() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let (reload_tx, mut reload_rx) = mpsc::channel::<()>(1);
        let config = ApiConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port,
            tokens: Vec::new(),
            rate_limit: ApiRateLimitConfig::default(),
            websocket: WebSocketConfig::default(),
            cors: CorsConfig::default(),
            openapi_enabled: true,
            default_page_size: 50,
            max_page_size: 200,
            batch_max_size: 1000,
            max_request_body_size: 1_048_576,
            access_log: true,
            tls: crate::config::ApiTlsConfig::default(),
        };
        let server = ApiServer::new(
            &config,
            Arc::new(StdMutex::new(Vec::new())),
            None,
            Arc::new(StdMutex::new(HashMap::new())),
            Instant::now(),
            None,
            None,
            reload_tx,
            mpsc::channel(8).0,
            None,
            None,
            None,
            &ActionConfig::default(),
        );
        let cancel = server.cancel_token();
        server.spawn().unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        stream
            .write_all(b"POST /api/v1/reload HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);

        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("リロードをトリガーしました"));

        // リロードシグナルが受信されたことを確認
        let received = reload_rx.try_recv();
        assert!(received.is_ok());

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_api_server_events_no_store() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let (reload_tx, _reload_rx) = mpsc::channel::<()>(1);
        let config = ApiConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port,
            tokens: Vec::new(),
            rate_limit: ApiRateLimitConfig::default(),
            websocket: WebSocketConfig::default(),
            cors: CorsConfig::default(),
            openapi_enabled: true,
            default_page_size: 50,
            max_page_size: 200,
            batch_max_size: 1000,
            max_request_body_size: 1_048_576,
            access_log: true,
            tls: crate::config::ApiTlsConfig::default(),
        };
        let server = ApiServer::new(
            &config,
            Arc::new(StdMutex::new(Vec::new())),
            None,
            Arc::new(StdMutex::new(HashMap::new())),
            Instant::now(),
            None, // event_store_db_path is None
            None,
            reload_tx,
            mpsc::channel(8).0,
            None,
            None,
            None,
            &ActionConfig::default(),
        );
        let cancel = server.cancel_token();
        server.spawn().unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        stream
            .write_all(b"GET /api/v1/events HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);

        assert!(response.contains("HTTP/1.1 503"));
        assert!(response.contains("イベントストアが無効です"));

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_api_server_404() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let (reload_tx, _reload_rx) = mpsc::channel::<()>(1);
        let config = ApiConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port,
            tokens: Vec::new(),
            rate_limit: ApiRateLimitConfig::default(),
            websocket: WebSocketConfig::default(),
            cors: CorsConfig::default(),
            openapi_enabled: true,
            default_page_size: 50,
            max_page_size: 200,
            batch_max_size: 1000,
            max_request_body_size: 1_048_576,
            access_log: true,
            tls: crate::config::ApiTlsConfig::default(),
        };
        let server = ApiServer::new(
            &config,
            Arc::new(StdMutex::new(Vec::new())),
            None,
            Arc::new(StdMutex::new(HashMap::new())),
            Instant::now(),
            None,
            None,
            reload_tx,
            mpsc::channel(8).0,
            None,
            None,
            None,
            &ActionConfig::default(),
        );
        let cancel = server.cancel_token();
        server.spawn().unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        stream
            .write_all(b"GET /unknown HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);

        assert!(response.contains("HTTP/1.1 404"));
        assert!(response.contains("エンドポイントが見つかりません"));

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_api_server_method_not_allowed() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let (reload_tx, _reload_rx) = mpsc::channel::<()>(1);
        let config = ApiConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port,
            tokens: Vec::new(),
            rate_limit: ApiRateLimitConfig::default(),
            websocket: WebSocketConfig::default(),
            cors: CorsConfig::default(),
            openapi_enabled: true,
            default_page_size: 50,
            max_page_size: 200,
            batch_max_size: 1000,
            max_request_body_size: 1_048_576,
            access_log: true,
            tls: crate::config::ApiTlsConfig::default(),
        };
        let server = ApiServer::new(
            &config,
            Arc::new(StdMutex::new(Vec::new())),
            None,
            Arc::new(StdMutex::new(HashMap::new())),
            Instant::now(),
            None,
            None,
            reload_tx,
            mpsc::channel(8).0,
            None,
            None,
            None,
            &ActionConfig::default(),
        );
        let cancel = server.cancel_token();
        server.spawn().unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // POST to a GET-only endpoint
        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        stream
            .write_all(b"POST /api/v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);

        assert!(response.contains("HTTP/1.1 405"));
        assert!(response.contains("許可されていないメソッドです"));

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[test]
    fn test_hash_token() {
        let hash = ApiServer::hash_token("my-secret-token");
        assert!(hash.starts_with("sha256:"));
        assert_eq!(hash.len(), 7 + 64); // "sha256:" + 64 hex chars
        // 同じ入力は同じハッシュ
        assert_eq!(hash, ApiServer::hash_token("my-secret-token"));
        // 異なる入力は異なるハッシュ
        assert_ne!(hash, ApiServer::hash_token("other-token"));
    }

    #[test]
    fn test_authenticate_no_tokens() {
        let raw = "GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let result = ApiServer::authenticate(raw, &[]);
        assert!(matches!(result, AuthResult::NoAuthRequired));
    }

    #[test]
    fn test_authenticate_valid_token() {
        let token = "test-token-123";
        let hash = ApiServer::hash_token(token);
        let tokens = vec![ApiTokenConfig {
            name: "test".to_string(),
            token_hash: hash,
            role: ApiRole::Admin,
        }];
        let raw = format!(
            "GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\n\r\n",
            token
        );
        let result = ApiServer::authenticate(&raw, &tokens);
        assert!(matches!(result, AuthResult::Authenticated(ApiRole::Admin)));
    }

    #[test]
    fn test_authenticate_invalid_token() {
        let tokens = vec![ApiTokenConfig {
            name: "test".to_string(),
            token_hash: ApiServer::hash_token("correct-token"),
            role: ApiRole::Admin,
        }];
        let raw = "GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer wrong-token\r\n\r\n";
        let result = ApiServer::authenticate(raw, &tokens);
        assert!(matches!(result, AuthResult::Unauthorized));
    }

    #[test]
    fn test_authenticate_no_header() {
        let tokens = vec![ApiTokenConfig {
            name: "test".to_string(),
            token_hash: ApiServer::hash_token("my-token"),
            role: ApiRole::ReadOnly,
        }];
        let raw = "GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let result = ApiServer::authenticate(raw, &tokens);
        assert!(matches!(result, AuthResult::Unauthorized));
    }

    #[test]
    fn test_role_permissions() {
        assert!(ApiRole::Admin.has_permission(&ApiRole::Admin));
        assert!(ApiRole::Admin.has_permission(&ApiRole::ReadOnly));
        assert!(ApiRole::ReadOnly.has_permission(&ApiRole::ReadOnly));
        assert!(!ApiRole::ReadOnly.has_permission(&ApiRole::Admin));
    }

    #[test]
    fn test_required_role_for_endpoints() {
        assert!(ApiServer::required_role(&HttpMethod::Get, "/api/v1/health").is_none());
        assert_eq!(
            ApiServer::required_role(&HttpMethod::Get, "/api/v1/status"),
            Some(ApiRole::ReadOnly)
        );
        assert_eq!(
            ApiServer::required_role(&HttpMethod::Get, "/api/v1/modules"),
            Some(ApiRole::ReadOnly)
        );
        assert_eq!(
            ApiServer::required_role(&HttpMethod::Get, "/api/v1/events"),
            Some(ApiRole::ReadOnly)
        );
        assert_eq!(
            ApiServer::required_role(&HttpMethod::Post, "/api/v1/reload"),
            Some(ApiRole::Admin)
        );
    }

    fn create_auth_server(tokens: Vec<ApiTokenConfig>) -> (u16, CancellationToken) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let (reload_tx, _reload_rx) = mpsc::channel::<()>(1);
        let config = ApiConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port,
            tokens,
            rate_limit: ApiRateLimitConfig::default(),
            websocket: WebSocketConfig::default(),
            cors: CorsConfig::default(),
            openapi_enabled: true,
            default_page_size: 50,
            max_page_size: 200,
            batch_max_size: 1000,
            max_request_body_size: 1_048_576,
            access_log: true,
            tls: crate::config::ApiTlsConfig::default(),
        };
        let server = ApiServer::new(
            &config,
            Arc::new(StdMutex::new(Vec::new())),
            None,
            Arc::new(StdMutex::new(HashMap::new())),
            Instant::now(),
            None,
            None,
            reload_tx,
            mpsc::channel(8).0,
            None,
            None,
            None,
            &ActionConfig::default(),
        );
        let cancel = server.cancel_token();
        server.spawn().unwrap();
        (port, cancel)
    }

    #[tokio::test]
    async fn test_auth_health_no_token_required() {
        let tokens = vec![ApiTokenConfig {
            name: "admin".to_string(),
            token_hash: ApiServer::hash_token("secret"),
            role: ApiRole::Admin,
        }];
        let (port, cancel) = create_auth_server(tokens);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // /health は認証不要
        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        stream
            .write_all(b"GET /api/v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);
        assert!(response.contains("HTTP/1.1 200 OK"));

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_auth_status_requires_token() {
        let tokens = vec![ApiTokenConfig {
            name: "admin".to_string(),
            token_hash: ApiServer::hash_token("secret"),
            role: ApiRole::Admin,
        }];
        let (port, cancel) = create_auth_server(tokens);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // トークンなしで /status にアクセス → 401
        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        stream
            .write_all(b"GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);
        assert!(response.contains("HTTP/1.1 401"));

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_auth_status_with_valid_token() {
        let token = "my-secret-token";
        let tokens = vec![ApiTokenConfig {
            name: "admin".to_string(),
            token_hash: ApiServer::hash_token(token),
            role: ApiRole::Admin,
        }];
        let (port, cancel) = create_auth_server(tokens);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        let req = format!(
            "GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\n\r\n",
            token
        );
        stream.write_all(req.as_bytes()).await.unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);
        assert!(response.contains("HTTP/1.1 200 OK"));

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_auth_reload_requires_admin() {
        let token = "read-only-token";
        let tokens = vec![ApiTokenConfig {
            name: "reader".to_string(),
            token_hash: ApiServer::hash_token(token),
            role: ApiRole::ReadOnly,
        }];
        let (port, cancel) = create_auth_server(tokens);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // read_only トークンで /reload にアクセス → 403
        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        let req = format!(
            "POST /api/v1/reload HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\n\r\n",
            token
        );
        stream.write_all(req.as_bytes()).await.unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);
        assert!(response.contains("HTTP/1.1 403"));

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_auth_no_tokens_allows_all() {
        let (port, cancel) = create_auth_server(Vec::new());
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // トークン未設定なら認証なしでアクセス可能
        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        stream
            .write_all(b"GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);
        assert!(response.contains("HTTP/1.1 200 OK"));

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    /// WebSocket テスト用のサーバーを作成するヘルパー
    fn create_ws_server(
        tokens: Vec<ApiTokenConfig>,
        ws_config: WebSocketConfig,
    ) -> (u16, CancellationToken, broadcast::Sender<SecurityEvent>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let (event_tx, _) = broadcast::channel::<SecurityEvent>(64);

        let (reload_tx, _reload_rx) = mpsc::channel::<()>(1);
        let config = ApiConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port,
            tokens,
            rate_limit: ApiRateLimitConfig::default(),
            websocket: ws_config,
            cors: CorsConfig::default(),
            openapi_enabled: true,
            default_page_size: 50,
            max_page_size: 200,
            batch_max_size: 1000,
            max_request_body_size: 1_048_576,
            access_log: true,
            tls: crate::config::ApiTlsConfig::default(),
        };
        let server = ApiServer::new(
            &config,
            Arc::new(StdMutex::new(Vec::new())),
            None,
            Arc::new(StdMutex::new(HashMap::new())),
            Instant::now(),
            None,
            None,
            reload_tx,
            mpsc::channel(8).0,
            Some(event_tx.clone()),
            None,
            None,
            &ActionConfig::default(),
        );
        let cancel = server.cancel_token();
        server.spawn().unwrap();
        (port, cancel, event_tx)
    }

    #[tokio::test]
    async fn test_ws_connect_success() {
        use tokio_tungstenite::connect_async;

        let ws_config = WebSocketConfig {
            enabled: true,
            max_connections: 10,
            ..WebSocketConfig::default()
        };
        let (port, cancel, _event_tx) = create_ws_server(Vec::new(), ws_config);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let url = format!("ws://127.0.0.1:{}/api/v1/events/stream", port);
        let result = connect_async(&url).await;
        assert!(result.is_ok(), "WebSocket 接続に成功するべき");

        let (mut ws, _response) = result.unwrap();
        // クリーンに切断
        use futures_util::SinkExt;
        let _ = ws
            .send(tokio_tungstenite::tungstenite::Message::Close(None))
            .await;

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_ws_connect_no_auth_required_when_no_tokens() {
        use tokio_tungstenite::connect_async;

        let ws_config = WebSocketConfig {
            enabled: true,
            max_connections: 10,
            ..WebSocketConfig::default()
        };
        // トークン未設定 → 認証不要
        let (port, cancel, _event_tx) = create_ws_server(Vec::new(), ws_config);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let url = format!("ws://127.0.0.1:{}/api/v1/events/stream", port);
        let result = connect_async(&url).await;
        assert!(result.is_ok(), "トークン未設定時は認証なしで接続可能");

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_ws_connect_auth_failure() {
        use tokio_tungstenite::connect_async;
        use tokio_tungstenite::tungstenite::http::Request;

        let tokens = vec![ApiTokenConfig {
            name: "admin".to_string(),
            token_hash: ApiServer::hash_token("correct-token"),
            role: ApiRole::Admin,
        }];
        let ws_config = WebSocketConfig {
            enabled: true,
            max_connections: 10,
            ..WebSocketConfig::default()
        };
        let (port, cancel, _event_tx) = create_ws_server(tokens, ws_config);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 不正トークンでの接続
        let url = format!("ws://127.0.0.1:{}/api/v1/events/stream", port);
        let request = Request::builder()
            .uri(&url)
            .header("Host", format!("127.0.0.1:{}", port))
            .header("Authorization", "Bearer wrong-token")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header(
                "Sec-WebSocket-Key",
                tokio_tungstenite::tungstenite::handshake::client::generate_key(),
            )
            .body(())
            .unwrap();

        let result = connect_async(request).await;
        assert!(result.is_err(), "不正トークンでは接続拒否されるべき");

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_ws_upgrade_required_without_upgrade_header() {
        // Upgrade ヘッダーなしで /api/v1/events/stream にアクセス → 426
        let ws_config = WebSocketConfig {
            enabled: true,
            max_connections: 10,
            ..WebSocketConfig::default()
        };
        let (port, cancel, _event_tx) = create_ws_server(Vec::new(), ws_config);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 通常の HTTP GET リクエスト（Upgrade なし）
        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        stream
            .write_all(b"GET /api/v1/events/stream HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);

        assert!(
            response.contains("426"),
            "Upgrade なしのリクエストは 426 を返すべき: {}",
            response
        );
        assert!(response.contains("WebSocket Upgrade"));

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_ws_event_receive() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::connect_async;
        use tokio_tungstenite::tungstenite::Message;

        let ws_config = WebSocketConfig {
            enabled: true,
            max_connections: 10,
            ping_interval_secs: 60,
            idle_timeout_secs: 300,
            buffer_size: 128,
        };
        let (port, cancel, event_tx) = create_ws_server(Vec::new(), ws_config);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let url = format!("ws://127.0.0.1:{}/api/v1/events/stream", port);
        let (mut ws, _) = connect_async(&url).await.unwrap();

        // サーバー側で subscribe が完了するまで少し待つ
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // イベントを送信
        let event = SecurityEvent::new(
            "test_event",
            Severity::Warning,
            "test_module",
            "テストイベント",
        );
        event_tx.send(event).unwrap();

        // WebSocket でイベントを受信
        let msg = tokio::time::timeout(std::time::Duration::from_secs(3), ws.next())
            .await
            .expect("タイムアウト: イベントを受信できなかった")
            .expect("ストリームが終了した")
            .expect("メッセージ受信エラー");

        match msg {
            Message::Text(text) => {
                let text_str: &str = &text;
                assert!(
                    text_str.contains("test_event"),
                    "イベントタイプが含まれるべき: {}",
                    text_str
                );
                assert!(
                    text_str.contains("WARNING"),
                    "Severity が含まれるべき: {}",
                    text_str
                );
                assert!(
                    text_str.contains("test_module"),
                    "モジュール名が含まれるべき: {}",
                    text_str
                );
            }
            other => panic!("テキストメッセージを期待したが {:?} を受信", other),
        }

        let _ = ws
            .send(tokio_tungstenite::tungstenite::Message::Close(None))
            .await;
        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_ws_severity_filter() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::connect_async;
        use tokio_tungstenite::tungstenite::Message;

        let ws_config = WebSocketConfig {
            enabled: true,
            max_connections: 10,
            ping_interval_secs: 60,
            idle_timeout_secs: 300,
            buffer_size: 128,
        };
        let (port, cancel, event_tx) = create_ws_server(Vec::new(), ws_config);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // severity=critical でフィルタ
        let url = format!(
            "ws://127.0.0.1:{}/api/v1/events/stream?severity=critical",
            port
        );
        let (mut ws, _) = connect_async(&url).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Info イベントを送信（フィルタされるべき）
        let info_event =
            SecurityEvent::new("info_event", Severity::Info, "test_module", "Info イベント");
        event_tx.send(info_event).unwrap();

        // Critical イベントを送信（受信されるべき）
        let critical_event = SecurityEvent::new(
            "critical_event",
            Severity::Critical,
            "test_module",
            "Critical イベント",
        );
        event_tx.send(critical_event).unwrap();

        // Critical イベントのみ受信されることを確認
        let msg = tokio::time::timeout(std::time::Duration::from_secs(3), ws.next())
            .await
            .expect("タイムアウト")
            .expect("ストリーム終了")
            .expect("受信エラー");

        match msg {
            Message::Text(text) => {
                let text_str: &str = &text;
                assert!(
                    text_str.contains("critical_event"),
                    "Critical イベントが受信されるべき: {}",
                    text_str
                );
                assert!(
                    !text_str.contains("info_event"),
                    "Info イベントはフィルタされるべき: {}",
                    text_str
                );
            }
            other => panic!("テキストメッセージを期待したが {:?} を受信", other),
        }

        let _ = ws
            .send(tokio_tungstenite::tungstenite::Message::Close(None))
            .await;
        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_ws_max_connections_exceeded() {
        use tokio_tungstenite::connect_async;

        let ws_config = WebSocketConfig {
            enabled: true,
            max_connections: 1, // 最大 1 接続
            ping_interval_secs: 60,
            idle_timeout_secs: 300,
            buffer_size: 128,
        };
        let (port, cancel, _event_tx) = create_ws_server(Vec::new(), ws_config);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let url = format!("ws://127.0.0.1:{}/api/v1/events/stream", port);

        // 1 接続目: 成功
        let first = connect_async(&url).await;
        assert!(first.is_ok(), "1 接続目は成功するべき");
        let (_ws1, _) = first.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 2 接続目: 上限超過で失敗
        let second = connect_async(&url).await;
        assert!(second.is_err(), "最大接続数超過時は接続拒否されるべき");

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let config = ApiRateLimitConfig {
            enabled: true,
            max_requests_per_second: 10.0,
            burst_size: 5,
            cleanup_interval_secs: 60,
        };
        let mut rl = RateLimiter::new(&config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        for _ in 0..5 {
            let result = rl.check_rate_limit(ip);
            assert!(result.allowed);
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let config = ApiRateLimitConfig {
            enabled: true,
            max_requests_per_second: 10.0,
            burst_size: 3,
            cleanup_interval_secs: 60,
        };
        let mut rl = RateLimiter::new(&config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        for _ in 0..3 {
            let result = rl.check_rate_limit(ip);
            assert!(result.allowed);
        }

        let result = rl.check_rate_limit(ip);
        assert!(!result.allowed);
        assert_eq!(result.remaining, 0);
        assert!(result.retry_after.is_some());
    }

    #[test]
    fn test_rate_limiter_refills_tokens() {
        let config = ApiRateLimitConfig {
            enabled: true,
            max_requests_per_second: 100.0,
            burst_size: 2,
            cleanup_interval_secs: 60,
        };
        let mut rl = RateLimiter::new(&config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // 全トークン消費
        assert!(rl.check_rate_limit(ip).allowed);
        assert!(rl.check_rate_limit(ip).allowed);
        assert!(!rl.check_rate_limit(ip).allowed);

        // 手動でバケットの last_refill を過去にずらして補充をシミュレート
        if let Some(bucket) = rl.buckets.get_mut(&ip) {
            bucket.last_refill = Instant::now() - std::time::Duration::from_millis(100);
        }

        // refill_rate=100/s, 100ms 経過 → 10 トークン補充（max_tokens=2 でクランプ）
        let result = rl.check_rate_limit(ip);
        assert!(result.allowed);
    }

    #[test]
    fn test_rate_limiter_cleanup() {
        let config = ApiRateLimitConfig {
            enabled: true,
            max_requests_per_second: 10.0,
            burst_size: 5,
            cleanup_interval_secs: 1,
        };
        let mut rl = RateLimiter::new(&config);
        let ip: IpAddr = "172.16.0.1".parse().unwrap();

        rl.check_rate_limit(ip);
        assert_eq!(rl.buckets.len(), 1);

        // last_refill を古くしてクリーンアップ対象にする
        if let Some(bucket) = rl.buckets.get_mut(&ip) {
            bucket.last_refill = Instant::now() - std::time::Duration::from_secs(10);
        }

        rl.cleanup();
        assert_eq!(rl.buckets.len(), 0);
    }

    #[test]
    fn test_rate_limiter_max_entries() {
        let config = ApiRateLimitConfig {
            enabled: true,
            max_requests_per_second: 10.0,
            burst_size: 5,
            cleanup_interval_secs: 60,
        };
        let mut rl = RateLimiter::new(&config);
        rl.max_entries = 3;

        // 3 エントリまでは許可
        for i in 1..=3u8 {
            let ip: IpAddr = format!("10.0.0.{}", i).parse().unwrap();
            let result = rl.check_rate_limit(ip);
            assert!(result.allowed);
        }
        assert_eq!(rl.buckets.len(), 3);

        // 4 番目の新規 IP は上限超過で拒否（クリーンアップしても空かない）
        let ip4: IpAddr = "10.0.0.4".parse().unwrap();
        let result = rl.check_rate_limit(ip4);
        assert!(!result.allowed);
        assert_eq!(rl.buckets.len(), 3);

        // 既存 IP はまだ使える
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let result = rl.check_rate_limit(ip1);
        assert!(result.allowed);

        // 古いエントリを期限切れにすればクリーンアップで空きができる
        if let Some(bucket) = rl.buckets.get_mut(&"10.0.0.2".parse::<IpAddr>().unwrap()) {
            bucket.last_refill = Instant::now() - std::time::Duration::from_secs(300);
        }
        let result = rl.check_rate_limit(ip4);
        assert!(result.allowed);
        assert_eq!(rl.buckets.len(), 3);
    }

    #[tokio::test]
    async fn test_api_server_rate_limit_429() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let (reload_tx, _reload_rx) = mpsc::channel::<()>(1);
        let config = ApiConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port,
            tokens: Vec::new(),
            rate_limit: ApiRateLimitConfig {
                enabled: true,
                max_requests_per_second: 1.0,
                burst_size: 2,
                cleanup_interval_secs: 60,
            },
            websocket: WebSocketConfig::default(),
            cors: CorsConfig::default(),
            openapi_enabled: true,
            default_page_size: 50,
            max_page_size: 200,
            batch_max_size: 1000,
            max_request_body_size: 1_048_576,
            access_log: true,
            tls: crate::config::ApiTlsConfig::default(),
        };
        let server = ApiServer::new(
            &config,
            Arc::new(StdMutex::new(Vec::new())),
            None,
            Arc::new(StdMutex::new(HashMap::new())),
            Instant::now(),
            None,
            None,
            reload_tx,
            mpsc::channel(8).0,
            None,
            None,
            None,
            &ActionConfig::default(),
        );
        let cancel = server.cancel_token();
        server.spawn().unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // バースト内のリクエストは許可（X-RateLimit ヘッダー付き）
        for _ in 0..2 {
            let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
                .await
                .unwrap();
            stream
                .write_all(b"GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await
                .unwrap();
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await.unwrap();
            let response = String::from_utf8_lossy(&buf);
            assert!(response.contains("HTTP/1.1 200 OK"));
            assert!(response.contains("X-RateLimit-Limit: 2"));
        }

        // 3 回目は 429
        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        stream
            .write_all(b"GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);
        assert!(response.contains("HTTP/1.1 429 Too Many Requests"));
        assert!(response.contains("Retry-After:"));
        assert!(response.contains("X-RateLimit-Limit: 2"));
        assert!(response.contains("X-RateLimit-Remaining: 0"));

        // /api/v1/health はレートリミット対象外
        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        stream
            .write_all(b"GET /api/v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);
        assert!(response.contains("HTTP/1.1 200 OK"));

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[test]
    fn test_parse_request_options() {
        let (method, path, _params) =
            ApiServer::parse_request("OPTIONS /api/v1/status HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(matches!(method, HttpMethod::Options));
        assert_eq!(path, "/api/v1/status");
    }

    #[test]
    fn test_extract_header_origin() {
        let raw =
            "GET /api/v1/health HTTP/1.1\r\nHost: localhost\r\nOrigin: https://example.com\r\n\r\n";
        assert_eq!(
            ApiServer::extract_header(raw, "origin"),
            Some("https://example.com")
        );
    }

    #[test]
    fn test_extract_header_case_insensitive() {
        let raw = "GET / HTTP/1.1\r\norigin: https://test.com\r\n\r\n";
        assert_eq!(
            ApiServer::extract_header(raw, "Origin"),
            Some("https://test.com")
        );
    }

    #[test]
    fn test_extract_header_missing() {
        let raw = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert_eq!(ApiServer::extract_header(raw, "origin"), None);
    }

    #[test]
    fn test_cors_disabled() {
        let config = CorsConfig::default();
        let headers = ApiServer::build_cors_headers(&config, Some("https://example.com"), false);
        assert!(headers.is_empty());
    }

    #[test]
    fn test_cors_wildcard_origin() {
        let config = CorsConfig {
            enabled: true,
            allowed_origins: Vec::new(),
            ..CorsConfig::default()
        };
        let headers = ApiServer::build_cors_headers(&config, Some("https://example.com"), false);
        assert!(headers.contains("Access-Control-Allow-Origin: *"));
        assert!(headers.contains("Vary: Origin"));
    }

    #[test]
    fn test_cors_specific_origin_allowed() {
        let config = CorsConfig {
            enabled: true,
            allowed_origins: vec!["https://app.example.com".to_string()],
            ..CorsConfig::default()
        };
        let headers =
            ApiServer::build_cors_headers(&config, Some("https://app.example.com"), false);
        assert!(headers.contains("Access-Control-Allow-Origin: https://app.example.com"));
    }

    #[test]
    fn test_cors_specific_origin_rejected() {
        let config = CorsConfig {
            enabled: true,
            allowed_origins: vec!["https://app.example.com".to_string()],
            ..CorsConfig::default()
        };
        let headers =
            ApiServer::build_cors_headers(&config, Some("https://evil.example.com"), false);
        assert!(headers.is_empty());
    }

    #[test]
    fn test_cors_no_origin_header() {
        let config = CorsConfig {
            enabled: true,
            ..CorsConfig::default()
        };
        let headers = ApiServer::build_cors_headers(&config, None, false);
        assert!(headers.is_empty());
    }

    #[test]
    fn test_cors_null_origin_rejected() {
        let config = CorsConfig {
            enabled: true,
            ..CorsConfig::default()
        };
        let headers = ApiServer::build_cors_headers(&config, Some("null"), false);
        assert!(headers.is_empty());
    }

    #[test]
    fn test_cors_preflight_headers() {
        let config = CorsConfig {
            enabled: true,
            allowed_origins: Vec::new(),
            allowed_methods: vec!["GET".to_string(), "POST".to_string()],
            allowed_headers: vec!["Content-Type".to_string(), "Authorization".to_string()],
            max_age: 3600,
            ..CorsConfig::default()
        };
        let headers = ApiServer::build_cors_headers(&config, Some("https://example.com"), true);
        assert!(headers.contains("Access-Control-Allow-Methods: GET, POST"));
        assert!(headers.contains("Access-Control-Allow-Headers: Content-Type, Authorization"));
        assert!(headers.contains("Access-Control-Max-Age: 3600"));
    }

    #[test]
    fn test_cors_credentials_with_specific_origin() {
        let config = CorsConfig {
            enabled: true,
            allowed_origins: vec!["https://app.example.com".to_string()],
            allow_credentials: true,
            ..CorsConfig::default()
        };
        let headers =
            ApiServer::build_cors_headers(&config, Some("https://app.example.com"), false);
        assert!(headers.contains("Access-Control-Allow-Credentials: true"));
        assert!(headers.contains("Access-Control-Allow-Origin: https://app.example.com"));
    }

    #[test]
    fn test_cors_credentials_with_wildcard_echoes_origin() {
        let config = CorsConfig {
            enabled: true,
            allowed_origins: Vec::new(),
            allow_credentials: true,
            ..CorsConfig::default()
        };
        let headers = ApiServer::build_cors_headers(&config, Some("https://example.com"), false);
        assert!(headers.contains("Access-Control-Allow-Origin: https://example.com"));
        assert!(!headers.contains("Access-Control-Allow-Origin: *"));
        assert!(headers.contains("Access-Control-Allow-Credentials: true"));
    }

    #[tokio::test]
    async fn test_api_server_cors_preflight() {
        let port = 19260;
        let cancel = CancellationToken::new();

        let (reload_tx, _reload_rx) = mpsc::channel::<()>(1);
        let config = ApiConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port,
            tokens: Vec::new(),
            rate_limit: ApiRateLimitConfig::default(),
            websocket: WebSocketConfig::default(),
            cors: CorsConfig {
                enabled: true,
                allowed_origins: vec!["https://dashboard.example.com".to_string()],
                ..CorsConfig::default()
            },
            openapi_enabled: true,
            default_page_size: 50,
            max_page_size: 200,
            batch_max_size: 1000,
            max_request_body_size: 1_048_576,
            access_log: true,
            tls: crate::config::ApiTlsConfig::default(),
        };
        let server = ApiServer::new(
            &config,
            Arc::new(StdMutex::new(Vec::new())),
            None,
            Arc::new(StdMutex::new(HashMap::new())),
            Instant::now(),
            None,
            None,
            reload_tx,
            mpsc::channel(8).0,
            None,
            None,
            None,
            &ActionConfig::default(),
        );
        let server_cancel = server.cancel_token();
        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            cancel_clone.cancelled().await;
            server_cancel.cancel();
        });
        server.spawn().unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        stream
            .write_all(
                b"OPTIONS /api/v1/status HTTP/1.1\r\nHost: localhost\r\nOrigin: https://dashboard.example.com\r\nAccess-Control-Request-Method: GET\r\n\r\n",
            )
            .await
            .unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);
        assert!(response.contains("HTTP/1.1 204 No Content"));
        assert!(response.contains("Access-Control-Allow-Origin: https://dashboard.example.com"));
        assert!(response.contains("Access-Control-Allow-Methods:"));
        assert!(response.contains("Access-Control-Max-Age:"));

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_api_server_cors_regular_request() {
        let port = 19261;
        let cancel = CancellationToken::new();

        let (reload_tx, _reload_rx) = mpsc::channel::<()>(1);
        let config = ApiConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port,
            tokens: Vec::new(),
            rate_limit: ApiRateLimitConfig::default(),
            websocket: WebSocketConfig::default(),
            cors: CorsConfig {
                enabled: true,
                allowed_origins: Vec::new(),
                ..CorsConfig::default()
            },
            openapi_enabled: true,
            default_page_size: 50,
            max_page_size: 200,
            batch_max_size: 1000,
            max_request_body_size: 1_048_576,
            access_log: true,
            tls: crate::config::ApiTlsConfig::default(),
        };
        let server = ApiServer::new(
            &config,
            Arc::new(StdMutex::new(Vec::new())),
            None,
            Arc::new(StdMutex::new(HashMap::new())),
            Instant::now(),
            None,
            None,
            reload_tx,
            mpsc::channel(8).0,
            None,
            None,
            None,
            &ActionConfig::default(),
        );
        let server_cancel = server.cancel_token();
        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            cancel_clone.cancelled().await;
            server_cancel.cancel();
        });
        server.spawn().unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        stream
            .write_all(
                b"GET /api/v1/health HTTP/1.1\r\nHost: localhost\r\nOrigin: https://any.example.com\r\n\r\n",
            )
            .await
            .unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);
        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("Access-Control-Allow-Origin: *"));
        assert!(response.contains("Vary: Origin"));

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_api_server_cors_rejected_origin() {
        let port = 19262;
        let cancel = CancellationToken::new();

        let (reload_tx, _reload_rx) = mpsc::channel::<()>(1);
        let config = ApiConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port,
            tokens: Vec::new(),
            rate_limit: ApiRateLimitConfig::default(),
            websocket: WebSocketConfig::default(),
            cors: CorsConfig {
                enabled: true,
                allowed_origins: vec!["https://allowed.example.com".to_string()],
                ..CorsConfig::default()
            },
            openapi_enabled: true,
            default_page_size: 50,
            max_page_size: 200,
            batch_max_size: 1000,
            max_request_body_size: 1_048_576,
            access_log: true,
            tls: crate::config::ApiTlsConfig::default(),
        };
        let server = ApiServer::new(
            &config,
            Arc::new(StdMutex::new(Vec::new())),
            None,
            Arc::new(StdMutex::new(HashMap::new())),
            Instant::now(),
            None,
            None,
            reload_tx,
            mpsc::channel(8).0,
            None,
            None,
            None,
            &ActionConfig::default(),
        );
        let server_cancel = server.cancel_token();
        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            cancel_clone.cancelled().await;
            server_cancel.cancel();
        });
        server.spawn().unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        stream
            .write_all(
                b"GET /api/v1/health HTTP/1.1\r\nHost: localhost\r\nOrigin: https://evil.example.com\r\n\r\n",
            )
            .await
            .unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);
        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(!response.contains("Access-Control-Allow-Origin"));

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_api_server_openapi_endpoint() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let (reload_tx, _reload_rx) = mpsc::channel::<()>(1);
        let config = ApiConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port,
            tokens: Vec::new(),
            rate_limit: ApiRateLimitConfig::default(),
            websocket: WebSocketConfig::default(),
            cors: CorsConfig::default(),
            openapi_enabled: true,
            default_page_size: 50,
            max_page_size: 200,
            batch_max_size: 1000,
            max_request_body_size: 1_048_576,
            access_log: true,
            tls: crate::config::ApiTlsConfig::default(),
        };
        let server = ApiServer::new(
            &config,
            Arc::new(StdMutex::new(Vec::new())),
            None,
            Arc::new(StdMutex::new(HashMap::new())),
            Instant::now(),
            None,
            None,
            reload_tx,
            mpsc::channel(8).0,
            None,
            None,
            None,
            &ActionConfig::default(),
        );
        let cancel = server.cancel_token();
        server.spawn().unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        stream
            .write_all(b"GET /api/v1/openapi.json HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);
        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("\"openapi\":\"3.0.3\""));
        assert!(response.contains("\"paths\""));
        assert!(response.contains("/api/v1/health"));

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_api_server_openapi_disabled() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let (reload_tx, _reload_rx) = mpsc::channel::<()>(1);
        let config = ApiConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port,
            tokens: Vec::new(),
            rate_limit: ApiRateLimitConfig::default(),
            websocket: WebSocketConfig::default(),
            cors: CorsConfig::default(),
            openapi_enabled: false,
            default_page_size: 50,
            max_page_size: 200,
            batch_max_size: 1000,
            max_request_body_size: 1_048_576,
            access_log: true,
            tls: crate::config::ApiTlsConfig::default(),
        };
        let server = ApiServer::new(
            &config,
            Arc::new(StdMutex::new(Vec::new())),
            None,
            Arc::new(StdMutex::new(HashMap::new())),
            Instant::now(),
            None,
            None,
            reload_tx,
            mpsc::channel(8).0,
            None,
            None,
            None,
            &ActionConfig::default(),
        );
        let cancel = server.cancel_token();
        server.spawn().unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        stream
            .write_all(b"GET /api/v1/openapi.json HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);
        assert!(response.contains("HTTP/1.1 404"));
        assert!(response.contains("OpenAPI"));

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    fn setup_test_db(count: usize) -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = rusqlite::Connection::open(tmp.path()).unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_module TEXT NOT NULL,
                event_type TEXT NOT NULL,
                message TEXT NOT NULL,
                details TEXT
            )",
        )
        .unwrap();
        for i in 0..count {
            conn.execute(
                "INSERT INTO security_events (timestamp, severity, source_module, event_type, message) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    format!("2026-01-01T00:{:02}:00", i),
                    "INFO",
                    "test_module",
                    "test_event",
                    format!("テストイベント{}", i),
                ],
            )
            .unwrap();
        }
        tmp
    }

    #[test]
    fn test_events_pagination_basic() {
        let tmp = setup_test_db(3);
        let db_path = tmp.path().to_str().unwrap();
        let params = HashMap::new();
        let result = ApiServer::build_events_response(db_path, &params, 50, 200).unwrap();
        assert!(result.contains(r#""items":["#));
        assert!(result.contains(r#""has_more":false"#));
        assert!(result.contains(r#""next_cursor":null"#));
        assert!(result.contains(r#""count":3"#));
    }

    #[test]
    fn test_events_pagination_with_cursor() {
        let tmp = setup_test_db(5);
        let db_path = tmp.path().to_str().unwrap();

        // 最初のページ（limit=2）
        let mut params = HashMap::new();
        params.insert("limit".to_string(), "2".to_string());
        let result = ApiServer::build_events_response(db_path, &params, 50, 200).unwrap();
        assert!(result.contains(r#""has_more":true"#));
        assert!(result.contains(r#""count":2"#));

        // next_cursor を取得
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        let next_cursor = parsed["next_cursor"].as_i64().unwrap();

        // 2ページ目
        let mut params2 = HashMap::new();
        params2.insert("limit".to_string(), "2".to_string());
        params2.insert("cursor".to_string(), next_cursor.to_string());
        let result2 = ApiServer::build_events_response(db_path, &params2, 50, 200).unwrap();
        let parsed2: serde_json::Value = serde_json::from_str(&result2).unwrap();
        assert_eq!(parsed2["count"].as_i64().unwrap(), 2);
        assert!(parsed2["has_more"].as_bool().unwrap());

        // 各アイテムの id が cursor より小さいこと
        for item in parsed2["items"].as_array().unwrap() {
            assert!(item["id"].as_i64().unwrap() < next_cursor);
        }
    }

    #[test]
    fn test_events_pagination_has_more() {
        let tmp = setup_test_db(5);
        let db_path = tmp.path().to_str().unwrap();

        // limit=5 で 5件ちょうど → has_more=false
        let mut params = HashMap::new();
        params.insert("limit".to_string(), "5".to_string());
        let result = ApiServer::build_events_response(db_path, &params, 50, 200).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(!parsed["has_more"].as_bool().unwrap());
        assert_eq!(parsed["count"].as_i64().unwrap(), 5);
        assert!(parsed["next_cursor"].is_null());

        // limit=4 で 5件中4件 → has_more=true
        let mut params2 = HashMap::new();
        params2.insert("limit".to_string(), "4".to_string());
        let result2 = ApiServer::build_events_response(db_path, &params2, 50, 200).unwrap();
        let parsed2: serde_json::Value = serde_json::from_str(&result2).unwrap();
        assert!(parsed2["has_more"].as_bool().unwrap());
        assert_eq!(parsed2["count"].as_i64().unwrap(), 4);
        assert!(parsed2["next_cursor"].is_number());
    }

    #[test]
    fn test_required_role_batch_endpoints() {
        assert_eq!(
            ApiServer::required_role(&HttpMethod::Post, "/api/v1/events/batch/delete"),
            Some(ApiRole::Admin)
        );
        assert_eq!(
            ApiServer::required_role(&HttpMethod::Post, "/api/v1/events/batch/export"),
            Some(ApiRole::ReadOnly)
        );
        assert_eq!(
            ApiServer::required_role(&HttpMethod::Post, "/api/v1/events/batch/acknowledge"),
            Some(ApiRole::Admin)
        );
    }

    #[test]
    fn test_access_log_flag() {
        let config = ApiConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port: 0,
            tokens: vec![],
            rate_limit: ApiRateLimitConfig::default(),
            websocket: WebSocketConfig::default(),
            cors: CorsConfig::default(),
            openapi_enabled: true,
            default_page_size: 50,
            max_page_size: 200,
            batch_max_size: 1000,
            max_request_body_size: 1_048_576,
            access_log: false,
            tls: crate::config::ApiTlsConfig::default(),
        };
        let server = ApiServer::new(
            &config,
            Arc::new(StdMutex::new(Vec::new())),
            None,
            Arc::new(StdMutex::new(HashMap::new())),
            Instant::now(),
            None,
            None,
            tokio::sync::mpsc::channel(1).0,
            mpsc::channel(8).0,
            None,
            None,
            None,
            &ActionConfig::default(),
        );
        let flag = server.access_log_flag();
        assert!(!flag.load(Ordering::Relaxed));

        flag.store(true, Ordering::Relaxed);
        assert!(server.access_log_flag().load(Ordering::Relaxed));
    }

    #[test]
    fn test_access_log_default_true() {
        let config = ApiConfig::default();
        assert!(config.access_log);
    }

    #[test]
    fn test_tls_config_default() {
        let config = crate::config::ApiTlsConfig::default();
        assert!(!config.enabled);
        assert!(config.cert_file.is_empty());
        assert!(config.key_file.is_empty());
        assert!(!config.mtls.enabled);
        assert!(config.mtls.client_ca_file.is_empty());
        assert_eq!(config.mtls.client_auth_mode, "required");
    }

    #[test]
    fn test_tls_config_deserialize_disabled() {
        let toml_str = r#"
            enabled = false
        "#;
        let config: crate::config::ApiTlsConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.enabled);
        assert!(config.cert_file.is_empty());
        assert!(config.key_file.is_empty());
    }

    #[test]
    fn test_tls_config_deserialize_enabled() {
        let toml_str = r#"
            enabled = true
            cert_file = "/etc/certs/server.crt"
            key_file = "/etc/certs/server.key"
        "#;
        let config: crate::config::ApiTlsConfig = toml::from_str(toml_str).unwrap();
        assert!(config.enabled);
        assert_eq!(config.cert_file, "/etc/certs/server.crt");
        assert_eq!(config.key_file, "/etc/certs/server.key");
    }

    #[test]
    fn test_api_config_with_tls_deserialize() {
        let toml_str = r#"
            enabled = true
            bind_address = "0.0.0.0"
            port = 9201
            [tls]
            enabled = true
            cert_file = "/path/to/cert.pem"
            key_file = "/path/to/key.pem"
        "#;
        let config: ApiConfig = toml::from_str(toml_str).unwrap();
        assert!(config.tls.enabled);
        assert_eq!(config.tls.cert_file, "/path/to/cert.pem");
        assert_eq!(config.tls.key_file, "/path/to/key.pem");
    }

    #[test]
    fn test_api_config_without_tls_section() {
        let toml_str = r#"
            enabled = true
            bind_address = "127.0.0.1"
            port = 9201
        "#;
        let config: ApiConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.tls.enabled);
        assert!(config.tls.cert_file.is_empty());
        assert!(config.tls.key_file.is_empty());
    }

    #[test]
    fn test_build_tls_acceptor_invalid_cert_path() {
        let tls_config = crate::config::ApiTlsConfig {
            enabled: true,
            cert_file: "/nonexistent/cert.pem".to_string(),
            key_file: "/nonexistent/key.pem".to_string(),
            mtls: Default::default(),
        };
        let result = build_tls_acceptor(&tls_config);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.to_string().contains("証明書ファイルを開けません"));
    }

    #[test]
    fn test_build_tls_acceptor_invalid_key_path() {
        // 証明書ファイルだけ存在するが秘密鍵がない場合
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");

        // rcgen で自己署名証明書を生成
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_pem = cert.cert.pem();
        std::fs::write(&cert_path, cert_pem).unwrap();

        let tls_config = crate::config::ApiTlsConfig {
            enabled: true,
            cert_file: cert_path.to_string_lossy().to_string(),
            key_file: "/nonexistent/key.pem".to_string(),
            mtls: Default::default(),
        };
        let result = build_tls_acceptor(&tls_config);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.to_string().contains("秘密鍵ファイルを開けません"));
    }

    #[test]
    fn test_build_tls_acceptor_success() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");

        // rcgen で自己署名証明書と秘密鍵を生成
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();
        std::fs::write(&cert_path, cert_pem).unwrap();
        std::fs::write(&key_path, key_pem).unwrap();

        let tls_config = crate::config::ApiTlsConfig {
            enabled: true,
            cert_file: cert_path.to_string_lossy().to_string(),
            key_file: key_path.to_string_lossy().to_string(),
            mtls: Default::default(),
        };
        let result = build_tls_acceptor(&tls_config);
        assert!(
            result.is_ok(),
            "TLS アクセプター構築に失敗: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_build_tls_acceptor_empty_cert_file() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("empty_cert.pem");
        let key_path = dir.path().join("empty_key.pem");
        std::fs::write(&cert_path, "").unwrap();
        std::fs::write(&key_path, "").unwrap();

        let tls_config = crate::config::ApiTlsConfig {
            enabled: true,
            cert_file: cert_path.to_string_lossy().to_string(),
            key_file: key_path.to_string_lossy().to_string(),
            mtls: Default::default(),
        };
        let result = build_tls_acceptor(&tls_config);
        assert!(result.is_err());
    }

    #[test]
    fn test_mtls_config_default() {
        let config = crate::config::ApiMtlsConfig::default();
        assert!(!config.enabled);
        assert!(config.client_ca_file.is_empty());
        assert_eq!(config.client_auth_mode, "required");
    }

    #[test]
    fn test_mtls_config_deserialize() {
        let toml_str = r#"
            enabled = true
            client_ca_file = "/etc/certs/client-ca.crt"
            client_auth_mode = "optional"
        "#;
        let config: crate::config::ApiMtlsConfig = toml::from_str(toml_str).unwrap();
        assert!(config.enabled);
        assert_eq!(config.client_ca_file, "/etc/certs/client-ca.crt");
        assert_eq!(config.client_auth_mode, "optional");
    }

    #[test]
    fn test_mtls_config_deserialize_default_mode() {
        let toml_str = r#"
            enabled = true
            client_ca_file = "/etc/certs/client-ca.crt"
        "#;
        let config: crate::config::ApiMtlsConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.client_auth_mode, "required");
    }

    #[test]
    fn test_tls_config_with_mtls_deserialize() {
        let toml_str = r#"
            enabled = true
            cert_file = "/path/to/cert.pem"
            key_file = "/path/to/key.pem"
            [mtls]
            enabled = true
            client_ca_file = "/path/to/client-ca.crt"
            client_auth_mode = "required"
        "#;
        let config: crate::config::ApiTlsConfig = toml::from_str(toml_str).unwrap();
        assert!(config.enabled);
        assert!(config.mtls.enabled);
        assert_eq!(config.mtls.client_ca_file, "/path/to/client-ca.crt");
        assert_eq!(config.mtls.client_auth_mode, "required");
    }

    #[test]
    fn test_tls_config_without_mtls_section() {
        let toml_str = r#"
            enabled = true
            cert_file = "/path/to/cert.pem"
            key_file = "/path/to/key.pem"
        "#;
        let config: crate::config::ApiTlsConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.mtls.enabled);
    }

    #[test]
    fn test_build_tls_acceptor_mtls_invalid_ca_path() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

        let tls_config = crate::config::ApiTlsConfig {
            enabled: true,
            cert_file: cert_path.to_string_lossy().to_string(),
            key_file: key_path.to_string_lossy().to_string(),
            mtls: crate::config::ApiMtlsConfig {
                enabled: true,
                client_ca_file: "/nonexistent/client-ca.crt".to_string(),
                client_auth_mode: "required".to_string(),
            },
        };
        let result = build_tls_acceptor(&tls_config);
        assert!(result.is_err());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("クライアント CA 証明書ファイルを開けません")
        );
    }

    #[test]
    fn test_build_tls_acceptor_mtls_required() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        let ca_path = dir.path().join("client-ca.crt");

        let ca = rcgen::generate_simple_self_signed(vec!["CA".to_string()]).unwrap();
        let server = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        std::fs::write(&cert_path, server.cert.pem()).unwrap();
        std::fs::write(&key_path, server.key_pair.serialize_pem()).unwrap();
        std::fs::write(&ca_path, ca.cert.pem()).unwrap();

        let tls_config = crate::config::ApiTlsConfig {
            enabled: true,
            cert_file: cert_path.to_string_lossy().to_string(),
            key_file: key_path.to_string_lossy().to_string(),
            mtls: crate::config::ApiMtlsConfig {
                enabled: true,
                client_ca_file: ca_path.to_string_lossy().to_string(),
                client_auth_mode: "required".to_string(),
            },
        };
        let result = build_tls_acceptor(&tls_config);
        assert!(
            result.is_ok(),
            "mTLS (required) の構築に失敗: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_build_tls_acceptor_mtls_optional() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        let ca_path = dir.path().join("client-ca.crt");

        let ca = rcgen::generate_simple_self_signed(vec!["CA".to_string()]).unwrap();
        let server = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        std::fs::write(&cert_path, server.cert.pem()).unwrap();
        std::fs::write(&key_path, server.key_pair.serialize_pem()).unwrap();
        std::fs::write(&ca_path, ca.cert.pem()).unwrap();

        let tls_config = crate::config::ApiTlsConfig {
            enabled: true,
            cert_file: cert_path.to_string_lossy().to_string(),
            key_file: key_path.to_string_lossy().to_string(),
            mtls: crate::config::ApiMtlsConfig {
                enabled: true,
                client_ca_file: ca_path.to_string_lossy().to_string(),
                client_auth_mode: "optional".to_string(),
            },
        };
        let result = build_tls_acceptor(&tls_config);
        assert!(
            result.is_ok(),
            "mTLS (optional) の構築に失敗: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_build_tls_acceptor_mtls_invalid_mode_falls_back_to_required() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        let ca_path = dir.path().join("client-ca.crt");

        let ca = rcgen::generate_simple_self_signed(vec!["CA".to_string()]).unwrap();
        let server = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        std::fs::write(&cert_path, server.cert.pem()).unwrap();
        std::fs::write(&key_path, server.key_pair.serialize_pem()).unwrap();
        std::fs::write(&ca_path, ca.cert.pem()).unwrap();

        let tls_config = crate::config::ApiTlsConfig {
            enabled: true,
            cert_file: cert_path.to_string_lossy().to_string(),
            key_file: key_path.to_string_lossy().to_string(),
            mtls: crate::config::ApiMtlsConfig {
                enabled: true,
                client_ca_file: ca_path.to_string_lossy().to_string(),
                client_auth_mode: "invalid_mode".to_string(),
            },
        };
        let result = build_tls_acceptor(&tls_config);
        assert!(
            result.is_ok(),
            "不正な client_auth_mode は required にフォールバックすべき: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_build_tls_acceptor_mtls_invalid_ca_cert_content() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        let ca_path = dir.path().join("client-ca.crt");

        let server = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        std::fs::write(&cert_path, server.cert.pem()).unwrap();
        std::fs::write(&key_path, server.key_pair.serialize_pem()).unwrap();
        std::fs::write(&ca_path, "not a valid certificate").unwrap();

        let tls_config = crate::config::ApiTlsConfig {
            enabled: true,
            cert_file: cert_path.to_string_lossy().to_string(),
            key_file: key_path.to_string_lossy().to_string(),
            mtls: crate::config::ApiMtlsConfig {
                enabled: true,
                client_ca_file: ca_path.to_string_lossy().to_string(),
                client_auth_mode: "required".to_string(),
            },
        };
        let result = build_tls_acceptor(&tls_config);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_tls_acceptor_mtls_disabled_ignores_mtls_settings() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");

        let server = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        std::fs::write(&cert_path, server.cert.pem()).unwrap();
        std::fs::write(&key_path, server.key_pair.serialize_pem()).unwrap();

        let tls_config = crate::config::ApiTlsConfig {
            enabled: true,
            cert_file: cert_path.to_string_lossy().to_string(),
            key_file: key_path.to_string_lossy().to_string(),
            mtls: crate::config::ApiMtlsConfig {
                enabled: false,
                client_ca_file: "/nonexistent/path.crt".to_string(),
                client_auth_mode: "required".to_string(),
            },
        };
        let result = build_tls_acceptor(&tls_config);
        assert!(
            result.is_ok(),
            "mTLS 無効時は CA パスが不正でもエラーにならないべき: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_parse_request_delete() {
        let (method, path, params) = ApiServer::parse_request(
            "DELETE /api/v1/archives/events_20260101.jsonl HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        assert!(matches!(method, HttpMethod::Delete));
        assert_eq!(path, "/api/v1/archives/events_20260101.jsonl");
        assert!(params.is_empty());
    }

    #[test]
    fn test_required_role_archives_list() {
        let role = ApiServer::required_role(&HttpMethod::Get, "/api/v1/archives");
        assert_eq!(role, Some(ApiRole::ReadOnly));
    }

    #[test]
    fn test_required_role_archives_create() {
        let role = ApiServer::required_role(&HttpMethod::Post, "/api/v1/archives");
        assert_eq!(role, Some(ApiRole::Admin));
    }

    #[test]
    fn test_required_role_archives_restore() {
        let role = ApiServer::required_role(&HttpMethod::Post, "/api/v1/archives/restore");
        assert_eq!(role, Some(ApiRole::Admin));
    }

    #[test]
    fn test_required_role_archives_rotate() {
        let role = ApiServer::required_role(&HttpMethod::Post, "/api/v1/archives/rotate");
        assert_eq!(role, Some(ApiRole::Admin));
    }

    #[test]
    fn test_required_role_archives_delete() {
        let role =
            ApiServer::required_role(&HttpMethod::Delete, "/api/v1/archives/some_file.jsonl");
        assert_eq!(role, Some(ApiRole::Admin));
    }

    #[test]
    fn test_required_role_module_control_start() {
        let role = ApiServer::required_role(
            &HttpMethod::Post,
            "/api/v1/modules/DNS設定改ざん検知モジュール/start",
        );
        assert_eq!(role, Some(ApiRole::Admin));
    }

    #[test]
    fn test_required_role_module_control_stop() {
        let role = ApiServer::required_role(
            &HttpMethod::Post,
            "/api/v1/modules/DNS設定改ざん検知モジュール/stop",
        );
        assert_eq!(role, Some(ApiRole::Admin));
    }

    #[test]
    fn test_required_role_module_control_restart() {
        let role = ApiServer::required_role(
            &HttpMethod::Post,
            "/api/v1/modules/DNS設定改ざん検知モジュール/restart",
        );
        assert_eq!(role, Some(ApiRole::Admin));
    }

    #[test]
    fn test_required_role_module_control_get_not_matched() {
        let role = ApiServer::required_role(
            &HttpMethod::Get,
            "/api/v1/modules/DNS設定改ざん検知モジュール/start",
        );
        assert_eq!(role, None);
    }

    #[test]
    fn test_webhooks_response_empty() {
        let config = ActionConfig {
            enabled: true,
            rules: vec![],
            rate_limit: None,
            digest: None,
        };
        let shared = Arc::new(StdMutex::new(config));
        let body = ApiServer::build_webhooks_response(&shared);
        assert!(body.contains(r#""total":0"#));
        assert!(body.contains(r#""webhooks":[]"#));
    }

    #[test]
    fn test_webhooks_response_with_rule() {
        let config = ActionConfig {
            enabled: true,
            rules: vec![ActionRuleConfig {
                name: "test_webhook".to_string(),
                severity: Some("Critical".to_string()),
                module: None,
                action: "webhook".to_string(),
                command: None,
                timeout_secs: 10,
                url: Some("https://hooks.example.com/services/abc".to_string()),
                method: Some("POST".to_string()),
                headers: Some(std::collections::HashMap::new()),
                body_template: None,
                max_retries: Some(3),
            }],
            rate_limit: None,
            digest: None,
        };
        let shared = Arc::new(StdMutex::new(config));
        let body = ApiServer::build_webhooks_response(&shared);
        assert!(body.contains(r#""total":1"#));
        assert!(body.contains(r#""name":"test_webhook""#));
        assert!(body.contains(r#""action_type":"rule""#));
        assert!(body.contains(r#""url_masked":"https://hooks.example.com/*****""#));
        assert!(body.contains(r#""has_body_template":false"#));
    }

    #[test]
    fn test_webhooks_response_with_digest() {
        let config = ActionConfig {
            enabled: true,
            rules: vec![],
            rate_limit: None,
            digest: Some(DigestConfig {
                enabled: true,
                webhook_url: Some("https://example.com/digest".to_string()),
                ..DigestConfig::default()
            }),
        };
        let shared = Arc::new(StdMutex::new(config));
        let body = ApiServer::build_webhooks_response(&shared);
        assert!(body.contains(r#""total":1"#));
        assert!(body.contains(r#""action_type":"digest""#));
        assert!(body.contains(r#""name":"digest_notification""#));
    }

    #[test]
    fn test_webhooks_response_skips_non_webhook_rules() {
        let config = ActionConfig {
            enabled: true,
            rules: vec![ActionRuleConfig {
                name: "log_only".to_string(),
                severity: None,
                module: None,
                action: "log".to_string(),
                command: None,
                timeout_secs: 30,
                url: None,
                method: None,
                headers: None,
                body_template: None,
                max_retries: None,
            }],
            rate_limit: None,
            digest: None,
        };
        let shared = Arc::new(StdMutex::new(config));
        let body = ApiServer::build_webhooks_response(&shared);
        assert!(body.contains(r#""total":0"#));
    }

    #[test]
    fn test_webhooks_required_roles() {
        let role = ApiServer::required_role(&HttpMethod::Get, "/api/v1/webhooks");
        assert_eq!(role, Some(ApiRole::ReadOnly));

        let role = ApiServer::required_role(&HttpMethod::Post, "/api/v1/webhooks/test");
        assert_eq!(role, Some(ApiRole::Admin));
    }

    #[test]
    fn test_extract_json_string() {
        let json = r#"{"name": "test_webhook", "other": 123}"#;
        assert_eq!(
            ApiServer::extract_json_string(json, "name"),
            Some("test_webhook".to_string())
        );
        assert_eq!(ApiServer::extract_json_string(json, "missing"), None);
    }

    #[test]
    fn test_extract_json_string_escaped() {
        let json = r#"{"name": "test\"quoted"}"#;
        assert_eq!(
            ApiServer::extract_json_string(json, "name"),
            Some(r#"test"quoted"#.to_string())
        );
    }

    // ================================================================
    // イベントサマリー API テスト
    // ================================================================

    #[test]
    fn test_summary_endpoints_required_role() {
        let paths = [
            "/api/v1/events/summary",
            "/api/v1/events/summary/timeline",
            "/api/v1/events/summary/modules",
            "/api/v1/events/summary/severity",
        ];
        for path in &paths {
            let role = ApiServer::required_role(&HttpMethod::Get, path);
            assert_eq!(role, Some(ApiRole::ReadOnly), "path={}", path);
        }
    }

    /// テスト用ヘルパー: サマリーテスト用の SQLite DB ファイルを作成
    fn create_summary_test_db() -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = rusqlite::Connection::open(tmp.path()).unwrap();
        crate::core::event_store::init_database(&conn).unwrap();

        let base = 1_775_952_000i64; // 2026-04-10 00:00:00 UTC
        for (ts, sev, module) in &[
            (base, "INFO", "mod_a"),
            (base + 3600, "WARNING", "mod_a"),
            (base + 7200, "CRITICAL", "mod_b"),
        ] {
            conn.execute(
                "INSERT INTO security_events (timestamp, severity, source_module, event_type, message) \
                 VALUES (?1, ?2, ?3, 'test', 'msg')",
                rusqlite::params![ts, sev, module],
            )
            .unwrap();
        }
        tmp
    }

    #[test]
    fn test_handle_events_summary_default() {
        let db = create_summary_test_db();
        let db_path = db.path().to_str().unwrap();
        let params = HashMap::new();

        let result = ApiServer::handle_events_summary(db_path, "", &params);
        assert!(result.is_ok());
        let body = result.unwrap();
        assert!(body.contains("\"total\""));
        assert!(body.contains("\"by_severity\""));
        assert!(body.contains("\"by_module\""));
    }

    #[test]
    fn test_handle_events_summary_invalid_since() {
        let db = create_summary_test_db();
        let db_path = db.path().to_str().unwrap();
        let mut params = HashMap::new();
        params.insert("since".to_string(), "not-a-date".to_string());

        let result = ApiServer::handle_events_summary(db_path, "", &params);
        assert!(result.is_err());
        let (code, _msg) = result.unwrap_err();
        assert_eq!(code, 400);
    }

    #[test]
    fn test_handle_events_summary_since_after_until() {
        let db = create_summary_test_db();
        let db_path = db.path().to_str().unwrap();
        let mut params = HashMap::new();
        params.insert("since".to_string(), "2026-04-15".to_string());
        params.insert("until".to_string(), "2026-04-10".to_string());

        let result = ApiServer::handle_events_summary(db_path, "", &params);
        assert!(result.is_err());
        let (code, msg) = result.unwrap_err();
        assert_eq!(code, 400);
        assert!(msg.contains("since"));
    }

    #[test]
    fn test_handle_events_summary_period_exceeds_90_days() {
        let db = create_summary_test_db();
        let db_path = db.path().to_str().unwrap();
        let mut params = HashMap::new();
        params.insert("since".to_string(), "2026-01-01".to_string());
        params.insert("until".to_string(), "2026-06-01".to_string());

        let result = ApiServer::handle_events_summary(db_path, "", &params);
        assert!(result.is_err());
        let (code, msg) = result.unwrap_err();
        assert_eq!(code, 400);
        assert!(msg.contains("90"));
    }

    #[test]
    fn test_handle_events_summary_invalid_severity() {
        let db = create_summary_test_db();
        let db_path = db.path().to_str().unwrap();
        let mut params = HashMap::new();
        params.insert("severity".to_string(), "UNKNOWN".to_string());

        let result = ApiServer::handle_events_summary(db_path, "", &params);
        assert!(result.is_err());
        let (code, _msg) = result.unwrap_err();
        assert_eq!(code, 400);
    }

    #[test]
    fn test_handle_events_summary_invalid_interval() {
        let db = create_summary_test_db();
        let db_path = db.path().to_str().unwrap();
        let mut params = HashMap::new();
        params.insert("interval".to_string(), "minute".to_string());

        let result = ApiServer::handle_events_summary(db_path, "/timeline", &params);
        assert!(result.is_err());
        let (code, _msg) = result.unwrap_err();
        assert_eq!(code, 400);
    }

    #[test]
    fn test_handle_events_summary_limit_zero() {
        let db = create_summary_test_db();
        let db_path = db.path().to_str().unwrap();
        let mut params = HashMap::new();
        params.insert("limit".to_string(), "0".to_string());

        let result = ApiServer::handle_events_summary(db_path, "/modules", &params);
        assert!(result.is_err());
        let (code, _msg) = result.unwrap_err();
        assert_eq!(code, 400);
    }

    #[test]
    fn test_handle_events_summary_unknown_sub_path() {
        let db = create_summary_test_db();
        let db_path = db.path().to_str().unwrap();
        let params = HashMap::new();

        let result = ApiServer::handle_events_summary(db_path, "/unknown", &params);
        assert!(result.is_err());
        let (code, _msg) = result.unwrap_err();
        assert_eq!(code, 404);
    }

    #[test]
    fn test_handle_events_summary_timeline_ok() {
        let db = create_summary_test_db();
        let db_path = db.path().to_str().unwrap();
        let mut params = HashMap::new();
        params.insert("since".to_string(), "2026-04-10".to_string());
        params.insert("until".to_string(), "2026-04-11".to_string());
        params.insert("interval".to_string(), "hour".to_string());

        let result = ApiServer::handle_events_summary(db_path, "/timeline", &params);
        assert!(result.is_ok());
        let body = result.unwrap();
        assert!(body.contains("\"buckets\""));
        assert!(body.contains("\"interval\":\"hour\""));
    }

    #[test]
    fn test_handle_events_summary_modules_ok() {
        let db = create_summary_test_db();
        let db_path = db.path().to_str().unwrap();
        let mut params = HashMap::new();
        params.insert("since".to_string(), "2026-04-10".to_string());
        params.insert("until".to_string(), "2026-04-11".to_string());

        let result = ApiServer::handle_events_summary(db_path, "/modules", &params);
        assert!(result.is_ok());
        let body = result.unwrap();
        assert!(body.contains("\"modules\""));
    }

    #[test]
    fn test_handle_events_summary_severity_ok() {
        let db = create_summary_test_db();
        let db_path = db.path().to_str().unwrap();
        let mut params = HashMap::new();
        params.insert("since".to_string(), "2026-04-10".to_string());
        params.insert("until".to_string(), "2026-04-11".to_string());

        let result = ApiServer::handle_events_summary(db_path, "/severity", &params);
        assert!(result.is_ok());
        let body = result.unwrap();
        assert!(body.contains("\"severities\""));
        assert!(body.contains("\"total\""));
    }
}
