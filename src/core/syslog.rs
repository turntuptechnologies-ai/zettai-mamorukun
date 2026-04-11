//! Syslog イベント転送 — RFC 5424 / RFC 5425 形式で外部 SIEM に SecurityEvent を転送

use crate::config::SyslogConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{broadcast, watch};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls;

/// ホットリロード対象のランタイム設定
#[derive(Debug, Clone)]
pub struct SyslogRuntimeConfig {
    /// プロトコル（"udp", "tcp", "tls"）
    pub protocol: String,
    /// Syslog サーバのアドレス
    pub server: String,
    /// Syslog サーバのポート
    pub port: u16,
    /// Syslog facility
    pub facility: String,
    /// ホスト名
    pub hostname: String,
    /// アプリケーション名
    pub app_name: String,
    /// TLS CA 証明書ファイルパス（PEM 形式）
    pub tls_ca_cert_path: Option<String>,
    /// TLS ホスト名検証の有効/無効
    pub tls_verify_hostname: bool,
    /// TLS クライアント証明書ファイルパス（PEM 形式、mTLS 用）
    pub tls_client_cert_path: Option<String>,
    /// TLS クライアント秘密鍵ファイルパス（PEM 形式、mTLS 用）
    pub tls_client_key_path: Option<String>,
}

impl From<&SyslogConfig> for SyslogRuntimeConfig {
    fn from(config: &SyslogConfig) -> Self {
        Self {
            protocol: config.protocol.clone(),
            server: config.server.clone(),
            port: config.port,
            facility: config.facility.clone(),
            hostname: config.hostname.clone(),
            app_name: config.app_name.clone(),
            tls_ca_cert_path: config.tls.ca_cert_path.clone(),
            tls_verify_hostname: config.tls.verify_hostname,
            tls_client_cert_path: config.tls.client_cert_path.clone(),
            tls_client_key_path: config.tls.client_key_path.clone(),
        }
    }
}

/// Syslog 転送サブスクライバー
pub struct SyslogForwarder {
    receiver: broadcast::Receiver<SecurityEvent>,
    config_receiver: watch::Receiver<SyslogRuntimeConfig>,
    runtime: SyslogRuntimeConfig,
}

impl SyslogForwarder {
    /// 設定とイベントバスから SyslogForwarder を構築する
    pub fn new(
        config: &SyslogConfig,
        event_bus: &EventBus,
    ) -> (Self, watch::Sender<SyslogRuntimeConfig>) {
        let runtime = SyslogRuntimeConfig::from(config);
        let (config_sender, config_receiver) = watch::channel(runtime.clone());
        (
            Self {
                receiver: event_bus.subscribe(),
                config_receiver,
                runtime,
            },
            config_sender,
        )
    }

    /// 非同期タスクとして SyslogForwarder を起動する
    pub fn spawn(self) {
        tokio::spawn(async move {
            Self::run_loop(self.receiver, self.config_receiver, self.runtime).await;
        });
    }

    async fn run_loop(
        mut receiver: broadcast::Receiver<SecurityEvent>,
        mut config_receiver: watch::Receiver<SyslogRuntimeConfig>,
        mut runtime: SyslogRuntimeConfig,
    ) {
        let mut transport = Transport::connect(&runtime).await;

        loop {
            tokio::select! {
                result = receiver.recv() => {
                    match result {
                        Ok(event) => {
                            let message = format_rfc5424(&event, &runtime);
                            if let Err(e) = transport.send(&message, &runtime).await {
                                tracing::warn!(
                                    error = %e,
                                    "Syslog メッセージの送信に失敗しました"
                                );
                                transport = Transport::connect(&runtime).await;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(
                                skipped = n,
                                "Syslog: {} 件のイベントをスキップ（遅延）",
                                n
                            );
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            tracing::info!("イベントバスが閉じられました。Syslog フォワーダーを終了します");
                            break;
                        }
                    }
                }
                result = config_receiver.changed() => {
                    match result {
                        Ok(()) => {
                            let new_config = config_receiver.borrow_and_update().clone();
                            let needs_reconnect = new_config.protocol != runtime.protocol
                                || new_config.server != runtime.server
                                || new_config.port != runtime.port
                                || new_config.tls_ca_cert_path != runtime.tls_ca_cert_path
                                || new_config.tls_verify_hostname != runtime.tls_verify_hostname
                                || new_config.tls_client_cert_path != runtime.tls_client_cert_path
                                || new_config.tls_client_key_path != runtime.tls_client_key_path;
                            runtime = new_config;
                            if needs_reconnect {
                                tracing::info!(
                                    protocol = %runtime.protocol,
                                    server = %runtime.server,
                                    port = runtime.port,
                                    "Syslog: 接続先をリロードしました"
                                );
                                transport = Transport::connect(&runtime).await;
                            } else {
                                tracing::info!("Syslog: 設定をリロードしました");
                            }
                        }
                        Err(_) => {
                            tracing::info!("設定チャネルが閉じられました。Syslog フォワーダーを終了します");
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// Syslog facility を数値コードに変換する
fn facility_code(facility: &str) -> u8 {
    match facility {
        "kern" => 0,
        "user" => 1,
        "mail" => 2,
        "daemon" => 3,
        "auth" => 4,
        "syslog" => 5,
        "lpr" => 6,
        "news" => 7,
        "uucp" => 8,
        "cron" => 9,
        "authpriv" => 10,
        "ftp" => 11,
        "local0" => 16,
        "local1" => 17,
        "local2" => 18,
        "local3" => 19,
        "local4" => 20,
        "local5" => 21,
        "local6" => 22,
        "local7" => 23,
        _ => 16, // default to local0
    }
}

/// SecurityEvent の Severity を syslog severity (RFC 5424) に変換する
fn syslog_severity(severity: &Severity) -> u8 {
    match severity {
        Severity::Critical => 2, // Critical
        Severity::Warning => 4,  // Warning
        Severity::Info => 6,     // Informational
    }
}

/// PRI 値を計算する: facility * 8 + severity
fn pri_value(facility: &str, severity: &Severity) -> u8 {
    facility_code(facility) * 8 + syslog_severity(severity)
}

/// ホスト名を取得する（設定値が空ならシステムから自動取得）
fn resolve_hostname(configured: &str) -> String {
    if configured.is_empty() {
        gethostname::gethostname().to_string_lossy().into_owned()
    } else {
        configured.to_string()
    }
}

/// SystemTime を RFC 3339 形式のタイムスタンプに変換する
fn format_timestamp(ts: SystemTime) -> String {
    match ts.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(dur) => {
            let secs = dur.as_secs();
            let nanos = dur.subsec_nanos();

            let days_since_epoch = secs / 86400;
            let time_of_day = secs % 86400;
            let hours = time_of_day / 3600;
            let minutes = (time_of_day % 3600) / 60;
            let seconds = time_of_day % 60;

            // 年月日を計算
            let (year, month, day) = days_to_ymd(days_since_epoch);

            format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
                year,
                month,
                day,
                hours,
                minutes,
                seconds,
                nanos / 1000
            )
        }
        Err(_) => "-".to_string(),
    }
}

/// エポックからの日数を年月日に変換する
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Civil date from day count algorithm
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// SecurityEvent を RFC 5424 形式のメッセージにフォーマットする
fn format_rfc5424(event: &SecurityEvent, config: &SyslogRuntimeConfig) -> String {
    let pri = pri_value(&config.facility, &event.severity);
    let timestamp = format_timestamp(event.timestamp);
    let hostname = resolve_hostname(&config.hostname);
    let pid = std::process::id();

    // SD-ELEMENT: 構造化データ
    let details_param = match &event.details {
        Some(d) => {
            let escaped = sd_escape(d);
            format!(" details=\"{}\"", escaped)
        }
        None => String::new(),
    };
    let sd = format!(
        "[zettai@0 eventType=\"{}\" sourceModule=\"{}\" severity=\"{}\"{}]",
        sd_escape(&event.event_type),
        sd_escape(&event.source_module),
        event.severity,
        details_param
    );

    format!(
        "<{}>1 {} {} {} {} - {} {}",
        pri, timestamp, hostname, config.app_name, pid, sd, event.message
    )
}

/// SD-PARAM の値をエスケープする（RFC 5424 Section 6.3.3）
fn sd_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(']', "\\]")
}

/// TLS クライアント設定を構築する
fn build_tls_config(config: &SyslogRuntimeConfig) -> Result<rustls::ClientConfig, String> {
    // CryptoProvider がまだインストールされていなければ ring を設定
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut root_store = rustls::RootCertStore::empty();

    if let Some(ref ca_path) = config.tls_ca_cert_path {
        let pem_data = std::fs::read(ca_path)
            .map_err(|e| format!("CA 証明書ファイルの読み込みに失敗: {}: {}", ca_path, e))?;
        let mut cursor = std::io::Cursor::new(pem_data);
        let certs = rustls_pemfile::certs(&mut cursor)
            .filter_map(|r| r.ok())
            .collect::<Vec<_>>();
        if certs.is_empty() {
            return Err(format!(
                "CA 証明書ファイルに有効な証明書が見つかりません: {}",
                ca_path
            ));
        }
        for cert in certs {
            root_store
                .add(cert)
                .map_err(|e| format!("CA 証明書の追加に失敗: {}", e))?;
        }
    } else {
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let client_auth = match (&config.tls_client_cert_path, &config.tls_client_key_path) {
        (Some(cert_path), Some(key_path)) => {
            let cert_pem = std::fs::read(cert_path).map_err(|e| {
                format!(
                    "クライアント証明書ファイルの読み込みに失敗: {}: {}",
                    cert_path, e
                )
            })?;
            let mut cert_cursor = std::io::Cursor::new(cert_pem);
            let certs = rustls_pemfile::certs(&mut cert_cursor)
                .filter_map(|r| r.ok())
                .collect::<Vec<_>>();
            if certs.is_empty() {
                return Err(format!(
                    "クライアント証明書ファイルに有効な証明書が見つかりません: {}",
                    cert_path
                ));
            }

            let key_pem = std::fs::read(key_path).map_err(|e| {
                format!(
                    "クライアント秘密鍵ファイルの読み込みに失敗: {}: {}",
                    key_path, e
                )
            })?;
            let mut key_cursor = std::io::Cursor::new(key_pem);
            let key = rustls_pemfile::private_key(&mut key_cursor)
                .map_err(|e| format!("クライアント秘密鍵の読み込みに失敗: {}: {}", key_path, e))?
                .ok_or_else(|| {
                    format!(
                        "クライアント秘密鍵ファイルに有効な秘密鍵が見つかりません: {}",
                        key_path
                    )
                })?;

            Some((certs, key))
        }
        (Some(_), None) => {
            return Err(
                "クライアント証明書が設定されていますが、秘密鍵（client_key_path）が設定されていません"
                    .to_string(),
            );
        }
        (None, Some(_)) => {
            return Err(
                "クライアント秘密鍵が設定されていますが、証明書（client_cert_path）が設定されていません"
                    .to_string(),
            );
        }
        (None, None) => None,
    };

    if config.tls_verify_hostname {
        let builder = rustls::ClientConfig::builder().with_root_certificates(root_store);
        match client_auth {
            Some((certs, key)) => builder
                .with_client_auth_cert(certs, key)
                .map_err(|e| format!("クライアント証明書の設定に失敗: {}", e)),
            None => Ok(builder.with_no_client_auth()),
        }
    } else {
        tracing::warn!(
            "Syslog TLS: ホスト名検証が無効です。本番環境では有効にすることを推奨します"
        );
        let builder = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier));
        match client_auth {
            Some((certs, key)) => builder
                .with_client_auth_cert(certs, key)
                .map_err(|e| format!("クライアント証明書の設定に失敗: {}", e)),
            None => Ok(builder.with_no_client_auth()),
        }
    }
}

/// ホスト名検証をスキップするカスタム証明書検証器
///
/// CA 証明書による署名検証は行わず、サーバ証明書の SAN/CN とホスト名の一致も検証しない。
/// 自己署名証明書を使用するテスト環境等での利用を想定。
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// トランスポート層（UDP / TCP / TLS）
enum Transport {
    Udp(UdpSocket),
    Tcp(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    Disconnected,
}

impl Transport {
    async fn connect(config: &SyslogRuntimeConfig) -> Self {
        let addr = format!("{}:{}", config.server, config.port);
        match config.protocol.as_str() {
            "udp" => match UdpSocket::bind("0.0.0.0:0").await {
                Ok(socket) => match socket.connect(&addr).await {
                    Ok(()) => {
                        tracing::info!(
                            protocol = "udp",
                            server = %config.server,
                            port = config.port,
                            "Syslog: UDP ソケットを接続しました"
                        );
                        Transport::Udp(socket)
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Syslog: UDP 接続に失敗しました");
                        Transport::Disconnected
                    }
                },
                Err(e) => {
                    tracing::warn!(error = %e, "Syslog: UDP ソケットのバインドに失敗しました");
                    Transport::Disconnected
                }
            },
            "tcp" => match TcpStream::connect(&addr).await {
                Ok(stream) => {
                    tracing::info!(
                        protocol = "tcp",
                        server = %config.server,
                        port = config.port,
                        "Syslog: TCP 接続を確立しました"
                    );
                    Transport::Tcp(stream)
                }
                Err(e) => {
                    tracing::warn!(error = %e, addr = %addr, "Syslog: TCP 接続に失敗しました");
                    Transport::Disconnected
                }
            },
            "tls" => {
                let tls_config = match build_tls_config(config) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(error = %e, "Syslog: TLS 設定の構築に失敗しました");
                        return Transport::Disconnected;
                    }
                };
                let connector = TlsConnector::from(Arc::new(tls_config));
                let tcp_stream = match TcpStream::connect(&addr).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(error = %e, addr = %addr, "Syslog: TLS 用 TCP 接続に失敗しました");
                        return Transport::Disconnected;
                    }
                };
                let server_name = match rustls_pki_types::ServerName::try_from(
                    config.server.clone(),
                ) {
                    Ok(name) => name,
                    Err(e) => {
                        tracing::warn!(error = %e, server = %config.server, "Syslog: サーバ名の解析に失敗しました");
                        return Transport::Disconnected;
                    }
                };
                match connector.connect(server_name, tcp_stream).await {
                    Ok(tls_stream) => {
                        tracing::info!(
                            protocol = "tls",
                            server = %config.server,
                            port = config.port,
                            "Syslog: TLS 接続を確立しました"
                        );
                        Transport::Tls(Box::new(tls_stream))
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Syslog: TLS ハンドシェイクに失敗しました");
                        Transport::Disconnected
                    }
                }
            }
            _ => {
                tracing::error!(protocol = %config.protocol, "Syslog: 不明なプロトコル");
                Transport::Disconnected
            }
        }
    }

    async fn send(&mut self, message: &str, config: &SyslogRuntimeConfig) -> Result<(), String> {
        match self {
            Transport::Udp(socket) => {
                socket
                    .send(message.as_bytes())
                    .await
                    .map_err(|e| format!("UDP 送信エラー: {}", e))?;
                Ok(())
            }
            Transport::Tcp(stream) => {
                let framed = format!("{}\n", message);
                stream
                    .write_all(framed.as_bytes())
                    .await
                    .map_err(|e| format!("TCP 送信エラー: {}", e))?;
                Ok(())
            }
            Transport::Tls(stream) => {
                let framed = format!("{}\n", message);
                stream
                    .write_all(framed.as_bytes())
                    .await
                    .map_err(|e| format!("TLS 送信エラー: {}", e))?;
                Ok(())
            }
            Transport::Disconnected => {
                *self = Self::connect(config).await;
                match self {
                    Transport::Udp(socket) => {
                        socket
                            .send(message.as_bytes())
                            .await
                            .map_err(|e| format!("UDP 送信エラー（再接続後）: {}", e))?;
                        Ok(())
                    }
                    Transport::Tcp(stream) => {
                        let framed = format!("{}\n", message);
                        stream
                            .write_all(framed.as_bytes())
                            .await
                            .map_err(|e| format!("TCP 送信エラー（再接続後）: {}", e))?;
                        Ok(())
                    }
                    Transport::Tls(stream) => {
                        let framed = format!("{}\n", message);
                        stream
                            .write_all(framed.as_bytes())
                            .await
                            .map_err(|e| format!("TLS 送信エラー（再接続後）: {}", e))?;
                        Ok(())
                    }
                    Transport::Disconnected => {
                        Err("Syslog サーバへの接続に失敗しました".to_string())
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SyslogTlsConfig;

    #[test]
    fn test_facility_code() {
        assert_eq!(facility_code("kern"), 0);
        assert_eq!(facility_code("auth"), 4);
        assert_eq!(facility_code("authpriv"), 10);
        assert_eq!(facility_code("local0"), 16);
        assert_eq!(facility_code("local7"), 23);
        assert_eq!(facility_code("daemon"), 3);
        assert_eq!(facility_code("unknown"), 16);
    }

    #[test]
    fn test_syslog_severity() {
        assert_eq!(syslog_severity(&Severity::Critical), 2);
        assert_eq!(syslog_severity(&Severity::Warning), 4);
        assert_eq!(syslog_severity(&Severity::Info), 6);
    }

    #[test]
    fn test_pri_value() {
        // local0 (16) * 8 + critical (2) = 130
        assert_eq!(pri_value("local0", &Severity::Critical), 130);
        // auth (4) * 8 + warning (4) = 36
        assert_eq!(pri_value("auth", &Severity::Warning), 36);
        // daemon (3) * 8 + info (6) = 30
        assert_eq!(pri_value("daemon", &Severity::Info), 30);
    }

    #[test]
    fn test_sd_escape() {
        assert_eq!(sd_escape("hello"), "hello");
        assert_eq!(sd_escape(r#"a"b"#), r#"a\"b"#);
        assert_eq!(sd_escape("a\\b"), "a\\\\b");
        assert_eq!(sd_escape("a]b"), "a\\]b");
    }

    #[test]
    fn test_format_rfc5424_basic() {
        let event = SecurityEvent::new(
            "file_modified",
            Severity::Warning,
            "file_integrity",
            "ファイルが変更されました: /etc/passwd",
        );

        let config = SyslogRuntimeConfig {
            protocol: "udp".to_string(),
            server: "127.0.0.1".to_string(),
            port: 514,
            facility: "local0".to_string(),
            hostname: "test-host".to_string(),
            app_name: "zettai-mamorukun".to_string(),
            tls_ca_cert_path: None,
            tls_verify_hostname: true,
            tls_client_cert_path: None,
            tls_client_key_path: None,
        };

        let msg = format_rfc5424(&event, &config);
        // PRI: local0(16)*8 + warning(4) = 132
        assert!(msg.starts_with("<132>1 "));
        assert!(msg.contains("test-host"));
        assert!(msg.contains("zettai-mamorukun"));
        assert!(msg.contains("eventType=\"file_modified\""));
        assert!(msg.contains("sourceModule=\"file_integrity\""));
        assert!(msg.contains("severity=\"WARNING\""));
        assert!(msg.contains("ファイルが変更されました: /etc/passwd"));
    }

    #[test]
    fn test_format_rfc5424_with_details() {
        let event = SecurityEvent::new(
            "process_anomaly",
            Severity::Critical,
            "process_monitor",
            "不審なプロセス検知",
        )
        .with_details("pid=1234, name=suspicious");

        let config = SyslogRuntimeConfig {
            protocol: "udp".to_string(),
            server: "127.0.0.1".to_string(),
            port: 514,
            facility: "auth".to_string(),
            hostname: "prod-server".to_string(),
            app_name: "zettai-mamorukun".to_string(),
            tls_ca_cert_path: None,
            tls_verify_hostname: true,
            tls_client_cert_path: None,
            tls_client_key_path: None,
        };

        let msg = format_rfc5424(&event, &config);
        // PRI: auth(4)*8 + critical(2) = 34
        assert!(msg.starts_with("<34>1 "));
        assert!(msg.contains("details=\"pid=1234, name=suspicious\""));
    }

    #[test]
    fn test_format_rfc5424_sd_escape_in_values() {
        let event = SecurityEvent::new("test\"event", Severity::Info, "test]module", "メッセージ");

        let config = SyslogRuntimeConfig {
            protocol: "udp".to_string(),
            server: "127.0.0.1".to_string(),
            port: 514,
            facility: "local0".to_string(),
            hostname: "host".to_string(),
            app_name: "app".to_string(),
            tls_ca_cert_path: None,
            tls_verify_hostname: true,
            tls_client_cert_path: None,
            tls_client_key_path: None,
        };

        let msg = format_rfc5424(&event, &config);
        assert!(msg.contains(r#"eventType="test\"event""#));
        assert!(msg.contains(r#"sourceModule="test\]module""#));
    }

    #[test]
    fn test_format_timestamp() {
        let ts = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1700000000);
        let formatted = format_timestamp(ts);
        assert!(formatted.starts_with("2023-11-14T"));
        assert!(formatted.ends_with('Z'));
    }

    #[test]
    fn test_days_to_ymd() {
        // 1970-01-01
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
        // 2000-01-01 = day 10957
        assert_eq!(days_to_ymd(10957), (2000, 1, 1));
    }

    #[test]
    fn test_resolve_hostname_configured() {
        assert_eq!(resolve_hostname("my-host"), "my-host");
    }

    #[test]
    fn test_resolve_hostname_auto() {
        let hostname = resolve_hostname("");
        assert!(!hostname.is_empty());
    }

    #[test]
    fn test_syslog_runtime_config_from_syslog_config() {
        let config = SyslogConfig {
            enabled: true,
            protocol: "tcp".to_string(),
            server: "192.168.1.100".to_string(),
            port: 1514,
            facility: "auth".to_string(),
            hostname: "my-server".to_string(),
            app_name: "test-app".to_string(),
            tls: SyslogTlsConfig::default(),
        };
        let runtime = SyslogRuntimeConfig::from(&config);
        assert_eq!(runtime.protocol, "tcp");
        assert_eq!(runtime.server, "192.168.1.100");
        assert_eq!(runtime.port, 1514);
        assert_eq!(runtime.facility, "auth");
        assert_eq!(runtime.hostname, "my-server");
        assert_eq!(runtime.app_name, "test-app");
        assert!(runtime.tls_ca_cert_path.is_none());
        assert!(runtime.tls_verify_hostname);
    }

    #[test]
    fn test_syslog_runtime_config_from_syslog_config_with_tls() {
        let config = SyslogConfig {
            enabled: true,
            protocol: "tls".to_string(),
            server: "siem.example.com".to_string(),
            port: 6514,
            facility: "local0".to_string(),
            hostname: "tls-host".to_string(),
            app_name: "zettai-tls".to_string(),
            tls: SyslogTlsConfig {
                ca_cert_path: Some("/etc/ssl/ca.pem".to_string()),
                verify_hostname: false,
                client_cert_path: None,
                client_key_path: None,
            },
        };
        let runtime = SyslogRuntimeConfig::from(&config);
        assert_eq!(runtime.protocol, "tls");
        assert_eq!(runtime.server, "siem.example.com");
        assert_eq!(runtime.port, 6514);
        assert_eq!(
            runtime.tls_ca_cert_path,
            Some("/etc/ssl/ca.pem".to_string())
        );
        assert!(!runtime.tls_verify_hostname);
    }

    #[test]
    fn test_syslog_forwarder_new() {
        let config = SyslogConfig::default();
        let bus = EventBus::new(16);
        let (forwarder, _sender) = SyslogForwarder::new(&config, &bus);
        assert_eq!(forwarder.runtime.protocol, "udp");
        assert_eq!(forwarder.runtime.server, "127.0.0.1");
        assert_eq!(forwarder.runtime.port, 514);
    }

    #[tokio::test]
    async fn test_syslog_forwarder_config_channel_closed() {
        let config = SyslogConfig {
            enabled: true,
            protocol: "udp".to_string(),
            server: "127.0.0.1".to_string(),
            port: 19514,
            facility: "local0".to_string(),
            hostname: "test".to_string(),
            app_name: "test".to_string(),
            tls: SyslogTlsConfig::default(),
        };
        let bus = EventBus::new(16);
        let (forwarder, sender) = SyslogForwarder::new(&config, &bus);
        forwarder.spawn();

        // sender をドロップしてチャネルを閉じる
        drop(sender);

        // フォワーダーが正常に終了することを確認
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    #[tokio::test]
    async fn test_syslog_forwarder_receives_and_sends_udp() {
        // ローカル UDP サーバを起動
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let config = SyslogConfig {
            enabled: true,
            protocol: "udp".to_string(),
            server: "127.0.0.1".to_string(),
            port: server_addr.port(),
            facility: "local0".to_string(),
            hostname: "test-host".to_string(),
            app_name: "zettai-test".to_string(),
            tls: SyslogTlsConfig::default(),
        };
        let bus = EventBus::new(16);
        let (forwarder, _sender) = SyslogForwarder::new(&config, &bus);
        forwarder.spawn();

        // イベントを発行
        bus.publish(SecurityEvent::new(
            "test_event",
            Severity::Warning,
            "test_module",
            "テストメッセージ",
        ));

        // メッセージの受信を待つ
        let mut buf = [0u8; 4096];
        let timeout = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            server_socket.recv(&mut buf),
        )
        .await;

        match timeout {
            Ok(Ok(len)) => {
                let received = std::str::from_utf8(&buf[..len]).unwrap();
                assert!(received.contains("<132>1 "));
                assert!(received.contains("test-host"));
                assert!(received.contains("zettai-test"));
                assert!(received.contains("eventType=\"test_event\""));
                assert!(received.contains("テストメッセージ"));
            }
            _ => panic!("UDP メッセージを受信できませんでした"),
        }
    }

    #[tokio::test]
    async fn test_syslog_forwarder_receives_and_sends_tcp() {
        // ローカル TCP サーバを起動
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let config = SyslogConfig {
            enabled: true,
            protocol: "tcp".to_string(),
            server: "127.0.0.1".to_string(),
            port: server_addr.port(),
            facility: "auth".to_string(),
            hostname: "tcp-test".to_string(),
            app_name: "zettai-tcp".to_string(),
            tls: SyslogTlsConfig::default(),
        };
        let bus = EventBus::new(16);
        let (forwarder, _sender) = SyslogForwarder::new(&config, &bus);
        forwarder.spawn();

        // TCP 接続が確立されるのを待つ
        let (mut stream, _) =
            tokio::time::timeout(std::time::Duration::from_secs(2), listener.accept())
                .await
                .unwrap()
                .unwrap();

        // イベントを発行
        bus.publish(SecurityEvent::new(
            "tcp_test_event",
            Severity::Critical,
            "tcp_module",
            "TCP テストメッセージ",
        ));

        // メッセージの受信を待つ
        let mut buf = [0u8; 4096];
        let timeout = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::io::AsyncReadExt::read(&mut stream, &mut buf),
        )
        .await;

        match timeout {
            Ok(Ok(len)) => {
                let received = std::str::from_utf8(&buf[..len]).unwrap();
                // PRI: auth(4)*8 + critical(2) = 34
                assert!(received.contains("<34>1 "));
                assert!(received.contains("tcp-test"));
                assert!(received.contains("zettai-tcp"));
                assert!(received.contains("TCP テストメッセージ"));
                assert!(received.ends_with('\n'));
            }
            _ => panic!("TCP メッセージを受信できませんでした"),
        }
    }

    #[tokio::test]
    async fn test_syslog_forwarder_hot_reload() {
        // ローカル UDP サーバを起動
        let server1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr1 = server1.local_addr().unwrap();

        let config = SyslogConfig {
            enabled: true,
            protocol: "udp".to_string(),
            server: "127.0.0.1".to_string(),
            port: addr1.port(),
            facility: "local0".to_string(),
            hostname: "reload-test".to_string(),
            app_name: "zettai-reload".to_string(),
            tls: SyslogTlsConfig::default(),
        };
        let bus = EventBus::new(16);
        let (forwarder, sender) = SyslogForwarder::new(&config, &bus);
        forwarder.spawn();

        // facility のみ変更（再接続不要）
        let new_runtime = SyslogRuntimeConfig {
            protocol: "udp".to_string(),
            server: "127.0.0.1".to_string(),
            port: addr1.port(),
            facility: "auth".to_string(),
            hostname: "reload-test".to_string(),
            app_name: "zettai-reload".to_string(),
            tls_ca_cert_path: None,
            tls_verify_hostname: true,
            tls_client_cert_path: None,
            tls_client_key_path: None,
        };
        sender.send(new_runtime).unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 新しい facility でイベント送信
        bus.publish(SecurityEvent::new(
            "reload_test",
            Severity::Info,
            "test",
            "リロードテスト",
        ));

        let mut buf = [0u8; 4096];
        let timeout =
            tokio::time::timeout(std::time::Duration::from_secs(2), server1.recv(&mut buf)).await;

        match timeout {
            Ok(Ok(len)) => {
                let received = std::str::from_utf8(&buf[..len]).unwrap();
                // PRI: auth(4)*8 + info(6) = 38
                assert!(received.starts_with("<38>1 "));
            }
            _ => panic!("リロード後の UDP メッセージを受信できませんでした"),
        }
    }

    #[tokio::test]
    async fn test_syslog_forwarder_receives_and_sends_tls() {
        use rcgen::{CertificateParams, KeyPair};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        // CryptoProvider を初期化
        let _ = rustls::crypto::ring::default_provider().install_default();

        // 自己署名 CA 証明書とサーバ証明書を生成
        let ca_key_pair = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(vec!["Test CA".to_string()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key_pair).unwrap();

        let server_key_pair = KeyPair::generate().unwrap();
        let server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let server_cert = server_params
            .signed_by(&server_key_pair, &ca_cert, &ca_key_pair)
            .unwrap();

        // CA 証明書を一時ファイルに書き出す
        let ca_pem = ca_cert.pem();
        let ca_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(ca_file.path(), ca_pem.as_bytes()).unwrap();

        // TLS サーバ設定
        let server_cert_der = CertificateDer::from(server_cert.der().to_vec());
        let server_key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key_pair.serialize_der()));

        let tls_server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![server_cert_der], server_key_der)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(tls_server_config));

        // ローカル TLS サーバを起動
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let accept_handle = tokio::spawn(async move {
            let (tcp_stream, _) = listener.accept().await.unwrap();
            let mut tls_stream = acceptor.accept(tcp_stream).await.unwrap();
            let mut buf = [0u8; 4096];
            let len = tokio::io::AsyncReadExt::read(&mut tls_stream, &mut buf)
                .await
                .unwrap();
            String::from_utf8_lossy(&buf[..len]).to_string()
        });

        // SyslogForwarder を TLS モードで起動
        let config = SyslogConfig {
            enabled: true,
            protocol: "tls".to_string(),
            server: "localhost".to_string(),
            port: server_addr.port(),
            facility: "local0".to_string(),
            hostname: "tls-test-host".to_string(),
            app_name: "zettai-tls-test".to_string(),
            tls: SyslogTlsConfig {
                ca_cert_path: Some(ca_file.path().to_string_lossy().into_owned()),
                verify_hostname: true,
                client_cert_path: None,
                client_key_path: None,
            },
        };
        let bus = EventBus::new(16);
        let (forwarder, _sender) = SyslogForwarder::new(&config, &bus);
        forwarder.spawn();

        // 接続確立を少し待つ
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // イベントを発行
        bus.publish(SecurityEvent::new(
            "tls_test_event",
            Severity::Warning,
            "tls_module",
            "TLS テストメッセージ",
        ));

        // メッセージの受信を待つ
        let received = tokio::time::timeout(std::time::Duration::from_secs(5), accept_handle)
            .await
            .expect("TLS メッセージ受信がタイムアウトしました")
            .expect("TLS サーバタスクがパニックしました");

        // PRI: local0(16)*8 + warning(4) = 132
        assert!(
            received.contains("<132>1 "),
            "PRI 値が正しくありません: {}",
            received
        );
        assert!(
            received.contains("tls-test-host"),
            "ホスト名が含まれていません: {}",
            received
        );
        assert!(
            received.contains("zettai-tls-test"),
            "アプリ名が含まれていません: {}",
            received
        );
        assert!(
            received.contains("eventType=\"tls_test_event\""),
            "イベントタイプが含まれていません: {}",
            received
        );
        assert!(
            received.contains("TLS テストメッセージ"),
            "メッセージが含まれていません: {}",
            received
        );
        assert!(
            received.ends_with('\n'),
            "改行で終わっていません: {}",
            received
        );
    }

    #[tokio::test]
    async fn test_syslog_forwarder_receives_and_sends_tls_mtls() {
        use rcgen::{CertificateParams, KeyPair};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        let _ = rustls::crypto::ring::default_provider().install_default();

        // CA 証明書を生成
        let ca_key_pair = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(vec!["Test CA".to_string()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key_pair).unwrap();

        // サーバ証明書を生成
        let server_key_pair = KeyPair::generate().unwrap();
        let server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let server_cert = server_params
            .signed_by(&server_key_pair, &ca_cert, &ca_key_pair)
            .unwrap();

        // クライアント証明書を生成
        let client_key_pair = KeyPair::generate().unwrap();
        let client_params =
            CertificateParams::new(vec!["zettai-mamorukun-client".to_string()]).unwrap();
        let client_cert = client_params
            .signed_by(&client_key_pair, &ca_cert, &ca_key_pair)
            .unwrap();

        // CA 証明書を一時ファイルに書き出す
        let ca_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(ca_file.path(), ca_cert.pem().as_bytes()).unwrap();

        // クライアント証明書・秘密鍵を一時ファイルに書き出す
        let client_cert_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(client_cert_file.path(), client_cert.pem().as_bytes()).unwrap();

        let client_key_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            client_key_file.path(),
            client_key_pair.serialize_pem().as_bytes(),
        )
        .unwrap();

        // mTLS を要求するサーバ設定
        let ca_cert_der = CertificateDer::from(ca_cert.der().to_vec());
        let mut client_auth_roots = rustls::RootCertStore::empty();
        client_auth_roots.add(ca_cert_der).unwrap();
        let client_verifier =
            rustls::server::WebPkiClientVerifier::builder(Arc::new(client_auth_roots))
                .build()
                .unwrap();

        let server_cert_der = CertificateDer::from(server_cert.der().to_vec());
        let server_key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key_pair.serialize_der()));

        let tls_server_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(vec![server_cert_der], server_key_der)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(tls_server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let accept_handle = tokio::spawn(async move {
            let (tcp_stream, _) = listener.accept().await.unwrap();
            let mut tls_stream = acceptor.accept(tcp_stream).await.unwrap();
            let mut buf = [0u8; 4096];
            let len = tokio::io::AsyncReadExt::read(&mut tls_stream, &mut buf)
                .await
                .unwrap();
            String::from_utf8_lossy(&buf[..len]).to_string()
        });

        let config = SyslogConfig {
            enabled: true,
            protocol: "tls".to_string(),
            server: "localhost".to_string(),
            port: server_addr.port(),
            facility: "local0".to_string(),
            hostname: "mtls-test-host".to_string(),
            app_name: "zettai-mtls-test".to_string(),
            tls: SyslogTlsConfig {
                ca_cert_path: Some(ca_file.path().to_string_lossy().into_owned()),
                verify_hostname: true,
                client_cert_path: Some(client_cert_file.path().to_string_lossy().into_owned()),
                client_key_path: Some(client_key_file.path().to_string_lossy().into_owned()),
            },
        };
        let bus = EventBus::new(16);
        let (forwarder, _sender) = SyslogForwarder::new(&config, &bus);
        forwarder.spawn();

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        bus.publish(SecurityEvent::new(
            "mtls_test_event",
            Severity::Warning,
            "mtls_module",
            "mTLS テストメッセージ",
        ));

        let received = tokio::time::timeout(std::time::Duration::from_secs(5), accept_handle)
            .await
            .expect("mTLS メッセージ受信がタイムアウトしました")
            .expect("mTLS サーバタスクがパニックしました");

        assert!(
            received.contains("<132>1 "),
            "PRI 値が正しくありません: {}",
            received
        );
        assert!(
            received.contains("mtls-test-host"),
            "ホスト名が含まれていません: {}",
            received
        );
        assert!(
            received.contains("zettai-mtls-test"),
            "アプリ名が含まれていません: {}",
            received
        );
        assert!(
            received.contains("eventType=\"mtls_test_event\""),
            "イベントタイプが含まれていません: {}",
            received
        );
        assert!(
            received.contains("mTLS テストメッセージ"),
            "メッセージが含まれていません: {}",
            received
        );
    }

    #[test]
    fn test_build_tls_config_client_cert_only_error() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let config = SyslogRuntimeConfig {
            protocol: "tls".to_string(),
            server: "localhost".to_string(),
            port: 6514,
            facility: "local0".to_string(),
            hostname: "test".to_string(),
            app_name: "test".to_string(),
            tls_ca_cert_path: None,
            tls_verify_hostname: true,
            tls_client_cert_path: Some("/tmp/nonexistent-cert.pem".to_string()),
            tls_client_key_path: None,
        };
        let result = build_tls_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("秘密鍵"));
    }

    #[test]
    fn test_build_tls_config_client_key_only_error() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let config = SyslogRuntimeConfig {
            protocol: "tls".to_string(),
            server: "localhost".to_string(),
            port: 6514,
            facility: "local0".to_string(),
            hostname: "test".to_string(),
            app_name: "test".to_string(),
            tls_ca_cert_path: None,
            tls_verify_hostname: true,
            tls_client_cert_path: None,
            tls_client_key_path: Some("/tmp/nonexistent-key.pem".to_string()),
        };
        let result = build_tls_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("証明書"));
    }

    #[test]
    fn test_syslog_runtime_config_from_syslog_config_with_mtls() {
        let config = SyslogConfig {
            enabled: true,
            protocol: "tls".to_string(),
            server: "siem.example.com".to_string(),
            port: 6514,
            facility: "local0".to_string(),
            hostname: "test-host".to_string(),
            app_name: "zettai-mamorukun".to_string(),
            tls: SyslogTlsConfig {
                ca_cert_path: Some("/path/to/ca.pem".to_string()),
                verify_hostname: true,
                client_cert_path: Some("/path/to/client.pem".to_string()),
                client_key_path: Some("/path/to/client-key.pem".to_string()),
            },
        };
        let runtime = SyslogRuntimeConfig::from(&config);
        assert_eq!(
            runtime.tls_client_cert_path,
            Some("/path/to/client.pem".to_string())
        );
        assert_eq!(
            runtime.tls_client_key_path,
            Some("/path/to/client-key.pem".to_string())
        );
    }
}
