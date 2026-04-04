//! ネットワークリスニングポート監視モジュール
//!
//! `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6` を定期スキャンし、
//! 想定外のリスニングポートやバインドアドレスの変更を検知する。
//!
//! 検知対象:
//! - 許可リスト外のリスニングポート → Critical
//! - ベースラインに存在しない新規ポート → Warning
//! - ベースラインに存在したポートの消失 → Info

use crate::config::ListeningPortMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio_util::sync::CancellationToken;

/// プロトコル種別
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Protocol {
    Tcp,
    Udp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
        }
    }
}

/// リスニングポートのエントリ
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ListeningPort {
    protocol: Protocol,
    addr: IpAddr,
    port: u16,
}

/// リスニングポートのスナップショット
///
/// キー: (Protocol, port), 値: バインドアドレスのリスト
type PortSnapshot = BTreeMap<(Protocol, u16), Vec<IpAddr>>;

/// hex 文字列から IPv4 アドレスをパースする
///
/// /proc/net/tcp のアドレスはホストバイトオーダーの u32 hex 表記
fn parse_ipv4_hex(hex: &str) -> Option<Ipv4Addr> {
    let n = u32::from_str_radix(hex, 16).ok()?;
    Some(Ipv4Addr::from(n.to_ne_bytes()))
}

/// hex 文字列から IPv6 アドレスをパースする
///
/// /proc/net/tcp6 のアドレスは 4 つの 32bit ワード（各ホストバイトオーダー）の hex 表記
fn parse_ipv6_hex(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut octets = [0u8; 16];
    for i in 0..4 {
        let word_hex = &hex[i * 8..(i + 1) * 8];
        let word = u32::from_str_radix(word_hex, 16).ok()?;
        let bytes = word.to_ne_bytes();
        octets[i * 4..i * 4 + 4].copy_from_slice(&bytes);
    }
    Some(Ipv6Addr::from(octets))
}

/// hex ポート文字列をパースする
fn parse_port_hex(hex: &str) -> Option<u16> {
    u16::from_str_radix(hex, 16).ok()
}

/// /proc/net/tcp または /proc/net/tcp6 をパースし、LISTEN 状態のポートを返す
fn parse_tcp_file(path: &str, is_ipv6: bool) -> Vec<ListeningPort> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(path = %path, error = %e, "TCP ファイルの読み取りに失敗しました");
            return Vec::new();
        }
    };

    let mut entries = Vec::new();
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }

        // st (state) フィールド: 0A = TCP_LISTEN
        let state = cols[3];
        if state != "0A" {
            continue;
        }

        // local_address: HEXIP:HEXPORT
        let local_addr = cols[1];
        let Some((addr_hex, port_hex)) = local_addr.split_once(':') else {
            continue;
        };

        let Some(port) = parse_port_hex(port_hex) else {
            continue;
        };

        let addr: IpAddr = if is_ipv6 {
            let Some(ip) = parse_ipv6_hex(addr_hex) else {
                continue;
            };
            IpAddr::V6(ip)
        } else {
            let Some(ip) = parse_ipv4_hex(addr_hex) else {
                continue;
            };
            IpAddr::V4(ip)
        };

        entries.push(ListeningPort {
            protocol: Protocol::Tcp,
            addr,
            port,
        });
    }
    entries
}

/// /proc/net/udp または /proc/net/udp6 をパースし、リスニング状態のポートを返す
///
/// UDP には LISTEN 状態がないため、rem_address が全ゼロのソケットをリスニングとみなす
fn parse_udp_file(path: &str, is_ipv6: bool) -> Vec<ListeningPort> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(path = %path, error = %e, "UDP ファイルの読み取りに失敗しました");
            return Vec::new();
        }
    };

    let zero_remote_v4 = "00000000:0000";
    let zero_remote_v6 = "00000000000000000000000000000000:0000";

    let mut entries = Vec::new();
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 3 {
            continue;
        }

        // rem_address が全ゼロならリスニング
        let rem_addr = cols[2];
        let is_listening = if is_ipv6 {
            rem_addr == zero_remote_v6
        } else {
            rem_addr == zero_remote_v4
        };

        if !is_listening {
            continue;
        }

        let local_addr = cols[1];
        let Some((addr_hex, port_hex)) = local_addr.split_once(':') else {
            continue;
        };

        let Some(port) = parse_port_hex(port_hex) else {
            continue;
        };

        // ポート 0 のソケットはスキップ（一時的なソケット）
        if port == 0 {
            continue;
        }

        let addr: IpAddr = if is_ipv6 {
            let Some(ip) = parse_ipv6_hex(addr_hex) else {
                continue;
            };
            IpAddr::V6(ip)
        } else {
            let Some(ip) = parse_ipv4_hex(addr_hex) else {
                continue;
            };
            IpAddr::V4(ip)
        };

        entries.push(ListeningPort {
            protocol: Protocol::Udp,
            addr,
            port,
        });
    }
    entries
}

/// 許可ポートリストの文字列をパースする
///
/// 形式: "tcp:22", "udp:53"
fn parse_allowed_port(s: &str) -> Result<(Protocol, u16), String> {
    let Some((proto_str, port_str)) = s.split_once(':') else {
        return Err(format!(
            "無効な形式です（'プロトコル:ポート' が必要）: {}",
            s
        ));
    };
    let protocol = match proto_str.to_lowercase().as_str() {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        _ => {
            return Err(format!(
                "無効なプロトコルです（tcp/udp のみ）: {}",
                proto_str
            ));
        }
    };
    let port: u16 = port_str
        .parse()
        .map_err(|_| format!("無効なポート番号です: {}", port_str))?;
    Ok((protocol, port))
}

/// スナップショットを取得する
fn take_snapshot(config: &ListeningPortMonitorConfig) -> PortSnapshot {
    let mut all_ports: Vec<ListeningPort> = Vec::new();

    all_ports.extend(parse_tcp_file(&config.tcp_path, false));
    all_ports.extend(parse_udp_file(&config.udp_path, false));

    if config.enable_ipv6 {
        all_ports.extend(parse_tcp_file(&config.tcp6_path, true));
        all_ports.extend(parse_udp_file(&config.udp6_path, true));
    }

    // (Protocol, port) → Vec<IpAddr> に集約
    let mut snapshot: PortSnapshot = BTreeMap::new();
    for lp in all_ports {
        snapshot
            .entry((lp.protocol, lp.port))
            .or_default()
            .push(lp.addr);
    }
    // アドレスリストをソートして安定化
    for addrs in snapshot.values_mut() {
        addrs.sort_by_key(|a| a.to_string());
        addrs.dedup();
    }
    snapshot
}

/// ベースラインと現在のスナップショットを比較し、変更を検知し���イベント発行する
///
/// 変更があった場合は `true` を返す。
fn detect_and_report(
    baseline: &PortSnapshot,
    current: &PortSnapshot,
    allowed: &HashSet<(Protocol, u16)>,
    event_bus: &Option<EventBus>,
) -> bool {
    let mut has_changes = false;

    // ホワイトリスト違反の検知（allowed が非空の場合のみ）
    if !allowed.is_empty() {
        for ((protocol, port), addrs) in current {
            if !allowed.contains(&(*protocol, *port)) {
                let addr_str = addrs
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                let details = format!(
                    "プロトコル={}, ポート={}, アドレス={}",
                    protocol, port, addr_str
                );
                tracing::error!(
                    protocol = %protocol,
                    port = port,
                    addresses = %addr_str,
                    "許可されていないリスニングポートを検知しました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "unauthorized_listening_port",
                            Severity::Critical,
                            "listening_port_monitor",
                            format!(
                                "許可されていないリスニングポートを検知しました: {}:{} ({})",
                                protocol, port, addr_str
                            ),
                        )
                        .with_details(details),
                    );
                }
                has_changes = true;
            }
        }
    }

    // 新規ポートの検知
    for ((protocol, port), addrs) in current {
        if !baseline.contains_key(&(*protocol, *port)) {
            let addr_str = addrs
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            let details = format!(
                "プロトコル={}, ポート={}, アドレス={}",
                protocol, port, addr_str
            );
            tracing::warn!(
                protocol = %protocol,
                port = port,
                addresses = %addr_str,
                "新しいリスニングポートを検知しました"
            );
            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        "new_listening_port",
                        Severity::Warning,
                        "listening_port_monitor",
                        format!(
                            "新しいリスニングポートを検知しました: {}:{} ({})",
                            protocol, port, addr_str
                        ),
                    )
                    .with_details(details),
                );
            }
            has_changes = true;
        }
    }

    // ポート消失の検知
    for ((protocol, port), addrs) in baseline {
        if !current.contains_key(&(*protocol, *port)) {
            let addr_str = addrs
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            let details = format!(
                "プロトコル={}, ポート={}, アドレス={}",
                protocol, port, addr_str
            );
            tracing::info!(
                protocol = %protocol,
                port = port,
                addresses = %addr_str,
                "リスニングポートが閉じられました"
            );
            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        "listening_port_closed",
                        Severity::Info,
                        "listening_port_monitor",
                        format!(
                            "リスニングポートが閉じられました: {}:{} ({})",
                            protocol, port, addr_str
                        ),
                    )
                    .with_details(details),
                );
            }
            has_changes = true;
        }
    }

    has_changes
}

/// ネットワークリスニングポート監視モジュール
///
/// `/proc/net/tcp{,6}`, `/proc/net/udp{,6}` を定期スキャンし、
/// 想定外のリスニングポートを検知する。
pub struct ListeningPortMonitorModule {
    config: ListeningPortMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl ListeningPortMonitorModule {
    /// 新しいリスニングポート監視モジュールを作成する
    pub fn new(config: ListeningPortMonitorConfig, event_bus: Option<EventBus>) -> Self {
        Self {
            config,
            cancel_token: CancellationToken::new(),
            event_bus,
        }
    }

    /// キャンセルトークンのクローンを返す
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }
}

impl Module for ListeningPortMonitorModule {
    fn name(&self) -> &str {
        "listening_port_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        // allowed_ports のパース検証
        for entry in &self.config.allowed_ports {
            parse_allowed_port(entry).map_err(|e| AppError::ModuleConfig {
                message: format!("allowed_ports の設定が無効です: {}", e),
            })?;
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            allowed_ports = self.config.allowed_ports.len(),
            enable_ipv6 = self.config.enable_ipv6,
            "リスニングポート監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<(), AppError> {
        let config = self.config.clone();
        let scan_interval_secs = self.config.scan_interval_secs;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        // 許可ポートセットを構築
        let allowed: HashSet<(Protocol, u16)> = self
            .config
            .allowed_ports
            .iter()
            .filter_map(|s| parse_allowed_port(s).ok())
            .collect();

        let baseline = take_snapshot(&config);
        tracing::info!(
            listening_ports = baseline.len(),
            "リスニングポート ベースラインスキャンが完了しました"
        );

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            interval.tick().await;

            let mut baseline = baseline;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("リスニングポート監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = take_snapshot(&config);
                        let changed = detect_and_report(&baseline, &current, &allowed, &event_bus);

                        if changed {
                            baseline = current;
                        } else {
                            tracing::debug!("リスニングポートに変更はありません");
                        }
                    }
                }
            }
        });

        Ok(())
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();
        let snapshot = take_snapshot(&self.config);

        let items_scanned: usize = snapshot.values().map(|addrs| addrs.len()).sum();

        // ホワイトリスト違反のカウント
        let allowed: HashSet<(Protocol, u16)> = self
            .config
            .allowed_ports
            .iter()
            .filter_map(|s| parse_allowed_port(s).ok())
            .collect();

        let issues_found = if allowed.is_empty() {
            0
        } else {
            snapshot
                .keys()
                .filter(|(proto, port)| !allowed.contains(&(*proto, *port)))
                .count()
        };

        // スナップショットデータを構築
        let mut scan_snapshot: BTreeMap<String, String> = BTreeMap::new();
        for ((protocol, port), addrs) in &snapshot {
            let key = format!("listening:{}:{}", protocol, port);
            let value = addrs
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(",");
            scan_snapshot.insert(key, value);
        }

        let tcp_count = snapshot.keys().filter(|(p, _)| *p == Protocol::Tcp).count();
        let udp_count = snapshot.keys().filter(|(p, _)| *p == Protocol::Udp).count();

        tracing::info!(
            tcp_ports = tcp_count,
            udp_ports = udp_count,
            issues = issues_found,
            "起動時スキャン: リスニングポートをスキャンしました"
        );

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "リスニングポート {}件をスキャン（TCP: {}件, UDP: {}件, 違反: {}件）",
                snapshot.len(),
                tcp_count,
                udp_count,
                issues_found
            ),
            snapshot: scan_snapshot,
        })
    }

    async fn stop(&mut self) -> Result<(), AppError> {
        self.cancel_token.cancel();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp_file(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file
    }

    fn empty_temp_file() -> NamedTempFile {
        write_temp_file("")
    }

    fn make_config(
        tcp: &NamedTempFile,
        tcp6: &NamedTempFile,
        udp: &NamedTempFile,
        udp6: &NamedTempFile,
    ) -> ListeningPortMonitorConfig {
        ListeningPortMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            allowed_ports: Vec::new(),
            enable_ipv6: true,
            tcp_path: tcp.path().to_str().unwrap().to_string(),
            tcp6_path: tcp6.path().to_str().unwrap().to_string(),
            udp_path: udp.path().to_str().unwrap().to_string(),
            udp6_path: udp6.path().to_str().unwrap().to_string(),
        }
    }

    // --- parse_ipv4_hex ---

    #[test]
    fn test_parse_ipv4_hex_zeros() {
        let addr = parse_ipv4_hex("00000000").unwrap();
        assert_eq!(addr, Ipv4Addr::new(0, 0, 0, 0));
    }

    #[test]
    fn test_parse_ipv4_hex_loopback() {
        // 127.0.0.1 in host byte order (little-endian): 0100007F
        let addr = parse_ipv4_hex("0100007F").unwrap();
        assert_eq!(addr, Ipv4Addr::new(127, 0, 0, 1));
    }

    #[test]
    fn test_parse_ipv4_hex_invalid() {
        assert!(parse_ipv4_hex("ZZZZZZZZ").is_none());
    }

    // --- parse_ipv6_hex ---

    #[test]
    fn test_parse_ipv6_hex_zeros() {
        let addr = parse_ipv6_hex("00000000000000000000000000000000").unwrap();
        assert_eq!(addr, Ipv6Addr::UNSPECIFIED);
    }

    #[test]
    fn test_parse_ipv6_hex_loopback() {
        // ::1 in /proc format: 00000000000000000000000001000000
        let addr = parse_ipv6_hex("00000000000000000000000001000000").unwrap();
        assert_eq!(addr, Ipv6Addr::LOCALHOST);
    }

    #[test]
    fn test_parse_ipv6_hex_wrong_length() {
        assert!(parse_ipv6_hex("0000").is_none());
    }

    // --- parse_port_hex ---

    #[test]
    fn test_parse_port_hex() {
        assert_eq!(parse_port_hex("0016"), Some(22));
        assert_eq!(parse_port_hex("0050"), Some(80));
        assert_eq!(parse_port_hex("01BB"), Some(443));
        assert_eq!(parse_port_hex("ZZZZ"), None);
    }

    // --- parse_tcp_file ---

    #[test]
    fn test_parse_tcp_file_listen_only() {
        let content = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                        0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1\n\
                        1: 0100007F:0035 0100007F:C000 01 00000000:00000000 00:00000000 00000000     0        0 12346 1\n";
        let file = write_temp_file(content);
        let ports = parse_tcp_file(file.path().to_str().unwrap(), false);
        // Only LISTEN (0A) entries, not ESTABLISHED (01)
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].port, 22);
        assert_eq!(ports[0].protocol, Protocol::Tcp);
    }

    #[test]
    fn test_parse_tcp6_file() {
        let content = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                        0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 54321 1\n";
        let file = write_temp_file(content);
        let ports = parse_tcp_file(file.path().to_str().unwrap(), true);
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].port, 80);
        assert_eq!(ports[0].addr, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
    }

    #[test]
    fn test_parse_tcp_file_nonexistent() {
        let ports = parse_tcp_file("/nonexistent/path", false);
        assert!(ports.is_empty());
    }

    #[test]
    fn test_parse_tcp_file_skips_invalid() {
        let content = "  sl  local_address rem_address   st\n\
                        0: bad\n\
                        1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1\n";
        let file = write_temp_file(content);
        let ports = parse_tcp_file(file.path().to_str().unwrap(), false);
        assert_eq!(ports.len(), 1);
    }

    // --- parse_udp_file ---

    #[test]
    fn test_parse_udp_file_listening() {
        let content = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n\
                        0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 11111 2\n\
                        1: 0100007F:0035 0100007F:1234 01 00000000:00000000 00:00000000 00000000     0        0 11112 2\n";
        let file = write_temp_file(content);
        let ports = parse_udp_file(file.path().to_str().unwrap(), false);
        // Only zero remote address entry
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].port, 53);
        assert_eq!(ports[0].protocol, Protocol::Udp);
    }

    #[test]
    fn test_parse_udp_file_skips_port_zero() {
        let content = "  sl  local_address rem_address   st\n\
                        0: 00000000:0000 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 11111 2\n";
        let file = write_temp_file(content);
        let ports = parse_udp_file(file.path().to_str().unwrap(), false);
        assert!(ports.is_empty());
    }

    #[test]
    fn test_parse_udp_file_nonexistent() {
        let ports = parse_udp_file("/nonexistent/path", false);
        assert!(ports.is_empty());
    }

    #[test]
    fn test_parse_udp6_file() {
        let content = "  sl  local_address                         remote_address                        st\n\
                        0: 00000000000000000000000000000000:0035 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 22222 2\n";
        let file = write_temp_file(content);
        let ports = parse_udp_file(file.path().to_str().unwrap(), true);
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].port, 53);
    }

    // --- parse_allowed_port ---

    #[test]
    fn test_parse_allowed_port_valid() {
        assert_eq!(parse_allowed_port("tcp:22"), Ok((Protocol::Tcp, 22)));
        assert_eq!(parse_allowed_port("udp:53"), Ok((Protocol::Udp, 53)));
        assert_eq!(parse_allowed_port("TCP:443"), Ok((Protocol::Tcp, 443)));
    }

    #[test]
    fn test_parse_allowed_port_invalid() {
        assert!(parse_allowed_port("invalid").is_err());
        assert!(parse_allowed_port("tcp:abc").is_err());
        assert!(parse_allowed_port("icmp:8").is_err());
    }

    // --- take_snapshot ---

    #[test]
    fn test_take_snapshot() {
        let tcp = write_temp_file(
            "  sl  local_address rem_address   st\n\
             0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1\n",
        );
        let udp = write_temp_file(
            "  sl  local_address rem_address   st\n\
             0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 11111 2\n",
        );
        let empty = empty_temp_file();
        let empty2 = empty_temp_file();

        let config = make_config(&tcp, &empty, &udp, &empty2);
        let snapshot = take_snapshot(&config);

        assert_eq!(snapshot.len(), 2);
        assert!(snapshot.contains_key(&(Protocol::Tcp, 22)));
        assert!(snapshot.contains_key(&(Protocol::Udp, 53)));
    }

    // --- detect_and_report ---

    #[test]
    fn test_detect_no_changes() {
        let mut baseline: PortSnapshot = BTreeMap::new();
        baseline.insert((Protocol::Tcp, 22), vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)]);

        let allowed = HashSet::new();
        assert!(!detect_and_report(&baseline, &baseline, &allowed, &None));
    }

    #[test]
    fn test_detect_new_port() {
        let baseline: PortSnapshot = BTreeMap::new();
        let mut current: PortSnapshot = BTreeMap::new();
        current.insert(
            (Protocol::Tcp, 4444),
            vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)],
        );

        let allowed = HashSet::new();
        assert!(detect_and_report(&baseline, &current, &allowed, &None));
    }

    #[test]
    fn test_detect_port_closed() {
        let mut baseline: PortSnapshot = BTreeMap::new();
        baseline.insert(
            (Protocol::Tcp, 8080),
            vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)],
        );

        let current: PortSnapshot = BTreeMap::new();
        let allowed = HashSet::new();
        assert!(detect_and_report(&baseline, &current, &allowed, &None));
    }

    #[test]
    fn test_detect_unauthorized_port() {
        let baseline: PortSnapshot = BTreeMap::new();
        let mut current: PortSnapshot = BTreeMap::new();
        current.insert(
            (Protocol::Tcp, 4444),
            vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)],
        );

        let allowed: HashSet<(Protocol, u16)> =
            HashSet::from([(Protocol::Tcp, 22), (Protocol::Tcp, 80)]);
        assert!(detect_and_report(&baseline, &current, &allowed, &None));
    }

    #[test]
    fn test_detect_authorized_port_no_alert() {
        let mut baseline: PortSnapshot = BTreeMap::new();
        baseline.insert((Protocol::Tcp, 22), vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)]);

        let mut current: PortSnapshot = BTreeMap::new();
        current.insert((Protocol::Tcp, 22), vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)]);

        let allowed: HashSet<(Protocol, u16)> = HashSet::from([(Protocol::Tcp, 22)]);
        assert!(!detect_and_report(&baseline, &current, &allowed, &None));
    }

    // --- Module lifecycle ---

    #[test]
    fn test_init_zero_interval() {
        let empty = empty_temp_file();
        let empty2 = empty_temp_file();
        let empty3 = empty_temp_file();
        let empty4 = empty_temp_file();
        let mut config = make_config(&empty, &empty2, &empty3, &empty4);
        config.scan_interval_secs = 0;
        let mut module = ListeningPortMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_invalid_allowed_ports() {
        let empty = empty_temp_file();
        let empty2 = empty_temp_file();
        let empty3 = empty_temp_file();
        let empty4 = empty_temp_file();
        let mut config = make_config(&empty, &empty2, &empty3, &empty4);
        config.allowed_ports = vec!["invalid".to_string()];
        let mut module = ListeningPortMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let empty = empty_temp_file();
        let empty2 = empty_temp_file();
        let empty3 = empty_temp_file();
        let empty4 = empty_temp_file();
        let mut config = make_config(&empty, &empty2, &empty3, &empty4);
        config.allowed_ports = vec!["tcp:22".to_string(), "udp:53".to_string()];
        let mut module = ListeningPortMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let tcp = write_temp_file(
            "  sl  local_address rem_address   st\n\
             0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1\n",
        );
        let empty = empty_temp_file();
        let empty2 = empty_temp_file();
        let empty3 = empty_temp_file();

        let config = make_config(&tcp, &empty, &empty2, &empty3);
        let mut module = ListeningPortMonitorModule::new(config, None);
        assert!(module.init().is_ok());
        assert!(module.start().await.is_ok());
        assert!(module.stop().await.is_ok());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let tcp = write_temp_file(
            "  sl  local_address rem_address   st\n\
             0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1\n\
             1: 0100007F:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1\n",
        );
        let udp = write_temp_file(
            "  sl  local_address rem_address   st\n\
             0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 11111 2\n",
        );
        let empty = empty_temp_file();
        let empty2 = empty_temp_file();

        let config = make_config(&tcp, &empty, &udp, &empty2);
        let module = ListeningPortMonitorModule::new(config, None);
        let result = module.initial_scan().await.unwrap();

        assert_eq!(result.items_scanned, 3); // 2 TCP addrs + 1 UDP addr
        assert_eq!(result.issues_found, 0);
        assert!(result.snapshot.contains_key("listening:tcp:22"));
        assert!(result.snapshot.contains_key("listening:tcp:443"));
        assert!(result.snapshot.contains_key("listening:udp:53"));
    }

    #[tokio::test]
    async fn test_initial_scan_with_whitelist_violations() {
        let tcp = write_temp_file(
            "  sl  local_address rem_address   st\n\
             0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1\n\
             1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12347 1\n",
        );
        let empty = empty_temp_file();
        let empty2 = empty_temp_file();
        let empty3 = empty_temp_file();

        let mut config = make_config(&tcp, &empty, &empty2, &empty3);
        config.allowed_ports = vec!["tcp:22".to_string()];

        let module = ListeningPortMonitorModule::new(config, None);
        let result = module.initial_scan().await.unwrap();

        // Port 8080 (0x1F90) is not in allowed list
        assert_eq!(result.issues_found, 1);
    }
}
