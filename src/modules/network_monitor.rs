//! ネットワーク接続監視モジュール
//!
//! `/proc/net/tcp` と `/proc/net/udp` を定期的に読み取り、不審な接続を検知する。
//! `enable_ipv6` が有効な場合は `/proc/net/tcp6` と `/proc/net/udp6` も監視する。
//!
//! 検知対象:
//! - 不審なポートへの接続（C2 サーバ等で使われるポート）
//! - 接続数の異常な増加（DDoS やワームの兆候）

use crate::config::NetworkMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio_util::sync::CancellationToken;

/// プロトコル種別
#[derive(Debug, Clone, PartialEq, Eq)]
enum Protocol {
    Tcp,
    Udp,
}

/// アドレスファミリ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressFamily {
    V4,
    V6,
}

/// パースされた接続エントリ
#[derive(Debug, Clone)]
struct ConnectionEntry {
    protocol: Protocol,
    local_addr: IpAddr,
    local_port: u16,
    remote_addr: IpAddr,
    remote_port: u16,
    state: u8,
}

/// `/proc/net/tcp` または `/proc/net/udp` の内容をパースする
fn parse_proc_net(
    content: &str,
    protocol: Protocol,
    address_family: AddressFamily,
) -> Vec<ConnectionEntry> {
    let mut entries = Vec::new();

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            tracing::debug!(line = line, "フィールド数が不足しているためスキップします");
            continue;
        }

        let local = fields[1];
        let remote = fields[2];
        let state_str = fields[3];

        let (local_addr, local_port) = match address_family {
            AddressFamily::V4 => {
                let Some((addr, port)) = parse_addr_port(local) else {
                    tracing::debug!(field = local, "ローカルアドレスのパースに失敗しました");
                    continue;
                };
                (IpAddr::V4(addr), port)
            }
            AddressFamily::V6 => {
                let Some((addr, port)) = parse_addr_port_v6(local) else {
                    tracing::debug!(field = local, "ローカルアドレス(v6)のパースに失敗しました");
                    continue;
                };
                (IpAddr::V6(addr), port)
            }
        };

        let (remote_addr, remote_port) = match address_family {
            AddressFamily::V4 => {
                let Some((addr, port)) = parse_addr_port(remote) else {
                    tracing::debug!(field = remote, "リモートアドレスのパースに失敗しました");
                    continue;
                };
                (IpAddr::V4(addr), port)
            }
            AddressFamily::V6 => {
                let Some((addr, port)) = parse_addr_port_v6(remote) else {
                    tracing::debug!(field = remote, "リモートアドレス(v6)のパースに失敗しました");
                    continue;
                };
                (IpAddr::V6(addr), port)
            }
        };

        let Ok(state) = u8::from_str_radix(state_str, 16) else {
            tracing::debug!(field = state_str, "ステートのパースに失敗しました");
            continue;
        };

        entries.push(ConnectionEntry {
            protocol: protocol.clone(),
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            state,
        });
    }

    entries
}

/// `AABBCCDD:PORT` 形式のアドレスをパースする
///
/// `/proc/net/tcp` は IP アドレスをホストバイトオーダーの 16 進数で格納するため、
/// `to_ne_bytes` でバイト列に変換して `Ipv4Addr` を構築する。
fn parse_addr_port(field: &str) -> Option<(Ipv4Addr, u16)> {
    let (addr_hex, port_hex) = field.split_once(':')?;
    let raw = u32::from_str_radix(addr_hex, 16).ok()?;
    let addr = Ipv4Addr::from(raw.to_ne_bytes());
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    Some((addr, port))
}

/// `/proc/net/tcp6` 形式の IPv6 アドレスをパースする
///
/// 32 文字の 16 進数 + `:` + 4 文字の 16 進数ポート。
/// IPv6 は 4 つの 32bit ワードをそれぞれホストバイトオーダーで格納する。
fn parse_addr_port_v6(field: &str) -> Option<(Ipv6Addr, u16)> {
    let (addr_hex, port_hex) = field.split_once(':')?;
    if addr_hex.len() != 32 {
        return None;
    }
    let port = u16::from_str_radix(port_hex, 16).ok()?;

    // 4つの32bitワードをパース（各ワードはホストバイトオーダー）
    let mut octets = [0u8; 16];
    for i in 0..4 {
        let word_hex = &addr_hex[i * 8..(i + 1) * 8];
        let word = u32::from_str_radix(word_hex, 16).ok()?;
        let bytes = word.to_ne_bytes();
        octets[i * 4] = bytes[0];
        octets[i * 4 + 1] = bytes[1];
        octets[i * 4 + 2] = bytes[2];
        octets[i * 4 + 3] = bytes[3];
    }

    Some((Ipv6Addr::from(octets), port))
}

/// 不審なポートへの接続を検知する
///
/// TCP ESTABLISHED (state==0x01) で remote_port が suspicious_ports に含まれる接続、
/// または remote_addr が未指定でない UDP 接続を返す。
fn detect_suspicious_port_connections(
    entries: &[ConnectionEntry],
    suspicious_ports: &HashSet<u16>,
) -> Vec<ConnectionEntry> {
    entries
        .iter()
        .filter(|e| match e.protocol {
            Protocol::Tcp => e.state == 0x01 && suspicious_ports.contains(&e.remote_port),
            Protocol::Udp => {
                !is_unspecified_addr(&e.remote_addr) && suspicious_ports.contains(&e.remote_port)
            }
        })
        .cloned()
        .collect()
}

/// 接続数が閾値を超過しているか検知する
///
/// ESTABLISHED TCP 接続とアクティブ UDP 接続（remote_addr が未指定でない）の
/// 合計が max_connections を超過している場合、その接続数を返す。
fn detect_connection_count_exceeded(
    entries: &[ConnectionEntry],
    max_connections: u32,
) -> Option<u32> {
    let count = entries
        .iter()
        .filter(|e| match e.protocol {
            Protocol::Tcp => e.state == 0x01,
            Protocol::Udp => !is_unspecified_addr(&e.remote_addr),
        })
        .count() as u32;

    if count > max_connections {
        Some(count)
    } else {
        None
    }
}

/// アドレスが未指定（0.0.0.0 または ::）かどうかを判定する
fn is_unspecified_addr(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => *v4 == Ipv4Addr::new(0, 0, 0, 0),
        IpAddr::V6(v6) => v6.is_unspecified(),
    }
}

/// 非ルーティング可能なアドレスかどうかを判定する
fn is_non_routable_addr(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => is_non_routable_ipv4(v4),
        IpAddr::V6(v6) => is_non_routable_ipv6(v6),
    }
}

/// 非ルーティング可能な IPv4 アドレスかどうかを判定する
fn is_non_routable_ipv4(addr: &Ipv4Addr) -> bool {
    let octets = addr.octets();
    // 10.0.0.0/8
    if octets[0] == 10 {
        return true;
    }
    // 172.16.0.0/12
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return true;
    }
    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }
    // 127.0.0.0/8
    if octets[0] == 127 {
        return true;
    }
    // 0.0.0.0
    *addr == Ipv4Addr::new(0, 0, 0, 0)
}

/// 非ルーティング可能な IPv6 アドレスかどうかを判定する
fn is_non_routable_ipv6(addr: &Ipv6Addr) -> bool {
    // ループバック ::1
    if addr.is_loopback() {
        return true;
    }
    // 未指定 ::
    if addr.is_unspecified() {
        return true;
    }

    let segments = addr.segments();
    // リンクローカル fe80::/10
    if segments[0] & 0xffc0 == 0xfe80 {
        return true;
    }
    // ユニークローカル fc00::/7
    if segments[0] & 0xfe00 == 0xfc00 {
        return true;
    }
    // IPv4マッピング ::ffff:0:0/96
    if segments[0] == 0
        && segments[1] == 0
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0xffff
    {
        return true;
    }
    // IPv4互換アドレス（deprecated） ::x.x.x.x/96
    if segments[0..6].iter().all(|&s| s == 0) && (segments[6] != 0 || segments[7] > 1) {
        return true;
    }
    false
}

/// ネットワーク接続監視モジュール
///
/// `/proc/net/tcp` と `/proc/net/udp` を定期的にスキャンし、
/// 不審な接続を検知してイベントを発行する。
/// `enable_ipv6` が有効な場合は `/proc/net/tcp6` と `/proc/net/udp6` も監視する。
pub struct NetworkMonitorModule {
    config: NetworkMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl NetworkMonitorModule {
    /// 新しいネットワーク接続監視モジュールを作成する
    pub fn new(config: NetworkMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// `/proc/net/tcp` と `/proc/net/udp` を読み取り、接続エントリを返す
    ///
    /// `enable_ipv6` が `true` の場合は `/proc/net/tcp6` と `/proc/net/udp6` も読み取る。
    fn read_connections(enable_ipv6: bool) -> Vec<ConnectionEntry> {
        let mut entries = Vec::new();

        if let Ok(content) = std::fs::read_to_string("/proc/net/tcp") {
            entries.extend(parse_proc_net(&content, Protocol::Tcp, AddressFamily::V4));
        } else {
            tracing::warn!("/proc/net/tcp の読み取りに失敗しました");
        }

        if let Ok(content) = std::fs::read_to_string("/proc/net/udp") {
            entries.extend(parse_proc_net(&content, Protocol::Udp, AddressFamily::V4));
        } else {
            tracing::warn!("/proc/net/udp の読み取りに失敗しました");
        }

        if enable_ipv6 {
            if let Ok(content) = std::fs::read_to_string("/proc/net/tcp6") {
                entries.extend(parse_proc_net(&content, Protocol::Tcp, AddressFamily::V6));
            } else {
                tracing::warn!("/proc/net/tcp6 の読み取りに失敗しました");
            }

            if let Ok(content) = std::fs::read_to_string("/proc/net/udp6") {
                entries.extend(parse_proc_net(&content, Protocol::Udp, AddressFamily::V6));
            } else {
                tracing::warn!("/proc/net/udp6 の読み取りに失敗しました");
            }
        }

        entries
    }
}

impl Module for NetworkMonitorModule {
    fn name(&self) -> &str {
        "network_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        if self.config.suspicious_ports.is_empty() {
            tracing::warn!("suspicious_ports が空です。不審ポート検知は行われません");
        }

        tracing::info!(
            interval_secs = self.config.interval_secs,
            suspicious_ports = ?self.config.suspicious_ports,
            max_connections = self.config.max_connections,
            enable_ipv6 = self.config.enable_ipv6,
            "ネットワーク接続監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<(), AppError> {
        // 初回スキャンで動作確認
        let connections = Self::read_connections(self.config.enable_ipv6);
        tracing::info!(
            connection_count = connections.len(),
            "初回ネットワーク接続スキャンが完了しました"
        );

        let suspicious_ports: HashSet<u16> = self.config.suspicious_ports.iter().copied().collect();
        let max_connections = self.config.max_connections;
        let interval_secs = self.config.interval_secs;
        let enable_ipv6 = self.config.enable_ipv6;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        // 既知の不審接続を記録し、同じ接続の繰り返し警告を抑制
        let mut known_suspicious: HashSet<(IpAddr, u16)> = HashSet::new();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            // 最初の tick は即座に発火するのでスキップ
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("ネットワーク接続監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let entries = NetworkMonitorModule::read_connections(enable_ipv6);

                        // 不審ポート接続の検知
                        let suspicious =
                            detect_suspicious_port_connections(&entries, &suspicious_ports);

                        // 現在の不審接続セットを構築
                        let current_keys: HashSet<(IpAddr, u16)> = suspicious
                            .iter()
                            .map(|e| (e.remote_addr, e.remote_port))
                            .collect();

                        // 消えた接続を known から除去
                        known_suspicious.retain(|key| current_keys.contains(key));

                        for entry in &suspicious {
                            let key = (entry.remote_addr, entry.remote_port);
                            if known_suspicious.insert(key) {
                                let proto = match entry.protocol {
                                    Protocol::Tcp => "TCP",
                                    Protocol::Udp => "UDP",
                                };
                                let non_routable = is_non_routable_addr(&entry.remote_addr);
                                tracing::warn!(
                                    protocol = proto,
                                    local = %format!("{}:{}", entry.local_addr, entry.local_port),
                                    remote = %format!("{}:{}", entry.remote_addr, entry.remote_port),
                                    non_routable = non_routable,
                                    "不審なポートへの接続を検知しました"
                                );
                                if let Some(ref bus) = event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            "suspicious_port_connection",
                                            Severity::Warning,
                                            "network_monitor",
                                            format!(
                                                "不審なポートへの接続を検知しました: {} {}:{} -> {}:{}",
                                                proto,
                                                entry.local_addr,
                                                entry.local_port,
                                                entry.remote_addr,
                                                entry.remote_port,
                                            ),
                                        )
                                        .with_details(format!(
                                            "protocol={}, local={}:{}, remote={}:{}, non_routable={}",
                                            proto,
                                            entry.local_addr,
                                            entry.local_port,
                                            entry.remote_addr,
                                            entry.remote_port,
                                            non_routable,
                                        )),
                                    );
                                }
                            }
                        }

                        // 接続数超過の検知
                        if let Some(count) =
                            detect_connection_count_exceeded(&entries, max_connections)
                        {
                            tracing::warn!(
                                count = count,
                                max = max_connections,
                                "接続数が閾値を超過しています"
                            );
                            if let Some(ref bus) = event_bus {
                                bus.publish(
                                    SecurityEvent::new(
                                        "connection_count_exceeded",
                                        Severity::Warning,
                                        "network_monitor",
                                        format!(
                                            "接続数が閾値を超過しています: {} (閾値: {})",
                                            count, max_connections,
                                        ),
                                    )
                                    .with_details(format!(
                                        "count={}, max_connections={}",
                                        count, max_connections,
                                    )),
                                );
                            }
                        }

                        if suspicious.is_empty() {
                            tracing::debug!("不審なネットワーク接続は検知されませんでした");
                        }
                    }
                }
            }
        });

        Ok(())
    }

    async fn stop(&mut self) -> Result<(), AppError> {
        self.cancel_token.cancel();
        Ok(())
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();

        let entries = Self::read_connections(self.config.enable_ipv6);
        let items_scanned = entries.len();

        let suspicious_ports: HashSet<u16> = self.config.suspicious_ports.iter().copied().collect();
        let suspicious = detect_suspicious_port_connections(&entries, &suspicious_ports);
        let issues_found = suspicious.len();

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "ネットワーク接続 {}件をスキャンしました（不審な接続: {}件）",
                items_scanned, issues_found
            ),
            snapshot: BTreeMap::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_proc_net_tcp() {
        let content = r#"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0CEA 0100A8C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 67890 1 0000000000000000 100 0 0 10 0"#;

        let entries = parse_proc_net(content, Protocol::Tcp, AddressFamily::V4);
        assert_eq!(entries.len(), 2);

        // 最初のエントリ: 127.0.0.1:53 -> 0.0.0.0:0, state=0x0A (LISTEN)
        assert_eq!(entries[0].protocol, Protocol::Tcp);
        assert_eq!(
            entries[0].local_addr,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
        );
        assert_eq!(entries[0].local_port, 53);
        assert_eq!(
            entries[0].remote_addr,
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
        );
        assert_eq!(entries[0].remote_port, 0);
        assert_eq!(entries[0].state, 0x0A);

        // 2番目のエントリ: 127.0.0.1:3306 -> 192.168.0.1:443, state=0x01 (ESTABLISHED)
        assert_eq!(entries[1].protocol, Protocol::Tcp);
        assert_eq!(
            entries[1].local_addr,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
        );
        assert_eq!(entries[1].local_port, 3306);
        assert_eq!(
            entries[1].remote_addr,
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))
        );
        assert_eq!(entries[1].remote_port, 443);
        assert_eq!(entries[1].state, 0x01);
    }

    #[test]
    fn test_parse_proc_net_udp() {
        let content = r#"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0"#;

        let entries = parse_proc_net(content, Protocol::Udp, AddressFamily::V4);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].protocol, Protocol::Udp);
        assert_eq!(
            entries[0].local_addr,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
        );
        assert_eq!(entries[0].local_port, 53);
        assert_eq!(entries[0].state, 0x07);
    }

    #[test]
    fn test_parse_proc_net_invalid_lines() {
        let content = r#"  sl  local_address rem_address   st
   invalid line
   short"#;

        let entries = parse_proc_net(content, Protocol::Tcp, AddressFamily::V4);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_proc_net_empty() {
        let entries = parse_proc_net("", Protocol::Tcp, AddressFamily::V4);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_proc_net_header_only() {
        let content = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
        let entries = parse_proc_net(content, Protocol::Tcp, AddressFamily::V4);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_detect_suspicious_port_connections_tcp() {
        let suspicious_ports: HashSet<u16> = [4444, 5555].into_iter().collect();

        let entries = vec![
            ConnectionEntry {
                protocol: Protocol::Tcp,
                local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                local_port: 54321,
                remote_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                remote_port: 4444,
                state: 0x01, // ESTABLISHED
            },
            ConnectionEntry {
                protocol: Protocol::Tcp,
                local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                local_port: 54322,
                remote_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                remote_port: 80,
                state: 0x01, // ESTABLISHED
            },
        ];

        let result = detect_suspicious_port_connections(&entries, &suspicious_ports);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].remote_port, 4444);
    }

    #[test]
    fn test_detect_suspicious_port_connections_tcp_not_established() {
        let suspicious_ports: HashSet<u16> = [4444].into_iter().collect();

        let entries = vec![ConnectionEntry {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            local_port: 54321,
            remote_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            remote_port: 4444,
            state: 0x0A, // LISTEN - not ESTABLISHED
        }];

        let result = detect_suspicious_port_connections(&entries, &suspicious_ports);
        assert!(result.is_empty());
    }

    #[test]
    fn test_detect_suspicious_port_connections_normal_ports() {
        let suspicious_ports: HashSet<u16> = [4444, 5555].into_iter().collect();

        let entries = vec![
            ConnectionEntry {
                protocol: Protocol::Tcp,
                local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                local_port: 54321,
                remote_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                remote_port: 443,
                state: 0x01,
            },
            ConnectionEntry {
                protocol: Protocol::Tcp,
                local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                local_port: 54322,
                remote_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                remote_port: 80,
                state: 0x01,
            },
        ];

        let result = detect_suspicious_port_connections(&entries, &suspicious_ports);
        assert!(result.is_empty());
    }

    #[test]
    fn test_detect_suspicious_port_connections_udp() {
        let suspicious_ports: HashSet<u16> = [6666].into_iter().collect();

        let entries = vec![
            ConnectionEntry {
                protocol: Protocol::Udp,
                local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                local_port: 54321,
                remote_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                remote_port: 6666,
                state: 0x07,
            },
            // remote_addr が 0.0.0.0 の UDP は除外
            ConnectionEntry {
                protocol: Protocol::Udp,
                local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                local_port: 53,
                remote_addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                remote_port: 6666,
                state: 0x07,
            },
        ];

        let result = detect_suspicious_port_connections(&entries, &suspicious_ports);
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0].remote_addr,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        );
    }

    #[test]
    fn test_detect_connection_count_exceeded() {
        let entries: Vec<ConnectionEntry> = (0..10)
            .map(|i| ConnectionEntry {
                protocol: Protocol::Tcp,
                local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                local_port: 50000 + i,
                remote_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                remote_port: 80,
                state: 0x01, // ESTABLISHED
            })
            .collect();

        // 閾値 5 → 10 接続で超過
        assert_eq!(detect_connection_count_exceeded(&entries, 5), Some(10));
    }

    #[test]
    fn test_detect_connection_count_not_exceeded() {
        let entries: Vec<ConnectionEntry> = (0..5)
            .map(|i| ConnectionEntry {
                protocol: Protocol::Tcp,
                local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                local_port: 50000 + i,
                remote_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                remote_port: 80,
                state: 0x01,
            })
            .collect();

        // 閾値 5 → 5 接続で超過なし（> であり >= ではない）
        assert_eq!(detect_connection_count_exceeded(&entries, 5), None);
    }

    #[test]
    fn test_detect_connection_count_excludes_listen() {
        let entries = vec![
            ConnectionEntry {
                protocol: Protocol::Tcp,
                local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                local_port: 80,
                remote_addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                remote_port: 0,
                state: 0x0A, // LISTEN
            },
            ConnectionEntry {
                protocol: Protocol::Tcp,
                local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                local_port: 50000,
                remote_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                remote_port: 80,
                state: 0x01, // ESTABLISHED
            },
        ];

        // LISTEN は数えないので 1 接続のみ
        assert_eq!(detect_connection_count_exceeded(&entries, 0), Some(1));
        assert_eq!(detect_connection_count_exceeded(&entries, 1), None);
    }

    #[test]
    fn test_is_non_routable_ipv4_10() {
        assert!(is_non_routable_ipv4(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_non_routable_ipv4(&Ipv4Addr::new(10, 255, 255, 255)));
    }

    #[test]
    fn test_is_non_routable_ipv4_172() {
        assert!(is_non_routable_ipv4(&Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_non_routable_ipv4(&Ipv4Addr::new(172, 31, 255, 255)));
        assert!(!is_non_routable_ipv4(&Ipv4Addr::new(172, 15, 0, 1)));
        assert!(!is_non_routable_ipv4(&Ipv4Addr::new(172, 32, 0, 1)));
    }

    #[test]
    fn test_is_non_routable_ipv4_192_168() {
        assert!(is_non_routable_ipv4(&Ipv4Addr::new(192, 168, 0, 1)));
        assert!(is_non_routable_ipv4(&Ipv4Addr::new(192, 168, 255, 255)));
        assert!(!is_non_routable_ipv4(&Ipv4Addr::new(192, 169, 0, 1)));
    }

    #[test]
    fn test_is_non_routable_ipv4_127() {
        assert!(is_non_routable_ipv4(&Ipv4Addr::new(127, 0, 0, 1)));
        assert!(is_non_routable_ipv4(&Ipv4Addr::new(127, 255, 255, 255)));
    }

    #[test]
    fn test_is_non_routable_ipv4_zero() {
        assert!(is_non_routable_ipv4(&Ipv4Addr::new(0, 0, 0, 0)));
    }

    #[test]
    fn test_is_non_routable_ipv4_public() {
        assert!(!is_non_routable_ipv4(&Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_non_routable_ipv4(&Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!is_non_routable_ipv4(&Ipv4Addr::new(203, 0, 113, 1)));
    }

    #[test]
    fn test_parse_addr_port() {
        // 0100007F:0035 → 127.0.0.1:53
        let result = parse_addr_port("0100007F:0035");
        assert!(result.is_some());
        let (addr, port) = result.unwrap();
        assert_eq!(addr, Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(port, 53);
    }

    #[test]
    fn test_parse_addr_port_invalid() {
        assert!(parse_addr_port("invalid").is_none());
        assert!(parse_addr_port("GGGGGGGG:0035").is_none());
        assert!(parse_addr_port("0100007F:GGGG").is_none());
    }

    #[test]
    fn test_parse_addr_port_v6() {
        // ::1 (loopback) in /proc/net/tcp6 format
        // ::1 は 00000000000000000000000001000000 (リトルエンディアンの場合)
        // 実際には各32bitワードがホストバイトオーダーなのでプラットフォーム依存
        // テストではパース関数の基本動作を確認
        let loopback_hex = format!(
            "{}{}{}{}",
            format!("{:08X}", u32::from_ne_bytes([0, 0, 0, 0])),
            format!("{:08X}", u32::from_ne_bytes([0, 0, 0, 0])),
            format!("{:08X}", u32::from_ne_bytes([0, 0, 0, 0])),
            format!("{:08X}", u32::from_ne_bytes([0, 0, 0, 1])),
        );
        let field = format!("{}:0050", loopback_hex);
        let result = parse_addr_port_v6(&field);
        assert!(result.is_some());
        let (addr, port) = result.unwrap();
        assert_eq!(addr, Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(port, 80);
    }

    #[test]
    fn test_parse_addr_port_v6_loopback() {
        // ::1 のバイト列を直接構築
        let loopback_hex = format!(
            "{}{}{}{}",
            format!("{:08X}", u32::from_ne_bytes([0, 0, 0, 0])),
            format!("{:08X}", u32::from_ne_bytes([0, 0, 0, 0])),
            format!("{:08X}", u32::from_ne_bytes([0, 0, 0, 0])),
            format!("{:08X}", u32::from_ne_bytes([0, 0, 0, 1])),
        );
        let field = format!("{}:1F90", loopback_hex);
        let result = parse_addr_port_v6(&field);
        assert!(result.is_some());
        let (addr, port) = result.unwrap();
        assert!(addr.is_loopback());
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_addr_port_v6_invalid() {
        // コロンなし
        assert!(parse_addr_port_v6("invalid").is_none());
        // アドレス部分が短すぎる
        assert!(parse_addr_port_v6("0100007F:0035").is_none());
        // 不正な16進数
        assert!(parse_addr_port_v6("GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG:0035").is_none());
        // ポートが不正
        assert!(parse_addr_port_v6("00000000000000000000000000000000:GGGG").is_none());
    }

    #[test]
    fn test_parse_proc_net_tcp6() {
        // ::1:80 -> :::0 の LISTEN エントリ
        let loopback_hex = format!(
            "{}{}{}{}",
            format!("{:08X}", u32::from_ne_bytes([0, 0, 0, 0])),
            format!("{:08X}", u32::from_ne_bytes([0, 0, 0, 0])),
            format!("{:08X}", u32::from_ne_bytes([0, 0, 0, 0])),
            format!("{:08X}", u32::from_ne_bytes([0, 0, 0, 1])),
        );
        let zero_hex = "00000000000000000000000000000000";
        let content = format!(
            "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: {}:0050 {}:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0",
            loopback_hex, zero_hex
        );

        let entries = parse_proc_net(&content, Protocol::Tcp, AddressFamily::V6);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].protocol, Protocol::Tcp);
        assert_eq!(
            entries[0].local_addr,
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))
        );
        assert_eq!(entries[0].local_port, 80);
        assert_eq!(entries[0].remote_addr, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        assert_eq!(entries[0].remote_port, 0);
        assert_eq!(entries[0].state, 0x0A);
    }

    #[test]
    fn test_detect_suspicious_port_connections_ipv6() {
        let suspicious_ports: HashSet<u16> = [4444].into_iter().collect();

        let entries = vec![ConnectionEntry {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            local_port: 54321,
            remote_addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
            remote_port: 4444,
            state: 0x01, // ESTABLISHED
        }];

        let result = detect_suspicious_port_connections(&entries, &suspicious_ports);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].remote_port, 4444);
    }

    #[test]
    fn test_detect_connection_count_mixed() {
        // IPv4 + IPv6 混在の接続数カウント
        let entries = vec![
            ConnectionEntry {
                protocol: Protocol::Tcp,
                local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                local_port: 50000,
                remote_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                remote_port: 80,
                state: 0x01,
            },
            ConnectionEntry {
                protocol: Protocol::Tcp,
                local_addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                local_port: 50001,
                remote_addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
                remote_port: 443,
                state: 0x01,
            },
            ConnectionEntry {
                protocol: Protocol::Tcp,
                local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                local_port: 80,
                remote_addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                remote_port: 0,
                state: 0x0A, // LISTEN - カウントしない
            },
        ];

        // ESTABLISHED は 2 つ
        assert_eq!(detect_connection_count_exceeded(&entries, 1), Some(2));
        assert_eq!(detect_connection_count_exceeded(&entries, 2), None);
    }

    #[test]
    fn test_is_non_routable_ipv6_loopback() {
        assert!(is_non_routable_ipv6(&Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_is_non_routable_ipv6_link_local() {
        // fe80::1
        assert!(is_non_routable_ipv6(&Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        )));
        // fe80::dead:beef
        assert!(is_non_routable_ipv6(&Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0xdead, 0xbeef
        )));
    }

    #[test]
    fn test_is_non_routable_ipv6_unique_local() {
        // fc00::1
        assert!(is_non_routable_ipv6(&Ipv6Addr::new(
            0xfc00, 0, 0, 0, 0, 0, 0, 1
        )));
        // fd00::1
        assert!(is_non_routable_ipv6(&Ipv6Addr::new(
            0xfd00, 0, 0, 0, 0, 0, 0, 1
        )));
    }

    #[test]
    fn test_is_non_routable_ipv6_ipv4_mapped() {
        // ::ffff:192.168.1.1
        assert!(is_non_routable_ipv6(&Ipv6Addr::new(
            0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0101
        )));
    }

    #[test]
    fn test_is_non_routable_ipv6_public() {
        // 2001:db8::1 はドキュメント用アドレスだが、ここではルーティング可能として扱う
        assert!(!is_non_routable_ipv6(&Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
        )));
        // 2001:4860:4860::8888 (Google DNS)
        assert!(!is_non_routable_ipv6(&Ipv6Addr::new(
            0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888
        )));
    }

    #[test]
    fn test_is_non_routable_ipv4_compat() {
        // ::192.168.1.1 (IPv4互換アドレス、deprecated)
        assert!(is_non_routable_ipv6(&Ipv6Addr::new(
            0, 0, 0, 0, 0, 0, 0xc0a8, 0x0101
        )));
    }

    #[test]
    fn test_is_non_routable_addr_v4() {
        assert!(is_non_routable_addr(&IpAddr::V4(Ipv4Addr::new(
            127, 0, 0, 1
        ))));
        assert!(!is_non_routable_addr(&IpAddr::V4(Ipv4Addr::new(
            8, 8, 8, 8
        ))));
    }

    #[test]
    fn test_is_non_routable_addr_v6() {
        assert!(is_non_routable_addr(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!is_non_routable_addr(&IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
        ))));
    }

    #[test]
    fn test_is_unspecified_addr() {
        assert!(is_unspecified_addr(&IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
        assert!(is_unspecified_addr(&IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        assert!(!is_unspecified_addr(&IpAddr::V4(Ipv4Addr::new(
            127, 0, 0, 1
        ))));
        assert!(!is_unspecified_addr(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn test_init_zero_interval() {
        let config = NetworkMonitorConfig {
            enabled: true,
            interval_secs: 0,
            suspicious_ports: vec![4444],
            max_connections: 1000,
            enable_ipv6: true,
        };
        let mut module = NetworkMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_init_valid_config() {
        let config = NetworkMonitorConfig {
            enabled: true,
            interval_secs: 30,
            suspicious_ports: vec![4444, 5555],
            max_connections: 1000,
            enable_ipv6: true,
        };
        let mut module = NetworkMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_ok());
    }

    #[test]
    fn test_init_empty_suspicious_ports() {
        let config = NetworkMonitorConfig {
            enabled: true,
            interval_secs: 30,
            suspicious_ports: vec![],
            max_connections: 1000,
            enable_ipv6: true,
        };
        let mut module = NetworkMonitorModule::new(config, None);
        // 空でもエラーにはならない（warn のみ）
        let result = module.init();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let config = NetworkMonitorConfig {
            enabled: true,
            interval_secs: 3600,
            suspicious_ports: vec![4444],
            max_connections: 1000,
            enable_ipv6: true,
        };
        let mut module = NetworkMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[test]
    fn test_init_with_event_bus_none() {
        let config = NetworkMonitorConfig {
            enabled: true,
            interval_secs: 30,
            suspicious_ports: vec![4444],
            max_connections: 1000,
            enable_ipv6: true,
        };
        let mut module = NetworkMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[test]
    fn test_init_with_event_bus_some() {
        let config = NetworkMonitorConfig {
            enabled: true,
            interval_secs: 30,
            suspicious_ports: vec![4444],
            max_connections: 1000,
            enable_ipv6: true,
        };
        let bus = EventBus::new(16);
        let mut module = NetworkMonitorModule::new(config, Some(bus));
        assert!(module.init().is_ok());
    }

    #[test]
    fn test_detect_suspicious_port_connections_udp_ipv6() {
        let suspicious_ports: HashSet<u16> = [6666].into_iter().collect();

        let entries = vec![
            // アクティブな IPv6 UDP 接続 → 検知される
            ConnectionEntry {
                protocol: Protocol::Udp,
                local_addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                local_port: 54321,
                remote_addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
                remote_port: 6666,
                state: 0x07,
            },
            // remote_addr が :: の UDP は除外
            ConnectionEntry {
                protocol: Protocol::Udp,
                local_addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                local_port: 53,
                remote_addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                remote_port: 6666,
                state: 0x07,
            },
        ];

        let result = detect_suspicious_port_connections(&entries, &suspicious_ports);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].remote_port, 6666);
        assert_eq!(
            result[0].remote_addr,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2))
        );
    }

    #[test]
    fn test_is_non_routable_ipv6_unspecified() {
        assert!(is_non_routable_ipv6(&Ipv6Addr::UNSPECIFIED));
    }

    #[test]
    fn test_detect_connection_count_udp_ipv6() {
        let entries = vec![
            // アクティブな IPv6 UDP → カウントされる
            ConnectionEntry {
                protocol: Protocol::Udp,
                local_addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                local_port: 54321,
                remote_addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
                remote_port: 53,
                state: 0x07,
            },
            // remote_addr が :: の UDP → カウントされない
            ConnectionEntry {
                protocol: Protocol::Udp,
                local_addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                local_port: 53,
                remote_addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                remote_port: 0,
                state: 0x07,
            },
        ];

        // アクティブ接続は 1 つのみ
        assert_eq!(detect_connection_count_exceeded(&entries, 0), Some(1));
        assert_eq!(detect_connection_count_exceeded(&entries, 1), None);
    }

    #[test]
    fn test_enable_ipv6_default() {
        let config = NetworkMonitorConfig::default();
        assert!(config.enable_ipv6);
    }

    #[test]
    fn test_parse_addr_port_v6_all_zeros() {
        // :: (未指定アドレス)
        let field = "00000000000000000000000000000000:0000";
        let result = parse_addr_port_v6(field);
        assert!(result.is_some());
        let (addr, port) = result.unwrap();
        assert!(addr.is_unspecified());
        assert_eq!(port, 0);
    }

    #[test]
    fn test_parse_proc_net_tcp6_established() {
        // 2001:db8::1:443 -> 2001:db8::2:54321 ESTABLISHED
        let local_hex = format!(
            "{}{}{}{}",
            format!("{:08X}", u32::from_ne_bytes([0x20, 0x01, 0x0d, 0xb8])),
            format!("{:08X}", u32::from_ne_bytes([0, 0, 0, 0])),
            format!("{:08X}", u32::from_ne_bytes([0, 0, 0, 0])),
            format!("{:08X}", u32::from_ne_bytes([0, 0, 0, 1])),
        );
        let remote_hex = format!(
            "{}{}{}{}",
            format!("{:08X}", u32::from_ne_bytes([0x20, 0x01, 0x0d, 0xb8])),
            format!("{:08X}", u32::from_ne_bytes([0, 0, 0, 0])),
            format!("{:08X}", u32::from_ne_bytes([0, 0, 0, 0])),
            format!("{:08X}", u32::from_ne_bytes([0, 0, 0, 2])),
        );
        let content = format!(
            "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: {}:01BB {}:D431 01 00000000:00000000 00:00000000 00000000  1000        0 67890 1 0000000000000000 100 0 0 10 0",
            local_hex, remote_hex
        );

        let entries = parse_proc_net(&content, Protocol::Tcp, AddressFamily::V6);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].local_port, 443);
        assert_eq!(entries[0].remote_port, 0xD431);
        assert_eq!(entries[0].state, 0x01);
        assert_eq!(
            entries[0].local_addr,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))
        );
        assert_eq!(
            entries[0].remote_addr,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2))
        );
    }

    #[tokio::test]
    async fn test_initial_scan_returns_connections() {
        let config = NetworkMonitorConfig {
            enabled: true,
            interval_secs: 60,
            suspicious_ports: vec![4444, 5555],
            max_connections: 1000,
            enable_ipv6: false,
        };
        let module = NetworkMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert!(result.summary.contains("ネットワーク接続"));
        assert!(result.summary.contains("不審な接続"));
    }
}
