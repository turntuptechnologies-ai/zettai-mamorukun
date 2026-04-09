//! ソケットベースのバックドア検知モジュール
//!
//! `/proc/net/tcp`, `/proc/net/tcp6` を定期スキャンし、ホワイトリスト（許可ポート・
//! 許可プロセス名）に含まれないリスニングソケットを検知してバックドアの存在を警告する。
//!
//! 検知対象:
//! - 許可ポートリスト・許可プロセスリスト双方に含まれないリスニングソケット → High
//!
//! 既存の `listening_port_monitor` との違い:
//! - プロセス識別: リスニングソケットの所有プロセスを特定する
//! - プロセス名ベースのホワイトリスト
//! - ループバック除外オプション

use crate::config::BackdoorDetectorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio_util::sync::CancellationToken;

/// リスニングソケット情報
#[derive(Debug, Clone, PartialEq, Eq)]
struct ListeningSocket {
    /// バインドアドレス
    addr: IpAddr,
    /// ポート番号
    port: u16,
    /// ソケットの inode 番号
    inode: u64,
}

/// プロセス情報付きリスニングソケット
#[derive(Debug, Clone, PartialEq, Eq)]
struct SocketWithProcess {
    addr: IpAddr,
    port: u16,
    pid: Option<u32>,
    process_name: Option<String>,
}

/// hex 文字列から IPv4 アドレスをパースする
fn parse_ipv4_hex(hex: &str) -> Option<Ipv4Addr> {
    let n = u32::from_str_radix(hex, 16).ok()?;
    Some(Ipv4Addr::from(n.to_ne_bytes()))
}

/// hex 文字列から IPv6 アドレスをパースする
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

/// /proc/net/tcp または /proc/net/tcp6 をパースし、LISTEN 状態のソケットを返す
fn parse_tcp_listen(path: &str, is_ipv6: bool) -> Vec<ListeningSocket> {
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
        if cols.len() < 10 {
            continue;
        }

        // st (state) フィールド: 0A = TCP_LISTEN
        let state = cols[3];
        if state != "0A" {
            continue;
        }

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

        // inode は 10 番目のフィールド (インデックス 9)
        let inode: u64 = match cols[9].parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        entries.push(ListeningSocket { addr, port, inode });
    }
    entries
}

/// inode → PID のマッピングを構築する
///
/// /proc/{pid}/fd/ 配下のシンボリックリンクを読み、socket:[inode] を探す
fn build_inode_to_pid_map(proc_path: &str, target_inodes: &HashSet<u64>) -> HashMap<u64, u32> {
    let mut map = HashMap::new();

    if target_inodes.is_empty() {
        return map;
    }

    let proc_dir = match std::fs::read_dir(proc_path) {
        Ok(d) => d,
        Err(e) => {
            tracing::debug!(error = %e, "proc ディレクトリの読み取りに失敗しました");
            return map;
        }
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // PID ディレクトリのみ処理
        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let fd_path = format!("{}/{}/fd", proc_path, pid);
        let fd_dir = match std::fs::read_dir(&fd_path) {
            Ok(d) => d,
            Err(_) => continue,
        };

        for fd_entry in fd_dir.flatten() {
            let link = match std::fs::read_link(fd_entry.path()) {
                Ok(l) => l,
                Err(_) => continue,
            };

            let link_str = link.to_string_lossy();
            // socket:[12345] の形式
            if let Some(inode_str) = link_str
                .strip_prefix("socket:[")
                .and_then(|s| s.strip_suffix(']'))
                && let Ok(inode) = inode_str.parse::<u64>()
                && target_inodes.contains(&inode)
            {
                map.insert(inode, pid);
                // すべての inode が見つかったら早期終了
                if map.len() == target_inodes.len() {
                    return map;
                }
            }
        }
    }

    map
}

/// PID からプロセス名を取得する
fn get_process_name(proc_path: &str, pid: u32) -> Option<String> {
    let comm_path = format!("{}/{}/comm", proc_path, pid);
    std::fs::read_to_string(comm_path)
        .ok()
        .map(|s| s.trim().to_string())
}

/// アドレスがループバックかどうかを判定する
fn is_loopback(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// アドレスが全ゼロ（UNSPECIFIED）かどうかを判定する
fn is_unspecified(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_unspecified(),
    }
}

/// リスニングソケットをスキャンし、プロセス情報を付与する
fn scan_sockets(config: &BackdoorDetectorConfig) -> Vec<SocketWithProcess> {
    let mut sockets = Vec::new();
    sockets.extend(parse_tcp_listen(&config.tcp_path, false));
    sockets.extend(parse_tcp_listen(&config.tcp6_path, true));

    if sockets.is_empty() {
        return Vec::new();
    }

    let target_inodes: HashSet<u64> = sockets.iter().map(|s| s.inode).collect();
    let inode_to_pid = build_inode_to_pid_map(&config.proc_path, &target_inodes);

    sockets
        .into_iter()
        .map(|s| {
            let pid = inode_to_pid.get(&s.inode).copied();
            let process_name = pid.and_then(|p| get_process_name(&config.proc_path, p));
            SocketWithProcess {
                addr: s.addr,
                port: s.port,
                pid,
                process_name,
            }
        })
        .collect()
}

/// ソケットがホワイトリストで許可されているか判定する
fn is_allowed(
    socket: &SocketWithProcess,
    allowed_ports: &HashSet<u16>,
    allowed_processes: &HashSet<String>,
    alert_on_loopback: bool,
) -> bool {
    // ループバック除外
    if !alert_on_loopback && is_loopback(&socket.addr) {
        return true;
    }

    // ポート番号ベースの許可
    if allowed_ports.contains(&socket.port) {
        return true;
    }

    // プロセス名ベースの許可
    if let Some(ref name) = socket.process_name
        && allowed_processes.contains(name)
    {
        return true;
    }

    false
}

/// 不審なソケットを検知してイベントを発行する
fn detect_suspicious_sockets(
    sockets: &[SocketWithProcess],
    allowed_ports: &HashSet<u16>,
    allowed_processes: &HashSet<String>,
    alert_on_loopback: bool,
    event_bus: &Option<EventBus>,
) -> usize {
    let mut suspicious_count = 0;

    // ポートごとにソケットをグループ化（同一ポートで複数アドレスの場合をまとめる）
    let mut port_sockets: BTreeMap<u16, Vec<&SocketWithProcess>> = BTreeMap::new();
    for socket in sockets {
        port_sockets.entry(socket.port).or_default().push(socket);
    }

    for (port, group) in &port_sockets {
        // グループ内の全ソケットをチェック
        // UNSPECIFIED アドレス (0.0.0.0/::) でリッスンしている場合はループバック除外を適用しない
        let has_unspecified = group.iter().any(|s| is_unspecified(&s.addr));

        for socket in group {
            let effective_alert_on_loopback = if has_unspecified {
                true
            } else {
                alert_on_loopback
            };

            if is_allowed(
                socket,
                allowed_ports,
                allowed_processes,
                effective_alert_on_loopback,
            ) {
                continue;
            }

            let addr_str = socket.addr.to_string();
            let pid_str = socket.pid.map_or("不明".to_string(), |p| p.to_string());
            let proc_str = socket.process_name.as_deref().unwrap_or("不明");

            let details = format!(
                "ポート={}, アドレス={}, PID={}, プロセス={}",
                port, addr_str, pid_str, proc_str
            );

            tracing::warn!(
                port = port,
                address = %addr_str,
                pid = %pid_str,
                process = %proc_str,
                "不審なリスニングソケットを検知しました"
            );

            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        "suspicious_listening_socket",
                        Severity::Critical,
                        "backdoor_detector",
                        format!(
                            "不審なリスニングソケットを検知しました: ポート {} ({}, PID: {}, プロセス: {})",
                            port, addr_str, pid_str, proc_str
                        ),
                    )
                    .with_details(details),
                );
            }

            suspicious_count += 1;
        }
    }

    suspicious_count
}

/// ソケットベースのバックドア検知モジュール
///
/// `/proc/net/tcp{,6}` を定期スキャンし、ホワイトリストに含まれない
/// リスニングソケットを検知してバックドアの存在を警告する。
pub struct BackdoorDetectorModule {
    config: BackdoorDetectorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl BackdoorDetectorModule {
    /// 新しいバックドア検知モジュールを作成する
    pub fn new(config: BackdoorDetectorConfig, event_bus: Option<EventBus>) -> Self {
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

impl Module for BackdoorDetectorModule {
    fn name(&self) -> &str {
        "backdoor_detector"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            allowed_ports = self.config.allowed_ports.len(),
            allowed_processes = self.config.allowed_processes.len(),
            alert_on_loopback = self.config.alert_on_loopback,
            "バックドア検知モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<(), AppError> {
        let config = self.config.clone();
        let scan_interval_secs = self.config.scan_interval_secs;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        let allowed_ports: HashSet<u16> = self.config.allowed_ports.iter().copied().collect();
        let allowed_processes: HashSet<String> =
            self.config.allowed_processes.iter().cloned().collect();
        let alert_on_loopback = self.config.alert_on_loopback;

        // 初回スキャン
        let sockets = scan_sockets(&config);
        tracing::info!(
            listening_sockets = sockets.len(),
            "バックドア検知 初回スキャンが完了しました"
        );

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("バックドア検知モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let sockets = scan_sockets(&config);
                        let suspicious = detect_suspicious_sockets(
                            &sockets,
                            &allowed_ports,
                            &allowed_processes,
                            alert_on_loopback,
                            &event_bus,
                        );

                        if suspicious == 0 {
                            tracing::debug!(
                                total_sockets = sockets.len(),
                                "不審なリスニングソケットは検知されませんでした"
                            );
                        }
                    }
                }
            }
        });

        Ok(())
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();
        let sockets = scan_sockets(&self.config);

        let allowed_ports: HashSet<u16> = self.config.allowed_ports.iter().copied().collect();
        let allowed_processes: HashSet<String> =
            self.config.allowed_processes.iter().cloned().collect();

        let items_scanned = sockets.len();

        // ホワイトリストに含まれないソケットの検知
        let issues_found = if allowed_ports.is_empty() && allowed_processes.is_empty() {
            0
        } else {
            sockets
                .iter()
                .filter(|s| {
                    !is_allowed(
                        s,
                        &allowed_ports,
                        &allowed_processes,
                        self.config.alert_on_loopback,
                    )
                })
                .count()
        };

        // スナップショットデータを構築
        let mut snapshot: BTreeMap<String, String> = BTreeMap::new();
        for socket in &sockets {
            let key = format!("backdoor:tcp:{}", socket.port);
            let value = format!(
                "addr={},pid={},proc={}",
                socket.addr,
                socket.pid.map_or("unknown".to_string(), |p| p.to_string()),
                socket.process_name.as_deref().unwrap_or("unknown")
            );
            snapshot.insert(key, value);
        }

        tracing::info!(
            total_sockets = items_scanned,
            suspicious = issues_found,
            "起動時スキャン: リスニングソケットをスキャンしました"
        );

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "リスニングソケット {}件をスキャン（不審: {}件）",
                items_scanned, issues_found
            ),
            snapshot,
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

    fn make_config(tcp: &NamedTempFile, tcp6: &NamedTempFile) -> BackdoorDetectorConfig {
        BackdoorDetectorConfig {
            enabled: true,
            scan_interval_secs: 30,
            allowed_ports: Vec::new(),
            allowed_processes: Vec::new(),
            alert_on_loopback: false,
            tcp_path: tcp.path().to_str().unwrap().to_string(),
            tcp6_path: tcp6.path().to_str().unwrap().to_string(),
            proc_path: "/nonexistent".to_string(),
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

    // --- parse_tcp_listen ---

    #[test]
    fn test_parse_tcp_listen_only() {
        let content = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                        0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1\n\
                        1: 0100007F:0035 0100007F:C000 01 00000000:00000000 00:00000000 00000000     0        0 12346 1\n";
        let file = write_temp_file(content);
        let sockets = parse_tcp_listen(file.path().to_str().unwrap(), false);
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].port, 22);
        assert_eq!(sockets[0].inode, 12345);
    }

    #[test]
    fn test_parse_tcp6_listen() {
        let content = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                        0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 54321 1\n";
        let file = write_temp_file(content);
        let sockets = parse_tcp_listen(file.path().to_str().unwrap(), true);
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].port, 80);
        assert_eq!(sockets[0].addr, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        assert_eq!(sockets[0].inode, 54321);
    }

    #[test]
    fn test_parse_tcp_listen_nonexistent() {
        let sockets = parse_tcp_listen("/nonexistent/path", false);
        assert!(sockets.is_empty());
    }

    #[test]
    fn test_parse_tcp_listen_skips_insufficient_cols() {
        let content = "  sl  local_address rem_address   st\n\
                        0: bad\n\
                        1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1\n";
        let file = write_temp_file(content);
        let sockets = parse_tcp_listen(file.path().to_str().unwrap(), false);
        assert_eq!(sockets.len(), 1);
    }

    // --- is_loopback ---

    #[test]
    fn test_is_loopback() {
        assert!(is_loopback(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_loopback(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!is_loopback(&IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(!is_loopback(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    // --- is_unspecified ---

    #[test]
    fn test_is_unspecified() {
        assert!(is_unspecified(&IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(is_unspecified(&IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        assert!(!is_unspecified(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    // --- is_allowed ---

    #[test]
    fn test_is_allowed_by_port() {
        let socket = SocketWithProcess {
            addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: 22,
            pid: Some(100),
            process_name: Some("sshd".to_string()),
        };
        let allowed_ports: HashSet<u16> = [22].into();
        let allowed_processes: HashSet<String> = HashSet::new();
        assert!(is_allowed(
            &socket,
            &allowed_ports,
            &allowed_processes,
            false
        ));
    }

    #[test]
    fn test_is_allowed_by_process() {
        let socket = SocketWithProcess {
            addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: 8080,
            pid: Some(200),
            process_name: Some("nginx".to_string()),
        };
        let allowed_ports: HashSet<u16> = HashSet::new();
        let allowed_processes: HashSet<String> = ["nginx".to_string()].into();
        assert!(is_allowed(
            &socket,
            &allowed_ports,
            &allowed_processes,
            false
        ));
    }

    #[test]
    fn test_is_allowed_loopback_excluded() {
        let socket = SocketWithProcess {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 9999,
            pid: Some(300),
            process_name: Some("unknown_proc".to_string()),
        };
        let allowed_ports: HashSet<u16> = HashSet::new();
        let allowed_processes: HashSet<String> = HashSet::new();
        // alert_on_loopback = false → ループバックは許可
        assert!(is_allowed(
            &socket,
            &allowed_ports,
            &allowed_processes,
            false
        ));
        // alert_on_loopback = true → ループバックもアラート対象
        assert!(!is_allowed(
            &socket,
            &allowed_ports,
            &allowed_processes,
            true
        ));
    }

    #[test]
    fn test_not_allowed() {
        let socket = SocketWithProcess {
            addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: 4444,
            pid: Some(999),
            process_name: Some("malicious".to_string()),
        };
        let allowed_ports: HashSet<u16> = [22, 80, 443].into();
        let allowed_processes: HashSet<String> = ["sshd".to_string(), "nginx".to_string()].into();
        assert!(!is_allowed(
            &socket,
            &allowed_ports,
            &allowed_processes,
            false
        ));
    }

    // --- detect_suspicious_sockets ---

    #[test]
    fn test_detect_no_suspicious() {
        let sockets = vec![SocketWithProcess {
            addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: 22,
            pid: Some(100),
            process_name: Some("sshd".to_string()),
        }];
        let allowed_ports: HashSet<u16> = [22].into();
        let allowed_processes: HashSet<String> = HashSet::new();
        let count =
            detect_suspicious_sockets(&sockets, &allowed_ports, &allowed_processes, false, &None);
        assert_eq!(count, 0);
    }

    #[test]
    fn test_detect_suspicious_socket() {
        let sockets = vec![
            SocketWithProcess {
                addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                port: 22,
                pid: Some(100),
                process_name: Some("sshd".to_string()),
            },
            SocketWithProcess {
                addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                port: 4444,
                pid: Some(999),
                process_name: Some("nc".to_string()),
            },
        ];
        let allowed_ports: HashSet<u16> = [22, 80, 443].into();
        let allowed_processes: HashSet<String> = HashSet::new();
        let count =
            detect_suspicious_sockets(&sockets, &allowed_ports, &allowed_processes, false, &None);
        assert_eq!(count, 1);
    }

    #[test]
    fn test_detect_loopback_excluded() {
        let sockets = vec![SocketWithProcess {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 9999,
            pid: Some(300),
            process_name: Some("debug_server".to_string()),
        }];
        let allowed_ports: HashSet<u16> = HashSet::new();
        let allowed_processes: HashSet<String> = HashSet::new();
        // alert_on_loopback = false
        let count =
            detect_suspicious_sockets(&sockets, &allowed_ports, &allowed_processes, false, &None);
        assert_eq!(count, 0);
    }

    #[test]
    fn test_detect_loopback_alerted() {
        let sockets = vec![SocketWithProcess {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 9999,
            pid: Some(300),
            process_name: Some("debug_server".to_string()),
        }];
        let allowed_ports: HashSet<u16> = HashSet::new();
        let allowed_processes: HashSet<String> = HashSet::new();
        // alert_on_loopback = true
        let count =
            detect_suspicious_sockets(&sockets, &allowed_ports, &allowed_processes, true, &None);
        assert_eq!(count, 1);
    }

    #[test]
    fn test_detect_allowed_by_process_name() {
        let sockets = vec![SocketWithProcess {
            addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: 8080,
            pid: Some(200),
            process_name: Some("nginx".to_string()),
        }];
        let allowed_ports: HashSet<u16> = HashSet::new();
        let allowed_processes: HashSet<String> = ["nginx".to_string()].into();
        let count =
            detect_suspicious_sockets(&sockets, &allowed_ports, &allowed_processes, false, &None);
        assert_eq!(count, 0);
    }

    // --- scan_sockets (with temp files) ---

    #[test]
    fn test_scan_sockets_empty() {
        let tcp = empty_temp_file();
        let tcp6 = empty_temp_file();
        let config = make_config(&tcp, &tcp6);
        let sockets = scan_sockets(&config);
        assert!(sockets.is_empty());
    }

    #[test]
    fn test_scan_sockets_with_data() {
        let tcp = write_temp_file(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
             0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1\n",
        );
        let tcp6 = empty_temp_file();
        let config = make_config(&tcp, &tcp6);
        let sockets = scan_sockets(&config);
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].port, 22);
        // /nonexistent proc path → PID/process は取得できない
        assert!(sockets[0].pid.is_none());
        assert!(sockets[0].process_name.is_none());
    }

    // --- Module lifecycle ---

    #[test]
    fn test_init_zero_interval() {
        let tcp = empty_temp_file();
        let tcp6 = empty_temp_file();
        let mut config = make_config(&tcp, &tcp6);
        config.scan_interval_secs = 0;
        let mut module = BackdoorDetectorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let tcp = empty_temp_file();
        let tcp6 = empty_temp_file();
        let mut config = make_config(&tcp, &tcp6);
        config.allowed_ports = vec![22, 80, 443];
        config.allowed_processes = vec!["sshd".to_string(), "nginx".to_string()];
        let mut module = BackdoorDetectorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let tcp = write_temp_file(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
             0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1\n",
        );
        let tcp6 = empty_temp_file();
        let config = make_config(&tcp, &tcp6);
        let mut module = BackdoorDetectorModule::new(config, None);
        assert!(module.init().is_ok());
        assert!(module.start().await.is_ok());
        assert!(module.stop().await.is_ok());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let tcp = write_temp_file(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
             0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1\n\
             1: 0100007F:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1\n",
        );
        let tcp6 = empty_temp_file();
        let config = make_config(&tcp, &tcp6);
        let module = BackdoorDetectorModule::new(config, None);
        let result = module.initial_scan().await.unwrap();

        assert_eq!(result.items_scanned, 2);
        assert_eq!(result.issues_found, 0); // ホワイトリスト空 → 違反カウントなし
        assert!(result.snapshot.contains_key("backdoor:tcp:22"));
        assert!(result.snapshot.contains_key("backdoor:tcp:443"));
    }

    #[tokio::test]
    async fn test_initial_scan_with_violations() {
        let tcp = write_temp_file(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
             0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1\n\
             1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12347 1\n",
        );
        let tcp6 = empty_temp_file();
        let mut config = make_config(&tcp, &tcp6);
        config.allowed_ports = vec![22];

        let module = BackdoorDetectorModule::new(config, None);
        let result = module.initial_scan().await.unwrap();

        // Port 8080 (0x1F90) は許可リストに含まれない
        assert_eq!(result.issues_found, 1);
    }
}
