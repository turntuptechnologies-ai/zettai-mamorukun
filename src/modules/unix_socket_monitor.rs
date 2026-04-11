//! UNIX ソケット監視モジュール
//!
//! /proc/net/unix をパースして UNIX ドメインソケットを定期スキャンし、
//! 不審なソケットの出現・消失を検知する。
//!
//! 検知対象:
//! - 新規ソケットの出現
//! - 既知ソケットの消失
//! - 不審なパス（隠しディレクトリ等）にあるソケット
//! - /tmp、/var/tmp 等の一時ディレクトリにあるソケット

use crate::config::UnixSocketMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::{BTreeMap, HashMap};
use tokio_util::sync::CancellationToken;

/// UNIX ドメインソケットの情報
#[derive(Debug, Clone, PartialEq, Eq)]
struct UnixSocketInfo {
    /// ソケットパス
    path: String,
    /// ソケットタイプ（STREAM / DGRAM / SEQPACKET）
    socket_type: String,
    /// 状態（unconnected / connecting / connected / disconnecting）
    state: String,
    /// inode 番号
    inode: u64,
}

/// UNIX ドメインソケットのスナップショット
struct UnixSocketSnapshot {
    /// パスごとのソケット情報
    sockets: HashMap<String, UnixSocketInfo>,
}

/// UNIX ソケット監視モジュール
///
/// `/proc/net/unix` を定期スキャンし、UNIX ドメインソケットの出現・消失・不審なパスを検知する。
pub struct UnixSocketMonitorModule {
    config: UnixSocketMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl UnixSocketMonitorModule {
    /// 新しい UNIX ソケット監視モジュールを作成する
    pub fn new(config: UnixSocketMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// /proc/net/unix をパースして UNIX ソケット情報を取得する
    fn parse_proc_net_unix(proc_path: &str) -> Vec<UnixSocketInfo> {
        let path = format!("{}/net/unix", proc_path);
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(err) => {
                tracing::debug!(error = %err, path = %path, "/proc/net/unix の読み取りに失敗しました");
                return Vec::new();
            }
        };

        let mut sockets = Vec::new();

        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // 最低 7 フィールド必要（Num, RefCount, Protocol, Flags, Type, St, Inode）
            // フィールド 8 がパス（存在しない場合はスキップ）
            if fields.len() < 8 {
                continue;
            }

            let socket_type = match fields[4] {
                "0001" => "STREAM".to_string(),
                "0002" => "DGRAM".to_string(),
                "0005" => "SEQPACKET".to_string(),
                other => format!("UNKNOWN({})", other),
            };

            let state = match fields[5] {
                "01" => "unconnected".to_string(),
                "02" => "connecting".to_string(),
                "03" => "connected".to_string(),
                "04" => "disconnecting".to_string(),
                other => format!("unknown({})", other),
            };

            let inode = match fields[6].parse::<u64>() {
                Ok(i) => i,
                Err(_) => continue,
            };

            let path = fields[7].to_string();

            sockets.push(UnixSocketInfo {
                path,
                socket_type,
                state,
                inode,
            });
        }

        sockets
    }

    /// 監視対象ディレクトリ内のソケットをスキャンしてスナップショットを返す
    fn scan_sockets(proc_path: &str, watch_dirs: &[String]) -> UnixSocketSnapshot {
        let all_sockets = Self::parse_proc_net_unix(proc_path);

        let mut sockets = HashMap::new();
        for info in all_sockets {
            // watch_dirs のいずれかで始まるパスのみ対象
            let matched = watch_dirs.iter().any(|dir| info.path.starts_with(dir));
            if matched {
                sockets.insert(info.path.clone(), info);
            }
        }

        UnixSocketSnapshot { sockets }
    }

    /// パスが不審かどうかを判定する
    ///
    /// - 隠しディレクトリを含むパス（例: `/tmp/.hidden/socket`）
    /// - 深すぎるネスト（パスコンポーネントが 6 を超える）
    fn is_suspicious_path(path: &str) -> bool {
        // 隠しディレクトリの検出（パスコンポーネントにドットで始まるものがあるか）
        let components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        for component in &components {
            // 最後のコンポーネント（ファイル名）は除外し、ディレクトリ部分のみチェック
            if component == components.last().unwrap_or(&"") {
                continue;
            }
            if component.starts_with('.') {
                return true;
            }
        }

        // 深いネストの検出（6 コンポーネント超）
        if components.len() > 6 {
            return true;
        }

        false
    }

    /// ベースラインと現在のスナップショットを比較し、変更を検知する。
    /// 変更があった場合は `true` を返す。
    fn detect_and_report(
        baseline: &UnixSocketSnapshot,
        current: &UnixSocketSnapshot,
        event_bus: &Option<EventBus>,
        known_sockets: &[String],
    ) -> bool {
        let mut has_changes = false;

        // 新規ソケットの検知
        for (path, info) in &current.sockets {
            if !baseline.sockets.contains_key(path) {
                if Self::is_suspicious_path(path) {
                    // 不審なパスの新規ソケット（Warning）
                    tracing::warn!(
                        path = %path,
                        socket_type = %info.socket_type,
                        state = %info.state,
                        inode = info.inode,
                        "不審なパスに UNIX ソケットが出現しました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "unix_socket_suspicious",
                                Severity::Warning,
                                "unix_socket_monitor",
                                "不審なパスに UNIX ソケットが出現しました",
                            )
                            .with_details(format!(
                                "path={}, type={}, state={}, inode={}",
                                path, info.socket_type, info.state, info.inode
                            )),
                        );
                    }
                    has_changes = true;
                } else {
                    // 通常の新規ソケット（Info）
                    tracing::info!(
                        path = %path,
                        socket_type = %info.socket_type,
                        state = %info.state,
                        inode = info.inode,
                        "新規 UNIX ソケットが出現しました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "unix_socket_new",
                                Severity::Info,
                                "unix_socket_monitor",
                                "新規 UNIX ソケットが出現しました",
                            )
                            .with_details(format!(
                                "path={}, type={}, state={}, inode={}",
                                path, info.socket_type, info.state, info.inode
                            )),
                        );
                    }
                    has_changes = true;
                }
            }
        }

        // 消失の検知
        for path in baseline.sockets.keys() {
            if !current.sockets.contains_key(path) {
                let is_known = known_sockets.iter().any(|k| k == path);
                if is_known {
                    // 既知ソケットの消失（Warning）
                    tracing::warn!(
                        path = %path,
                        "既知の UNIX ソケットが消失しました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "unix_socket_known_removed",
                                Severity::Warning,
                                "unix_socket_monitor",
                                "既知の UNIX ソケットが消失しました",
                            )
                            .with_details(path.clone()),
                        );
                    }
                    has_changes = true;
                } else {
                    // 通常のソケット消失（Info）
                    tracing::info!(
                        path = %path,
                        "UNIX ソケットが消失しました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "unix_socket_removed",
                                Severity::Info,
                                "unix_socket_monitor",
                                "UNIX ソケットが消失しました",
                            )
                            .with_details(path.clone()),
                        );
                    }
                    has_changes = true;
                }
            }
        }

        has_changes
    }
}

impl Module for UnixSocketMonitorModule {
    fn name(&self) -> &str {
        "unix_socket_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            watch_dirs = ?self.config.watch_dirs,
            known_sockets_count = self.config.known_sockets.len(),
            "UNIX ソケット監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        let baseline = Self::scan_sockets(&self.config.proc_path, &self.config.watch_dirs);
        tracing::info!(
            socket_count = baseline.sockets.len(),
            "ベースラインスキャンが完了しました"
        );

        let proc_path = self.config.proc_path.clone();
        let watch_dirs = self.config.watch_dirs.clone();
        let known_sockets = self.config.known_sockets.clone();
        let scan_interval_secs = self.config.scan_interval_secs;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            interval.tick().await;

            let mut baseline = baseline;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("UNIX ソケット監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = UnixSocketMonitorModule::scan_sockets(&proc_path, &watch_dirs);
                        let changed = UnixSocketMonitorModule::detect_and_report(
                            &baseline,
                            &current,
                            &event_bus,
                            &known_sockets,
                        );

                        if changed {
                            baseline = current;
                        } else {
                            tracing::debug!("UNIX ソケットに変更はありません");
                        }
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn stop(&mut self) -> Result<(), AppError> {
        self.cancel_token.cancel();
        Ok(())
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();

        let snapshot = Self::scan_sockets(&self.config.proc_path, &self.config.watch_dirs);

        let mut issues_found = 0;
        for path in snapshot.sockets.keys() {
            if Self::is_suspicious_path(path) {
                issues_found += 1;
            }
        }

        let scan_snapshot: BTreeMap<String, String> = snapshot
            .sockets
            .iter()
            .map(|(path, info)| {
                (
                    path.clone(),
                    format!(
                        "type={},state={},inode={}",
                        info.socket_type, info.state, info.inode
                    ),
                )
            })
            .collect();

        let items_scanned = snapshot.sockets.len();
        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "UNIX ソケットを {}件スキャンし、{}件の問題を検出しました",
                items_scanned, issues_found
            ),
            snapshot: scan_snapshot,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn make_config(proc_dir: &std::path::Path) -> UnixSocketMonitorConfig {
        UnixSocketMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            watch_dirs: vec!["/run".to_string(), "/tmp".to_string(), "/var".to_string()],
            known_sockets: vec!["/run/dbus/system_bus_socket".to_string()],
            proc_path: proc_dir.to_string_lossy().to_string(),
        }
    }

    fn write_proc_net_unix(dir: &std::path::Path, content: &str) {
        let net_dir = dir.join("net");
        fs::create_dir_all(&net_dir).unwrap();
        fs::write(net_dir.join("unix"), content).unwrap();
    }

    const SAMPLE_PROC_NET_UNIX: &str = "\
Num       RefCount Protocol Flags    Type St Inode Path
0000000000000000: 00000002 00000000 00010000 0001 01 12345 /run/dbus/system_bus_socket
0000000000000000: 00000002 00000000 00010000 0002 01 12346 /run/systemd/notify
0000000000000000: 00000002 00000000 00010000 0005 03 12347 /tmp/app.sock
";

    #[test]
    fn test_parse_proc_net_unix() {
        let dir = TempDir::new().unwrap();
        write_proc_net_unix(dir.path(), SAMPLE_PROC_NET_UNIX);

        let sockets = UnixSocketMonitorModule::parse_proc_net_unix(&dir.path().to_string_lossy());
        assert_eq!(sockets.len(), 3);

        assert_eq!(sockets[0].path, "/run/dbus/system_bus_socket");
        assert_eq!(sockets[0].socket_type, "STREAM");
        assert_eq!(sockets[0].state, "unconnected");
        assert_eq!(sockets[0].inode, 12345);

        assert_eq!(sockets[1].path, "/run/systemd/notify");
        assert_eq!(sockets[1].socket_type, "DGRAM");

        assert_eq!(sockets[2].path, "/tmp/app.sock");
        assert_eq!(sockets[2].socket_type, "SEQPACKET");
        assert_eq!(sockets[2].state, "connected");
    }

    #[test]
    fn test_parse_proc_net_unix_empty() {
        let dir = TempDir::new().unwrap();
        write_proc_net_unix(
            dir.path(),
            "Num       RefCount Protocol Flags    Type St Inode Path\n",
        );

        let sockets = UnixSocketMonitorModule::parse_proc_net_unix(&dir.path().to_string_lossy());
        assert!(sockets.is_empty());
    }

    #[test]
    fn test_parse_proc_net_unix_no_path() {
        let dir = TempDir::new().unwrap();
        let content = "\
Num       RefCount Protocol Flags    Type St Inode Path
0000000000000000: 00000002 00000000 00010000 0001 01 12345
0000000000000000: 00000002 00000000 00010000 0001 01 12346
";
        write_proc_net_unix(dir.path(), content);

        let sockets = UnixSocketMonitorModule::parse_proc_net_unix(&dir.path().to_string_lossy());
        assert!(sockets.is_empty());
    }

    #[test]
    fn test_scan_sockets_filters_by_watch_dirs() {
        let dir = TempDir::new().unwrap();
        write_proc_net_unix(dir.path(), SAMPLE_PROC_NET_UNIX);

        let watch_dirs = vec!["/run".to_string()];
        let snapshot =
            UnixSocketMonitorModule::scan_sockets(&dir.path().to_string_lossy(), &watch_dirs);
        assert_eq!(snapshot.sockets.len(), 2);
        assert!(snapshot.sockets.contains_key("/run/dbus/system_bus_socket"));
        assert!(snapshot.sockets.contains_key("/run/systemd/notify"));
        assert!(!snapshot.sockets.contains_key("/tmp/app.sock"));
    }

    #[test]
    fn test_is_suspicious_path_hidden_dir() {
        assert!(UnixSocketMonitorModule::is_suspicious_path(
            "/tmp/.hidden/socket"
        ));
        assert!(UnixSocketMonitorModule::is_suspicious_path(
            "/var/.secret/app.sock"
        ));
    }

    #[test]
    fn test_is_suspicious_path_deep_nesting() {
        assert!(UnixSocketMonitorModule::is_suspicious_path(
            "/a/b/c/d/e/f/g/socket"
        ));
    }

    #[test]
    fn test_is_suspicious_path_normal() {
        assert!(!UnixSocketMonitorModule::is_suspicious_path(
            "/run/dbus/system_bus_socket"
        ));
        assert!(!UnixSocketMonitorModule::is_suspicious_path(
            "/tmp/app.sock"
        ));
        assert!(!UnixSocketMonitorModule::is_suspicious_path(
            "/var/run/docker.sock"
        ));
    }

    #[test]
    fn test_detect_new_socket() {
        let baseline = UnixSocketSnapshot {
            sockets: HashMap::new(),
        };
        let mut current_sockets = HashMap::new();
        current_sockets.insert(
            "/run/new.sock".to_string(),
            UnixSocketInfo {
                path: "/run/new.sock".to_string(),
                socket_type: "STREAM".to_string(),
                state: "unconnected".to_string(),
                inode: 100,
            },
        );
        let current = UnixSocketSnapshot {
            sockets: current_sockets,
        };
        let known: Vec<String> = Vec::new();
        assert!(UnixSocketMonitorModule::detect_and_report(
            &baseline, &current, &None, &known,
        ));
    }

    #[test]
    fn test_detect_removed_socket() {
        let mut baseline_sockets = HashMap::new();
        baseline_sockets.insert(
            "/run/old.sock".to_string(),
            UnixSocketInfo {
                path: "/run/old.sock".to_string(),
                socket_type: "STREAM".to_string(),
                state: "unconnected".to_string(),
                inode: 100,
            },
        );
        let baseline = UnixSocketSnapshot {
            sockets: baseline_sockets,
        };
        let current = UnixSocketSnapshot {
            sockets: HashMap::new(),
        };
        let known: Vec<String> = Vec::new();
        assert!(UnixSocketMonitorModule::detect_and_report(
            &baseline, &current, &None, &known,
        ));
    }

    #[test]
    fn test_detect_suspicious_new_socket() {
        let baseline = UnixSocketSnapshot {
            sockets: HashMap::new(),
        };
        let mut current_sockets = HashMap::new();
        current_sockets.insert(
            "/tmp/.hidden/backdoor.sock".to_string(),
            UnixSocketInfo {
                path: "/tmp/.hidden/backdoor.sock".to_string(),
                socket_type: "STREAM".to_string(),
                state: "unconnected".to_string(),
                inode: 200,
            },
        );
        let current = UnixSocketSnapshot {
            sockets: current_sockets,
        };
        let known: Vec<String> = Vec::new();
        assert!(UnixSocketMonitorModule::detect_and_report(
            &baseline, &current, &None, &known,
        ));
    }

    #[test]
    fn test_detect_known_socket_removed() {
        let mut baseline_sockets = HashMap::new();
        baseline_sockets.insert(
            "/run/dbus/system_bus_socket".to_string(),
            UnixSocketInfo {
                path: "/run/dbus/system_bus_socket".to_string(),
                socket_type: "STREAM".to_string(),
                state: "unconnected".to_string(),
                inode: 12345,
            },
        );
        let baseline = UnixSocketSnapshot {
            sockets: baseline_sockets,
        };
        let current = UnixSocketSnapshot {
            sockets: HashMap::new(),
        };
        let known = vec!["/run/dbus/system_bus_socket".to_string()];
        assert!(UnixSocketMonitorModule::detect_and_report(
            &baseline, &current, &None, &known,
        ));
    }

    #[test]
    fn test_detect_no_changes() {
        let path = "/run/existing.sock".to_string();
        let info = UnixSocketInfo {
            path: path.clone(),
            socket_type: "STREAM".to_string(),
            state: "unconnected".to_string(),
            inode: 100,
        };

        let mut sockets = HashMap::new();
        sockets.insert(path.clone(), info.clone());
        let baseline = UnixSocketSnapshot {
            sockets: sockets.clone(),
        };
        let current = UnixSocketSnapshot { sockets };
        let known: Vec<String> = Vec::new();
        assert!(!UnixSocketMonitorModule::detect_and_report(
            &baseline, &current, &None, &known,
        ));
    }

    #[test]
    fn test_init_zero_interval() {
        let dir = TempDir::new().unwrap();
        let config = UnixSocketMonitorConfig {
            enabled: true,
            scan_interval_secs: 0,
            watch_dirs: vec!["/run".to_string()],
            known_sockets: Vec::new(),
            proc_path: dir.path().to_string_lossy().to_string(),
        };
        let mut module = UnixSocketMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let dir = TempDir::new().unwrap();
        let config = make_config(dir.path());
        let mut module = UnixSocketMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let dir = TempDir::new().unwrap();
        write_proc_net_unix(dir.path(), SAMPLE_PROC_NET_UNIX);

        let config = UnixSocketMonitorConfig {
            enabled: true,
            scan_interval_secs: 3600,
            watch_dirs: vec!["/run".to_string()],
            known_sockets: Vec::new(),
            proc_path: dir.path().to_string_lossy().to_string(),
        };
        let mut module = UnixSocketMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();
        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let dir = TempDir::new().unwrap();
        write_proc_net_unix(dir.path(), SAMPLE_PROC_NET_UNIX);

        let config = UnixSocketMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            watch_dirs: vec!["/run".to_string(), "/tmp".to_string()],
            known_sockets: Vec::new(),
            proc_path: dir.path().to_string_lossy().to_string(),
        };
        let module = UnixSocketMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 3);
        assert_eq!(result.issues_found, 0);
    }
}
