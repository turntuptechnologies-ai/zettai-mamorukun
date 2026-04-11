//! 抽象ソケット名前空間監視モジュール
//!
//! /proc/net/unix をパースして抽象 UNIX ソケット（@ プレフィックス）を定期スキャンし、
//! 不審なソケットの出現・消失を検知する。
//!
//! 抽象ソケットはファイルシステムに痕跡を残さないため、マルウェアによる
//! 秘密通信（Covert IPC）に悪用されやすい。
//!
//! 検知対象:
//! - 許可パターンに一致しない抽象ソケットの出現
//! - 抽象ソケットの消失
//! - 短時間での大量出現（バースト検知）

use crate::config::AbstractSocketMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::{BTreeMap, HashMap};
use tokio_util::sync::CancellationToken;

/// 抽象 UNIX ソケットの情報
#[derive(Debug, Clone, PartialEq, Eq)]
struct AbstractSocketInfo {
    /// ソケットパス（@ プレフィックス付き）
    path: String,
    /// ソケットタイプ（STREAM / DGRAM / SEQPACKET）
    socket_type: String,
    /// 状態（unconnected / connecting / connected / disconnecting）
    state: String,
    /// inode 番号
    inode: u64,
    /// 参照カウント
    ref_count: u64,
}

/// 抽象ソケットのスナップショット
struct AbstractSocketSnapshot {
    /// パスごとのソケット情報
    sockets: HashMap<String, AbstractSocketInfo>,
}

/// 簡易パターンマッチング
///
/// `*` をワイルドカードとして使用する。
/// - 末尾の `*` は任意のサフィックスにマッチ
/// - 中間の `*` は任意の部分文字列にマッチ
/// - ワイルドカードなしの場合は完全一致
fn matches_pattern(text: &str, pattern: &str) -> bool {
    if !pattern.contains('*') {
        return text == pattern;
    }

    let parts: Vec<&str> = pattern.split('*').collect();

    // 先頭パーツとの一致チェック
    if !text.starts_with(parts[0]) {
        return false;
    }

    let mut pos = parts[0].len();
    for (i, part) in parts.iter().enumerate().skip(1) {
        if part.is_empty() {
            // 末尾の `*` の場合は残り全体にマッチ
            if i == parts.len() - 1 {
                return true;
            }
            continue;
        }
        match text[pos..].find(part) {
            Some(found) => {
                pos += found + part.len();
            }
            None => return false,
        }
    }

    // 末尾が `*` でない場合は、テキスト末尾まで消費している必要がある
    if !pattern.ends_with('*') {
        return pos == text.len();
    }

    true
}

/// 抽象ソケット名前空間監視モジュール
///
/// `/proc/net/unix` を定期スキャンし、抽象 UNIX ソケット（@ プレフィックス）の
/// 出現・消失・バースト検知を行う。
pub struct AbstractSocketMonitorModule {
    config: AbstractSocketMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl AbstractSocketMonitorModule {
    /// 新しい抽象ソケット名前空間監視モジュールを作成する
    pub fn new(config: AbstractSocketMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// /proc/net/unix をパースして抽象ソケット情報のみを取得する
    fn parse_abstract_sockets(proc_path: &str) -> Vec<AbstractSocketInfo> {
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

            let socket_path = fields[7];

            // 抽象ソケット（@ プレフィックス）のみ対象
            if !socket_path.starts_with('@') {
                continue;
            }

            let ref_count = match fields[1].parse::<u64>() {
                Ok(r) => r,
                Err(_) => continue,
            };

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

            sockets.push(AbstractSocketInfo {
                path: socket_path.to_string(),
                socket_type,
                state,
                inode,
                ref_count,
            });
        }

        sockets
    }

    /// 抽象ソケットをスキャンしてスナップショットを返す
    fn scan_sockets(proc_path: &str) -> AbstractSocketSnapshot {
        let all_sockets = Self::parse_abstract_sockets(proc_path);

        let mut sockets = HashMap::new();
        for info in all_sockets {
            sockets.insert(info.path.clone(), info);
        }

        AbstractSocketSnapshot { sockets }
    }

    /// ソケットパスが許可パターンのいずれかにマッチするかを判定する
    fn is_allowed(path: &str, allowed_patterns: &[String]) -> bool {
        allowed_patterns
            .iter()
            .any(|pattern| matches_pattern(path, pattern))
    }

    /// ベースラインと現在のスナップショットを比較し、変更を検知する。
    /// 変更があった場合は `true` を返す。
    fn detect_and_report(
        baseline: &AbstractSocketSnapshot,
        current: &AbstractSocketSnapshot,
        event_bus: &Option<EventBus>,
        allowed_patterns: &[String],
        burst_threshold: usize,
    ) -> bool {
        let mut has_changes = false;
        let mut new_socket_count: usize = 0;

        // 新規ソケットの検知
        for (path, info) in &current.sockets {
            if !baseline.sockets.contains_key(path) {
                new_socket_count += 1;

                if Self::is_allowed(path, allowed_patterns) {
                    // 許可パターンに一致する新規ソケット（Info）
                    tracing::info!(
                        path = %path,
                        socket_type = %info.socket_type,
                        state = %info.state,
                        inode = info.inode,
                        ref_count = info.ref_count,
                        "許可パターンに一致する抽象ソケットが出現しました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "abstract_socket_new",
                                Severity::Info,
                                "abstract_socket_monitor",
                                "許可パターンに一致する抽象ソケットが出現しました",
                            )
                            .with_details(format!(
                                "path={}, type={}, state={}, inode={}, ref_count={}",
                                path, info.socket_type, info.state, info.inode, info.ref_count
                            )),
                        );
                    }
                } else {
                    // 許可パターンに一致しない新規ソケット（Warning）
                    tracing::warn!(
                        path = %path,
                        socket_type = %info.socket_type,
                        state = %info.state,
                        inode = info.inode,
                        ref_count = info.ref_count,
                        "不明な抽象ソケットが出現しました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "abstract_socket_unknown",
                                Severity::Warning,
                                "abstract_socket_monitor",
                                "不明な抽象ソケットが出現しました",
                            )
                            .with_details(format!(
                                "path={}, type={}, state={}, inode={}, ref_count={}",
                                path, info.socket_type, info.state, info.inode, info.ref_count
                            )),
                        );
                    }
                }
                has_changes = true;
            }
        }

        // 消失の検知
        for path in baseline.sockets.keys() {
            if !current.sockets.contains_key(path) {
                tracing::info!(
                    path = %path,
                    "抽象ソケットが消失しました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "abstract_socket_removed",
                            Severity::Info,
                            "abstract_socket_monitor",
                            "抽象ソケットが消失しました",
                        )
                        .with_details(path.clone()),
                    );
                }
                has_changes = true;
            }
        }

        // バースト検知
        if new_socket_count > burst_threshold {
            tracing::warn!(
                new_count = new_socket_count,
                threshold = burst_threshold,
                "抽象ソケットの大量出現を検知しました"
            );
            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        "abstract_socket_burst",
                        Severity::Warning,
                        "abstract_socket_monitor",
                        "抽象ソケットの大量出現を検知しました",
                    )
                    .with_details(format!(
                        "new_count={}, threshold={}",
                        new_socket_count, burst_threshold
                    )),
                );
            }
        }

        has_changes
    }
}

impl Module for AbstractSocketMonitorModule {
    fn name(&self) -> &str {
        "abstract_socket_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            allowed_patterns = ?self.config.allowed_patterns,
            burst_threshold = self.config.burst_threshold,
            "抽象ソケット名前空間監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        let baseline = Self::scan_sockets(&self.config.proc_path);
        tracing::info!(
            socket_count = baseline.sockets.len(),
            "ベースラインスキャンが完了しました"
        );

        let proc_path = self.config.proc_path.clone();
        let allowed_patterns = self.config.allowed_patterns.clone();
        let burst_threshold = self.config.burst_threshold;
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
                        tracing::info!("抽象ソケット名前空間監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = AbstractSocketMonitorModule::scan_sockets(&proc_path);
                        let changed = AbstractSocketMonitorModule::detect_and_report(
                            &baseline,
                            &current,
                            &event_bus,
                            &allowed_patterns,
                            burst_threshold,
                        );

                        if changed {
                            baseline = current;
                        } else {
                            tracing::debug!("抽象ソケットに変更はありません");
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

        let snapshot = Self::scan_sockets(&self.config.proc_path);

        let mut issues_found = 0;
        for path in snapshot.sockets.keys() {
            if !Self::is_allowed(path, &self.config.allowed_patterns) {
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
                        "type={},state={},inode={},ref_count={}",
                        info.socket_type, info.state, info.inode, info.ref_count
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
                "抽象ソケットを {}件スキャンし、{}件の問題を検出しました",
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

    fn make_config(proc_dir: &std::path::Path) -> AbstractSocketMonitorConfig {
        AbstractSocketMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            allowed_patterns: vec![
                "@/tmp/.X11-unix/*".to_string(),
                "@/run/dbus-*".to_string(),
                "@/run/systemd/*".to_string(),
            ],
            burst_threshold: 10,
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
0000000000000000: 00000002 00000000 00010000 0001 01 12345 @/tmp/.X11-unix/X0
0000000000000000: 00000003 00000000 00010000 0002 01 12346 @/run/dbus-abcdef
0000000000000000: 00000002 00000000 00010000 0005 03 12347 /run/systemd/notify
0000000000000000: 00000001 00000000 00010000 0001 01 12348 @/tmp/suspicious-socket
";

    #[test]
    fn test_parse_abstract_sockets() {
        let dir = TempDir::new().unwrap();
        write_proc_net_unix(dir.path(), SAMPLE_PROC_NET_UNIX);

        let sockets =
            AbstractSocketMonitorModule::parse_abstract_sockets(&dir.path().to_string_lossy());
        // /run/systemd/notify はファイルシステムソケットなので除外される
        assert_eq!(sockets.len(), 3);

        assert_eq!(sockets[0].path, "@/tmp/.X11-unix/X0");
        assert_eq!(sockets[0].socket_type, "STREAM");
        assert_eq!(sockets[0].state, "unconnected");
        assert_eq!(sockets[0].inode, 12345);
        assert_eq!(sockets[0].ref_count, 2);

        assert_eq!(sockets[1].path, "@/run/dbus-abcdef");
        assert_eq!(sockets[1].socket_type, "DGRAM");
        assert_eq!(sockets[1].ref_count, 3);

        assert_eq!(sockets[2].path, "@/tmp/suspicious-socket");
        assert_eq!(sockets[2].socket_type, "STREAM");
        assert_eq!(sockets[2].ref_count, 1);
    }

    #[test]
    fn test_parse_abstract_sockets_empty() {
        let dir = TempDir::new().unwrap();
        write_proc_net_unix(
            dir.path(),
            "Num       RefCount Protocol Flags    Type St Inode Path\n",
        );

        let sockets =
            AbstractSocketMonitorModule::parse_abstract_sockets(&dir.path().to_string_lossy());
        assert!(sockets.is_empty());
    }

    #[test]
    fn test_pattern_matching() {
        // 末尾ワイルドカード
        assert!(matches_pattern("@/tmp/.X11-unix/X0", "@/tmp/.X11-unix/*"));
        assert!(matches_pattern("@/tmp/.X11-unix/X100", "@/tmp/.X11-unix/*"));
        assert!(!matches_pattern("@/tmp/.X11-unix", "@/tmp/.X11-unix/*"));

        // 中間ワイルドカード（prefix-*-suffix のようなケース）
        assert!(matches_pattern("@/run/dbus-abcdef", "@/run/dbus-*"));
        assert!(matches_pattern("@/run/dbus-12345", "@/run/dbus-*"));
        assert!(!matches_pattern("@/run/other-abcdef", "@/run/dbus-*"));

        // 完全一致
        assert!(matches_pattern("@/run/exact", "@/run/exact"));
        assert!(!matches_pattern("@/run/exact-extra", "@/run/exact"));

        // 中間 * のマッチ
        assert!(matches_pattern("@/run/user/1000/bus", "@/run/user/*/bus"));
        assert!(!matches_pattern(
            "@/run/user/1000/notbus",
            "@/run/user/*/bus"
        ));
    }

    #[test]
    fn test_detect_unknown_socket() {
        let baseline = AbstractSocketSnapshot {
            sockets: HashMap::new(),
        };
        let mut current_sockets = HashMap::new();
        current_sockets.insert(
            "@/tmp/malware-c2".to_string(),
            AbstractSocketInfo {
                path: "@/tmp/malware-c2".to_string(),
                socket_type: "STREAM".to_string(),
                state: "unconnected".to_string(),
                inode: 100,
                ref_count: 1,
            },
        );
        let current = AbstractSocketSnapshot {
            sockets: current_sockets,
        };
        let allowed = vec!["@/run/systemd/*".to_string()];
        assert!(AbstractSocketMonitorModule::detect_and_report(
            &baseline, &current, &None, &allowed, 10,
        ));
    }

    #[test]
    fn test_detect_allowed_socket() {
        let baseline = AbstractSocketSnapshot {
            sockets: HashMap::new(),
        };
        let mut current_sockets = HashMap::new();
        current_sockets.insert(
            "@/run/systemd/notify".to_string(),
            AbstractSocketInfo {
                path: "@/run/systemd/notify".to_string(),
                socket_type: "DGRAM".to_string(),
                state: "unconnected".to_string(),
                inode: 200,
                ref_count: 2,
            },
        );
        let current = AbstractSocketSnapshot {
            sockets: current_sockets,
        };
        let allowed = vec!["@/run/systemd/*".to_string()];
        assert!(AbstractSocketMonitorModule::detect_and_report(
            &baseline, &current, &None, &allowed, 10,
        ));
    }

    #[test]
    fn test_detect_removed_socket() {
        let mut baseline_sockets = HashMap::new();
        baseline_sockets.insert(
            "@/tmp/old-socket".to_string(),
            AbstractSocketInfo {
                path: "@/tmp/old-socket".to_string(),
                socket_type: "STREAM".to_string(),
                state: "unconnected".to_string(),
                inode: 100,
                ref_count: 1,
            },
        );
        let baseline = AbstractSocketSnapshot {
            sockets: baseline_sockets,
        };
        let current = AbstractSocketSnapshot {
            sockets: HashMap::new(),
        };
        let allowed: Vec<String> = Vec::new();
        assert!(AbstractSocketMonitorModule::detect_and_report(
            &baseline, &current, &None, &allowed, 10,
        ));
    }

    #[test]
    fn test_detect_burst() {
        let baseline = AbstractSocketSnapshot {
            sockets: HashMap::new(),
        };
        let mut current_sockets = HashMap::new();
        // バースト閾値（3）を超える数のソケットを追加
        for i in 0..5 {
            let path = format!("@/tmp/burst-{}", i);
            current_sockets.insert(
                path.clone(),
                AbstractSocketInfo {
                    path,
                    socket_type: "STREAM".to_string(),
                    state: "unconnected".to_string(),
                    inode: 1000 + i,
                    ref_count: 1,
                },
            );
        }
        let current = AbstractSocketSnapshot {
            sockets: current_sockets,
        };
        let allowed: Vec<String> = Vec::new();
        // 閾値を 3 に設定して 5 個出現 → バースト検知
        assert!(AbstractSocketMonitorModule::detect_and_report(
            &baseline, &current, &None, &allowed, 3,
        ));
    }

    #[test]
    fn test_detect_no_changes() {
        let path = "@/run/systemd/notify".to_string();
        let info = AbstractSocketInfo {
            path: path.clone(),
            socket_type: "DGRAM".to_string(),
            state: "unconnected".to_string(),
            inode: 100,
            ref_count: 2,
        };

        let mut sockets = HashMap::new();
        sockets.insert(path, info);
        let baseline = AbstractSocketSnapshot {
            sockets: sockets.clone(),
        };
        let current = AbstractSocketSnapshot { sockets };
        let allowed: Vec<String> = Vec::new();
        assert!(!AbstractSocketMonitorModule::detect_and_report(
            &baseline, &current, &None, &allowed, 10,
        ));
    }

    #[test]
    fn test_init_zero_interval() {
        let dir = TempDir::new().unwrap();
        let config = AbstractSocketMonitorConfig {
            enabled: true,
            scan_interval_secs: 0,
            allowed_patterns: Vec::new(),
            burst_threshold: 10,
            proc_path: dir.path().to_string_lossy().to_string(),
        };
        let mut module = AbstractSocketMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let dir = TempDir::new().unwrap();
        let config = make_config(dir.path());
        let mut module = AbstractSocketMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let dir = TempDir::new().unwrap();
        write_proc_net_unix(dir.path(), SAMPLE_PROC_NET_UNIX);

        let config = AbstractSocketMonitorConfig {
            enabled: true,
            scan_interval_secs: 3600,
            allowed_patterns: vec!["@/tmp/.X11-unix/*".to_string()],
            burst_threshold: 10,
            proc_path: dir.path().to_string_lossy().to_string(),
        };
        let mut module = AbstractSocketMonitorModule::new(config, None);
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

        let config = AbstractSocketMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            allowed_patterns: vec!["@/tmp/.X11-unix/*".to_string(), "@/run/dbus-*".to_string()],
            burst_threshold: 10,
            proc_path: dir.path().to_string_lossy().to_string(),
        };
        let module = AbstractSocketMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        // 3 つの抽象ソケット（@/tmp/.X11-unix/X0, @/run/dbus-abcdef, @/tmp/suspicious-socket）
        assert_eq!(result.items_scanned, 3);
        // @/tmp/suspicious-socket は許可パターンに一致しないため問題として検出
        assert_eq!(result.issues_found, 1);
    }
}
