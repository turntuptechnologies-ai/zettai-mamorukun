//! eBPF プログラム監視モジュール
//!
//! `/proc/[pid]/fdinfo/[fd]` を走査し、BPF ファイルディスクリプタを検出する。
//! `prog_type` フィールドから eBPF プログラムの種別を識別し、
//! 不正な eBPF プログラムのロード（ルートキット、ネットワーク傍受等）を検知する。
//!
//! 検知対象:
//! - カーネルフック系 eBPF プログラム（kprobe, tracepoint, raw_tracepoint, lsm 等）→ Critical
//! - その他の新規 eBPF プログラム → Warning
//! - 許可リスト内のプログラム → Info（ログのみ）

use crate::config::EbpfMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use tokio_util::sync::CancellationToken;

/// eBPF プログラムの種別を表す prog_type の値
///
/// <https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/bpf.h>
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BpfProgInfo {
    /// プロセス ID
    pid: u32,
    /// ファイルディスクリプタ番号
    fd: u32,
    /// prog_type の数値
    prog_type: u32,
    /// prog_type の文字列表現
    prog_type_name: String,
    /// プロセス名（/proc/[pid]/comm から取得）
    comm: String,
}

/// prog_type の数値を文字列に変換する
fn prog_type_to_name(prog_type: u32) -> &'static str {
    match prog_type {
        0 => "unspec",
        1 => "socket_filter",
        2 => "kprobe",
        3 => "sched_cls",
        4 => "sched_act",
        5 => "tracepoint",
        6 => "xdp",
        7 => "perf_event",
        8 => "cgroup_skb",
        9 => "cgroup_sock",
        10 => "lwt_in",
        11 => "lwt_out",
        12 => "lwt_xmit",
        13 => "sock_ops",
        14 => "sk_skb",
        15 => "cgroup_device",
        16 => "sk_msg",
        17 => "raw_tracepoint",
        18 => "cgroup_sock_addr",
        19 => "lwt_seg6local",
        20 => "lirc_mode2",
        21 => "sk_reuseport",
        22 => "flow_dissector",
        23 => "cgroup_sysctl",
        24 => "raw_tracepoint_writable",
        25 => "cgroup_sockopt",
        26 => "tracing",
        27 => "struct_ops",
        28 => "ext",
        29 => "lsm",
        30 => "sk_lookup",
        31 => "syscall",
        _ => "unknown",
    }
}

/// カーネルフック系の prog_type かどうかを判定する
///
/// これらの種別はカーネルの内部動作に直接フックするため、
/// 攻撃者がルートキットやカーネル改ざんに悪用するリスクが高い。
fn is_kernel_hook_type(prog_type: u32) -> bool {
    matches!(
        prog_type,
        2  // kprobe
        | 5  // tracepoint
        | 7  // perf_event
        | 17 // raw_tracepoint
        | 24 // raw_tracepoint_writable
        | 26 // tracing
        | 29 // lsm
    )
}

/// /proc/[pid]/comm からプロセス名を読み取る
fn read_comm(proc_path: &Path, pid: u32) -> String {
    let comm_path = proc_path.join(format!("{}/comm", pid));
    match std::fs::read_to_string(&comm_path) {
        Ok(content) => content.trim().to_string(),
        Err(_) => "(unknown)".to_string(),
    }
}

/// /proc/[pid]/fdinfo/[fd] から BPF 関連のプログラム情報を解析する
fn parse_fdinfo_for_bpf(content: &str) -> Option<u32> {
    for line in content.lines() {
        if let Some(value) = line.strip_prefix("prog_type:")
            && let Ok(prog_type) = value.trim().parse::<u32>()
        {
            return Some(prog_type);
        }
    }
    None
}

/// システム全体の eBPF プログラムスナップショットを取得する
fn scan_ebpf_programs(proc_path: &Path) -> Vec<BpfProgInfo> {
    let mut programs = Vec::new();

    let proc_dir = match std::fs::read_dir(proc_path) {
        Ok(dir) => dir,
        Err(e) => {
            tracing::debug!(error = %e, "proc ディレクトリの読み取りに失敗");
            return programs;
        }
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // 数値ディレクトリ（PID）のみ対象
        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let fdinfo_dir = proc_path.join(format!("{}/fdinfo", pid));
        let fd_entries = match std::fs::read_dir(&fdinfo_dir) {
            Ok(dir) => dir,
            Err(_) => continue,
        };

        for fd_entry in fd_entries.flatten() {
            let fd_name = fd_entry.file_name();
            let fd_str = fd_name.to_string_lossy();
            let fd_num: u32 = match fd_str.parse() {
                Ok(f) => f,
                Err(_) => continue,
            };

            let fdinfo_path = fdinfo_dir.join(&fd_name);
            let content = match std::fs::read_to_string(&fdinfo_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            if let Some(prog_type) = parse_fdinfo_for_bpf(&content) {
                let comm = read_comm(proc_path, pid);
                programs.push(BpfProgInfo {
                    pid,
                    fd: fd_num,
                    prog_type,
                    prog_type_name: prog_type_to_name(prog_type).to_string(),
                    comm,
                });
            }
        }
    }

    programs
}

/// eBPF プログラム監視モジュール
///
/// `/proc/[pid]/fdinfo/[fd]` を定期スキャンし、
/// eBPF プログラムのロード・アンロードを検知する。
pub struct EbpfMonitorModule {
    config: EbpfMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl EbpfMonitorModule {
    /// 新しい eBPF プログラム監視モジュールを作成する
    pub fn new(config: EbpfMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// 検知した eBPF プログラムを評価し、イベントを発行する
    fn evaluate_and_report(
        programs: &[BpfProgInfo],
        previous: &HashMap<(u32, u32), BpfProgInfo>,
        allowed_programs: &[String],
        event_bus: &Option<EventBus>,
    ) -> bool {
        let mut has_new = false;

        for prog in programs {
            let key = (prog.pid, prog.fd);
            if previous.contains_key(&key) {
                continue;
            }

            has_new = true;

            // 許可リストチェック
            if allowed_programs.contains(&prog.comm) {
                tracing::info!(
                    pid = prog.pid,
                    fd = prog.fd,
                    prog_type = prog.prog_type,
                    prog_type_name = %prog.prog_type_name,
                    comm = %prog.comm,
                    "許可リスト内の eBPF プログラムを検出"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "ebpf_program_allowed",
                            Severity::Info,
                            "ebpf_monitor",
                            format!(
                                "許可リスト内の eBPF プログラムを検出: {} ({})",
                                prog.comm, prog.prog_type_name
                            ),
                        )
                        .with_details(format!(
                            "pid={}, fd={}, prog_type={} ({}), comm={}",
                            prog.pid, prog.fd, prog.prog_type, prog.prog_type_name, prog.comm
                        )),
                    );
                }
                continue;
            }

            // カーネルフック系の判定
            let (severity, event_type, message) = if is_kernel_hook_type(prog.prog_type) {
                (
                    Severity::Critical,
                    "ebpf_kernel_hook_detected",
                    format!(
                        "カーネルフック系 eBPF プログラムを検知: {} (prog_type={})",
                        prog.comm, prog.prog_type_name
                    ),
                )
            } else {
                (
                    Severity::Warning,
                    "ebpf_program_detected",
                    format!(
                        "新規 eBPF プログラムを検知: {} (prog_type={})",
                        prog.comm, prog.prog_type_name
                    ),
                )
            };

            tracing::warn!(
                pid = prog.pid,
                fd = prog.fd,
                prog_type = prog.prog_type,
                prog_type_name = %prog.prog_type_name,
                comm = %prog.comm,
                severity = ?severity,
                "{}",
                message
            );

            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(event_type, severity, "ebpf_monitor", &message)
                        .with_details(format!(
                            "pid={}, fd={}, prog_type={} ({}), comm={}",
                            prog.pid, prog.fd, prog.prog_type, prog.prog_type_name, prog.comm
                        )),
                );
            }
        }

        has_new
    }
}

impl Module for EbpfMonitorModule {
    fn name(&self) -> &str {
        "ebpf_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            proc_path = %self.config.proc_path,
            allowed_programs = ?self.config.allowed_programs,
            "eBPF プログラム監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<(), AppError> {
        let proc_path = self.config.proc_path.clone();
        let scan_interval_secs = self.config.scan_interval_secs;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();
        let allowed_programs = self.config.allowed_programs.clone();

        let initial_programs = scan_ebpf_programs(Path::new(&proc_path));
        let mut known: HashMap<(u32, u32), BpfProgInfo> = initial_programs
            .into_iter()
            .map(|p| ((p.pid, p.fd), p))
            .collect();

        tracing::info!(
            known_programs = known.len(),
            "eBPF プログラムベースラインスキャンが完了しました"
        );

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("eBPF プログラム監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = scan_ebpf_programs(Path::new(&proc_path));
                        let changed = Self::evaluate_and_report(
                            &current, &known, &allowed_programs, &event_bus,
                        );

                        if changed {
                            // 既知リストを更新
                            known = current
                                .into_iter()
                                .map(|p| ((p.pid, p.fd), p))
                                .collect();
                        } else {
                            tracing::debug!("eBPF プログラムに変更はありません");
                        }
                    }
                }
            }
        });

        Ok(())
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();
        let proc_path = Path::new(&self.config.proc_path);
        let programs = scan_ebpf_programs(proc_path);

        let items_scanned = programs.len();
        let mut issues_found = 0;
        let mut scan_snapshot: BTreeMap<String, String> = BTreeMap::new();

        for prog in &programs {
            let key = format!("ebpf:pid{}:fd{}", prog.pid, prog.fd);
            let value = format!(
                "prog_type={} ({}), comm={}",
                prog.prog_type, prog.prog_type_name, prog.comm
            );
            scan_snapshot.insert(key, value);

            // 許可リスト外のカーネルフック系は問題としてカウント
            let is_allowed = self.config.allowed_programs.contains(&prog.comm);

            if !is_allowed && is_kernel_hook_type(prog.prog_type) {
                tracing::warn!(
                    pid = prog.pid,
                    fd = prog.fd,
                    prog_type = prog.prog_type,
                    prog_type_name = %prog.prog_type_name,
                    comm = %prog.comm,
                    "起動時スキャン: カーネルフック系 eBPF プログラムを検出"
                );
                if let Some(bus) = &self.event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "ebpf_startup_kernel_hook",
                            Severity::Critical,
                            "ebpf_monitor",
                            format!(
                                "起動時スキャン: カーネルフック系 eBPF プログラムを検出: {} ({})",
                                prog.comm, prog.prog_type_name
                            ),
                        )
                        .with_details(format!(
                            "pid={}, fd={}, prog_type={} ({}), comm={}",
                            prog.pid, prog.fd, prog.prog_type, prog.prog_type_name, prog.comm
                        )),
                    );
                }
                issues_found += 1;
            } else if !is_allowed {
                tracing::info!(
                    pid = prog.pid,
                    fd = prog.fd,
                    prog_type = prog.prog_type,
                    prog_type_name = %prog.prog_type_name,
                    comm = %prog.comm,
                    "起動時スキャン: eBPF プログラムを検出"
                );
            }
        }

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "eBPF プログラム {}件をスキャン（うち{}件が要注意）",
                items_scanned, issues_found
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
    use tempfile::TempDir;

    fn create_proc_structure(dir: &TempDir, pid: u32, comm: &str, fds: &[(u32, &str)]) {
        // /proc/[pid]/comm
        let comm_path = dir.path().join(format!("{}/comm", pid));
        if let Some(parent) = comm_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&comm_path, format!("{}\n", comm)).unwrap();

        // /proc/[pid]/fdinfo/[fd]
        let fdinfo_dir = dir.path().join(format!("{}/fdinfo", pid));
        std::fs::create_dir_all(&fdinfo_dir).unwrap();
        for (fd, content) in fds {
            std::fs::write(fdinfo_dir.join(fd.to_string()), content).unwrap();
        }
    }

    fn default_config_with_path(proc_path: &str) -> EbpfMonitorConfig {
        EbpfMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            proc_path: proc_path.to_string(),
            allowed_programs: vec![],
        }
    }

    #[test]
    fn test_prog_type_to_name() {
        assert_eq!(prog_type_to_name(0), "unspec");
        assert_eq!(prog_type_to_name(2), "kprobe");
        assert_eq!(prog_type_to_name(5), "tracepoint");
        assert_eq!(prog_type_to_name(6), "xdp");
        assert_eq!(prog_type_to_name(29), "lsm");
        assert_eq!(prog_type_to_name(999), "unknown");
    }

    #[test]
    fn test_is_kernel_hook_type() {
        assert!(is_kernel_hook_type(2)); // kprobe
        assert!(is_kernel_hook_type(5)); // tracepoint
        assert!(is_kernel_hook_type(7)); // perf_event
        assert!(is_kernel_hook_type(17)); // raw_tracepoint
        assert!(is_kernel_hook_type(26)); // tracing
        assert!(is_kernel_hook_type(29)); // lsm
        assert!(!is_kernel_hook_type(1)); // socket_filter
        assert!(!is_kernel_hook_type(6)); // xdp
        assert!(!is_kernel_hook_type(0)); // unspec
    }

    #[test]
    fn test_parse_fdinfo_for_bpf() {
        let content = "pos:\t0\nflags:\t02000002\nmnt_id:\t15\nprog_type:\t2\nprog_jited:\t1\n";
        assert_eq!(parse_fdinfo_for_bpf(content), Some(2));
    }

    #[test]
    fn test_parse_fdinfo_non_bpf() {
        let content = "pos:\t0\nflags:\t02000002\nmnt_id:\t15\n";
        assert_eq!(parse_fdinfo_for_bpf(content), None);
    }

    #[test]
    fn test_parse_fdinfo_invalid_prog_type() {
        let content = "prog_type:\tabc\n";
        assert_eq!(parse_fdinfo_for_bpf(content), None);
    }

    #[test]
    fn test_scan_ebpf_programs() {
        let dir = TempDir::new().unwrap();
        create_proc_structure(
            &dir,
            1234,
            "bpftrace",
            &[
                (3, "pos:\t0\nflags:\t02\nprog_type:\t2\nprog_jited:\t1\n"),
                (4, "pos:\t0\nflags:\t02\nmnt_id:\t15\n"), // non-BPF
            ],
        );

        let programs = scan_ebpf_programs(dir.path());
        assert_eq!(programs.len(), 1);
        assert_eq!(programs[0].pid, 1234);
        assert_eq!(programs[0].fd, 3);
        assert_eq!(programs[0].prog_type, 2);
        assert_eq!(programs[0].prog_type_name, "kprobe");
        assert_eq!(programs[0].comm, "bpftrace");
    }

    #[test]
    fn test_scan_empty_proc() {
        let dir = TempDir::new().unwrap();
        let programs = scan_ebpf_programs(dir.path());
        assert!(programs.is_empty());
    }

    #[test]
    fn test_evaluate_no_changes() {
        let programs = vec![BpfProgInfo {
            pid: 100,
            fd: 3,
            prog_type: 1,
            prog_type_name: "socket_filter".to_string(),
            comm: "test".to_string(),
        }];
        let mut previous = HashMap::new();
        previous.insert((100u32, 3u32), programs[0].clone());

        assert!(!EbpfMonitorModule::evaluate_and_report(
            &programs,
            &previous,
            &[],
            &None,
        ));
    }

    #[test]
    fn test_evaluate_new_program() {
        let programs = vec![BpfProgInfo {
            pid: 100,
            fd: 3,
            prog_type: 1,
            prog_type_name: "socket_filter".to_string(),
            comm: "test".to_string(),
        }];
        let previous = HashMap::new();

        assert!(EbpfMonitorModule::evaluate_and_report(
            &programs,
            &previous,
            &[],
            &None,
        ));
    }

    #[test]
    fn test_evaluate_allowed_program() {
        let programs = vec![BpfProgInfo {
            pid: 100,
            fd: 3,
            prog_type: 2,
            prog_type_name: "kprobe".to_string(),
            comm: "bpftrace".to_string(),
        }];
        let previous = HashMap::new();

        // 許可リストに含まれていても新規検知は true
        assert!(EbpfMonitorModule::evaluate_and_report(
            &programs,
            &previous,
            &["bpftrace".to_string()],
            &None,
        ));
    }

    #[test]
    fn test_evaluate_kernel_hook_type() {
        let programs = vec![BpfProgInfo {
            pid: 100,
            fd: 3,
            prog_type: 2, // kprobe
            prog_type_name: "kprobe".to_string(),
            comm: "suspicious".to_string(),
        }];
        let previous = HashMap::new();

        assert!(EbpfMonitorModule::evaluate_and_report(
            &programs,
            &previous,
            &[],
            &None,
        ));
    }

    #[test]
    fn test_read_comm() {
        let dir = TempDir::new().unwrap();
        let pid_dir = dir.path().join("1234");
        std::fs::create_dir_all(&pid_dir).unwrap();
        std::fs::write(pid_dir.join("comm"), "myprocess\n").unwrap();

        assert_eq!(read_comm(dir.path(), 1234), "myprocess");
    }

    #[test]
    fn test_read_comm_nonexistent() {
        let dir = TempDir::new().unwrap();
        assert_eq!(read_comm(dir.path(), 9999), "(unknown)");
    }

    #[test]
    fn test_init_valid() {
        let dir = TempDir::new().unwrap();
        let config = default_config_with_path(dir.path().to_str().unwrap());
        let mut module = EbpfMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[test]
    fn test_init_zero_interval() {
        let mut config = EbpfMonitorConfig::default();
        config.scan_interval_secs = 0;
        let mut module = EbpfMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let dir = TempDir::new().unwrap();
        let config = default_config_with_path(dir.path().to_str().unwrap());
        let mut module = EbpfMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan_empty() {
        let dir = TempDir::new().unwrap();
        let config = default_config_with_path(dir.path().to_str().unwrap());
        let module = EbpfMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
        assert!(result.summary.contains("eBPF"));
    }

    #[tokio::test]
    async fn test_initial_scan_detects_kernel_hook() {
        let dir = TempDir::new().unwrap();
        create_proc_structure(
            &dir,
            1234,
            "suspicious",
            &[(3, "pos:\t0\nprog_type:\t2\n")], // kprobe
        );

        let config = default_config_with_path(dir.path().to_str().unwrap());
        let module = EbpfMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 1);
        assert_eq!(result.issues_found, 1);
    }

    #[tokio::test]
    async fn test_initial_scan_allowed_program_not_issue() {
        let dir = TempDir::new().unwrap();
        create_proc_structure(
            &dir,
            1234,
            "bpftrace",
            &[(3, "pos:\t0\nprog_type:\t2\n")], // kprobe but allowed
        );

        let mut config = default_config_with_path(dir.path().to_str().unwrap());
        config.allowed_programs = vec!["bpftrace".to_string()];
        let module = EbpfMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 1);
        assert_eq!(result.issues_found, 0); // allowed なので問題なし
    }

    #[tokio::test]
    async fn test_initial_scan_non_kernel_hook_no_issue() {
        let dir = TempDir::new().unwrap();
        create_proc_structure(
            &dir,
            1234,
            "myapp",
            &[(3, "pos:\t0\nprog_type:\t1\n")], // socket_filter
        );

        let config = default_config_with_path(dir.path().to_str().unwrap());
        let module = EbpfMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 1);
        assert_eq!(result.issues_found, 0); // socket_filter はカーネルフック系ではない
    }

    #[test]
    fn test_multiple_programs_multiple_pids() {
        let dir = TempDir::new().unwrap();
        create_proc_structure(&dir, 100, "prog_a", &[(3, "pos:\t0\nprog_type:\t2\n")]);
        create_proc_structure(&dir, 200, "prog_b", &[(5, "pos:\t0\nprog_type:\t6\n")]);

        let programs = scan_ebpf_programs(dir.path());
        assert_eq!(programs.len(), 2);
    }
}
