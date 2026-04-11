//! Linux capabilities 監視モジュール
//!
//! `/proc/*/status` の CapEff/CapPrm フィールドを定期スキャンし、
//! 危険な capabilities を持つプロセスを検知する。
//!
//! 検知対象:
//! - 危険な capabilities を持つ新規プロセスの出現
//! - 既存プロセスの capabilities 変化（特権昇格の兆候）
//! - 通常は capabilities を持たないプロセスの取得

use crate::config::CapabilitiesMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;
use tokio_util::sync::CancellationToken;

/// 既知の Linux capabilities 名（ビット番号順）
const CAP_NAMES: &[(u8, &str)] = &[
    (0, "CAP_CHOWN"),
    (1, "CAP_DAC_OVERRIDE"),
    (2, "CAP_DAC_READ_SEARCH"),
    (3, "CAP_FOWNER"),
    (4, "CAP_FSETID"),
    (5, "CAP_KILL"),
    (6, "CAP_SETGID"),
    (7, "CAP_SETUID"),
    (8, "CAP_SETPCAP"),
    (9, "CAP_LINUX_IMMUTABLE"),
    (10, "CAP_NET_BIND_SERVICE"),
    (11, "CAP_NET_BROADCAST"),
    (12, "CAP_NET_ADMIN"),
    (13, "CAP_NET_RAW"),
    (14, "CAP_IPC_LOCK"),
    (15, "CAP_IPC_OWNER"),
    (16, "CAP_SYS_MODULE"),
    (17, "CAP_SYS_RAWIO"),
    (18, "CAP_SYS_CHROOT"),
    (19, "CAP_SYS_PTRACE"),
    (20, "CAP_SYS_PACCT"),
    (21, "CAP_SYS_ADMIN"),
    (22, "CAP_SYS_BOOT"),
    (23, "CAP_SYS_NICE"),
    (24, "CAP_SYS_RESOURCE"),
    (25, "CAP_SYS_TIME"),
    (26, "CAP_SYS_TTY_CONFIG"),
    (27, "CAP_MKNOD"),
    (28, "CAP_LEASE"),
    (29, "CAP_AUDIT_WRITE"),
    (30, "CAP_AUDIT_CONTROL"),
    (31, "CAP_SETFCAP"),
    (36, "CAP_MAC_OVERRIDE"),
    (37, "CAP_MAC_ADMIN"),
    (38, "CAP_SYSLOG"),
    (39, "CAP_WAKE_ALARM"),
    (40, "CAP_BLOCK_SUSPEND"),
    (41, "CAP_AUDIT_READ"),
    (42, "CAP_PERFMON"),
    (43, "CAP_BPF"),
    (44, "CAP_CHECKPOINT_RESTORE"),
];

/// デフォルトの危険な capabilities（ビット番号）
#[cfg(test)]
const DEFAULT_DANGEROUS_CAPS: &[u8] = &[
    1,  // CAP_DAC_OVERRIDE
    6,  // CAP_SETGID
    7,  // CAP_SETUID
    12, // CAP_NET_ADMIN
    13, // CAP_NET_RAW
    16, // CAP_SYS_MODULE
    19, // CAP_SYS_PTRACE
    21, // CAP_SYS_ADMIN
];

/// プロセスの capabilities 情報
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessCapInfo {
    /// プロセス ID
    pid: u32,
    /// プロセス名
    name: String,
    /// 実効 capabilities（ビットマスク）
    cap_eff: u64,
    /// 許可 capabilities（ビットマスク）
    cap_prm: u64,
}

/// capabilities のスナップショット（PID → 情報）
struct CapabilitiesSnapshot {
    processes: BTreeMap<u32, ProcessCapInfo>,
}

/// capabilities のビット番号から名前を返す
fn cap_name(bit: u8) -> &'static str {
    for &(b, name) in CAP_NAMES {
        if b == bit {
            return name;
        }
    }
    "UNKNOWN"
}

/// ビットマスクから設定されている capabilities のビット番号リストを返す
#[cfg(test)]
fn caps_from_mask(mask: u64) -> Vec<u8> {
    let mut caps = Vec::new();
    for bit in 0..64 {
        if mask & (1u64 << bit) != 0 {
            caps.push(bit);
        }
    }
    caps
}

/// ビットマスクと危険リストから一致する capabilities 名のリストを返す
fn dangerous_caps_in_mask(mask: u64, dangerous: &[u8]) -> Vec<String> {
    let mut result = Vec::new();
    for &bit in dangerous {
        if mask & (1u64 << bit) != 0 {
            result.push(cap_name(bit).to_string());
        }
    }
    result
}

/// 16進数文字列から u64 にパースする
fn parse_hex_caps(hex: &str) -> Option<u64> {
    u64::from_str_radix(hex.trim(), 16).ok()
}

/// `/proc/{pid}/status` からプロセス名と capabilities をパースする
fn parse_proc_status(content: &str) -> Option<(String, u64, u64)> {
    let mut name = None;
    let mut cap_eff = None;
    let mut cap_prm = None;

    for line in content.lines() {
        if let Some(val) = line.strip_prefix("Name:\t") {
            name = Some(val.trim().to_string());
        } else if let Some(val) = line.strip_prefix("CapEff:\t") {
            cap_eff = parse_hex_caps(val);
        } else if let Some(val) = line.strip_prefix("CapPrm:\t") {
            cap_prm = parse_hex_caps(val);
        }
    }

    match (name, cap_eff, cap_prm) {
        (Some(n), Some(e), Some(p)) => Some((n, e, p)),
        _ => None,
    }
}

/// Linux capabilities 監視モジュール
///
/// `/proc/*/status` を定期スキャンし、危険な capabilities を持つプロセスを検知する。
pub struct CapabilitiesMonitorModule {
    config: CapabilitiesMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl CapabilitiesMonitorModule {
    /// 新しい capabilities 監視モジュールを作成する
    pub fn new(config: CapabilitiesMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// /proc を走査して capabilities のスナップショットを取得する
    fn scan_proc(
        proc_path: &Path,
        dangerous_caps: &[u8],
        whitelist: &[String],
    ) -> CapabilitiesSnapshot {
        let mut processes = BTreeMap::new();

        let entries = match std::fs::read_dir(proc_path) {
            Ok(entries) => entries,
            Err(err) => {
                tracing::debug!(error = %err, "proc ディレクトリの読み取りに失敗しました");
                return CapabilitiesSnapshot { processes };
            }
        };

        for entry in entries.filter_map(|e| e.ok()) {
            let file_name = entry.file_name();
            let pid_str = file_name.to_string_lossy();

            // 数値ディレクトリ（PID）のみ処理
            let pid: u32 = match pid_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            let status_path = proc_path.join(pid_str.to_string()).join("status");
            let content = match std::fs::read_to_string(&status_path) {
                Ok(c) => c,
                Err(_) => continue, // プロセスが終了した可能性
            };

            let (name, cap_eff, cap_prm) = match parse_proc_status(&content) {
                Some(parsed) => parsed,
                None => continue,
            };

            // ホワイトリストチェック
            if whitelist.contains(&name) {
                continue;
            }

            // 危険な capabilities を持つプロセスのみ記録
            let dangerous_mask: u64 = dangerous_caps
                .iter()
                .fold(0u64, |acc, &bit| acc | (1u64 << bit));

            if (cap_eff & dangerous_mask) != 0 || (cap_prm & dangerous_mask) != 0 {
                processes.insert(
                    pid,
                    ProcessCapInfo {
                        pid,
                        name,
                        cap_eff,
                        cap_prm,
                    },
                );
            }
        }

        CapabilitiesSnapshot { processes }
    }

    /// ベースラインと現在のスナップショットを比較し、変更を検知してイベント発行する
    fn detect_and_report(
        baseline: &CapabilitiesSnapshot,
        current: &CapabilitiesSnapshot,
        dangerous_caps: &[u8],
        event_bus: &Option<EventBus>,
    ) -> bool {
        let mut has_changes = false;

        // 新規プロセスの検知（同名プロセスがベースラインにない場合）
        for (pid, info) in &current.processes {
            let is_known = baseline.processes.values().any(|b| b.name == info.name);

            if !is_known {
                let dangerous = dangerous_caps_in_mask(info.cap_eff | info.cap_prm, dangerous_caps);
                let details = format!(
                    "PID={}, プロセス={}, 危険な capabilities: {}",
                    pid,
                    info.name,
                    dangerous.join(", ")
                );
                tracing::warn!(
                    pid = pid,
                    process = %info.name,
                    capabilities = ?dangerous,
                    "危険な capabilities を持つ新規プロセスを検知しました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "capabilities_new_process",
                            Severity::Critical,
                            "capabilities_monitor",
                            "危険な capabilities を持つ新規プロセスを検知しました",
                        )
                        .with_details(details),
                    );
                }
                has_changes = true;
            }
        }

        // 既存プロセスの capabilities 変化検知
        for (pid, current_info) in &current.processes {
            if let Some(baseline_info) = baseline
                .processes
                .values()
                .find(|b| b.name == current_info.name)
            {
                // capabilities が変化した場合
                if baseline_info.cap_eff != current_info.cap_eff
                    || baseline_info.cap_prm != current_info.cap_prm
                {
                    let new_dangerous = dangerous_caps_in_mask(
                        current_info.cap_eff | current_info.cap_prm,
                        dangerous_caps,
                    );
                    let details = format!(
                        "PID={}, プロセス={}, 変更された capabilities: {}",
                        pid,
                        current_info.name,
                        new_dangerous.join(", ")
                    );
                    tracing::warn!(
                        pid = pid,
                        process = %current_info.name,
                        old_cap_eff = format!("{:016x}", baseline_info.cap_eff),
                        new_cap_eff = format!("{:016x}", current_info.cap_eff),
                        "プロセスの capabilities が変化しました（特権昇格の可能性）"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "capabilities_changed",
                                Severity::Critical,
                                "capabilities_monitor",
                                "プロセスの capabilities が変化しました（特権昇格の可能性）",
                            )
                            .with_details(details),
                        );
                    }
                    has_changes = true;
                }
            }
        }

        has_changes
    }
}

impl Module for CapabilitiesMonitorModule {
    fn name(&self) -> &str {
        "capabilities_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            dangerous_caps_count = self.config.dangerous_caps.len(),
            whitelist_count = self.config.whitelist_processes.len(),
            "capabilities 監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        let baseline = Self::scan_proc(
            Path::new("/proc"),
            &self.config.dangerous_caps,
            &self.config.whitelist_processes,
        );
        tracing::info!(
            process_count = baseline.processes.len(),
            "capabilities ベースラインスキャンが完了しました"
        );

        let dangerous_caps = self.config.dangerous_caps.clone();
        let whitelist = self.config.whitelist_processes.clone();
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
                        tracing::info!("capabilities 監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = CapabilitiesMonitorModule::scan_proc(
                            Path::new("/proc"),
                            &dangerous_caps,
                            &whitelist,
                        );
                        let changed = CapabilitiesMonitorModule::detect_and_report(
                            &baseline, &current, &dangerous_caps, &event_bus,
                        );

                        if changed {
                            baseline = current;
                        } else {
                            tracing::debug!("capabilities に変更はありません");
                        }
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();
        let snapshot = Self::scan_proc(
            Path::new("/proc"),
            &self.config.dangerous_caps,
            &self.config.whitelist_processes,
        );

        let items_scanned = snapshot.processes.len();
        let mut issues_found = 0;

        // 危険な capabilities を持つプロセスを警告
        for info in snapshot.processes.values() {
            let dangerous =
                dangerous_caps_in_mask(info.cap_eff | info.cap_prm, &self.config.dangerous_caps);
            if !dangerous.is_empty() {
                tracing::warn!(
                    pid = info.pid,
                    process = %info.name,
                    capabilities = ?dangerous,
                    "起動時スキャン: 危険な capabilities を持つプロセスを検出"
                );
                if let Some(bus) = &self.event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "capabilities_startup_detected",
                            Severity::Warning,
                            "capabilities_monitor",
                            "起動時スキャン: 危険な capabilities を持つプロセスを検出",
                        )
                        .with_details(format!(
                            "PID={}, プロセス={}, capabilities: {}",
                            info.pid,
                            info.name,
                            dangerous.join(", ")
                        )),
                    );
                }
                issues_found += 1;
            }
        }

        let scan_snapshot: BTreeMap<String, String> = snapshot
            .processes
            .iter()
            .map(|(pid, info)| {
                let mut desc = String::new();
                let _ = write!(
                    desc,
                    "name={},cap_eff={:016x},cap_prm={:016x}",
                    info.name, info.cap_eff, info.cap_prm
                );
                (pid.to_string(), desc)
            })
            .collect();
        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "危険な capabilities を持つプロセス {}件を検出（うち{}件が要注意）",
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

    #[test]
    fn test_parse_hex_caps_valid() {
        assert_eq!(parse_hex_caps("0000000000000000"), Some(0));
        assert_eq!(parse_hex_caps("0000003fffffffff"), Some(0x0000003fffffffff));
        assert_eq!(parse_hex_caps("00000000a80c25fb"), Some(0x00000000a80c25fb));
    }

    #[test]
    fn test_parse_hex_caps_invalid() {
        assert_eq!(parse_hex_caps("not_hex"), None);
        assert_eq!(parse_hex_caps(""), None);
    }

    #[test]
    fn test_parse_hex_caps_trimmed() {
        assert_eq!(parse_hex_caps("  0000000000000001  "), Some(1));
    }

    #[test]
    fn test_parse_proc_status_valid() {
        let content = "Name:\tsshd\nUmask:\t0022\nState:\tS (sleeping)\n\
                        Tgid:\t1234\nPid:\t1234\nCapInh:\t0000000000000000\n\
                        CapPrm:\t000001ffffffffff\nCapEff:\t000001ffffffffff\n\
                        CapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\n";
        let result = parse_proc_status(content);
        assert!(result.is_some());
        let (name, cap_eff, cap_prm) = result.unwrap();
        assert_eq!(name, "sshd");
        assert_eq!(cap_eff, 0x000001ffffffffff);
        assert_eq!(cap_prm, 0x000001ffffffffff);
    }

    #[test]
    fn test_parse_proc_status_missing_fields() {
        let content = "Name:\tsshd\nPid:\t1234\n";
        assert!(parse_proc_status(content).is_none());
    }

    #[test]
    fn test_parse_proc_status_empty() {
        assert!(parse_proc_status("").is_none());
    }

    #[test]
    fn test_cap_name_known() {
        assert_eq!(cap_name(0), "CAP_CHOWN");
        assert_eq!(cap_name(21), "CAP_SYS_ADMIN");
        assert_eq!(cap_name(13), "CAP_NET_RAW");
        assert_eq!(cap_name(7), "CAP_SETUID");
    }

    #[test]
    fn test_cap_name_unknown() {
        assert_eq!(cap_name(63), "UNKNOWN");
        assert_eq!(cap_name(50), "UNKNOWN");
    }

    #[test]
    fn test_caps_from_mask() {
        // CAP_SYS_ADMIN (21) のみ
        let caps = caps_from_mask(1u64 << 21);
        assert_eq!(caps, vec![21]);

        // 複数の capabilities
        let mask = (1u64 << 7) | (1u64 << 21); // CAP_SETUID + CAP_SYS_ADMIN
        let caps = caps_from_mask(mask);
        assert_eq!(caps, vec![7, 21]);

        // 空のマスク
        let caps = caps_from_mask(0);
        assert!(caps.is_empty());
    }

    #[test]
    fn test_dangerous_caps_in_mask() {
        let dangerous = vec![7, 21]; // CAP_SETUID, CAP_SYS_ADMIN
        let mask = (1u64 << 7) | (1u64 << 21) | (1u64 << 0); // SETUID + SYS_ADMIN + CHOWN

        let result = dangerous_caps_in_mask(mask, &dangerous);
        assert_eq!(result.len(), 2);
        assert!(result.contains(&"CAP_SETUID".to_string()));
        assert!(result.contains(&"CAP_SYS_ADMIN".to_string()));
    }

    #[test]
    fn test_dangerous_caps_in_mask_none() {
        let dangerous = vec![21]; // CAP_SYS_ADMIN のみ
        let mask = 1u64 << 0; // CAP_CHOWN のみ

        let result = dangerous_caps_in_mask(mask, &dangerous);
        assert!(result.is_empty());
    }

    #[test]
    fn test_detect_no_changes() {
        let mut processes = BTreeMap::new();
        processes.insert(
            100,
            ProcessCapInfo {
                pid: 100,
                name: "test_proc".to_string(),
                cap_eff: 1u64 << 21,
                cap_prm: 1u64 << 21,
            },
        );
        let baseline = CapabilitiesSnapshot {
            processes: processes.clone(),
        };
        let current = CapabilitiesSnapshot { processes };

        assert!(!CapabilitiesMonitorModule::detect_and_report(
            &baseline,
            &current,
            DEFAULT_DANGEROUS_CAPS,
            &None,
        ));
    }

    #[test]
    fn test_detect_new_process() {
        let baseline = CapabilitiesSnapshot {
            processes: BTreeMap::new(),
        };
        let mut current_procs = BTreeMap::new();
        current_procs.insert(
            200,
            ProcessCapInfo {
                pid: 200,
                name: "evil_proc".to_string(),
                cap_eff: 1u64 << 21,
                cap_prm: 1u64 << 21,
            },
        );
        let current = CapabilitiesSnapshot {
            processes: current_procs,
        };

        assert!(CapabilitiesMonitorModule::detect_and_report(
            &baseline,
            &current,
            DEFAULT_DANGEROUS_CAPS,
            &None,
        ));
    }

    #[test]
    fn test_detect_capabilities_changed() {
        let mut baseline_procs = BTreeMap::new();
        baseline_procs.insert(
            100,
            ProcessCapInfo {
                pid: 100,
                name: "some_proc".to_string(),
                cap_eff: 0,
                cap_prm: 0,
            },
        );
        let baseline = CapabilitiesSnapshot {
            processes: baseline_procs,
        };

        let mut current_procs = BTreeMap::new();
        current_procs.insert(
            100,
            ProcessCapInfo {
                pid: 100,
                name: "some_proc".to_string(),
                cap_eff: 1u64 << 21, // CAP_SYS_ADMIN 取得
                cap_prm: 1u64 << 21,
            },
        );
        let current = CapabilitiesSnapshot {
            processes: current_procs,
        };

        assert!(CapabilitiesMonitorModule::detect_and_report(
            &baseline,
            &current,
            DEFAULT_DANGEROUS_CAPS,
            &None,
        ));
    }

    #[test]
    fn test_init_zero_interval() {
        let config = CapabilitiesMonitorConfig {
            enabled: true,
            scan_interval_secs: 0,
            dangerous_caps: DEFAULT_DANGEROUS_CAPS.to_vec(),
            whitelist_processes: vec![],
        };
        let mut module = CapabilitiesMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let config = CapabilitiesMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            dangerous_caps: DEFAULT_DANGEROUS_CAPS.to_vec(),
            whitelist_processes: vec!["systemd".to_string()],
        };
        let mut module = CapabilitiesMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let config = CapabilitiesMonitorConfig {
            enabled: true,
            scan_interval_secs: 3600,
            dangerous_caps: DEFAULT_DANGEROUS_CAPS.to_vec(),
            whitelist_processes: vec![],
        };
        let mut module = CapabilitiesMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let config = CapabilitiesMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            dangerous_caps: DEFAULT_DANGEROUS_CAPS.to_vec(),
            whitelist_processes: vec![],
        };
        let module = CapabilitiesMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        // テスト環境ではプロセスが存在する
        assert!(result.summary.contains("件"));
    }

    #[test]
    fn test_scan_proc_with_whitelist() {
        // ホワイトリストにすべてのプロセスを含めると結果は空
        let snapshot = CapabilitiesMonitorModule::scan_proc(
            Path::new("/proc"),
            DEFAULT_DANGEROUS_CAPS,
            &[
                "systemd".to_string(),
                "sshd".to_string(),
                "bash".to_string(),
            ],
        );
        // ホワイトリストに含まれないプロセスのみ返される
        for info in snapshot.processes.values() {
            assert!(info.name != "systemd");
            assert!(info.name != "sshd");
            assert!(info.name != "bash");
        }
    }

    #[test]
    fn test_scan_proc_nonexistent_dir() {
        let snapshot = CapabilitiesMonitorModule::scan_proc(
            Path::new("/nonexistent_proc_dir"),
            DEFAULT_DANGEROUS_CAPS,
            &[],
        );
        assert!(snapshot.processes.is_empty());
    }
}
