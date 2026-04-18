//! NTP / 時刻同期設定監視モジュール
//!
//! 時刻同期設定ファイル（`/etc/systemd/timesyncd.conf`、`/etc/ntp.conf`、
//! `/etc/chrony/chrony.conf`、`/etc/chrony.conf`）を定期的にスキャンし、
//! 以下を検知する:
//!
//! - **ファイル内容の変更検知** — SHA-256 ハッシュの変化で改ざんを検知
//! - **危険な設定の監査**:
//!   - `timesyncd.conf`: `NTP=` が空、または `FallbackNTP=` も未設定で同期先が存在しない
//!   - `chrony.conf` / `ntp.conf`: `server` / `pool` エントリが 1 件もない（同期無効化）
//!   - `chrony.conf`: `makestep` が設定されていない（クロックスキューの強制修正なし）
//!
//! 攻撃者は時刻同期を無効化しログのタイムスタンプを改ざんすることで、フォレンジック
//! 調査を妨害することがあるため、設定ファイルの変更検知と危険設定の検知が重要である。

use crate::config::NtpConfigMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::core::module_stats::ModuleStatsHandle;
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;
use tokio_util::sync::CancellationToken;

/// モジュール識別子（`ModuleStats` に登録する統計上のモジュール名）
pub(crate) const MODULE_STATS_NAME: &str = "NTP/時刻同期設定監視モジュール";

/// NTP 設定ファイルの種別
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NtpConfigKind {
    /// systemd-timesyncd (`timesyncd.conf`)
    Timesyncd,
    /// chrony (`chrony.conf`)
    Chrony,
    /// ntp / ntpd (`ntp.conf`)
    Ntp,
    /// 自動判定できない場合（ハッシュのみ監視）
    Unknown,
}

impl NtpConfigKind {
    /// パスからファイル種別を判定する
    fn from_path(path: &Path) -> Self {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        if name == "timesyncd.conf" {
            Self::Timesyncd
        } else if name == "chrony.conf" {
            Self::Chrony
        } else if name == "ntp.conf" {
            Self::Ntp
        } else {
            Self::Unknown
        }
    }
}

/// 監査結果
#[derive(Debug, Clone, PartialEq, Eq)]
struct AuditFinding {
    /// 検知項目の識別子（イベント種別の suffix）
    kind: String,
    /// 深刻度
    severity: Severity,
    /// 説明メッセージ
    message: String,
}

/// SHA-256 ハッシュを計算する
fn compute_sha256(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    format!("{:x}", hasher.finalize())
}

/// 行をトリムし、コメントと空行を除外した有効なディレクティブ行のみ返す
fn effective_lines(content: &str) -> impl Iterator<Item = &str> {
    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with(';'))
}

/// `timesyncd.conf` の `[Time]` セクションからキーを検索する
///
/// `key=value` 形式で一致した最初の値を返す。見つからなければ `None`。
fn find_timesyncd_value<'a>(content: &'a str, key: &str) -> Option<&'a str> {
    let key_lower = key.to_ascii_lowercase();
    for line in effective_lines(content) {
        // セクション行 `[Time]` などは無視
        if line.starts_with('[') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        if k.trim().eq_ignore_ascii_case(&key_lower) {
            return Some(v.trim());
        }
    }
    None
}

/// `chrony.conf` / `ntp.conf` でキーワード行を検索する
///
/// 行頭が `keyword ` または `keyword\t` で始まる行の値部分を返すイテレータ
fn find_keyword_lines<'a>(
    content: &'a str,
    keyword: &'a str,
) -> impl Iterator<Item = &'a str> + 'a {
    effective_lines(content).filter_map(move |line| {
        let mut parts = line.splitn(2, |c: char| c.is_whitespace());
        let key = parts.next()?;
        if key.eq_ignore_ascii_case(keyword) {
            Some(parts.next().unwrap_or("").trim())
        } else {
            None
        }
    })
}

/// `timesyncd.conf` の監査
fn audit_timesyncd(content: &str) -> Vec<AuditFinding> {
    let mut findings = Vec::new();

    let ntp = find_timesyncd_value(content, "NTP").unwrap_or("");
    let fallback = find_timesyncd_value(content, "FallbackNTP").unwrap_or("");

    let ntp_empty = ntp.trim().is_empty();
    let fallback_empty = fallback.trim().is_empty();

    if ntp_empty && fallback_empty {
        findings.push(AuditFinding {
            kind: "timesyncd_no_servers".to_string(),
            severity: Severity::Warning,
            message: "timesyncd.conf に NTP= / FallbackNTP= どちらも設定されていません。時刻同期が無効化されている可能性があります".to_string(),
        });
    }

    findings
}

/// `chrony.conf` / `ntp.conf` の監査
fn audit_ntp_servers(content: &str, kind: NtpConfigKind) -> Vec<AuditFinding> {
    let mut findings = Vec::new();

    let server_count = find_keyword_lines(content, "server").count();
    let pool_count = find_keyword_lines(content, "pool").count();

    if server_count == 0 && pool_count == 0 {
        let kind_label = match kind {
            NtpConfigKind::Chrony => "chrony.conf",
            NtpConfigKind::Ntp => "ntp.conf",
            _ => "NTP 設定",
        };
        findings.push(AuditFinding {
            kind: "ntp_no_servers".to_string(),
            severity: Severity::Warning,
            message: format!(
                "{} に server / pool エントリが設定されていません。時刻同期が無効化されている可能性があります",
                kind_label
            ),
        });
    }

    // chrony 固有: makestep 未設定の警告
    if matches!(kind, NtpConfigKind::Chrony) {
        let has_makestep = find_keyword_lines(content, "makestep").count() > 0;
        if !has_makestep {
            findings.push(AuditFinding {
                kind: "chrony_no_makestep".to_string(),
                severity: Severity::Info,
                message: "chrony.conf に makestep が設定されていません。起動直後の大きなクロックスキューが強制修正されない可能性があります".to_string(),
            });
        }
    }

    findings
}

/// 種別に応じた監査関数をディスパッチする
fn audit_by_kind(kind: NtpConfigKind, content: &str) -> Vec<AuditFinding> {
    match kind {
        NtpConfigKind::Timesyncd => audit_timesyncd(content),
        NtpConfigKind::Chrony | NtpConfigKind::Ntp => audit_ntp_servers(content, kind),
        NtpConfigKind::Unknown => Vec::new(),
    }
}

/// NTP / 時刻同期設定監視モジュール
pub struct NtpConfigMonitorModule {
    config: NtpConfigMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
    stats_handle: Option<ModuleStatsHandle>,
}

impl NtpConfigMonitorModule {
    /// 新しい NTP 設定監視モジュールを作成する
    pub fn new(config: NtpConfigMonitorConfig, event_bus: Option<EventBus>) -> Self {
        Self {
            config,
            cancel_token: CancellationToken::new(),
            event_bus,
            stats_handle: None,
        }
    }

    /// キャンセルトークンのクローンを返す
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    /// 指定ファイルをスキャンし、`(ハッシュ, 監査結果)` を返す
    ///
    /// ファイルが存在しない場合は `Ok(None)`（警告不要）、読み取り不可やサイズ超過なら `Err`。
    fn scan_config_file(
        path: &Path,
        config: &NtpConfigMonitorConfig,
    ) -> Result<Option<(String, Vec<AuditFinding>)>, String> {
        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(e) => {
                return Err(format!(
                    "ファイルのメタデータ取得に失敗しました: {} ({})",
                    path.display(),
                    e
                ));
            }
        };

        if !metadata.is_file() {
            return Err(format!("通常ファイルではありません: {}", path.display()));
        }

        if metadata.len() > config.max_file_size_bytes {
            return Err(format!(
                "ファイルサイズが上限 ({} bytes) を超えています: {} ({} bytes)",
                config.max_file_size_bytes,
                path.display(),
                metadata.len()
            ));
        }

        let content = std::fs::read_to_string(path).map_err(|e| {
            format!(
                "ファイルの読み取りに失敗しました: {} ({})",
                path.display(),
                e
            )
        })?;

        let hash = compute_sha256(content.as_bytes());
        let kind = NtpConfigKind::from_path(path);
        let findings = if config.audit_enabled {
            audit_by_kind(kind, &content)
        } else {
            Vec::new()
        };

        Ok(Some((hash, findings)))
    }
}

impl Module for NtpConfigMonitorModule {
    fn name(&self) -> &str {
        "ntp_config_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            config_paths = ?self.config.config_paths,
            audit_enabled = self.config.audit_enabled,
            "NTP / 時刻同期設定監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        // 初回実行時の状態を記録
        let mut issues_total = 0;
        let mut files_found = 0;
        for path_str in &self.config.config_paths {
            let path = Path::new(path_str);
            match Self::scan_config_file(path, &self.config) {
                Ok(Some((_, findings))) => {
                    files_found += 1;
                    issues_total += findings.len();
                }
                Ok(None) => {
                    tracing::debug!(path = %path.display(), "NTP 設定ファイルが存在しません（スキップ）");
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "初回 NTP 設定スキャンに失敗しました");
                }
            }
        }
        tracing::info!(
            files_found,
            total_issues = issues_total,
            "NTP 設定の初回スキャン完了"
        );

        let scan_interval_secs = self.config.scan_interval_secs;
        let config = self.config.clone();
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();
        let stats_handle = self.stats_handle.clone();

        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            interval.tick().await;

            let mut previous_hashes: BTreeMap<String, Option<String>> = BTreeMap::new();

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("NTP / 時刻同期設定監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let scan_start = std::time::Instant::now();
                        for path_str in &config.config_paths {
                            let path = Path::new(path_str);

                            match NtpConfigMonitorModule::scan_config_file(path, &config) {
                                Ok(Some((hash, findings))) => {
                                    let prev = previous_hashes.get(path_str.as_str()).cloned();

                                    // ファイルが新規出現または内容変更
                                    match prev {
                                        Some(Some(ref p)) if p != &hash => {
                                            tracing::info!(
                                                path = %path.display(),
                                                "NTP 設定ファイルの変更を検知しました"
                                            );
                                            if let Some(ref bus) = event_bus {
                                                bus.publish(
                                                    SecurityEvent::new(
                                                        "ntp_config_changed",
                                                        Severity::Warning,
                                                        "ntp_config_monitor",
                                                        format!(
                                                            "NTP 設定ファイルの変更を検知しました: {}",
                                                            path.display()
                                                        ),
                                                    )
                                                    .with_details(format!(
                                                        "path={}, hash={}",
                                                        path.display(),
                                                        hash
                                                    )),
                                                );
                                            }
                                        }
                                        Some(None) => {
                                            tracing::info!(
                                                path = %path.display(),
                                                "NTP 設定ファイルが新規に出現しました"
                                            );
                                            if let Some(ref bus) = event_bus {
                                                bus.publish(
                                                    SecurityEvent::new(
                                                        "ntp_config_appeared",
                                                        Severity::Warning,
                                                        "ntp_config_monitor",
                                                        format!(
                                                            "NTP 設定ファイルが新規に作成されました: {}",
                                                            path.display()
                                                        ),
                                                    )
                                                    .with_details(format!(
                                                        "path={}, hash={}",
                                                        path.display(),
                                                        hash
                                                    )),
                                                );
                                            }
                                        }
                                        _ => {}
                                    }

                                    previous_hashes.insert(path_str.clone(), Some(hash));

                                    for finding in &findings {
                                        tracing::warn!(
                                            kind = %finding.kind,
                                            severity = ?finding.severity,
                                            "{}", finding.message
                                        );
                                        if let Some(ref bus) = event_bus {
                                            bus.publish(
                                                SecurityEvent::new(
                                                    "ntp_config_insecure_setting",
                                                    finding.severity.clone(),
                                                    "ntp_config_monitor",
                                                    finding.message.clone(),
                                                )
                                                .with_details(format!(
                                                    "path={}, kind={}",
                                                    path.display(),
                                                    finding.kind
                                                )),
                                            );
                                        }
                                    }
                                }
                                Ok(None) => {
                                    // ファイル不在。以前存在していた場合は削除イベント発行
                                    if let Some(Some(_)) = previous_hashes.get(path_str.as_str()) {
                                        tracing::warn!(
                                            path = %path.display(),
                                            "NTP 設定ファイルの削除を検知しました"
                                        );
                                        if let Some(ref bus) = event_bus {
                                            bus.publish(
                                                SecurityEvent::new(
                                                    "ntp_config_removed",
                                                    Severity::Warning,
                                                    "ntp_config_monitor",
                                                    format!(
                                                        "NTP 設定ファイルが削除されました: {}",
                                                        path.display()
                                                    ),
                                                )
                                                .with_details(format!("path={}", path.display())),
                                            );
                                        }
                                    }
                                    previous_hashes.insert(path_str.clone(), None);
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        path = %path.display(),
                                        error = %e,
                                        "NTP 設定のスキャンに失敗しました"
                                    );
                                }
                            }
                        }
                        let scan_elapsed = scan_start.elapsed();
                        if let Some(ref handle) = stats_handle {
                            handle.record_scan_duration(MODULE_STATS_NAME, scan_elapsed);
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

    fn set_module_stats(&mut self, handle: ModuleStatsHandle) {
        self.stats_handle = Some(handle);
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();
        let mut items_scanned = 0;
        let mut issues_found = 0;
        let mut snapshot = BTreeMap::new();

        for path_str in &self.config.config_paths {
            let path = Path::new(path_str);
            match Self::scan_config_file(path, &self.config) {
                Ok(Some((hash, findings))) => {
                    items_scanned += 1;
                    issues_found += findings.len();
                    snapshot.insert(path_str.clone(), hash);
                }
                Ok(None) => {
                    tracing::debug!(path = %path.display(), "initial_scan: NTP 設定ファイルが存在しません（スキップ）");
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "initial_scan: NTP 設定のスキャンに失敗しました");
                }
            }
        }

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "NTP 設定ファイル {}件をスキャンしました（問題: {}件）",
                items_scanned, issues_found
            ),
            snapshot,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kind_from_path() {
        assert_eq!(
            NtpConfigKind::from_path(Path::new("/etc/systemd/timesyncd.conf")),
            NtpConfigKind::Timesyncd
        );
        assert_eq!(
            NtpConfigKind::from_path(Path::new("/etc/chrony/chrony.conf")),
            NtpConfigKind::Chrony
        );
        assert_eq!(
            NtpConfigKind::from_path(Path::new("/etc/chrony.conf")),
            NtpConfigKind::Chrony
        );
        assert_eq!(
            NtpConfigKind::from_path(Path::new("/etc/ntp.conf")),
            NtpConfigKind::Ntp
        );
        assert_eq!(
            NtpConfigKind::from_path(Path::new("/etc/random.conf")),
            NtpConfigKind::Unknown
        );
    }

    #[test]
    fn test_find_timesyncd_value_basic() {
        let content = "[Time]\nNTP=pool.ntp.org\n#FallbackNTP=\n";
        assert_eq!(find_timesyncd_value(content, "NTP"), Some("pool.ntp.org"));
        assert_eq!(find_timesyncd_value(content, "FallbackNTP"), None);
    }

    #[test]
    fn test_find_timesyncd_case_insensitive_key() {
        let content = "[Time]\nntp=example.org\n";
        assert_eq!(find_timesyncd_value(content, "NTP"), Some("example.org"));
    }

    #[test]
    fn test_audit_timesyncd_empty_detects() {
        let content = "[Time]\n#NTP=\n#FallbackNTP=\n";
        let findings = audit_timesyncd(content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "timesyncd_no_servers");
        assert!(matches!(findings[0].severity, Severity::Warning));
    }

    #[test]
    fn test_audit_timesyncd_ntp_set_no_finding() {
        let content = "[Time]\nNTP=time.cloudflare.com\n";
        let findings = audit_timesyncd(content);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_timesyncd_fallback_only_is_ok() {
        let content = "[Time]\nNTP=\nFallbackNTP=ntp.ubuntu.com\n";
        let findings = audit_timesyncd(content);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_timesyncd_empty_values_detects() {
        let content = "[Time]\nNTP=\nFallbackNTP=   \n";
        let findings = audit_timesyncd(content);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_audit_chrony_missing_servers_and_makestep() {
        let content = "# empty chrony\n";
        let findings = audit_ntp_servers(content, NtpConfigKind::Chrony);
        assert_eq!(findings.len(), 2);
        let kinds: Vec<_> = findings.iter().map(|f| f.kind.as_str()).collect();
        assert!(kinds.contains(&"ntp_no_servers"));
        assert!(kinds.contains(&"chrony_no_makestep"));
    }

    #[test]
    fn test_audit_chrony_with_pool_and_makestep() {
        let content = "pool 2.pool.ntp.org iburst\nmakestep 1.0 3\n";
        let findings = audit_ntp_servers(content, NtpConfigKind::Chrony);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_chrony_with_server_but_no_makestep() {
        let content = "server time.example.com iburst\n";
        let findings = audit_ntp_servers(content, NtpConfigKind::Chrony);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "chrony_no_makestep");
        assert!(matches!(findings[0].severity, Severity::Info));
    }

    #[test]
    fn test_audit_ntp_conf_missing_servers() {
        let content = "# no servers\n";
        let findings = audit_ntp_servers(content, NtpConfigKind::Ntp);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "ntp_no_servers");
        // ntp.conf では makestep チェックなし
    }

    #[test]
    fn test_audit_ntp_conf_with_server() {
        let content = "server 0.pool.ntp.org iburst\n";
        let findings = audit_ntp_servers(content, NtpConfigKind::Ntp);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_effective_lines_skips_comments_and_blank() {
        let content = "\n# comment\n; also comment\nserver foo\n   \n";
        let lines: Vec<_> = effective_lines(content).collect();
        assert_eq!(lines, vec!["server foo"]);
    }

    #[test]
    fn test_find_keyword_lines_multiple() {
        let content = "server a\npool b\nserver c iburst\n";
        let servers: Vec<_> = find_keyword_lines(content, "server").collect();
        assert_eq!(servers, vec!["a", "c iburst"]);
        let pools: Vec<_> = find_keyword_lines(content, "pool").collect();
        assert_eq!(pools, vec!["b"]);
    }

    #[test]
    fn test_module_name() {
        let config = NtpConfigMonitorConfig::default();
        let module = NtpConfigMonitorModule::new(config, None);
        assert_eq!(module.name(), "ntp_config_monitor");
    }

    #[test]
    fn test_init_zero_interval_rejected() {
        let config = NtpConfigMonitorConfig {
            scan_interval_secs: 0,
            ..Default::default()
        };
        let mut module = NtpConfigMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let config = NtpConfigMonitorConfig::default();
        let mut module = NtpConfigMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[test]
    fn test_scan_nonexistent_returns_none() {
        let config = NtpConfigMonitorConfig::default();
        let result = NtpConfigMonitorModule::scan_config_file(
            Path::new("/tmp/zettai-mamorukun-ntp-monitor-test-does-not-exist"),
            &config,
        )
        .expect("scan should succeed for missing file");
        assert!(result.is_none());
    }

    #[test]
    fn test_scan_file_size_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chrony.conf");
        std::fs::write(&path, "pool 2.pool.ntp.org iburst\nmakestep 1.0 3\n").unwrap();
        let config = NtpConfigMonitorConfig {
            max_file_size_bytes: 5,
            ..Default::default()
        };
        let result = NtpConfigMonitorModule::scan_config_file(&path, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_scan_chrony_safe_content_yields_no_findings() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chrony.conf");
        std::fs::write(&path, "pool 2.pool.ntp.org iburst\nmakestep 1.0 3\n").unwrap();
        let config = NtpConfigMonitorConfig::default();
        let (_, findings) = NtpConfigMonitorModule::scan_config_file(&path, &config)
            .expect("scan ok")
            .expect("file present");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_scan_audit_disabled_yields_no_findings() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chrony.conf");
        std::fs::write(&path, "# empty\n").unwrap();
        let config = NtpConfigMonitorConfig {
            audit_enabled: false,
            ..Default::default()
        };
        let (_, findings) = NtpConfigMonitorModule::scan_config_file(&path, &config)
            .expect("scan ok")
            .expect("file present");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_hash_changes_on_modification() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chrony.conf");
        std::fs::write(&path, "server a\nmakestep 1.0 3\n").unwrap();
        let config = NtpConfigMonitorConfig::default();
        let (hash1, _) = NtpConfigMonitorModule::scan_config_file(&path, &config)
            .expect("scan ok")
            .expect("file present");
        std::fs::write(&path, "server b\nmakestep 1.0 3\n").unwrap();
        let (hash2, _) = NtpConfigMonitorModule::scan_config_file(&path, &config)
            .expect("scan ok")
            .expect("file present");
        assert_ne!(hash1, hash2);
    }

    #[tokio::test]
    async fn test_initial_scan_counts_files_and_issues() {
        let dir = tempfile::tempdir().unwrap();
        let chrony_path = dir.path().join("chrony.conf");
        let ntp_path = dir.path().join("ntp.conf");
        let missing_path = dir.path().join("missing.conf");

        // chrony: pool あり / makestep なし → Info 1 件
        std::fs::write(&chrony_path, "pool 2.pool.ntp.org iburst\n").unwrap();
        // ntp: サーバなし → Warning 1 件
        std::fs::write(&ntp_path, "# empty\n").unwrap();

        let config = NtpConfigMonitorConfig {
            config_paths: vec![
                chrony_path.to_string_lossy().to_string(),
                ntp_path.to_string_lossy().to_string(),
                missing_path.to_string_lossy().to_string(),
            ],
            ..Default::default()
        };
        let module = NtpConfigMonitorModule::new(config, None);
        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 2);
        assert_eq!(result.issues_found, 2);
        assert_eq!(result.snapshot.len(), 2);
        assert!(result.summary.contains("2件"));
    }

    #[test]
    fn test_set_module_stats_stores_handle() {
        let config = NtpConfigMonitorConfig::default();
        let mut module = NtpConfigMonitorModule::new(config, None);
        assert!(module.stats_handle.is_none());
        module.set_module_stats(ModuleStatsHandle::new());
        assert!(module.stats_handle.is_some());
    }

    #[tokio::test]
    async fn test_periodic_scan_records_scan_duration() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chrony.conf");
        std::fs::write(&path, "pool 2.pool.ntp.org iburst\nmakestep 1.0 3\n").unwrap();

        let config = NtpConfigMonitorConfig {
            config_paths: vec![path.to_string_lossy().to_string()],
            scan_interval_secs: 1,
            ..Default::default()
        };
        let mut module = NtpConfigMonitorModule::new(config, None);
        module.init().unwrap();

        let stats = ModuleStatsHandle::new();
        module.set_module_stats(stats.clone());

        let handle = module.start().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
        module.stop().await.unwrap();
        let _ = handle.await;

        let s = stats.get(MODULE_STATS_NAME).expect("stats must exist");
        assert!(
            s.scan_count >= 1,
            "scan_count={} expected >= 1",
            s.scan_count
        );
    }
}
