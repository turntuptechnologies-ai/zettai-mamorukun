//! SSH 設定セキュリティ監査モジュール
//!
//! `sshd_config` ファイルを定期的にスキャンし、セキュリティ上の問題がある設定を検知する。
//!
//! 検知対象:
//! - `PermitRootLogin yes` — root ログインの許可
//! - `PasswordAuthentication yes` — パスワード認証の有効化
//! - `PermitEmptyPasswords yes` — 空パスワードの許可
//! - `Protocol 1` — 古いプロトコルバージョンの使用
//! - `X11Forwarding yes` — X11 転送の有効化
//! - `StrictModes no` — 厳密モードの無効化
//! - `MaxAuthTries` の閾値超過
//! - `GatewayPorts yes` — ゲートウェイポートの有効化
//! - `PermitTunnel yes` — トンネリングの許可

use crate::config::SshdConfigMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::core::module_stats::ModuleStatsHandle;
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;

/// モジュール識別子（`ModuleStats` に登録する統計上のモジュール名）
pub(crate) const MODULE_STATS_NAME: &str = "SSH 設定セキュリティ監査モジュール";

/// sshd_config のパース済みディレクティブ
#[derive(Debug, Clone, PartialEq)]
struct SshdDirective {
    /// ディレクティブのキー名
    key: String,
    /// ディレクティブの値
    value: String,
    /// 行番号
    line_number: usize,
}

/// 監査結果
#[derive(Debug, Clone)]
struct AuditFinding {
    /// 問題のあるディレクティブ名
    directive: String,
    /// ディレクティブの値
    value: String,
    /// 深刻度
    severity: Severity,
    /// 説明メッセージ
    message: String,
}

/// sshd_config の内容をパースする
///
/// 行ごとに `Key Value` 形式のディレクティブを抽出する。
/// コメント行と空行はスキップし、`Match` ブロック以降のディレクティブは無視する。
fn parse_sshd_config(content: &str) -> Vec<SshdDirective> {
    let mut directives = Vec::new();
    let mut in_match_block = false;

    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        // 空行・コメント行をスキップ
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Match ブロックの開始検出
        if trimmed.eq_ignore_ascii_case("match")
            || trimmed
                .split_whitespace()
                .next()
                .is_some_and(|k| k.eq_ignore_ascii_case("Match"))
        {
            in_match_block = true;
            continue;
        }

        // Match ブロック内のディレクティブは無視
        if in_match_block {
            continue;
        }

        // Key Value 形式をパース
        let mut parts = trimmed.splitn(2, |c: char| c.is_whitespace());
        if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
            directives.push(SshdDirective {
                key: key.to_string(),
                value: value.trim().to_string(),
                line_number: idx + 1,
            });
        }
    }

    directives
}

/// Include ディレクティブを展開する
///
/// glob パターンに対応し、循環参照を防止する（訪問済みファイルセット + 深度制限）。
fn resolve_includes(
    directives: &[SshdDirective],
    base_dir: &Path,
    depth: usize,
    max_depth: usize,
    max_file_size: u64,
    visited: &mut HashSet<PathBuf>,
) -> Result<Vec<SshdDirective>, AppError> {
    if depth > max_depth {
        return Err(AppError::ModuleConfig {
            message: format!("Include の再帰深度が上限 ({}) を超えました", max_depth),
        });
    }

    let mut result = Vec::new();

    for directive in directives {
        if directive.key.eq_ignore_ascii_case("Include") {
            let pattern = if Path::new(&directive.value).is_absolute() {
                directive.value.clone()
            } else {
                base_dir
                    .join(&directive.value)
                    .to_string_lossy()
                    .to_string()
            };

            let paths = glob::glob(&pattern).map_err(|e| AppError::ModuleConfig {
                message: format!("Include パターンが不正です: {} ({})", pattern, e),
            })?;

            for entry in paths {
                let path = match entry {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!(error = %e, "Include glob エントリの読み取りに失敗しました");
                        continue;
                    }
                };

                let canonical = match path.canonicalize() {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!(path = %path.display(), error = %e, "Include ファイルのパス解決に失敗しました");
                        continue;
                    }
                };

                // 循環参照防止
                if !visited.insert(canonical.clone()) {
                    tracing::warn!(path = %canonical.display(), "Include ファイルの循環参照を検知しました");
                    continue;
                }

                // ファイルサイズチェック
                match std::fs::metadata(&canonical) {
                    Ok(meta) => {
                        if meta.len() > max_file_size {
                            tracing::warn!(
                                path = %canonical.display(),
                                size = meta.len(),
                                limit = max_file_size,
                                "Include ファイルがサイズ上限を超えています"
                            );
                            continue;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(path = %canonical.display(), error = %e, "Include ファイルのメタデータ取得に失敗しました");
                        continue;
                    }
                }

                match std::fs::read_to_string(&canonical) {
                    Ok(content) => {
                        let sub_directives = parse_sshd_config(&content);
                        let include_base = canonical.parent().unwrap_or(base_dir);
                        let resolved = resolve_includes(
                            &sub_directives,
                            include_base,
                            depth + 1,
                            max_depth,
                            max_file_size,
                            visited,
                        )?;
                        result.extend(resolved);
                    }
                    Err(e) => {
                        tracing::warn!(path = %canonical.display(), error = %e, "Include ファイルの読み取りに失敗しました");
                    }
                }
            }
        } else {
            result.push(directive.clone());
        }
    }

    Ok(result)
}

/// ディレクティブに対してセキュリティ監査を実行する
fn audit_directives(
    directives: &[SshdDirective],
    config: &SshdConfigMonitorConfig,
) -> Vec<AuditFinding> {
    let mut findings = Vec::new();

    for directive in directives {
        let key_lower = directive.key.to_ascii_lowercase();
        let value_lower = directive.value.to_ascii_lowercase();

        match key_lower.as_str() {
            "permitrootlogin" if config.check_permit_root_login && value_lower == "yes" => {
                findings.push(AuditFinding {
                        directive: directive.key.clone(),
                        value: directive.value.clone(),
                        severity: Severity::Critical,
                        message: format!(
                            "PermitRootLogin が yes に設定されています（行 {}）。root の直接 SSH ログインが許可されます",
                            directive.line_number
                        ),
                    });
            }
            // without-password, prohibit-password, no は安全
            "passwordauthentication"
                if config.check_password_authentication && value_lower == "yes" =>
            {
                findings.push(AuditFinding {
                        directive: directive.key.clone(),
                        value: directive.value.clone(),
                        severity: Severity::Warning,
                        message: format!(
                            "PasswordAuthentication が yes に設定されています（行 {}）。鍵認証のみの運用を推奨します",
                            directive.line_number
                        ),
                    });
            }
            "permitemptypasswords"
                if config.check_permit_empty_passwords && value_lower == "yes" =>
            {
                findings.push(AuditFinding {
                        directive: directive.key.clone(),
                        value: directive.value.clone(),
                        severity: Severity::Critical,
                        message: format!(
                            "PermitEmptyPasswords が yes に設定されています（行 {}）。空パスワードでのログインが許可されます",
                            directive.line_number
                        ),
                    });
            }
            "protocol" if config.check_protocol_version && value_lower.contains('1') => {
                findings.push(AuditFinding {
                    directive: directive.key.clone(),
                    value: directive.value.clone(),
                    severity: Severity::Critical,
                    message: format!(
                        "Protocol に 1 が含まれています（行 {}）。SSH プロトコル v1 は脆弱です",
                        directive.line_number
                    ),
                });
            }
            "x11forwarding" if config.check_x11_forwarding && value_lower == "yes" => {
                findings.push(AuditFinding {
                        directive: directive.key.clone(),
                        value: directive.value.clone(),
                        severity: Severity::Info,
                        message: format!(
                            "X11Forwarding が yes に設定されています（行 {}）。不要な場合は無効化を推奨します",
                            directive.line_number
                        ),
                    });
            }
            "strictmodes" if config.check_strict_modes && value_lower == "no" => {
                findings.push(AuditFinding {
                        directive: directive.key.clone(),
                        value: directive.value.clone(),
                        severity: Severity::Warning,
                        message: format!(
                            "StrictModes が no に設定されています（行 {}）。ファイルパーミッションチェックが無効です",
                            directive.line_number
                        ),
                    });
            }
            "maxauthtries" if config.check_max_auth_tries => {
                if let Ok(tries) = directive.value.parse::<u32>()
                    && tries > config.max_auth_tries_threshold
                {
                    findings.push(AuditFinding {
                        directive: directive.key.clone(),
                        value: directive.value.clone(),
                        severity: Severity::Warning,
                        message: format!(
                            "MaxAuthTries が {} に設定されています（行 {}）。閾値 {} を超えています",
                            tries, directive.line_number, config.max_auth_tries_threshold
                        ),
                    });
                }
            }
            "gatewayports" if config.check_gateway_ports && value_lower == "yes" => {
                findings.push(AuditFinding {
                        directive: directive.key.clone(),
                        value: directive.value.clone(),
                        severity: Severity::Warning,
                        message: format!(
                            "GatewayPorts が yes に設定されています（行 {}）。リモートからのポート転送が許可されます",
                            directive.line_number
                        ),
                    });
            }
            "permittunnel" if config.check_permit_tunnel && value_lower == "yes" => {
                findings.push(AuditFinding {
                        directive: directive.key.clone(),
                        value: directive.value.clone(),
                        severity: Severity::Info,
                        message: format!(
                            "PermitTunnel が yes に設定されています（行 {}）。VPN トンネリングが許可されます",
                            directive.line_number
                        ),
                    });
            }
            _ => {}
        }
    }

    findings
}

/// SHA-256 ハッシュを計算する
fn compute_sha256(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    format!("{:x}", hasher.finalize())
}

/// SSH 設定セキュリティ監査モジュール
///
/// `sshd_config` のセキュリティ設定を定期的に監査し、危険な設定を検知する。
pub struct SshdConfigMonitorModule {
    config: SshdConfigMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
    stats_handle: Option<ModuleStatsHandle>,
}

impl SshdConfigMonitorModule {
    /// 新しい SSH 設定セキュリティ監査モジュールを作成する
    pub fn new(config: SshdConfigMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// 指定されたパスの sshd_config をスキャンし、監査結果を返す
    fn scan_config_file(
        path: &Path,
        config: &SshdConfigMonitorConfig,
    ) -> Result<(String, Vec<AuditFinding>), String> {
        // ファイルサイズチェック
        let metadata = std::fs::metadata(path).map_err(|e| {
            format!(
                "ファイルのメタデータ取得に失敗しました: {} ({})",
                path.display(),
                e
            )
        })?;

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
        let directives = parse_sshd_config(&content);

        // Include 展開
        let resolved = if config.follow_includes {
            let base_dir = path.parent().unwrap_or(Path::new("/etc/ssh"));
            let mut visited = HashSet::new();
            if let Ok(canonical) = path.canonicalize() {
                visited.insert(canonical);
            }
            match resolve_includes(
                &directives,
                base_dir,
                0,
                10,
                config.max_file_size_bytes,
                &mut visited,
            ) {
                Ok(resolved) => resolved,
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "Include 展開に失敗しました。展開前のディレクティブで監査を続行します");
                    directives
                        .into_iter()
                        .filter(|d| !d.key.eq_ignore_ascii_case("Include"))
                        .collect()
                }
            }
        } else {
            directives
                .into_iter()
                .filter(|d| !d.key.eq_ignore_ascii_case("Include"))
                .collect()
        };

        let findings = audit_directives(&resolved, config);

        Ok((hash, findings))
    }
}

impl Module for SshdConfigMonitorModule {
    fn name(&self) -> &str {
        "sshd_config_monitor"
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
            follow_includes = self.config.follow_includes,
            "SSH 設定セキュリティ監査モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        // 初回スキャン
        let mut issues_total = 0;
        for path_str in &self.config.config_paths {
            let path = Path::new(path_str);
            match Self::scan_config_file(path, &self.config) {
                Ok((_, findings)) => {
                    issues_total += findings.len();
                    tracing::info!(
                        path = %path.display(),
                        findings = findings.len(),
                        "初回 sshd_config スキャンが完了しました"
                    );
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "初回 sshd_config スキャンに失敗しました");
                }
            }
        }
        tracing::info!(total_issues = issues_total, "初回スキャン完了");

        let scan_interval_secs = self.config.scan_interval_secs;
        let config = self.config.clone();
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();
        let stats_handle = self.stats_handle.clone();

        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            // 最初の tick は即座に発火するのでスキップ
            interval.tick().await;

            // 前回のハッシュを記録して変更検知に使用
            let mut previous_hashes: BTreeMap<String, String> = BTreeMap::new();

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("SSH 設定セキュリティ監査モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let scan_start = std::time::Instant::now();
                        for path_str in &config.config_paths {
                            let path = Path::new(path_str);

                            match SshdConfigMonitorModule::scan_config_file(path, &config) {
                                Ok((hash, findings)) => {
                                    // 変更検知
                                    let changed = previous_hashes
                                        .get(path_str.as_str())
                                        .is_some_and(|prev| prev != &hash);

                                    if changed {
                                        tracing::info!(
                                            path = %path.display(),
                                            "sshd_config の変更を検知しました"
                                        );
                                        if let Some(ref bus) = event_bus {
                                            bus.publish(
                                                SecurityEvent::new(
                                                    "sshd_config_changed",
                                                    Severity::Warning,
                                                    "sshd_config_monitor",
                                                    format!(
                                                        "sshd_config ファイルの変更を検知しました: {}",
                                                        path.display()
                                                    ),
                                                )
                                                .with_details(format!("path={}, hash={}", path.display(), hash)),
                                            );
                                        }
                                    }

                                    previous_hashes.insert(path_str.clone(), hash);

                                    // 監査結果の発行
                                    for finding in &findings {
                                        tracing::warn!(
                                            directive = %finding.directive,
                                            value = %finding.value,
                                            severity = ?finding.severity,
                                            "{}", finding.message
                                        );
                                        if let Some(ref bus) = event_bus {
                                            bus.publish(
                                                SecurityEvent::new(
                                                    "sshd_config_insecure_setting",
                                                    finding.severity.clone(),
                                                    "sshd_config_monitor",
                                                    finding.message.clone(),
                                                )
                                                .with_details(format!(
                                                    "path={}, directive={}, value={}",
                                                    path.display(),
                                                    finding.directive,
                                                    finding.value
                                                )),
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        path = %path.display(),
                                        error = %e,
                                        "sshd_config のスキャンに失敗しました"
                                    );
                                    if let Some(ref bus) = event_bus {
                                        bus.publish(
                                            SecurityEvent::new(
                                                "sshd_config_include_error",
                                                Severity::Warning,
                                                "sshd_config_monitor",
                                                format!(
                                                    "sshd_config のスキャンに失敗しました: {} ({})",
                                                    path.display(),
                                                    e
                                                ),
                                            )
                                            .with_details(format!("path={}, error={}", path.display(), e)),
                                        );
                                    }
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
                Ok((hash, findings)) => {
                    items_scanned += 1;
                    issues_found += findings.len();
                    snapshot.insert(path_str.clone(), hash);
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "initial_scan: sshd_config のスキャンに失敗しました");
                }
            }
        }

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "sshd_config {}件をスキャンしました（問題: {}件）",
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
    fn test_parse_sshd_config_basic() {
        let content = "PermitRootLogin no\nPasswordAuthentication yes\nPort 22\n";
        let directives = parse_sshd_config(content);
        assert_eq!(directives.len(), 3);
        assert_eq!(directives[0].key, "PermitRootLogin");
        assert_eq!(directives[0].value, "no");
        assert_eq!(directives[0].line_number, 1);
        assert_eq!(directives[1].key, "PasswordAuthentication");
        assert_eq!(directives[1].value, "yes");
        assert_eq!(directives[2].key, "Port");
        assert_eq!(directives[2].value, "22");
    }

    #[test]
    fn test_parse_sshd_config_comments_and_empty() {
        let content = "# This is a comment\n\nPermitRootLogin no\n# Another comment\n\nPort 22\n";
        let directives = parse_sshd_config(content);
        assert_eq!(directives.len(), 2);
        assert_eq!(directives[0].key, "PermitRootLogin");
        assert_eq!(directives[1].key, "Port");
    }

    #[test]
    fn test_parse_sshd_config_match_block() {
        let content = "PermitRootLogin no\nMatch User admin\n  PermitRootLogin yes\n  X11Forwarding no\nPort 22\n";
        let directives = parse_sshd_config(content);
        // Match ブロック以降は無視されるので、PermitRootLogin のみ
        assert_eq!(directives.len(), 1);
        assert_eq!(directives[0].key, "PermitRootLogin");
        assert_eq!(directives[0].value, "no");
    }

    #[test]
    fn test_audit_permit_root_login_yes() {
        let directives = vec![SshdDirective {
            key: "PermitRootLogin".to_string(),
            value: "yes".to_string(),
            line_number: 1,
        }];
        let config = SshdConfigMonitorConfig::default();
        let findings = audit_directives(&directives, &config);
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0].severity, Severity::Critical));
        assert_eq!(findings[0].directive, "PermitRootLogin");
    }

    #[test]
    fn test_audit_permit_root_login_no() {
        let directives = vec![SshdDirective {
            key: "PermitRootLogin".to_string(),
            value: "no".to_string(),
            line_number: 1,
        }];
        let config = SshdConfigMonitorConfig::default();
        let findings = audit_directives(&directives, &config);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_password_auth_yes() {
        let directives = vec![SshdDirective {
            key: "PasswordAuthentication".to_string(),
            value: "yes".to_string(),
            line_number: 5,
        }];
        let config = SshdConfigMonitorConfig::default();
        let findings = audit_directives(&directives, &config);
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0].severity, Severity::Warning));
    }

    #[test]
    fn test_audit_permit_empty_passwords() {
        let directives = vec![SshdDirective {
            key: "PermitEmptyPasswords".to_string(),
            value: "yes".to_string(),
            line_number: 3,
        }];
        let config = SshdConfigMonitorConfig::default();
        let findings = audit_directives(&directives, &config);
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0].severity, Severity::Critical));
    }

    #[test]
    fn test_audit_protocol_1() {
        let directives = vec![SshdDirective {
            key: "Protocol".to_string(),
            value: "1".to_string(),
            line_number: 2,
        }];
        let config = SshdConfigMonitorConfig::default();
        let findings = audit_directives(&directives, &config);
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0].severity, Severity::Critical));
    }

    #[test]
    fn test_audit_x11_forwarding() {
        let directives = vec![SshdDirective {
            key: "X11Forwarding".to_string(),
            value: "yes".to_string(),
            line_number: 10,
        }];
        let config = SshdConfigMonitorConfig::default();
        let findings = audit_directives(&directives, &config);
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0].severity, Severity::Info));
    }

    #[test]
    fn test_audit_strict_modes_no() {
        let directives = vec![SshdDirective {
            key: "StrictModes".to_string(),
            value: "no".to_string(),
            line_number: 7,
        }];
        let config = SshdConfigMonitorConfig::default();
        let findings = audit_directives(&directives, &config);
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0].severity, Severity::Warning));
    }

    #[test]
    fn test_audit_max_auth_tries_high() {
        let directives = vec![SshdDirective {
            key: "MaxAuthTries".to_string(),
            value: "10".to_string(),
            line_number: 8,
        }];
        let config = SshdConfigMonitorConfig::default();
        let findings = audit_directives(&directives, &config);
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0].severity, Severity::Warning));
        assert!(findings[0].message.contains("10"));
    }

    #[test]
    fn test_audit_gateway_ports() {
        let directives = vec![SshdDirective {
            key: "GatewayPorts".to_string(),
            value: "yes".to_string(),
            line_number: 12,
        }];
        let config = SshdConfigMonitorConfig::default();
        let findings = audit_directives(&directives, &config);
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0].severity, Severity::Warning));
    }

    #[test]
    fn test_audit_permit_tunnel() {
        let directives = vec![SshdDirective {
            key: "PermitTunnel".to_string(),
            value: "yes".to_string(),
            line_number: 15,
        }];
        let config = SshdConfigMonitorConfig::default();
        let findings = audit_directives(&directives, &config);
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0].severity, Severity::Info));
    }

    #[test]
    fn test_audit_safe_config() {
        let directives = vec![
            SshdDirective {
                key: "PermitRootLogin".to_string(),
                value: "no".to_string(),
                line_number: 1,
            },
            SshdDirective {
                key: "PasswordAuthentication".to_string(),
                value: "no".to_string(),
                line_number: 2,
            },
            SshdDirective {
                key: "PermitEmptyPasswords".to_string(),
                value: "no".to_string(),
                line_number: 3,
            },
            SshdDirective {
                key: "Protocol".to_string(),
                value: "2".to_string(),
                line_number: 4,
            },
            SshdDirective {
                key: "X11Forwarding".to_string(),
                value: "no".to_string(),
                line_number: 5,
            },
            SshdDirective {
                key: "StrictModes".to_string(),
                value: "yes".to_string(),
                line_number: 6,
            },
            SshdDirective {
                key: "MaxAuthTries".to_string(),
                value: "3".to_string(),
                line_number: 7,
            },
            SshdDirective {
                key: "GatewayPorts".to_string(),
                value: "no".to_string(),
                line_number: 8,
            },
            SshdDirective {
                key: "PermitTunnel".to_string(),
                value: "no".to_string(),
                line_number: 9,
            },
        ];
        let config = SshdConfigMonitorConfig::default();
        let findings = audit_directives(&directives, &config);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_module_name() {
        let config = SshdConfigMonitorConfig::default();
        let module = SshdConfigMonitorModule::new(config, None);
        assert_eq!(module.name(), "sshd_config_monitor");
    }

    #[test]
    fn test_init_zero_interval() {
        let config = SshdConfigMonitorConfig {
            scan_interval_secs: 0,
            ..Default::default()
        };
        let mut module = SshdConfigMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let config = SshdConfigMonitorConfig::default();
        let mut module = SshdConfigMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let config = SshdConfigMonitorConfig {
            config_paths: vec!["/tmp/nonexistent-sshd-test-config".to_string()],
            ..Default::default()
        };
        let module = SshdConfigMonitorModule::new(config, None);
        let result = module.initial_scan().await;
        assert!(result.is_ok());
        let scan = result.unwrap();
        assert!(scan.summary.contains("sshd_config"));
    }

    #[test]
    fn test_parse_include_directive() {
        let content = "PermitRootLogin no\nInclude /etc/ssh/sshd_config.d/*.conf\nPort 22\n";
        let directives = parse_sshd_config(content);
        assert_eq!(directives.len(), 3);
        assert_eq!(directives[1].key, "Include");
        assert_eq!(directives[1].value, "/etc/ssh/sshd_config.d/*.conf");
    }

    #[test]
    fn test_file_size_limit() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("sshd_config");
        // 書き込むサイズ: 100 bytes 超の制限テスト
        let content = "PermitRootLogin yes\n".repeat(10);
        std::fs::write(&config_path, &content).unwrap();

        let config = SshdConfigMonitorConfig {
            config_paths: vec![config_path.to_string_lossy().to_string()],
            max_file_size_bytes: 10, // 非常に小さい制限
            ..Default::default()
        };

        let result = SshdConfigMonitorModule::scan_config_file(&config_path, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_hash_change_detection() {
        let content1 = "PermitRootLogin no\n";
        let content2 = "PermitRootLogin yes\n";
        let hash1 = compute_sha256(content1.as_bytes());
        let hash2 = compute_sha256(content2.as_bytes());
        assert_ne!(hash1, hash2);

        // 同じ内容は同じハッシュ
        let hash1_again = compute_sha256(content1.as_bytes());
        assert_eq!(hash1, hash1_again);
    }

    #[test]
    fn test_set_module_stats_stores_handle() {
        let config = SshdConfigMonitorConfig::default();
        let mut module = SshdConfigMonitorModule::new(config, None);
        assert!(module.stats_handle.is_none());
        module.set_module_stats(ModuleStatsHandle::new());
        assert!(module.stats_handle.is_some());
    }

    #[tokio::test]
    async fn test_periodic_scan_records_scan_duration() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("sshd_config");
        std::fs::write(&config_path, "PermitRootLogin no\n").unwrap();

        let config = SshdConfigMonitorConfig {
            config_paths: vec![config_path.to_string_lossy().to_string()],
            scan_interval_secs: 1,
            ..Default::default()
        };
        let mut module = SshdConfigMonitorModule::new(config, None);
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
