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
//!   - `chrony.conf`: `allow` ディレクティブの全開放（`all` / `0.0.0.0/0` / `::/0`）
//!   - `chrony.conf`: `bindcmdaddress` が全インターフェース公開（`0.0.0.0` / `::` / `*`）
//!   - `ntp.conf`: `restrict default` ディレクティブ欠如（既定ポリシー無制限）
//!   - `chrony.conf` / `ntp.conf`: `driftfile` が絶対パスでない
//!   - `chrony.conf`: `cmdport` / `port` が既定値（323 / 123）と異なる
//!   - `chrony.conf`: `ntpsigndsocket` が world-writable な一時領域を指す
//!   - `chrony.conf` / `ntp.conf`: `keys` で指定された鍵ファイルが存在しない
//!   - `chrony.conf` / `ntp.conf`: `keys` で指定された鍵ファイルが
//!     world-readable / world-writable な過剰パーミッション（共有鍵漏洩リスク）
//!   - `chrony.conf`: `keys` を設定しているのに `trustedkey` 未設定
//!   - `chrony.conf`: `keys` を設定しているのに `authselectmode require` 未使用
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

/// chrony の `allow` ディレクティブを監査する
///
/// - 引数なし（= `allow all`）または全開放（`0.0.0.0/0` / `::/0`）は Warning (`chrony_allow_open`)
/// - 具体的なサブネット指定は Info (`chrony_allow_network`)
fn audit_chrony_allow(content: &str) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    for value in find_keyword_lines(content, "allow") {
        let trimmed = value.trim();
        let is_open = trimmed.is_empty()
            || trimmed.eq_ignore_ascii_case("all")
            || trimmed == "0.0.0.0/0"
            || trimmed == "::/0";

        if is_open {
            findings.push(AuditFinding {
                kind: "chrony_allow_open".to_string(),
                severity: Severity::Warning,
                message: format!(
                    "chrony.conf の `allow` ディレクティブが全開放になっています: `allow {}`（NTP サービスを任意クライアントに公開しており、増幅攻撃の踏み台や意図しない外部公開のリスクがあります）",
                    if trimmed.is_empty() { "(引数なし)" } else { trimmed }
                ),
            });
        } else {
            findings.push(AuditFinding {
                kind: "chrony_allow_network".to_string(),
                severity: Severity::Info,
                message: format!(
                    "chrony.conf の `allow` ディレクティブでネットワークを許可しています: `allow {}`（意図した公開か確認してください）",
                    trimmed
                ),
            });
        }
    }
    findings
}

/// chrony の `bindcmdaddress` が公開アドレスでないかを監査する
fn audit_chrony_bindcmdaddress(content: &str) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    for value in find_keyword_lines(content, "bindcmdaddress") {
        let trimmed = value.trim();
        let is_public = trimmed == "0.0.0.0" || trimmed == "::" || trimmed == "*";
        if is_public {
            findings.push(AuditFinding {
                kind: "chrony_bindcmd_public".to_string(),
                severity: Severity::Warning,
                message: format!(
                    "chrony.conf の `bindcmdaddress {}` は chronyc のコマンドソケットを全インターフェースに公開します（localhost に制限することを推奨）",
                    trimmed
                ),
            });
        }
    }
    findings
}

/// ntp.conf の `restrict default` ディレクティブ欠如を監査する
fn audit_ntp_restrict_default(content: &str) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    let has_restrict_default = find_keyword_lines(content, "restrict").any(|value| {
        // `restrict` の引数先頭が `default` であれば有効とみなす
        let mut tokens = value.split_whitespace();
        matches!(tokens.next(), Some(tok) if tok.eq_ignore_ascii_case("default"))
    });

    if !has_restrict_default {
        findings.push(AuditFinding {
            kind: "ntp_no_restrict_default".to_string(),
            severity: Severity::Warning,
            message: "ntp.conf に `restrict default` ディレクティブが設定されていません（既定アクセスポリシーが制限されておらず、増幅攻撃の踏み台となるリスクがあります）".to_string(),
        });
    }
    findings
}

/// `driftfile` が絶対パスかを監査する
fn audit_driftfile_absolute(content: &str, kind: NtpConfigKind) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    for value in find_keyword_lines(content, "driftfile") {
        let trimmed = value.trim();
        // 値の先頭トークン（パス部分）を取り出す
        let path_value = trimmed.split_whitespace().next().unwrap_or("");
        if path_value.is_empty() || !path_value.starts_with('/') {
            let kind_label = match kind {
                NtpConfigKind::Chrony => "chrony.conf",
                NtpConfigKind::Ntp => "ntp.conf",
                _ => "NTP 設定",
            };
            findings.push(AuditFinding {
                kind: "driftfile_not_absolute".to_string(),
                severity: Severity::Info,
                message: format!(
                    "{} の `driftfile` が絶対パスではありません: `{}`（意図しない作業ディレクトリへの書き込みを避けるため絶対パスを推奨）",
                    kind_label, trimmed
                ),
            });
        }
    }
    findings
}

/// chrony の `cmdport` / `port` が既定値（cmdport=323 / port=123）と異なる場合を監査する
///
/// chronyc 制御ポート（`cmdport`）や NTP 待受ポート（`port`）を既定値から変更すると、
/// 運用上の正当な理由が無い限り検知・監視を回避する踏み台となり得る。
/// - 変更の事実 → Info
/// - `cmdport 0`（意図的な無効化） → Info
fn audit_chrony_cmdport_port(content: &str) -> Vec<AuditFinding> {
    let mut findings = Vec::new();

    for value in find_keyword_lines(content, "cmdport") {
        let trimmed = value.split_whitespace().next().unwrap_or("").trim();
        if trimmed == "323" {
            continue;
        }
        findings.push(AuditFinding {
            kind: "chrony_cmdport_non_default".to_string(),
            severity: Severity::Info,
            message: format!(
                "chrony.conf の `cmdport {}` は既定値 (323) と異なります（運用上の意図を確認してください）",
                trimmed
            ),
        });
    }

    for value in find_keyword_lines(content, "port") {
        let trimmed = value.split_whitespace().next().unwrap_or("").trim();
        if trimmed == "123" {
            continue;
        }
        findings.push(AuditFinding {
            kind: "chrony_port_non_default".to_string(),
            severity: Severity::Info,
            message: format!(
                "chrony.conf の `port {}` は既定値 (123) と異なります（運用上の意図を確認してください）",
                trimmed
            ),
        });
    }

    findings
}

/// chrony の `ntpsigndsocket` が world-writable な一時領域を指していないかを監査する
///
/// Samba 等と連携する MS-SNTP ソケットを `/tmp/` / `/var/tmp/` / `/dev/shm/` 配下に
/// 配置すると任意プロセスからの操作によりなりすましや権限昇格の踏み台となる危険がある。
fn audit_ntpsigndsocket_public(content: &str) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    const RISKY_PREFIXES: [&str; 3] = ["/tmp/", "/var/tmp/", "/dev/shm/"];

    for value in find_keyword_lines(content, "ntpsigndsocket") {
        let trimmed = value.split_whitespace().next().unwrap_or("").trim();
        if trimmed.is_empty() {
            continue;
        }
        let canonical = trimmed.trim_end_matches('/');
        let is_risky = RISKY_PREFIXES
            .iter()
            .any(|prefix| trimmed.starts_with(prefix) || canonical == prefix.trim_end_matches('/'));
        if is_risky {
            findings.push(AuditFinding {
                kind: "chrony_ntpsigndsocket_public".to_string(),
                severity: Severity::Warning,
                message: format!(
                    "chrony.conf の `ntpsigndsocket {}` は world-writable な一時領域に配置されています（MS-SNTP ソケットが任意プロセスから操作され、権限昇格・なりすましの踏み台になる恐れがあります）",
                    trimmed
                ),
            });
        }
    }

    findings
}

/// `keys` ディレクティブの値（パス）を反復する
///
/// 相対パスは設定ファイルのディレクトリを基準に解決する。値が空の行はスキップする。
fn iter_keys_paths<'a>(
    content: &'a str,
    config_path: &'a Path,
) -> impl Iterator<Item = (String, std::path::PathBuf)> + 'a {
    let base_dir = config_path.parent();
    find_keyword_lines(content, "keys").filter_map(move |value| {
        let trimmed = value.split_whitespace().next().unwrap_or("").trim();
        if trimmed.is_empty() {
            return None;
        }
        let candidate = std::path::PathBuf::from(trimmed);
        let resolved = if candidate.is_absolute() {
            candidate
        } else if let Some(dir) = base_dir {
            dir.join(candidate)
        } else {
            candidate
        };
        Some((trimmed.to_string(), resolved))
    })
}

fn kind_label(kind: NtpConfigKind) -> &'static str {
    match kind {
        NtpConfigKind::Chrony => "chrony.conf",
        NtpConfigKind::Ntp => "ntp.conf",
        _ => "NTP 設定",
    }
}

/// `keys` ディレクティブが指すファイルの存在を監査する
///
/// chrony.conf / ntp.conf で `keys` を指定しながら、指定ファイルが存在しない場合は
/// NTP 認証（`keyfile` / `trustedkey`）が無効化されている可能性を警告する。
/// 相対パスは設定ファイルのディレクトリを基準に解決する。
fn audit_keys_file_presence(
    content: &str,
    kind: NtpConfigKind,
    config_path: &Path,
) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    for (raw, resolved) in iter_keys_paths(content, config_path) {
        if !resolved.exists() {
            findings.push(AuditFinding {
                kind: "ntp_keys_file_missing".to_string(),
                severity: Severity::Warning,
                message: format!(
                    "{} の `keys {}` が指定されていますが鍵ファイルが存在しません（NTP 認証が無効化されている可能性があります）",
                    kind_label(kind),
                    raw
                ),
            });
        }
    }
    findings
}

/// `keys` で指定された鍵ファイルの過剰パーミッションを監査する
///
/// world-readable（`o+r`）または world-writable（`o+w`）は共有鍵漏洩・改ざんの
/// リスクがあるため Warning を発行する。対象ファイルが存在しない場合や
/// メタデータ取得に失敗した場合は検知しない（存在確認は `audit_keys_file_presence`
/// が担当する）。
fn audit_keys_file_permissions(
    content: &str,
    kind: NtpConfigKind,
    config_path: &Path,
) -> Vec<AuditFinding> {
    use std::os::unix::fs::PermissionsExt;

    let mut findings = Vec::new();
    for (raw, resolved) in iter_keys_paths(content, config_path) {
        let metadata = match std::fs::metadata(&resolved) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !metadata.is_file() {
            continue;
        }
        let mode = metadata.permissions().mode() & 0o777;
        let world_readable = mode & 0o004 != 0;
        let world_writable = mode & 0o002 != 0;
        if !world_readable && !world_writable {
            continue;
        }
        let mut flags = Vec::new();
        if world_readable {
            flags.push("world-readable");
        }
        if world_writable {
            flags.push("world-writable");
        }
        findings.push(AuditFinding {
            kind: "ntp_keys_file_insecure_perms".to_string(),
            severity: Severity::Warning,
            message: format!(
                "{} の `keys {}` が指す鍵ファイルのパーミッションが過剰です (mode=0o{:o}, {}): 共有鍵が他ユーザに漏洩する恐れがあります",
                kind_label(kind),
                raw,
                mode,
                flags.join(" / ")
            ),
        });
    }
    findings
}

/// chrony.conf で `keys` を設定しているのに `trustedkey` が未設定の場合を監査する
///
/// `trustedkey` は NTP サーバ認証で信頼する key ID を指定するディレクティブで、
/// 設定されていないと鍵ファイルがあっても認証が実効的に機能しない。
fn audit_chrony_trustedkey_missing(content: &str) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    let has_keys = find_keyword_lines(content, "keys")
        .any(|v| !v.split_whitespace().next().unwrap_or("").trim().is_empty());
    if !has_keys {
        return findings;
    }
    let has_trustedkey = find_keyword_lines(content, "trustedkey").any(|v| !v.trim().is_empty());
    if !has_trustedkey {
        findings.push(AuditFinding {
            kind: "chrony_no_trustedkey".to_string(),
            severity: Severity::Warning,
            message:
                "chrony.conf で `keys` を設定していますが `trustedkey` が指定されていません（信頼する key ID が無いため NTP 認証が実効的に機能しません）"
                    .to_string(),
        });
    }
    findings
}

/// chrony.conf で `keys` を設定しているのに `authselectmode require` が
/// 指定されていない場合を監査する
///
/// 既定の `prefer` モードでは認証失敗時に非認証同期へフォールバックしてしまうため、
/// 認証運用時は `require` を明示するのが安全。未設定もしくは require 以外なら Info。
fn audit_chrony_authselectmode_weak(content: &str) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    let has_keys = find_keyword_lines(content, "keys")
        .any(|v| !v.split_whitespace().next().unwrap_or("").trim().is_empty());
    if !has_keys {
        return findings;
    }

    let mut authselectmode_value: Option<String> = None;
    for value in find_keyword_lines(content, "authselectmode") {
        let token = value.split_whitespace().next().unwrap_or("").trim();
        if !token.is_empty() {
            authselectmode_value = Some(token.to_ascii_lowercase());
        }
    }

    match authselectmode_value.as_deref() {
        Some("require") => {}
        Some(other) => findings.push(AuditFinding {
            kind: "chrony_authselectmode_weak".to_string(),
            severity: Severity::Info,
            message: format!(
                "chrony.conf の `authselectmode {}` は認証失敗時に非認証同期へフォールバックします（認証運用時は `authselectmode require` を推奨）",
                other
            ),
        }),
        None => findings.push(AuditFinding {
            kind: "chrony_authselectmode_weak".to_string(),
            severity: Severity::Info,
            message:
                "chrony.conf に `authselectmode` が設定されていません（既定の `prefer` は認証失敗時に非認証同期へフォールバックするため、認証運用時は `authselectmode require` を推奨）"
                    .to_string(),
        }),
    }
    findings
}

/// 種別に応じた監査関数をディスパッチする
fn audit_by_kind(
    kind: NtpConfigKind,
    content: &str,
    config: &NtpConfigMonitorConfig,
    config_path: &Path,
) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    match kind {
        NtpConfigKind::Timesyncd => {
            findings.extend(audit_timesyncd(content));
        }
        NtpConfigKind::Chrony => {
            findings.extend(audit_ntp_servers(content, kind));
            if config.check_chrony_allow {
                findings.extend(audit_chrony_allow(content));
            }
            if config.check_chrony_bindcmdaddress {
                findings.extend(audit_chrony_bindcmdaddress(content));
            }
            if config.check_driftfile_absolute {
                findings.extend(audit_driftfile_absolute(content, kind));
            }
            if config.check_chrony_cmdport_port {
                findings.extend(audit_chrony_cmdport_port(content));
            }
            if config.check_ntpsigndsocket {
                findings.extend(audit_ntpsigndsocket_public(content));
            }
            if config.check_keys_file_presence {
                findings.extend(audit_keys_file_presence(content, kind, config_path));
            }
            if config.check_keys_file_permissions {
                findings.extend(audit_keys_file_permissions(content, kind, config_path));
            }
            if config.check_chrony_trustedkey {
                findings.extend(audit_chrony_trustedkey_missing(content));
            }
            if config.check_chrony_authselectmode {
                findings.extend(audit_chrony_authselectmode_weak(content));
            }
        }
        NtpConfigKind::Ntp => {
            findings.extend(audit_ntp_servers(content, kind));
            if config.check_ntp_restrict {
                findings.extend(audit_ntp_restrict_default(content));
            }
            if config.check_driftfile_absolute {
                findings.extend(audit_driftfile_absolute(content, kind));
            }
            if config.check_keys_file_presence {
                findings.extend(audit_keys_file_presence(content, kind, config_path));
            }
            if config.check_keys_file_permissions {
                findings.extend(audit_keys_file_permissions(content, kind, config_path));
            }
        }
        NtpConfigKind::Unknown => {}
    }
    findings
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
            audit_by_kind(kind, &content, config, path)
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
        // ntp: サーバなし → Warning 1 件 + restrict default 欠如 → Warning 1 件 = 2 件
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
        assert_eq!(result.issues_found, 3);
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

    #[test]
    fn test_audit_chrony_allow_open_variants() {
        // 引数なしの allow → Warning
        let content = "allow\n";
        let findings = audit_chrony_allow(content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "chrony_allow_open");
        assert!(matches!(findings[0].severity, Severity::Warning));

        // allow all → Warning
        let content = "allow all\n";
        let findings = audit_chrony_allow(content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "chrony_allow_open");

        // allow 0.0.0.0/0 → Warning
        let content = "allow 0.0.0.0/0\n";
        let findings = audit_chrony_allow(content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "chrony_allow_open");

        // allow ::/0 → Warning
        let content = "allow ::/0\n";
        let findings = audit_chrony_allow(content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "chrony_allow_open");
    }

    #[test]
    fn test_audit_chrony_allow_specific_subnet_is_info() {
        let content = "allow 192.168.0.0/24\n";
        let findings = audit_chrony_allow(content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "chrony_allow_network");
        assert!(matches!(findings[0].severity, Severity::Info));
    }

    #[test]
    fn test_audit_chrony_allow_multiple_lines() {
        let content =
            "allow 10.0.0.0/8\nallow 0.0.0.0/0\n# allow should not count\nallow 192.168.1.0/24\n";
        let findings = audit_chrony_allow(content);
        assert_eq!(findings.len(), 3);
        let kinds: Vec<_> = findings.iter().map(|f| f.kind.as_str()).collect();
        assert_eq!(
            kinds,
            vec![
                "chrony_allow_network",
                "chrony_allow_open",
                "chrony_allow_network",
            ]
        );
    }

    #[test]
    fn test_audit_chrony_allow_none_returns_empty() {
        let content = "server time.example.com iburst\n# allow foo\n";
        let findings = audit_chrony_allow(content);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_chrony_bindcmdaddress_public_addrs() {
        for addr in ["0.0.0.0", "::", "*"] {
            let content = format!("bindcmdaddress {}\n", addr);
            let findings = audit_chrony_bindcmdaddress(&content);
            assert_eq!(findings.len(), 1, "addr={}", addr);
            assert_eq!(findings[0].kind, "chrony_bindcmd_public");
            assert!(matches!(findings[0].severity, Severity::Warning));
        }
    }

    #[test]
    fn test_audit_chrony_bindcmdaddress_localhost_is_ok() {
        for addr in ["127.0.0.1", "::1", "192.168.0.10"] {
            let content = format!("bindcmdaddress {}\n", addr);
            let findings = audit_chrony_bindcmdaddress(&content);
            assert!(findings.is_empty(), "addr={} should not warn", addr);
        }
    }

    #[test]
    fn test_audit_chrony_bindcmdaddress_absent_is_ok() {
        let content = "server foo\n# bindcmdaddress 0.0.0.0\n";
        let findings = audit_chrony_bindcmdaddress(content);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_ntp_restrict_default_missing_detects() {
        let content = "server 0.pool.ntp.org iburst\nrestrict 127.0.0.1\n";
        let findings = audit_ntp_restrict_default(content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "ntp_no_restrict_default");
        assert!(matches!(findings[0].severity, Severity::Warning));
    }

    #[test]
    fn test_audit_ntp_restrict_default_ignore_is_ok() {
        let content = "restrict default ignore\n";
        let findings = audit_ntp_restrict_default(content);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_ntp_restrict_default_limited_is_ok() {
        let content = "restrict default limited kod nomodify notrap nopeer noquery\n";
        let findings = audit_ntp_restrict_default(content);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_ntp_restrict_default_commented_detects() {
        let content = "# restrict default ignore\nserver foo\n";
        let findings = audit_ntp_restrict_default(content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "ntp_no_restrict_default");
    }

    #[test]
    fn test_audit_driftfile_absolute_ok() {
        let content = "driftfile /var/lib/chrony/drift\n";
        let findings = audit_driftfile_absolute(content, NtpConfigKind::Chrony);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_driftfile_relative_detects() {
        let content = "driftfile drift\n";
        let findings = audit_driftfile_absolute(content, NtpConfigKind::Chrony);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "driftfile_not_absolute");
        assert!(matches!(findings[0].severity, Severity::Info));
    }

    #[test]
    fn test_audit_driftfile_missing_no_finding() {
        let content = "server foo\n";
        let findings = audit_driftfile_absolute(content, NtpConfigKind::Chrony);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_driftfile_empty_value_detects() {
        let content = "driftfile \n";
        let findings = audit_driftfile_absolute(content, NtpConfigKind::Chrony);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "driftfile_not_absolute");
    }

    #[test]
    fn test_audit_by_kind_chrony_flags_disable_individual_checks() {
        // chrony の allow/bindcmd をトリガーしつつ、サーバと makestep は設定済みにしておく
        let content =
            "pool foo\nmakestep 1.0 3\nallow all\nbindcmdaddress 0.0.0.0\ndriftfile drift\n";
        let path = Path::new("/etc/chrony/chrony.conf");

        // 全フラグ有効（デフォルト） → allow / bindcmd / driftfile の 3 件
        let mut config = NtpConfigMonitorConfig::default();
        let findings = audit_by_kind(NtpConfigKind::Chrony, content, &config, path);
        assert_eq!(findings.len(), 3);

        // allow のみ無効 → bindcmd / driftfile の 2 件
        config.check_chrony_allow = false;
        let findings = audit_by_kind(NtpConfigKind::Chrony, content, &config, path);
        assert_eq!(findings.len(), 2);
        assert!(
            findings
                .iter()
                .all(|f| f.kind != "chrony_allow_open" && f.kind != "chrony_allow_network")
        );

        // bindcmd も無効 → driftfile 1 件
        config.check_chrony_bindcmdaddress = false;
        let findings = audit_by_kind(NtpConfigKind::Chrony, content, &config, path);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "driftfile_not_absolute");

        // driftfile も無効 → 0 件
        config.check_driftfile_absolute = false;
        let findings = audit_by_kind(NtpConfigKind::Chrony, content, &config, path);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_by_kind_ntp_restrict_flag() {
        // ntp.conf: server あり / restrict default 無し / driftfile 相対
        let content = "server 0.pool.ntp.org iburst\ndriftfile drift\n";
        let path = Path::new("/etc/ntp.conf");

        // 全フラグ有効 → restrict 欠如 + driftfile 相対の 2 件
        let mut config = NtpConfigMonitorConfig::default();
        let findings = audit_by_kind(NtpConfigKind::Ntp, content, &config, path);
        assert_eq!(findings.len(), 2);

        // restrict チェック無効 → driftfile のみ
        config.check_ntp_restrict = false;
        let findings = audit_by_kind(NtpConfigKind::Ntp, content, &config, path);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "driftfile_not_absolute");

        // driftfile チェック無効 → 0 件
        config.check_driftfile_absolute = false;
        let findings = audit_by_kind(NtpConfigKind::Ntp, content, &config, path);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_by_kind_timesyncd_unaffected_by_new_flags() {
        // timesyncd は新しいフラグの影響を受けない
        let content = "[Time]\n#NTP=\n#FallbackNTP=\n";
        let config = NtpConfigMonitorConfig {
            check_chrony_allow: false,
            check_chrony_bindcmdaddress: false,
            check_ntp_restrict: false,
            check_driftfile_absolute: false,
            check_chrony_cmdport_port: false,
            check_ntpsigndsocket: false,
            check_keys_file_presence: false,
            check_keys_file_permissions: false,
            check_chrony_trustedkey: false,
            check_chrony_authselectmode: false,
            ..Default::default()
        };
        let findings = audit_by_kind(
            NtpConfigKind::Timesyncd,
            content,
            &config,
            Path::new("/etc/systemd/timesyncd.conf"),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "timesyncd_no_servers");
    }

    // ------------------------------------------------------------------
    // audit_chrony_cmdport_port
    // ------------------------------------------------------------------
    #[test]
    fn test_audit_chrony_cmdport_default_no_finding() {
        let content = "cmdport 323\nport 123\n";
        let findings = audit_chrony_cmdport_port(content);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_chrony_cmdport_non_default_detects() {
        let content = "cmdport 12345\n";
        let findings = audit_chrony_cmdport_port(content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "chrony_cmdport_non_default");
        assert!(matches!(findings[0].severity, Severity::Info));
        assert!(findings[0].message.contains("12345"));
    }

    #[test]
    fn test_audit_chrony_cmdport_zero_is_reported() {
        // cmdport 0 は意図的な無効化でも「既定と異なる」という情報提示は残す
        let content = "cmdport 0\n";
        let findings = audit_chrony_cmdport_port(content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "chrony_cmdport_non_default");
    }

    #[test]
    fn test_audit_chrony_port_non_default_detects() {
        let content = "port 1234\n";
        let findings = audit_chrony_cmdport_port(content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "chrony_port_non_default");
        assert!(matches!(findings[0].severity, Severity::Info));
    }

    #[test]
    fn test_audit_chrony_cmdport_and_port_both_nonstandard() {
        let content = "cmdport 999\nport 888\n";
        let findings = audit_chrony_cmdport_port(content);
        assert_eq!(findings.len(), 2);
        let kinds: Vec<_> = findings.iter().map(|f| f.kind.as_str()).collect();
        assert!(kinds.contains(&"chrony_cmdport_non_default"));
        assert!(kinds.contains(&"chrony_port_non_default"));
    }

    #[test]
    fn test_audit_chrony_cmdport_absent_no_finding() {
        let content = "server foo\n# cmdport 999\n";
        let findings = audit_chrony_cmdport_port(content);
        assert!(findings.is_empty());
    }

    // ------------------------------------------------------------------
    // audit_ntpsigndsocket_public
    // ------------------------------------------------------------------
    #[test]
    fn test_audit_ntpsigndsocket_public_risky_prefixes() {
        for path in [
            "/tmp/chrony.sock",
            "/var/tmp/chrony.sock",
            "/dev/shm/chrony.sock",
        ] {
            let content = format!("ntpsigndsocket {}\n", path);
            let findings = audit_ntpsigndsocket_public(&content);
            assert_eq!(findings.len(), 1, "path={}", path);
            assert_eq!(findings[0].kind, "chrony_ntpsigndsocket_public");
            assert!(matches!(findings[0].severity, Severity::Warning));
            assert!(findings[0].message.contains(path));
        }
    }

    #[test]
    fn test_audit_ntpsigndsocket_safe_paths() {
        for path in [
            "/var/lib/samba/ntp_signd/socket",
            "/run/chrony/ntp.signd",
            "/var/run/chrony.signd",
        ] {
            let content = format!("ntpsigndsocket {}\n", path);
            let findings = audit_ntpsigndsocket_public(&content);
            assert!(findings.is_empty(), "path={} should not warn", path);
        }
    }

    #[test]
    fn test_audit_ntpsigndsocket_empty_no_finding() {
        // 空値・未指定は検知しない
        let content = "ntpsigndsocket \n";
        let findings = audit_ntpsigndsocket_public(content);
        assert!(findings.is_empty());
        let content = "server foo\n";
        let findings = audit_ntpsigndsocket_public(content);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_ntpsigndsocket_commented_ignored() {
        let content = "# ntpsigndsocket /tmp/foo\n";
        let findings = audit_ntpsigndsocket_public(content);
        assert!(findings.is_empty());
    }

    // ------------------------------------------------------------------
    // audit_keys_file_presence
    // ------------------------------------------------------------------
    #[test]
    fn test_audit_keys_file_missing_absolute_detects() {
        let content = "keys /nonexistent/zettai-mamorukun/keys.file\n";
        let findings = audit_keys_file_presence(
            content,
            NtpConfigKind::Chrony,
            Path::new("/etc/chrony/chrony.conf"),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "ntp_keys_file_missing");
        assert!(matches!(findings[0].severity, Severity::Warning));
        assert!(findings[0].message.contains("chrony.conf"));
    }

    #[test]
    fn test_audit_keys_file_present_absolute_no_finding() {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys.file");
        std::fs::write(&keys, "1 MD5 key\n").unwrap();
        let content = format!("keys {}\n", keys.display());
        let findings = audit_keys_file_presence(
            &content,
            NtpConfigKind::Chrony,
            Path::new("/etc/chrony/chrony.conf"),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_keys_file_relative_resolved_from_config_dir() {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("chrony.keys");
        std::fs::write(&keys, "1 MD5 key\n").unwrap();
        let config_path = dir.path().join("chrony.conf");

        // 相対パスで指定 → 設定ファイルのディレクトリから解決され、存在するので検知なし
        let content = "keys chrony.keys\n";
        let findings = audit_keys_file_presence(content, NtpConfigKind::Chrony, &config_path);
        assert!(findings.is_empty());

        // 相対パス・別名で不在 → 検知
        let content = "keys missing.keys\n";
        let findings = audit_keys_file_presence(content, NtpConfigKind::Chrony, &config_path);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "ntp_keys_file_missing");
    }

    #[test]
    fn test_audit_keys_file_ntp_label_used_for_ntp_conf() {
        let content = "keys /nope/ntp.keys\n";
        let findings =
            audit_keys_file_presence(content, NtpConfigKind::Ntp, Path::new("/etc/ntp.conf"));
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("ntp.conf"));
    }

    #[test]
    fn test_audit_keys_file_no_directive_no_finding() {
        let content = "server 0.pool.ntp.org iburst\n# keys /etc/nope\n";
        let findings = audit_keys_file_presence(
            content,
            NtpConfigKind::Chrony,
            Path::new("/etc/chrony/chrony.conf"),
        );
        assert!(findings.is_empty());
    }

    // ------------------------------------------------------------------
    // audit_by_kind: 新フラグの有効/無効切替
    // ------------------------------------------------------------------
    #[test]
    fn test_audit_by_kind_chrony_new_flags_toggle() {
        // pool + makestep は正常。cmdport/port 非既定、ntpsigndsocket を /tmp/ に配置、
        // keys に不在ファイルを指定 → 新ルール 4 件（cmdport + port + ntpsigndsocket + keys）
        let content = "pool foo\nmakestep 1.0 3\ncmdport 5000\nport 6000\nntpsigndsocket /tmp/s\nkeys /nope/keys\n";
        let path = Path::new("/etc/chrony/chrony.conf");

        let mut config = NtpConfigMonitorConfig::default();
        let findings = audit_by_kind(NtpConfigKind::Chrony, content, &config, path);
        let kinds: Vec<_> = findings.iter().map(|f| f.kind.as_str()).collect();
        assert!(kinds.contains(&"chrony_cmdport_non_default"));
        assert!(kinds.contains(&"chrony_port_non_default"));
        assert!(kinds.contains(&"chrony_ntpsigndsocket_public"));
        assert!(kinds.contains(&"ntp_keys_file_missing"));

        // cmdport/port チェック無効 → 2 件だけ減る
        config.check_chrony_cmdport_port = false;
        let findings = audit_by_kind(NtpConfigKind::Chrony, content, &config, path);
        assert!(
            findings
                .iter()
                .all(|f| f.kind != "chrony_cmdport_non_default"
                    && f.kind != "chrony_port_non_default")
        );
        assert!(
            findings
                .iter()
                .any(|f| f.kind == "chrony_ntpsigndsocket_public")
        );
        assert!(findings.iter().any(|f| f.kind == "ntp_keys_file_missing"));

        // ntpsigndsocket も無効
        config.check_ntpsigndsocket = false;
        let findings = audit_by_kind(NtpConfigKind::Chrony, content, &config, path);
        assert!(
            findings
                .iter()
                .all(|f| f.kind != "chrony_ntpsigndsocket_public")
        );
        assert!(findings.iter().any(|f| f.kind == "ntp_keys_file_missing"));

        // keys チェックも無効 → 新ルール由来の finding は 0 件
        config.check_keys_file_presence = false;
        let findings = audit_by_kind(NtpConfigKind::Chrony, content, &config, path);
        assert!(
            findings
                .iter()
                .all(|f| f.kind != "chrony_cmdport_non_default"
                    && f.kind != "chrony_port_non_default"
                    && f.kind != "chrony_ntpsigndsocket_public"
                    && f.kind != "ntp_keys_file_missing")
        );
    }

    #[test]
    fn test_audit_by_kind_ntp_keys_flag_toggle() {
        // ntp.conf に restrict default を設定して他のルールは抑制、
        // driftfile 絶対パス、keys 不在のみ残す
        let content = "server 0.pool.ntp.org iburst\nrestrict default ignore\ndriftfile /var/ntp.drift\nkeys /nope/keys\n";
        let path = Path::new("/etc/ntp.conf");

        let mut config = NtpConfigMonitorConfig::default();
        let findings = audit_by_kind(NtpConfigKind::Ntp, content, &config, path);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "ntp_keys_file_missing");

        config.check_keys_file_presence = false;
        let findings = audit_by_kind(NtpConfigKind::Ntp, content, &config, path);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_scan_file_resolves_relative_keys_relative_to_config_dir() {
        // scan_config_file 経由でも相対パスが正しく解決されることを確認
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("chrony.keys");
        std::fs::write(&keys, "1 MD5 key\n").unwrap();

        let path = dir.path().join("chrony.conf");
        std::fs::write(
            &path,
            "pool 2.pool.ntp.org iburst\nmakestep 1.0 3\nkeys chrony.keys\n",
        )
        .unwrap();

        let config = NtpConfigMonitorConfig::default();
        let (_, findings) = NtpConfigMonitorModule::scan_config_file(&path, &config)
            .expect("scan ok")
            .expect("file present");
        assert!(
            findings.iter().all(|f| f.kind != "ntp_keys_file_missing"),
            "expected no keys-missing finding, got: {:?}",
            findings
        );
    }

    // ------------------------------------------------------------------
    // audit_keys_file_permissions
    // ------------------------------------------------------------------
    #[test]
    fn test_audit_keys_file_permissions_world_readable_detects() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("chrony.keys");
        std::fs::write(&keys, "1 MD5 secret\n").unwrap();
        // 0o644 は world-readable
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o644)).unwrap();

        let content = format!("keys {}\n", keys.display());
        let findings = audit_keys_file_permissions(
            &content,
            NtpConfigKind::Chrony,
            Path::new("/etc/chrony/chrony.conf"),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "ntp_keys_file_insecure_perms");
        assert!(matches!(findings[0].severity, Severity::Warning));
        assert!(findings[0].message.contains("world-readable"));
    }

    #[test]
    fn test_audit_keys_file_permissions_world_writable_detects() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("chrony.keys");
        std::fs::write(&keys, "1 MD5 secret\n").unwrap();
        // 0o622: owner rw / group w / other w — world-writable only
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o622)).unwrap();

        let content = format!("keys {}\n", keys.display());
        let findings = audit_keys_file_permissions(
            &content,
            NtpConfigKind::Chrony,
            Path::new("/etc/chrony/chrony.conf"),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "ntp_keys_file_insecure_perms");
        assert!(findings[0].message.contains("world-writable"));
        assert!(!findings[0].message.contains("world-readable"));
    }

    #[test]
    fn test_audit_keys_file_permissions_both_world_perms() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("chrony.keys");
        std::fs::write(&keys, "1 MD5 secret\n").unwrap();
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o666)).unwrap();

        let content = format!("keys {}\n", keys.display());
        let findings = audit_keys_file_permissions(
            &content,
            NtpConfigKind::Chrony,
            Path::new("/etc/chrony/chrony.conf"),
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("world-readable"));
        assert!(findings[0].message.contains("world-writable"));
    }

    #[test]
    fn test_audit_keys_file_permissions_safe_mode_no_finding() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("chrony.keys");
        std::fs::write(&keys, "1 MD5 secret\n").unwrap();
        // 0o600: owner のみ rw
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o600)).unwrap();

        let content = format!("keys {}\n", keys.display());
        let findings = audit_keys_file_permissions(
            &content,
            NtpConfigKind::Chrony,
            Path::new("/etc/chrony/chrony.conf"),
        );
        assert!(findings.is_empty());

        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o640)).unwrap();
        let findings = audit_keys_file_permissions(
            &content,
            NtpConfigKind::Chrony,
            Path::new("/etc/chrony/chrony.conf"),
        );
        assert!(findings.is_empty(), "group-read は許容されるべき");
    }

    #[test]
    fn test_audit_keys_file_permissions_missing_file_no_finding() {
        // ファイルが存在しない場合は permission チェックは検知しない
        // (存在チェックは audit_keys_file_presence の責務)
        let content = "keys /nonexistent/zettai/keys.file\n";
        let findings = audit_keys_file_permissions(
            content,
            NtpConfigKind::Chrony,
            Path::new("/etc/chrony/chrony.conf"),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_keys_file_permissions_ntp_kind_label() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("ntp.keys");
        std::fs::write(&keys, "1 MD5 secret\n").unwrap();
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o644)).unwrap();

        let content = format!("keys {}\n", keys.display());
        let findings =
            audit_keys_file_permissions(&content, NtpConfigKind::Ntp, Path::new("/etc/ntp.conf"));
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("ntp.conf"));
    }

    // ------------------------------------------------------------------
    // audit_chrony_trustedkey_missing
    // ------------------------------------------------------------------
    #[test]
    fn test_audit_chrony_trustedkey_missing_when_keys_set() {
        let content = "keys /etc/chrony.keys\nserver foo\n";
        let findings = audit_chrony_trustedkey_missing(content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "chrony_no_trustedkey");
        assert!(matches!(findings[0].severity, Severity::Warning));
    }

    #[test]
    fn test_audit_chrony_trustedkey_present_no_finding() {
        let content = "keys /etc/chrony.keys\ntrustedkey 1 2\n";
        let findings = audit_chrony_trustedkey_missing(content);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_chrony_trustedkey_no_keys_no_finding() {
        // keys が無ければ trustedkey 未設定でも検知しない
        let content = "server foo\n";
        let findings = audit_chrony_trustedkey_missing(content);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_chrony_trustedkey_empty_value_detects() {
        // trustedkey が空白のみの値しか無ければ未設定扱い
        let content = "keys /etc/chrony.keys\ntrustedkey    \n";
        let findings = audit_chrony_trustedkey_missing(content);
        assert_eq!(findings.len(), 1);
    }

    // ------------------------------------------------------------------
    // audit_chrony_authselectmode_weak
    // ------------------------------------------------------------------
    #[test]
    fn test_audit_chrony_authselectmode_missing_when_keys_set() {
        let content = "keys /etc/chrony.keys\ntrustedkey 1\n";
        let findings = audit_chrony_authselectmode_weak(content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "chrony_authselectmode_weak");
        assert!(matches!(findings[0].severity, Severity::Info));
        assert!(findings[0].message.contains("authselectmode"));
    }

    #[test]
    fn test_audit_chrony_authselectmode_require_no_finding() {
        let content = "keys /etc/chrony.keys\nauthselectmode require\n";
        let findings = audit_chrony_authselectmode_weak(content);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_chrony_authselectmode_require_case_insensitive() {
        let content = "keys /etc/chrony.keys\nauthselectmode REQUIRE\n";
        let findings = audit_chrony_authselectmode_weak(content);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_chrony_authselectmode_prefer_detects() {
        let content = "keys /etc/chrony.keys\nauthselectmode prefer\n";
        let findings = audit_chrony_authselectmode_weak(content);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("prefer"));
    }

    #[test]
    fn test_audit_chrony_authselectmode_mix_detects() {
        let content = "keys /etc/chrony.keys\nauthselectmode mix\n";
        let findings = audit_chrony_authselectmode_weak(content);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("mix"));
    }

    #[test]
    fn test_audit_chrony_authselectmode_no_keys_no_finding() {
        // keys 未指定なら authselectmode 設定が無くても検知しない
        let content = "server foo\n";
        let findings = audit_chrony_authselectmode_weak(content);
        assert!(findings.is_empty());
    }

    // ------------------------------------------------------------------
    // audit_by_kind: 新フラグの切替
    // ------------------------------------------------------------------
    #[test]
    fn test_audit_by_kind_chrony_auth_flags_toggle() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let keys_path = dir.path().join("chrony.keys");
        std::fs::write(&keys_path, "1 MD5 secret\n").unwrap();
        std::fs::set_permissions(&keys_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let config_path = dir.path().join("chrony.conf");

        // pool + makestep で基本ルールは抑制、keys あり & world-readable、
        // trustedkey / authselectmode 未設定
        let content = format!(
            "pool 2.pool.ntp.org iburst\nmakestep 1.0 3\nkeys {}\n",
            keys_path.display()
        );

        let mut config = NtpConfigMonitorConfig::default();
        let findings = audit_by_kind(NtpConfigKind::Chrony, &content, &config, &config_path);
        let kinds: Vec<_> = findings.iter().map(|f| f.kind.as_str()).collect();
        assert!(kinds.contains(&"ntp_keys_file_insecure_perms"));
        assert!(kinds.contains(&"chrony_no_trustedkey"));
        assert!(kinds.contains(&"chrony_authselectmode_weak"));

        // 各フラグを順に無効化
        config.check_keys_file_permissions = false;
        let findings = audit_by_kind(NtpConfigKind::Chrony, &content, &config, &config_path);
        assert!(
            findings
                .iter()
                .all(|f| f.kind != "ntp_keys_file_insecure_perms")
        );
        assert!(findings.iter().any(|f| f.kind == "chrony_no_trustedkey"));
        assert!(
            findings
                .iter()
                .any(|f| f.kind == "chrony_authselectmode_weak")
        );

        config.check_chrony_trustedkey = false;
        let findings = audit_by_kind(NtpConfigKind::Chrony, &content, &config, &config_path);
        assert!(findings.iter().all(|f| f.kind != "chrony_no_trustedkey"));
        assert!(
            findings
                .iter()
                .any(|f| f.kind == "chrony_authselectmode_weak")
        );

        config.check_chrony_authselectmode = false;
        let findings = audit_by_kind(NtpConfigKind::Chrony, &content, &config, &config_path);
        assert!(
            findings
                .iter()
                .all(|f| f.kind != "ntp_keys_file_insecure_perms"
                    && f.kind != "chrony_no_trustedkey"
                    && f.kind != "chrony_authselectmode_weak")
        );
    }

    #[test]
    fn test_audit_by_kind_ntp_keys_permissions_flag() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let keys_path = dir.path().join("ntp.keys");
        std::fs::write(&keys_path, "1 MD5 secret\n").unwrap();
        std::fs::set_permissions(&keys_path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let config_path = dir.path().join("ntp.conf");

        let content = format!(
            "server 0.pool.ntp.org iburst\nrestrict default ignore\ndriftfile /var/ntp.drift\nkeys {}\n",
            keys_path.display()
        );

        let mut config = NtpConfigMonitorConfig::default();
        let findings = audit_by_kind(NtpConfigKind::Ntp, &content, &config, &config_path);
        // ntp では trustedkey/authselectmode は検知しない
        assert!(findings.iter().all(|f| f.kind != "chrony_no_trustedkey"
            && f.kind != "chrony_authselectmode_weak"));
        assert!(
            findings
                .iter()
                .any(|f| f.kind == "ntp_keys_file_insecure_perms")
        );

        config.check_keys_file_permissions = false;
        let findings = audit_by_kind(NtpConfigKind::Ntp, &content, &config, &config_path);
        assert!(findings.is_empty());
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
