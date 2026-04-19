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
//!   - 設定ファイル本体の所有者 uid / gid が許容リスト外（既定: root のみ許容）
//!     — 権限昇格の足場となる所有者改ざんを検知
//!   - `keys` で指定された鍵ファイルの所有者 uid / gid が許容リスト外
//!   - `chrony.conf`: `leapsectz` 未設定（うるう秒情報ソースが指定されていない）
//!   - `chrony.conf`: `maxsamples` が閾値未満（0=無制限を除く。NTP フィルタアルゴリズムの
//!     サンプル数不足による時刻精度・外れ値耐性低下）
//!   - `chrony.conf`: `minsamples > maxsamples`（同期に必要なサンプル数が採取できない
//!     設定矛盾）
//!   - `chrony.conf`: `refclock` ディレクティブで `allowed_refclock_drivers` に
//!     含まれないドライバが使われている（特に `SHM` は /dev/shm 経由の時刻注入攻撃
//!     の足場となりうる）
//!   - `chrony.conf`: `rtcsync` ディレクティブ未設定（Linux で推奨される RTC
//!     定期書き戻しが無効化されており、サーバ再起動直後の時刻ずれによる
//!     ログ不整合・証明書検証エラー・TOTP / Kerberos 失敗を招くリスク）
//!   - `chrony.conf`: `rtcfile` が指定されているが絶対パスでない（`driftfile` と同様、
//!     chronyd の作業ディレクトリ依存の書き込みとなり RTC ドリフト情報が
//!     意図しない位置に保存される）
//! - **ドロップイン監視** — `chrony.conf` 内の `confdir` / `sourcedir` / `include`
//!   ディレクティブで参照される追加設定ファイル（例: `/etc/chrony/conf.d/*.conf`、
//!   `/etc/chrony/sources.d/*.sources`）も監視対象に加え、親ディレクトリも inotify
//!   watch に登録することで、メインの `chrony.conf` を書き換えずにドロップイン経由で
//!   NTP サーバ偽装や同期停止を行う攻撃を検知する。
//!
//! 攻撃者は時刻同期を無効化しログのタイムスタンプを改ざんすることで、フォレンジック
//! 調査を妨害することがあるため、設定ファイルの変更検知と危険設定の検知が重要である。

use crate::config::NtpConfigMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::core::module_stats::ModuleStatsHandle;
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use glob::glob;
use inotify::{Inotify, WatchDescriptor, WatchMask};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
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

/// 指定された uid / gid が許容リストに含まれるかを判定する
fn owner_uid_allowed(uid: u32, allowed: &[u32]) -> bool {
    allowed.is_empty() || allowed.contains(&uid)
}

fn owner_gid_allowed(gid: u32, allowed: &[u32]) -> bool {
    allowed.is_empty() || allowed.contains(&gid)
}

fn format_uid_list(uids: &[u32]) -> String {
    if uids.is_empty() {
        "(許容リスト空)".to_string()
    } else {
        uids.iter()
            .map(|u| u.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// NTP 設定ファイル自体の所有者・グループを監査する
///
/// 設定ファイル（chrony.conf / ntp.conf / timesyncd.conf）の uid / gid が
/// 許容リストから外れている場合、root 以外のユーザが設定を改変可能な状態となり、
/// 時刻同期の妨害や鍵ファイル経路の書き換えによる権限昇格の足場となりうる。
fn audit_config_file_owner(
    metadata: &std::fs::Metadata,
    path: &Path,
    config: &NtpConfigMonitorConfig,
) -> Vec<AuditFinding> {
    use std::os::unix::fs::MetadataExt;

    let mut findings = Vec::new();
    let uid = metadata.uid();
    let gid = metadata.gid();

    if !owner_uid_allowed(uid, &config.allowed_owner_uids) {
        findings.push(AuditFinding {
            kind: "ntp_config_insecure_owner".to_string(),
            severity: Severity::Warning,
            message: format!(
                "NTP 設定ファイル {} の所有者 uid={} が許容リスト ({}) に含まれていません（root 以外が所有する設定ファイルは権限昇格の足場となりえます）",
                path.display(),
                uid,
                format_uid_list(&config.allowed_owner_uids)
            ),
        });
    }

    if !owner_gid_allowed(gid, &config.allowed_owner_gids) {
        findings.push(AuditFinding {
            kind: "ntp_config_insecure_group".to_string(),
            severity: Severity::Warning,
            message: format!(
                "NTP 設定ファイル {} の所有グループ gid={} が許容リスト ({}) に含まれていません（書き込み権限を持つグループ経由での改ざんリスクがあります）",
                path.display(),
                gid,
                format_uid_list(&config.allowed_owner_gids)
            ),
        });
    }

    findings
}

/// `keys` で指定された鍵ファイルの所有者・グループを監査する
///
/// keys ファイルの uid / gid が許容リストから外れている場合、共有鍵が第三者の
/// 制御下にあり、認証情報の漏洩や書き換えが可能な状態を示す。対象ファイルが
/// 存在しない / メタデータ取得に失敗した場合は検知しない（存在確認は
/// `audit_keys_file_presence` の責務）。
fn audit_keys_file_owner(
    content: &str,
    kind: NtpConfigKind,
    config_path: &Path,
    config: &NtpConfigMonitorConfig,
) -> Vec<AuditFinding> {
    use std::os::unix::fs::MetadataExt;

    let mut findings = Vec::new();
    for (raw, resolved) in iter_keys_paths(content, config_path) {
        let metadata = match std::fs::metadata(&resolved) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !metadata.is_file() {
            continue;
        }
        let uid = metadata.uid();
        let gid = metadata.gid();

        if !owner_uid_allowed(uid, &config.allowed_owner_uids) {
            findings.push(AuditFinding {
                kind: "ntp_keys_file_insecure_owner".to_string(),
                severity: Severity::Warning,
                message: format!(
                    "{} の `keys {}` が指す鍵ファイルの所有者 uid={} が許容リスト ({}) に含まれていません（共有鍵の所有者改ざんは認証情報漏洩につながります）",
                    kind_label(kind),
                    raw,
                    uid,
                    format_uid_list(&config.allowed_owner_uids)
                ),
            });
        }

        if !owner_gid_allowed(gid, &config.allowed_owner_gids) {
            findings.push(AuditFinding {
                kind: "ntp_keys_file_insecure_group".to_string(),
                severity: Severity::Warning,
                message: format!(
                    "{} の `keys {}` が指す鍵ファイルの所有グループ gid={} が許容リスト ({}) に含まれていません",
                    kind_label(kind),
                    raw,
                    gid,
                    format_uid_list(&config.allowed_owner_gids)
                ),
            });
        }
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

/// chrony.conf の `leapsectz` が設定されていない場合を監査する
///
/// `leapsectz` は tzdata の閏秒情報ゾーン名（通常 `right/UTC`）を指定するディレクティブで、
/// 未設定の場合 chrony はサーバが通知する `Leap Indicator` のみに依存するため、閏秒挿入時
/// に時刻 step または周波数補正のズレが生じやすくなる。Info で警告する。
fn audit_chrony_leapsectz_missing(content: &str) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    let has_leapsectz = find_keyword_lines(content, "leapsectz")
        .any(|v| !v.split_whitespace().next().unwrap_or("").trim().is_empty());
    if !has_leapsectz {
        findings.push(AuditFinding {
            kind: "chrony_leapsectz_missing".to_string(),
            severity: Severity::Info,
            message:
                "chrony.conf に `leapsectz` が設定されていません（閏秒情報ソースが未指定のため、閏秒挿入時の動作が不安定になる可能性があります。tzdata ゾーン `right/UTC` の指定を推奨）"
                    .to_string(),
        });
    }
    findings
}

/// chrony.conf の top-level ディレクティブから整数値をパースする
///
/// `find_keyword_lines` は行頭トークンが一致した行のみ返すため、`server ... maxsamples N`
/// のような inline オプションには一致せず、top-level 設定だけを拾える。
/// 複数行がある場合は後者が優先。
fn parse_chrony_top_level_u32(content: &str, keyword: &str) -> Option<u32> {
    let mut last: Option<u32> = None;
    for value in find_keyword_lines(content, keyword) {
        let token = value.split_whitespace().next().unwrap_or("").trim();
        if let Ok(n) = token.parse::<u32>() {
            last = Some(n);
        }
    }
    last
}

/// chrony.conf の `maxsamples` / `minsamples` のサンプル数設定を監査する
///
/// - `maxsamples` が 0（= 無制限）を除き閾値未満 → `chrony_maxsamples_too_low` (Warning)
///   - NTP フィルタアルゴリズムが少ないサンプルで動作し、外れ値・ジッター耐性が低下する
/// - `minsamples > maxsamples`（両方設定かつ maxsamples != 0） → `chrony_minsamples_exceeds_maxsamples`
///   (Warning) — 設定矛盾により必要サンプル数が採取できない
fn audit_chrony_sample_counts(content: &str, maxsamples_min_threshold: u32) -> Vec<AuditFinding> {
    let mut findings = Vec::new();

    let maxsamples = parse_chrony_top_level_u32(content, "maxsamples");
    let minsamples = parse_chrony_top_level_u32(content, "minsamples");

    if let Some(max) = maxsamples
        && max != 0
        && max < maxsamples_min_threshold
    {
        findings.push(AuditFinding {
            kind: "chrony_maxsamples_too_low".to_string(),
            severity: Severity::Warning,
            message: format!(
                "chrony.conf の `maxsamples {}` は推奨値（{} 以上）を下回っています（NTP フィルタリングのサンプル数が不足し、時刻精度や外れ値耐性が低下します）",
                max, maxsamples_min_threshold
            ),
        });
    }

    if let (Some(max), Some(min)) = (maxsamples, minsamples)
        && max != 0
        && min > max
    {
        findings.push(AuditFinding {
            kind: "chrony_minsamples_exceeds_maxsamples".to_string(),
            severity: Severity::Warning,
            message: format!(
                "chrony.conf の `minsamples {}` が `maxsamples {}` を超えています（設定矛盾のため必要なサンプル数が採取されず、時刻同期が正常に機能しない可能性があります）",
                min, max
            ),
        });
    }

    findings
}

/// chrony.conf の `refclock` ディレクティブを監査する
///
/// 各 `refclock <driver> <parameters>` 行からドライバ名を抽出し、
/// `allowed_drivers`（大文字小文字無視）に含まれないドライバが使われていれば
/// Warning を発行する。特に `SHM` ドライバは /dev/shm 配下の共有メモリセグメントを
/// 時刻ソースとして参照するため、攻撃者が SHM セグメントへの書き込み権限を得ていれば
/// 任意の時刻を注入可能になる。明示的に許可されていない場合は SHM 固有の
/// 追加メッセージを付与する。
fn audit_chrony_refclock(content: &str, allowed_drivers: &[String]) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    let allowed_upper: BTreeSet<String> = allowed_drivers
        .iter()
        .map(|d| d.trim().to_ascii_uppercase())
        .filter(|d| !d.is_empty())
        .collect();
    let mut reported: BTreeSet<String> = BTreeSet::new();

    for value in find_keyword_lines(content, "refclock") {
        let driver = match value.split_whitespace().next() {
            Some(d) if !d.is_empty() => d,
            _ => continue,
        };
        let driver_upper = driver.to_ascii_uppercase();
        if allowed_upper.contains(&driver_upper) {
            continue;
        }
        if !reported.insert(driver_upper.clone()) {
            continue;
        }
        let suffix = if driver_upper == "SHM" {
            "（SHM refclock is a known time-injection attack vector — 書き込み可能な SHM セグメントを共有するプロセスから時刻を偽装される恐れがあります）"
        } else {
            ""
        };
        findings.push(AuditFinding {
            kind: "chrony_refclock_unexpected".to_string(),
            severity: Severity::Warning,
            message: format!(
                "chrony.conf に想定外の refclock ドライバ `{}` が設定されています。\
                 `allowed_refclock_drivers` に明示的に追加されていないドライバは外部時刻ソース偽装の原因になりうるため確認してください{}",
                driver, suffix
            ),
        });
    }
    findings
}

/// chrony.conf の `rtcsync` ディレクティブが設定されていない場合を監査する
///
/// `rtcsync` は Linux で system clock を RTC（ハードウェアクロック）に 11 分ごとに
/// 書き戻す設定で、chrony 公式ドキュメントで有効化が推奨されている。欠如すると
/// chronyd 停止中の RTC が補正されず、サーバ再起動直後に NTP 同期が確立するまでの間
/// システム時刻が大きくずれる可能性がある。時刻ずれは TLS 証明書検証の誤動作・
/// ログのタイムスタンプ不整合によるフォレンジック妨害・TOTP/Kerberos 認証の失敗
/// 等の二次被害を招くため Warning を発行する。
fn audit_chrony_rtcsync_missing(content: &str) -> Vec<AuditFinding> {
    let has_rtcsync = find_keyword_lines(content, "rtcsync").next().is_some();
    if has_rtcsync {
        return Vec::new();
    }
    vec![AuditFinding {
        kind: "chrony_rtcsync_missing".to_string(),
        severity: Severity::Warning,
        message:
            "chrony.conf に `rtcsync` が設定されていません（Linux では RTC への定期書き戻しが推奨されます。欠如するとサーバ再起動直後の時刻ずれによりログ不整合・証明書検証エラー・TOTP/Kerberos 認証失敗などの二次被害を招く可能性があります）"
                .to_string(),
    }]
}

/// chrony.conf の `rtcfile` が指定されているときに絶対パスかを監査する
///
/// `rtcfile` は RTC ドリフト情報の保存先ファイルパス。相対パス指定の場合
/// chronyd の作業ディレクトリ依存の書き込みとなり、意図しない位置に
/// ドリフト情報が残留する恐れがある。`driftfile` と同じパターンで Info を発行する。
fn audit_chrony_rtcfile_absolute(content: &str) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    for value in find_keyword_lines(content, "rtcfile") {
        let trimmed = value.trim();
        let path_value = trimmed.split_whitespace().next().unwrap_or("");
        if path_value.is_empty() || !path_value.starts_with('/') {
            findings.push(AuditFinding {
                kind: "chrony_rtcfile_not_absolute".to_string(),
                severity: Severity::Info,
                message: format!(
                    "chrony.conf の `rtcfile` が絶対パスではありません: `{}`（chronyd の作業ディレクトリに依存した書き込みを避けるため絶対パスを推奨）",
                    trimmed
                ),
            });
        }
    }
    findings
}

/// chrony のドロップイン取り込みディレクティブ
#[derive(Debug, Clone, PartialEq, Eq)]
enum ChronyDropinSpec {
    /// `confdir <dir>` — 指定ディレクトリ直下の `*.conf` を取り込む
    ConfDir(PathBuf),
    /// `sourcedir <dir>` — 指定ディレクトリ直下の `*.sources` を取り込む
    SourceDir(PathBuf),
    /// `include <glob>` — glob パターンに一致するファイルを取り込む
    Include(PathBuf),
}

/// 相対パスを `base_dir` 基準で絶対パスに解決する
///
/// 絶対パスの場合はそのまま返す。`base_dir` は `chrony.conf` のあるディレクトリ。
fn resolve_chrony_path(raw: &str, base_dir: &Path) -> PathBuf {
    let path = Path::new(raw);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    }
}

/// `chrony.conf` の `confdir` / `sourcedir` / `include` ディレクティブを抽出する
///
/// `base_dir` は chrony.conf のあるディレクトリ。相対パス指定の解決に使う。
/// 複数引数（`confdir /a /b`）や空行は chrony 側でも単一引数として扱われるため、
/// 先頭トークンのみを採用する。
fn parse_chrony_dropin_specs(content: &str, base_dir: &Path) -> Vec<ChronyDropinSpec> {
    let mut specs = Vec::new();
    for (keyword, ctor) in [
        (
            "confdir",
            &(ChronyDropinSpec::ConfDir as fn(PathBuf) -> ChronyDropinSpec),
        ),
        (
            "sourcedir",
            &(ChronyDropinSpec::SourceDir as fn(PathBuf) -> ChronyDropinSpec),
        ),
        (
            "include",
            &(ChronyDropinSpec::Include as fn(PathBuf) -> ChronyDropinSpec),
        ),
    ] {
        for value in find_keyword_lines(content, keyword) {
            let token = value.split_whitespace().next().unwrap_or("");
            if token.is_empty() {
                continue;
            }
            let resolved = resolve_chrony_path(token, base_dir);
            specs.push((ctor)(resolved));
        }
    }
    specs
}

/// 1 つの `ChronyDropinSpec` からドロップインファイルを列挙する
///
/// 戻り値は `(dropin_files, watch_dirs)`:
/// - `dropin_files` — 実在する取り込み対象のファイル
/// - `watch_dirs` — inotify で監視すべきディレクトリ（新規ドロップイン検知のため）
///
/// `max_remaining` が 0 の場合は何も追加せずに戻る（暴走防止）。
fn expand_dropin_spec(
    spec: &ChronyDropinSpec,
    max_remaining: &mut usize,
) -> (Vec<PathBuf>, Vec<PathBuf>) {
    if *max_remaining == 0 {
        return (Vec::new(), Vec::new());
    }

    match spec {
        ChronyDropinSpec::ConfDir(dir) | ChronyDropinSpec::SourceDir(dir) => {
            let ext = match spec {
                ChronyDropinSpec::SourceDir(_) => "sources",
                _ => "conf",
            };
            let watch_dirs = if dir.is_dir() {
                vec![dir.clone()]
            } else {
                Vec::new()
            };
            let mut files = Vec::new();
            let entries = match std::fs::read_dir(dir) {
                Ok(e) => e,
                Err(_) => return (files, watch_dirs),
            };
            for entry in entries.flatten() {
                if *max_remaining == 0 {
                    break;
                }
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                if path.extension().and_then(|s| s.to_str()) == Some(ext) {
                    files.push(path);
                    *max_remaining = max_remaining.saturating_sub(1);
                }
            }
            (files, watch_dirs)
        }
        ChronyDropinSpec::Include(pattern) => {
            let pattern_str = pattern.to_string_lossy();
            let mut files = Vec::new();
            let mut watch_dirs: BTreeSet<PathBuf> = BTreeSet::new();

            // `include` は glob も使えるが、固定パスも多い。固定パスならファイル/ディレクトリをそのまま扱う
            if !pattern_str.contains('*')
                && !pattern_str.contains('?')
                && !pattern_str.contains('[')
            {
                if pattern.is_file() {
                    if *max_remaining > 0 {
                        files.push(pattern.clone());
                        *max_remaining = max_remaining.saturating_sub(1);
                    }
                    if let Some(parent) = pattern.parent()
                        && parent.is_dir()
                    {
                        watch_dirs.insert(parent.to_path_buf());
                    }
                } else if pattern.is_dir() {
                    watch_dirs.insert(pattern.clone());
                }
                return (files, watch_dirs.into_iter().collect());
            }

            // glob 展開
            let iter = match glob(&pattern_str) {
                Ok(it) => it,
                Err(e) => {
                    tracing::warn!(
                        pattern = %pattern_str,
                        error = %e,
                        "chrony include の glob パターンが不正です"
                    );
                    return (files, Vec::new());
                }
            };
            for entry in iter {
                if *max_remaining == 0 {
                    break;
                }
                match entry {
                    Ok(path) => {
                        if path.is_file() {
                            if let Some(parent) = path.parent()
                                && parent.is_dir()
                            {
                                watch_dirs.insert(parent.to_path_buf());
                            }
                            files.push(path);
                            *max_remaining = max_remaining.saturating_sub(1);
                        }
                    }
                    Err(e) => {
                        tracing::debug!(
                            pattern = %pattern_str,
                            error = %e,
                            "chrony include の glob 要素でエラーが発生しました"
                        );
                    }
                }
            }
            (files, watch_dirs.into_iter().collect())
        }
    }
}

/// 複数の chrony 設定ファイルからドロップインを発見する
///
/// 戻り値は `(dropin_files, watch_dirs)`:
/// - `dropin_files` — 監視対象として追加すべきドロップインファイル（重複排除済み）
/// - `watch_dirs` — inotify で watch すべき追加ディレクトリ（重複排除済み）
///
/// 発見するファイル数は `max_files` で打ち切る。chrony.conf 以外は対象外。
fn discover_chrony_dropins(
    chrony_configs: &[&Path],
    max_files: u32,
) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut file_set: BTreeSet<PathBuf> = BTreeSet::new();
    let mut dir_set: BTreeSet<PathBuf> = BTreeSet::new();
    let mut remaining = max_files as usize;

    for config_path in chrony_configs {
        if NtpConfigKind::from_path(config_path) != NtpConfigKind::Chrony {
            continue;
        }
        let Some(base_dir) = config_path.parent() else {
            continue;
        };
        let content = match std::fs::read_to_string(config_path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let specs = parse_chrony_dropin_specs(&content, base_dir);
        for spec in &specs {
            let (files, dirs) = expand_dropin_spec(spec, &mut remaining);
            for f in files {
                file_set.insert(f);
            }
            for d in dirs {
                dir_set.insert(d);
            }
            if remaining == 0 {
                tracing::warn!(
                    max_files,
                    "chrony ドロップインの発見数が上限に達したため、以降のファイル列挙を打ち切ります"
                );
                break;
            }
        }
        if remaining == 0 {
            break;
        }
    }

    (
        file_set.into_iter().collect(),
        dir_set.into_iter().collect(),
    )
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
            if config.check_keys_file_owner {
                findings.extend(audit_keys_file_owner(content, kind, config_path, config));
            }
            if config.check_chrony_leapsectz {
                findings.extend(audit_chrony_leapsectz_missing(content));
            }
            if config.check_chrony_sample_counts {
                findings.extend(audit_chrony_sample_counts(
                    content,
                    config.maxsamples_min_threshold,
                ));
            }
            if config.check_chrony_refclock {
                findings.extend(audit_chrony_refclock(
                    content,
                    &config.allowed_refclock_drivers,
                ));
            }
            if config.check_chrony_rtcsync {
                findings.extend(audit_chrony_rtcsync_missing(content));
            }
            if config.check_chrony_rtcfile {
                findings.extend(audit_chrony_rtcfile_absolute(content));
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
            if config.check_keys_file_owner {
                findings.extend(audit_keys_file_owner(content, kind, config_path, config));
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
    ///
    /// `kind_override` が `Some` の場合はその種別で監査する（chrony ドロップインのように
    /// パス名からは `Unknown` に分類されるが chrony フォーマットとして扱いたいケース向け）。
    fn scan_config_file(
        path: &Path,
        kind_override: Option<NtpConfigKind>,
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
        let kind = kind_override.unwrap_or_else(|| NtpConfigKind::from_path(path));
        let mut findings = if config.audit_enabled {
            audit_by_kind(kind, &content, config, path)
        } else {
            Vec::new()
        };
        if config.audit_enabled && config.check_config_owner {
            findings.extend(audit_config_file_owner(&metadata, path, config));
        }

        Ok(Some((hash, findings)))
    }

    /// inotify を初期化し、監視対象ファイルの親ディレクトリに watch を登録する
    ///
    /// chrony / ntpd / timesyncd の設定ファイルは親ディレクトリ（例: `/etc/chrony/`）の
    /// 権限管理が基本であり、エディタによる書き込み・パッケージ更新時の置換
    /// （MOVED_TO 含む）を捕捉するため親ディレクトリを watch する。
    ///
    /// `extra_dirs` には chrony ドロップインディレクトリ（`/etc/chrony/conf.d/` 等）を
    /// 指定し、親ディレクトリだけではカバーできない別ディレクトリの変更も捕捉する。
    fn setup_inotify(
        config_paths: &[String],
        extra_dirs: &[PathBuf],
    ) -> Result<(Inotify, HashMap<WatchDescriptor, PathBuf>), AppError> {
        let inotify = Inotify::init().map_err(|e| AppError::ModuleConfig {
            message: format!("inotify の初期化に失敗しました: {}", e),
        })?;

        let watch_mask =
            WatchMask::CLOSE_WRITE | WatchMask::MOVED_TO | WatchMask::DELETE | WatchMask::CREATE;

        let mut watch_map: HashMap<WatchDescriptor, PathBuf> = HashMap::new();

        let register_dir = |dir: &Path, map: &mut HashMap<WatchDescriptor, PathBuf>| {
            if !dir.is_dir() {
                tracing::debug!(
                    dir = %dir.display(),
                    "NTP 設定の監視ディレクトリが存在しないため inotify watch をスキップします"
                );
                return;
            }
            if map.values().any(|p| p == dir) {
                return;
            }
            match inotify.watches().add(dir, watch_mask) {
                Ok(wd) => {
                    map.insert(wd, dir.to_path_buf());
                }
                Err(e) => {
                    tracing::warn!(
                        path = %dir.display(),
                        error = %e,
                        "inotify watch の登録に失敗しました"
                    );
                }
            }
        };

        for path_str in config_paths {
            let path = Path::new(path_str);
            let Some(parent) = path.parent() else {
                continue;
            };
            register_dir(parent, &mut watch_map);
        }

        for dir in extra_dirs {
            register_dir(dir, &mut watch_map);
        }

        Ok((inotify, watch_map))
    }

    /// 1 つの設定ファイルをスキャンし、差分検知とイベント発行を行う
    ///
    /// `previous_hashes` を更新し、検出元（`periodic_scan` / `inotify`）を
    /// `details` に `detection=...`、`source=main|dropin` として付加する。
    ///
    /// `kind_override` は chrony ドロップイン（拡張子 `.conf` 等）のように `from_path`
    /// では `Unknown` に分類されるが chrony フォーマットとして監査すべきケースで指定する。
    fn scan_and_publish(
        path_str: &str,
        kind_override: Option<NtpConfigKind>,
        source: &'static str,
        config: &NtpConfigMonitorConfig,
        event_bus: &Option<EventBus>,
        previous_hashes: &mut BTreeMap<String, Option<String>>,
        detection: &str,
    ) {
        let path = Path::new(path_str);
        match Self::scan_config_file(path, kind_override, config) {
            Ok(Some((hash, findings))) => {
                let prev = previous_hashes.get(path_str).cloned();

                match prev {
                    Some(Some(ref p)) if p != &hash => {
                        tracing::info!(
                            path = %path.display(),
                            detection = detection,
                            source = source,
                            "NTP 設定ファイルの変更を検知しました"
                        );
                        if let Some(bus) = event_bus {
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
                                    "path={}, hash={}, detection={}, source={}",
                                    path.display(),
                                    hash,
                                    detection,
                                    source
                                )),
                            );
                        }
                    }
                    Some(None) => {
                        tracing::info!(
                            path = %path.display(),
                            detection = detection,
                            source = source,
                            "NTP 設定ファイルが新規に出現しました"
                        );
                        if let Some(bus) = event_bus {
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
                                    "path={}, hash={}, detection={}, source={}",
                                    path.display(),
                                    hash,
                                    detection,
                                    source
                                )),
                            );
                        }
                    }
                    _ => {}
                }

                previous_hashes.insert(path_str.to_string(), Some(hash));

                for finding in &findings {
                    tracing::warn!(
                        kind = %finding.kind,
                        severity = ?finding.severity,
                        detection = detection,
                        source = source,
                        "{}", finding.message
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "ntp_config_insecure_setting",
                                finding.severity.clone(),
                                "ntp_config_monitor",
                                finding.message.clone(),
                            )
                            .with_details(format!(
                                "path={}, kind={}, detection={}, source={}",
                                path.display(),
                                finding.kind,
                                detection,
                                source
                            )),
                        );
                    }
                }
            }
            Ok(None) => {
                if let Some(Some(_)) = previous_hashes.get(path_str) {
                    tracing::warn!(
                        path = %path.display(),
                        detection = detection,
                        source = source,
                        "NTP 設定ファイルの削除を検知しました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "ntp_config_removed",
                                Severity::Warning,
                                "ntp_config_monitor",
                                format!("NTP 設定ファイルが削除されました: {}", path.display()),
                            )
                            .with_details(format!(
                                "path={}, detection={}, source={}",
                                path.display(),
                                detection,
                                source
                            )),
                        );
                    }
                }
                previous_hashes.insert(path_str.to_string(), None);
            }
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    detection = detection,
                    source = source,
                    "NTP 設定のスキャンに失敗しました"
                );
            }
        }
    }

    /// 現在の chrony 設定から dropin ファイル一覧と watch 対象ディレクトリを発見する
    ///
    /// `check_chrony_dropin` が無効ならば空の `(Vec, Vec)` を返す。
    fn discover_dropins_for(config: &NtpConfigMonitorConfig) -> (Vec<PathBuf>, Vec<PathBuf>) {
        if !config.check_chrony_dropin {
            return (Vec::new(), Vec::new());
        }
        let chrony_paths: Vec<&Path> = config
            .config_paths
            .iter()
            .map(|s| Path::new(s.as_str()))
            .filter(|p| NtpConfigKind::from_path(p) == NtpConfigKind::Chrony && p.is_file())
            .collect();
        if chrony_paths.is_empty() {
            return (Vec::new(), Vec::new());
        }
        discover_chrony_dropins(&chrony_paths, config.dropin_max_files)
    }

    /// 全監視対象（main + dropin）をスキャンする
    ///
    /// 定期スキャンや完全再スキャン時に呼び出される。dropin は毎回フル再発見され、
    /// 前回見えていたが今回存在しないパスも走査することで削除検知を行う。
    fn scan_all_targets(
        config: &NtpConfigMonitorConfig,
        event_bus: &Option<EventBus>,
        previous_hashes: &mut BTreeMap<String, Option<String>>,
        dropin_paths_seen: &mut BTreeSet<String>,
        detection: &str,
    ) {
        // main config
        for path_str in &config.config_paths {
            Self::scan_and_publish(
                path_str,
                None,
                "main",
                config,
                event_bus,
                previous_hashes,
                detection,
            );
        }
        Self::rescan_dropins(
            config,
            event_bus,
            previous_hashes,
            dropin_paths_seen,
            detection,
        );
    }

    /// chrony ドロップインのみを再発見・再スキャンする
    ///
    /// 新しいドロップインを発見したら tracked に加え、前回見えていて今回消えているものは
    /// 削除検知用に明示的にスキャンする。
    fn rescan_dropins(
        config: &NtpConfigMonitorConfig,
        event_bus: &Option<EventBus>,
        previous_hashes: &mut BTreeMap<String, Option<String>>,
        dropin_paths_seen: &mut BTreeSet<String>,
        detection: &str,
    ) {
        if !config.check_chrony_dropin {
            return;
        }

        let (current_dropins, _) = Self::discover_dropins_for(config);
        let current_set: BTreeSet<String> = current_dropins
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();

        // 今回発見されたドロップインをスキャン
        for p in &current_dropins {
            let s = p.to_string_lossy().to_string();
            // 初めて見たドロップインは `previous_hashes` に未登録なので、そのままだと
            // `scan_and_publish` の遷移判定で `_ => {}` に落ちてイベントが発行されない。
            // `Some(None)` を挿入しておき、初回スキャンで `ntp_config_appeared` を発火させる。
            if !previous_hashes.contains_key(&s) {
                previous_hashes.insert(s.clone(), None);
            }
            Self::scan_and_publish(
                &s,
                Some(NtpConfigKind::Chrony),
                "dropin",
                config,
                event_bus,
                previous_hashes,
                detection,
            );
            dropin_paths_seen.insert(s);
        }

        // 前回まで見えていたが今回消えたドロップインをスキャン（削除イベントを発行させる）
        let lost: Vec<String> = dropin_paths_seen
            .iter()
            .filter(|p| !current_set.contains(*p))
            .cloned()
            .collect();
        for s in &lost {
            Self::scan_and_publish(
                s,
                Some(NtpConfigKind::Chrony),
                "dropin",
                config,
                event_bus,
                previous_hashes,
                detection,
            );
            // 削除が確定した（previous_hashes[s] が None）場合のみ tracking から外す
            if matches!(previous_hashes.get(s), Some(None)) {
                dropin_paths_seen.remove(s);
            }
        }
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
            use_inotify = self.config.use_inotify,
            inotify_debounce_ms = self.config.inotify_debounce_ms,
            check_chrony_dropin = self.config.check_chrony_dropin,
            dropin_max_files = self.config.dropin_max_files,
            "NTP / 時刻同期設定監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        // 初回実行時の状態を記録し、後続の変更検知用ベースラインを構築する
        let mut issues_total = 0;
        let mut files_found = 0;
        let mut initial_hashes: BTreeMap<String, Option<String>> = BTreeMap::new();
        for path_str in &self.config.config_paths {
            let path = Path::new(path_str);
            match Self::scan_config_file(path, None, &self.config) {
                Ok(Some((hash, findings))) => {
                    files_found += 1;
                    issues_total += findings.len();
                    initial_hashes.insert(path_str.clone(), Some(hash));
                }
                Ok(None) => {
                    tracing::debug!(path = %path.display(), "NTP 設定ファイルが存在しません（スキップ）");
                    initial_hashes.insert(path_str.clone(), None);
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "初回 NTP 設定スキャンに失敗しました");
                }
            }
        }

        // chrony ドロップインの初回発見と inotify watch 用のディレクトリ収集
        let (initial_dropins, dropin_watch_dirs) = Self::discover_dropins_for(&self.config);
        let mut dropin_paths_seen: BTreeSet<String> = BTreeSet::new();
        for p in &initial_dropins {
            let s = p.to_string_lossy().to_string();
            match Self::scan_config_file(p, Some(NtpConfigKind::Chrony), &self.config) {
                Ok(Some((hash, findings))) => {
                    files_found += 1;
                    issues_total += findings.len();
                    initial_hashes.insert(s.clone(), Some(hash));
                    dropin_paths_seen.insert(s);
                }
                Ok(None) => {
                    tracing::debug!(
                        path = %p.display(),
                        "chrony ドロップインが存在しません（初回スキップ）"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        path = %p.display(),
                        error = %e,
                        "初回 chrony ドロップインスキャンに失敗しました"
                    );
                }
            }
        }

        tracing::info!(
            files_found,
            total_issues = issues_total,
            dropin_count = initial_dropins.len(),
            dropin_watch_dir_count = dropin_watch_dirs.len(),
            "NTP 設定の初回スキャン完了"
        );

        let scan_interval_secs = self.config.scan_interval_secs;
        let config = self.config.clone();
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();
        let stats_handle = self.stats_handle.clone();
        let use_inotify = self.config.use_inotify;
        let inotify_debounce_ms = self.config.inotify_debounce_ms;

        // inotify の初期化（有効時のみ）
        let inotify_state = if use_inotify {
            match Self::setup_inotify(&self.config.config_paths, &dropin_watch_dirs) {
                Ok((inotify, watch_map)) => {
                    tracing::info!(
                        watch_count = watch_map.len(),
                        "NTP 設定監視用の inotify watch を登録しました"
                    );
                    Some((inotify, watch_map))
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "inotify の初期化に失敗しました。定期スキャンのみで動作します"
                    );
                    None
                }
            }
        } else {
            None
        };

        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            interval.tick().await;

            let mut previous_hashes: BTreeMap<String, Option<String>> = initial_hashes;
            let mut dropin_paths_seen = dropin_paths_seen;

            if let Some((mut inotify, watch_map)) = inotify_state {
                let mut buffer = vec![0u8; 4096];
                let mut debounce_map: HashMap<PathBuf, Instant> = HashMap::new();
                let debounce_duration = Duration::from_millis(inotify_debounce_ms);
                let mut poll_interval = tokio::time::interval(Duration::from_millis(100));
                poll_interval.tick().await;

                loop {
                    tokio::select! {
                        _ = cancel_token.cancelled() => {
                            tracing::info!("NTP / 時刻同期設定監視モジュールを停止します");
                            break;
                        }
                        _ = interval.tick() => {
                            let scan_start = Instant::now();
                            Self::scan_all_targets(
                                &config,
                                &event_bus,
                                &mut previous_hashes,
                                &mut dropin_paths_seen,
                                "periodic_scan",
                            );
                            let scan_elapsed = scan_start.elapsed();
                            if let Some(ref handle) = stats_handle {
                                handle.record_scan_duration(MODULE_STATS_NAME, scan_elapsed);
                            }
                        }
                        _ = poll_interval.tick() => {
                            let events = match inotify.read_events(&mut buffer) {
                                Ok(events) => events,
                                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                                Err(e) => {
                                    tracing::error!(error = %e, "inotify イベントの読み取りに失敗しました");
                                    continue;
                                }
                            };

                            let now = Instant::now();
                            let mut main_targets: Vec<String> = Vec::new();
                            let mut dropin_dir_touched = false;

                            for event in events {
                                let dir_path = match watch_map.get(&event.wd) {
                                    Some(p) => p.clone(),
                                    None => continue,
                                };

                                let file_path = match &event.name {
                                    Some(name) => dir_path.join(name),
                                    None => dir_path.clone(),
                                };

                                if let Some(last_time) = debounce_map.get(&file_path)
                                    && now.duration_since(*last_time) < debounce_duration
                                {
                                    continue;
                                }
                                debounce_map.insert(file_path.clone(), now);

                                // 監視対象の config_paths にマッチするもののみ再スキャン
                                let mut matched_main = false;
                                for path_str in &config.config_paths {
                                    if Path::new(path_str) == file_path
                                        && !main_targets.iter().any(|t| t == path_str)
                                    {
                                        main_targets.push(path_str.clone());
                                        matched_main = true;
                                    }
                                }

                                // ドロップイン watch dir 配下の変更はフル再スキャンでドロップイン
                                // 発見・削除両方を処理する
                                if !matched_main
                                    && dropin_watch_dirs.iter().any(|d| d == &dir_path)
                                {
                                    dropin_dir_touched = true;
                                }
                            }

                            // main config のスキャン
                            for path_str in &main_targets {
                                NtpConfigMonitorModule::scan_and_publish(
                                    path_str,
                                    None,
                                    "main",
                                    &config,
                                    &event_bus,
                                    &mut previous_hashes,
                                    "inotify",
                                );
                            }

                            // chrony.conf 自体の変更、または dropin ディレクトリ配下の変更があれば
                            // ドロップインをフル再発見する（include/confdir の書き換えにも追随）
                            let chrony_main_changed = main_targets.iter().any(|p| {
                                NtpConfigKind::from_path(Path::new(p)) == NtpConfigKind::Chrony
                            });
                            if chrony_main_changed || dropin_dir_touched {
                                Self::rescan_dropins(
                                    &config,
                                    &event_bus,
                                    &mut previous_hashes,
                                    &mut dropin_paths_seen,
                                    "inotify",
                                );
                            }

                            if debounce_map.len() > 10000 {
                                let threshold = now - Duration::from_secs(60);
                                debounce_map.retain(|_, t| *t > threshold);
                            }
                        }
                    }
                }
            } else {
                loop {
                    tokio::select! {
                        _ = cancel_token.cancelled() => {
                            tracing::info!("NTP / 時刻同期設定監視モジュールを停止します");
                            break;
                        }
                        _ = interval.tick() => {
                            let scan_start = Instant::now();
                            Self::scan_all_targets(
                                &config,
                                &event_bus,
                                &mut previous_hashes,
                                &mut dropin_paths_seen,
                                "periodic_scan",
                            );
                            let scan_elapsed = scan_start.elapsed();
                            if let Some(ref handle) = stats_handle {
                                handle.record_scan_duration(MODULE_STATS_NAME, scan_elapsed);
                            }
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
            match Self::scan_config_file(path, None, &self.config) {
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

        // chrony ドロップインも initial_scan のスナップショットに含める
        let (dropins, _) = Self::discover_dropins_for(&self.config);
        let mut dropin_scanned = 0;
        for p in &dropins {
            match Self::scan_config_file(p, Some(NtpConfigKind::Chrony), &self.config) {
                Ok(Some((hash, findings))) => {
                    items_scanned += 1;
                    dropin_scanned += 1;
                    issues_found += findings.len();
                    snapshot.insert(p.to_string_lossy().to_string(), hash);
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(
                        path = %p.display(),
                        error = %e,
                        "initial_scan: chrony ドロップインのスキャンに失敗しました"
                    );
                }
            }
        }

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "NTP 設定ファイル {}件をスキャンしました（うちドロップイン: {}件、問題: {}件）",
                items_scanned, dropin_scanned, issues_found
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
            None,
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
        let result = NtpConfigMonitorModule::scan_config_file(&path, None, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_scan_chrony_safe_content_yields_no_findings() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chrony.conf");
        std::fs::write(
            &path,
            "pool 2.pool.ntp.org iburst\nmakestep 1.0 3\nleapsectz right/UTC\nrtcsync\n",
        )
        .unwrap();
        // owner 監査は既定有効だが、tempdir 配下は非 root 所有なので許容リストを空にして無効化
        let config = NtpConfigMonitorConfig {
            allowed_owner_uids: Vec::new(),
            allowed_owner_gids: Vec::new(),
            ..Default::default()
        };
        let (_, findings) = NtpConfigMonitorModule::scan_config_file(&path, None, &config)
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
        let (_, findings) = NtpConfigMonitorModule::scan_config_file(&path, None, &config)
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
        let (hash1, _) = NtpConfigMonitorModule::scan_config_file(&path, None, &config)
            .expect("scan ok")
            .expect("file present");
        std::fs::write(&path, "server b\nmakestep 1.0 3\n").unwrap();
        let (hash2, _) = NtpConfigMonitorModule::scan_config_file(&path, None, &config)
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
            // tempdir 配下は非 root 所有なので、既存の件数アサーションを維持するため
            // 所有者監査を無効化する
            check_config_owner: false,
            check_keys_file_owner: false,
            // leapsectz 未設定 / sample_counts / rtcsync の新規監査は件数に影響するため無効化
            check_chrony_leapsectz: false,
            check_chrony_sample_counts: false,
            check_chrony_rtcsync: false,
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
        // leapsectz / rtcsync 設定済み & maxsamples/minsamples 未設定で新規ルールが発火しない content にする
        let content = "pool foo\nmakestep 1.0 3\nrtcsync\nallow all\nbindcmdaddress 0.0.0.0\ndriftfile drift\nleapsectz right/UTC\n";
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
        let (_, findings) = NtpConfigMonitorModule::scan_config_file(&path, None, &config)
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

    // ------------------------------------------------------------------
    // audit_config_file_owner
    // ------------------------------------------------------------------
    #[test]
    fn test_audit_config_file_owner_self_uid_detects() {
        use std::os::unix::fs::MetadataExt;
        // 現在のテストプロセスは root 以外で動作している前提
        // （CI / 開発者環境は通常 uid != 0）
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chrony.conf");
        std::fs::write(&path, "pool foo\n").unwrap();

        let metadata = std::fs::metadata(&path).unwrap();
        if metadata.uid() == 0 {
            // root 環境ではこのテストをスキップ（既定許容 uid に一致するため）
            return;
        }

        let config = NtpConfigMonitorConfig::default();
        let findings = audit_config_file_owner(&metadata, &path, &config);
        let kinds: Vec<_> = findings.iter().map(|f| f.kind.as_str()).collect();
        assert!(kinds.contains(&"ntp_config_insecure_owner"));
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.severity, Severity::Warning))
        );
    }

    #[test]
    fn test_audit_config_file_owner_allowed_uid_no_finding() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chrony.conf");
        std::fs::write(&path, "pool foo\n").unwrap();

        let metadata = std::fs::metadata(&path).unwrap();
        // 現在の uid / gid を許容する
        let config = NtpConfigMonitorConfig {
            allowed_owner_uids: vec![metadata.uid()],
            allowed_owner_gids: vec![metadata.gid()],
            ..Default::default()
        };
        let findings = audit_config_file_owner(&metadata, &path, &config);
        assert!(findings.is_empty(), "許容 uid/gid で検知は発生しない");
    }

    #[test]
    fn test_audit_config_file_owner_empty_allowlist_allows_all() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chrony.conf");
        std::fs::write(&path, "pool foo\n").unwrap();

        let metadata = std::fs::metadata(&path).unwrap();
        let config = NtpConfigMonitorConfig {
            allowed_owner_uids: Vec::new(),
            allowed_owner_gids: Vec::new(),
            ..Default::default()
        };
        let findings = audit_config_file_owner(&metadata, &path, &config);
        assert!(findings.is_empty(), "空の許容リストは全 uid/gid を許容する");
    }

    #[test]
    fn test_audit_config_file_owner_group_only_violation() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chrony.conf");
        std::fs::write(&path, "pool foo\n").unwrap();

        let metadata = std::fs::metadata(&path).unwrap();
        // uid は許容、gid のみ違反させる
        let config = NtpConfigMonitorConfig {
            allowed_owner_uids: vec![metadata.uid()],
            allowed_owner_gids: vec![metadata.gid().wrapping_add(1)],
            ..Default::default()
        };
        let findings = audit_config_file_owner(&metadata, &path, &config);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "ntp_config_insecure_group");
    }

    // ------------------------------------------------------------------
    // audit_keys_file_owner
    // ------------------------------------------------------------------
    #[test]
    fn test_audit_keys_file_owner_self_uid_detects() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("chrony.keys");
        std::fs::write(&keys, "1 MD5 secret\n").unwrap();

        let metadata = std::fs::metadata(&keys).unwrap();
        if metadata.uid() == 0 {
            return;
        }

        let content = format!("keys {}\n", keys.display());
        let config = NtpConfigMonitorConfig::default();
        let findings = audit_keys_file_owner(
            &content,
            NtpConfigKind::Chrony,
            Path::new("/etc/chrony/chrony.conf"),
            &config,
        );
        assert!(
            findings
                .iter()
                .any(|f| f.kind == "ntp_keys_file_insecure_owner")
        );
    }

    #[test]
    fn test_audit_keys_file_owner_missing_file_skipped() {
        // 不在ファイルはスキップ（検知しない）
        let content = "keys /nonexistent/zettai/keys.file\n";
        let config = NtpConfigMonitorConfig::default();
        let findings = audit_keys_file_owner(
            content,
            NtpConfigKind::Chrony,
            Path::new("/etc/chrony/chrony.conf"),
            &config,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_keys_file_owner_allowed_uid_no_finding() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("chrony.keys");
        std::fs::write(&keys, "1 MD5 secret\n").unwrap();

        let metadata = std::fs::metadata(&keys).unwrap();
        let content = format!("keys {}\n", keys.display());
        let config = NtpConfigMonitorConfig {
            allowed_owner_uids: vec![metadata.uid()],
            allowed_owner_gids: vec![metadata.gid()],
            ..Default::default()
        };
        let findings = audit_keys_file_owner(
            &content,
            NtpConfigKind::Chrony,
            Path::new("/etc/chrony/chrony.conf"),
            &config,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_keys_file_owner_ntp_kind_label() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("ntp.keys");
        std::fs::write(&keys, "1 MD5 secret\n").unwrap();

        let metadata = std::fs::metadata(&keys).unwrap();
        if metadata.uid() == 0 {
            return;
        }

        let content = format!("keys {}\n", keys.display());
        let config = NtpConfigMonitorConfig::default();
        let findings = audit_keys_file_owner(
            &content,
            NtpConfigKind::Ntp,
            Path::new("/etc/ntp.conf"),
            &config,
        );
        assert!(findings.iter().any(|f| f.message.contains("ntp.conf")));
    }

    // ------------------------------------------------------------------
    // audit_by_kind: owner 監査フラグの切替
    // ------------------------------------------------------------------
    #[test]
    fn test_audit_by_kind_owner_flag_toggle() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("chrony.keys");
        std::fs::write(&keys, "1 MD5 secret\n").unwrap();
        std::fs::set_permissions(
            &keys,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
        )
        .unwrap();

        let metadata = std::fs::metadata(&keys).unwrap();
        if metadata.uid() == 0 {
            return;
        }

        let config_path = dir.path().join("chrony.conf");
        // pool+makestep で他ルールは抑制
        let content = format!(
            "pool 2.pool.ntp.org iburst\nmakestep 1.0 3\nkeys {}\ntrustedkey 1\nauthselectmode require\n",
            keys.display()
        );

        // 既定: check_keys_file_owner = true → owner/group の finding 両方
        let config = NtpConfigMonitorConfig::default();
        let findings = audit_by_kind(NtpConfigKind::Chrony, &content, &config, &config_path);
        let kinds: Vec<_> = findings.iter().map(|f| f.kind.as_str()).collect();
        assert!(kinds.contains(&"ntp_keys_file_insecure_owner"));
        assert!(kinds.contains(&"ntp_keys_file_insecure_group"));

        // 無効化 → 検知しない
        let config = NtpConfigMonitorConfig {
            check_keys_file_owner: false,
            ..Default::default()
        };
        let findings = audit_by_kind(NtpConfigKind::Chrony, &content, &config, &config_path);
        assert!(
            findings
                .iter()
                .all(|f| f.kind != "ntp_keys_file_insecure_owner"
                    && f.kind != "ntp_keys_file_insecure_group")
        );
    }

    #[test]
    fn test_scan_config_file_runs_config_owner_check() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chrony.conf");
        std::fs::write(&path, "pool 2.pool.ntp.org iburst\nmakestep 1.0 3\n").unwrap();

        let metadata = std::fs::metadata(&path).unwrap();
        if metadata.uid() == 0 {
            return;
        }

        // 既定（owner = true）: 非 root 所有 → ntp_config_insecure_owner 発生
        let config = NtpConfigMonitorConfig::default();
        let (_, findings) = NtpConfigMonitorModule::scan_config_file(&path, None, &config)
            .expect("scan ok")
            .expect("file present");
        assert!(
            findings
                .iter()
                .any(|f| f.kind == "ntp_config_insecure_owner")
        );

        // audit_enabled = false にすると owner 監査も実行されない
        let config = NtpConfigMonitorConfig {
            audit_enabled: false,
            ..Default::default()
        };
        let (_, findings) = NtpConfigMonitorModule::scan_config_file(&path, None, &config)
            .expect("scan ok")
            .expect("file present");
        assert!(
            findings
                .iter()
                .all(|f| f.kind != "ntp_config_insecure_owner")
        );

        // check_config_owner = false のみ無効化
        let config = NtpConfigMonitorConfig {
            check_config_owner: false,
            ..Default::default()
        };
        let (_, findings) = NtpConfigMonitorModule::scan_config_file(&path, None, &config)
            .expect("scan ok")
            .expect("file present");
        assert!(
            findings
                .iter()
                .all(|f| f.kind != "ntp_config_insecure_owner")
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
        // owner 監査は既定有効で tempdir ファイル（非 root 所有）を検知してしまうので無効化
        config.check_keys_file_owner = false;
        let findings = audit_by_kind(NtpConfigKind::Ntp, &content, &config, &config_path);
        assert!(findings.is_empty());
    }

    // ------------------------------------------------------------------
    // audit_chrony_leapsectz_missing
    // ------------------------------------------------------------------
    #[test]
    fn test_audit_chrony_leapsectz_missing_detects() {
        let content = "pool 2.pool.ntp.org iburst\nmakestep 1.0 3\n";
        let findings = audit_chrony_leapsectz_missing(content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "chrony_leapsectz_missing");
        assert!(matches!(findings[0].severity, Severity::Info));
    }

    #[test]
    fn test_audit_chrony_leapsectz_set_no_finding() {
        let content = "pool 2.pool.ntp.org iburst\nleapsectz right/UTC\n";
        let findings = audit_chrony_leapsectz_missing(content);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_chrony_leapsectz_empty_value_detects() {
        // 値が空なら未設定扱いで検知
        let content = "pool 2.pool.ntp.org iburst\nleapsectz \n";
        let findings = audit_chrony_leapsectz_missing(content);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_audit_chrony_leapsectz_comment_ignored() {
        // コメント行は未設定扱い
        let content = "pool foo\n# leapsectz right/UTC\n";
        let findings = audit_chrony_leapsectz_missing(content);
        assert_eq!(findings.len(), 1);
    }

    // ------------------------------------------------------------------
    // audit_chrony_sample_counts
    // ------------------------------------------------------------------
    #[test]
    fn test_audit_chrony_maxsamples_too_low_detects() {
        let content = "pool foo\nmaxsamples 2\n";
        let findings = audit_chrony_sample_counts(content, 4);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "chrony_maxsamples_too_low");
        assert!(matches!(findings[0].severity, Severity::Warning));
        assert!(findings[0].message.contains("maxsamples 2"));
    }

    #[test]
    fn test_audit_chrony_maxsamples_zero_is_unlimited_no_finding() {
        // 0 = 無制限なので検知しない
        let content = "pool foo\nmaxsamples 0\n";
        let findings = audit_chrony_sample_counts(content, 4);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_chrony_maxsamples_at_threshold_no_finding() {
        // 閾値ちょうど（4）は検知しない（< ではない）
        let content = "pool foo\nmaxsamples 4\n";
        let findings = audit_chrony_sample_counts(content, 4);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_chrony_maxsamples_high_value_no_finding() {
        let content = "pool foo\nmaxsamples 64\n";
        let findings = audit_chrony_sample_counts(content, 4);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_chrony_minsamples_exceeds_maxsamples_detects() {
        let content = "pool foo\nmaxsamples 8\nminsamples 12\n";
        let findings = audit_chrony_sample_counts(content, 4);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "chrony_minsamples_exceeds_maxsamples");
        assert!(matches!(findings[0].severity, Severity::Warning));
        assert!(findings[0].message.contains("minsamples 12"));
        assert!(findings[0].message.contains("maxsamples 8"));
    }

    #[test]
    fn test_audit_chrony_minsamples_equal_maxsamples_no_finding() {
        // min == max は許容（> で判定）
        let content = "pool foo\nmaxsamples 8\nminsamples 8\n";
        let findings = audit_chrony_sample_counts(content, 4);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_chrony_minsamples_with_maxsamples_zero_no_matrix_finding() {
        // maxsamples 0 = 無制限の場合、minsamples との比較は行わない
        let content = "pool foo\nmaxsamples 0\nminsamples 12\n";
        let findings = audit_chrony_sample_counts(content, 4);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_chrony_sample_counts_both_issues_detects() {
        // maxsamples 2 < 閾値 4 & minsamples 5 > maxsamples 2 の両方を検知
        let content = "pool foo\nmaxsamples 2\nminsamples 5\n";
        let findings = audit_chrony_sample_counts(content, 4);
        assert_eq!(findings.len(), 2);
        let kinds: Vec<_> = findings.iter().map(|f| f.kind.as_str()).collect();
        assert!(kinds.contains(&"chrony_maxsamples_too_low"));
        assert!(kinds.contains(&"chrony_minsamples_exceeds_maxsamples"));
    }

    #[test]
    fn test_audit_chrony_sample_counts_not_set_no_finding() {
        let content = "pool foo\nmakestep 1.0 3\n";
        let findings = audit_chrony_sample_counts(content, 4);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_chrony_sample_counts_inline_option_not_matched() {
        // server/pool の inline 引数として maxsamples 2 を指定しても、
        // find_keyword_lines は行頭トークン一致のみのため top-level には該当しない
        let content = "server 0.pool.ntp.org iburst maxsamples 2 minsamples 8\n";
        let findings = audit_chrony_sample_counts(content, 4);
        assert!(
            findings.is_empty(),
            "inline maxsamples/minsamples は誤検知しない"
        );
    }

    #[test]
    fn test_audit_chrony_sample_counts_custom_threshold() {
        // 閾値を 8 に設定すると maxsamples 5 が検知対象になる
        let content = "pool foo\nmaxsamples 5\n";
        let findings = audit_chrony_sample_counts(content, 8);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "chrony_maxsamples_too_low");
    }

    #[test]
    fn test_audit_chrony_sample_counts_threshold_zero_disabled() {
        // 閾値 0 の場合、maxsamples 過少は検知されない（u32 は 0 未満にならない）
        let content = "pool foo\nmaxsamples 1\n";
        let findings = audit_chrony_sample_counts(content, 0);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_parse_chrony_top_level_u32_last_wins() {
        let content = "maxsamples 2\nmaxsamples 8\n";
        assert_eq!(parse_chrony_top_level_u32(content, "maxsamples"), Some(8));
    }

    #[test]
    fn test_parse_chrony_top_level_u32_invalid_ignored() {
        let content = "maxsamples abc\nmaxsamples 7\n";
        assert_eq!(parse_chrony_top_level_u32(content, "maxsamples"), Some(7));
    }

    // ------------------------------------------------------------------
    // audit_by_kind: leapsectz / sample_counts フラグ切替
    // ------------------------------------------------------------------
    #[test]
    fn test_audit_by_kind_leapsectz_flag_toggle() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("chrony.conf");
        // pool+makestep+leapsectz 未設定、trustedkey / authselectmode 設定で他ルール抑制
        let content = "pool 2.pool.ntp.org iburst\nmakestep 1.0 3\n";

        // 既定有効: leapsectz 未設定を検知
        let mut config = NtpConfigMonitorConfig {
            check_keys_file_owner: false,
            check_config_owner: false,
            ..Default::default()
        };
        let findings = audit_by_kind(NtpConfigKind::Chrony, content, &config, &config_path);
        assert!(
            findings
                .iter()
                .any(|f| f.kind == "chrony_leapsectz_missing")
        );

        // 無効化 → 検知しない
        config.check_chrony_leapsectz = false;
        let findings = audit_by_kind(NtpConfigKind::Chrony, content, &config, &config_path);
        assert!(
            findings
                .iter()
                .all(|f| f.kind != "chrony_leapsectz_missing")
        );
    }

    #[test]
    fn test_audit_by_kind_sample_counts_flag_toggle() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("chrony.conf");
        let content = "pool 2.pool.ntp.org iburst\nmakestep 1.0 3\nleapsectz right/UTC\nmaxsamples 2\nminsamples 5\n";

        // 既定有効: too_low / exceeds 両方検知
        let mut config = NtpConfigMonitorConfig {
            check_keys_file_owner: false,
            check_config_owner: false,
            ..Default::default()
        };
        let findings = audit_by_kind(NtpConfigKind::Chrony, content, &config, &config_path);
        let kinds: Vec<_> = findings.iter().map(|f| f.kind.as_str()).collect();
        assert!(kinds.contains(&"chrony_maxsamples_too_low"));
        assert!(kinds.contains(&"chrony_minsamples_exceeds_maxsamples"));

        // 無効化 → 検知しない
        config.check_chrony_sample_counts = false;
        let findings = audit_by_kind(NtpConfigKind::Chrony, content, &config, &config_path);
        assert!(
            findings
                .iter()
                .all(|f| f.kind != "chrony_maxsamples_too_low"
                    && f.kind != "chrony_minsamples_exceeds_maxsamples")
        );
    }

    // ------------------------------------------------------------------
    // audit_chrony_refclock
    // ------------------------------------------------------------------
    #[test]
    fn test_audit_chrony_refclock_unexpected_driver_warns() {
        let content = "pool foo\nrefclock SHM 0 refid SHM0\n";
        let findings = audit_chrony_refclock(content, &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "chrony_refclock_unexpected");
        assert_eq!(findings[0].severity, Severity::Warning);
        assert!(
            findings[0].message.contains("SHM"),
            "message should identify the driver: {}",
            findings[0].message
        );
    }

    #[test]
    fn test_audit_chrony_refclock_shm_has_attack_vector_note() {
        let content = "refclock SHM 0\n";
        let findings = audit_chrony_refclock(content, &[]);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].message.contains("time-injection attack vector"),
            "SHM should carry the explicit attack-vector note: {}",
            findings[0].message
        );
    }

    #[test]
    fn test_audit_chrony_refclock_non_shm_omits_shm_note() {
        let content = "refclock PHC /dev/ptp0 poll 0\n";
        let findings = audit_chrony_refclock(content, &[]);
        assert_eq!(findings.len(), 1);
        assert!(
            !findings[0].message.contains("time-injection"),
            "non-SHM drivers should not include the SHM-specific note: {}",
            findings[0].message
        );
    }

    #[test]
    fn test_audit_chrony_refclock_allowed_driver_not_reported() {
        let content = "refclock PHC /dev/ptp0 poll 0\n";
        let findings = audit_chrony_refclock(content, &["phc".to_string()]);
        assert!(
            findings.is_empty(),
            "allowed driver match is case-insensitive"
        );
    }

    #[test]
    fn test_audit_chrony_refclock_allow_list_mixes_ok_and_bad() {
        let content = "refclock PHC /dev/ptp0 poll 0\nrefclock SHM 0 refid SHM0\n";
        let findings = audit_chrony_refclock(content, &["PHC".to_string()]);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("SHM"));
    }

    #[test]
    fn test_audit_chrony_refclock_deduplicates_same_driver() {
        let content = "refclock SHM 0\nrefclock SHM 1\n";
        let findings = audit_chrony_refclock(content, &[]);
        assert_eq!(findings.len(), 1, "same driver reported only once per scan");
    }

    #[test]
    fn test_audit_chrony_refclock_ignores_comments_and_empty_lines() {
        let content = "# refclock SHM 0\n; refclock SHM 1\n\nrefclock\nrefclock  \n";
        let findings = audit_chrony_refclock(content, &[]);
        assert!(
            findings.is_empty(),
            "comments and empty driver tokens should be ignored: {:?}",
            findings
        );
    }

    #[test]
    fn test_audit_chrony_refclock_allow_list_empty_string_ignored() {
        // 空文字列エントリ（TOML での `allowed_refclock_drivers = [""]` 等）は
        // 許可リストに含まれないとして扱う
        let content = "refclock SHM 0\n";
        let findings = audit_chrony_refclock(content, &["".to_string(), "  ".to_string()]);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_audit_by_kind_refclock_flag_toggle() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("chrony.conf");
        let content = "pool 2.pool.ntp.org iburst\nmakestep 1.0 3\nleapsectz right/UTC\nrefclock SHM 0 refid SHM0\n";

        let mut config = NtpConfigMonitorConfig {
            check_keys_file_owner: false,
            check_config_owner: false,
            ..Default::default()
        };
        let findings = audit_by_kind(NtpConfigKind::Chrony, content, &config, &config_path);
        assert!(
            findings
                .iter()
                .any(|f| f.kind == "chrony_refclock_unexpected"),
            "refclock audit should fire by default"
        );

        config.check_chrony_refclock = false;
        let findings = audit_by_kind(NtpConfigKind::Chrony, content, &config, &config_path);
        assert!(
            findings
                .iter()
                .all(|f| f.kind != "chrony_refclock_unexpected"),
            "disabling check_chrony_refclock suppresses the finding"
        );
    }

    #[test]
    fn test_audit_by_kind_refclock_honors_allow_list() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("chrony.conf");
        let content = "pool 2.pool.ntp.org iburst\nmakestep 1.0 3\nleapsectz right/UTC\nrefclock PHC /dev/ptp0 poll 0\n";

        let config = NtpConfigMonitorConfig {
            check_keys_file_owner: false,
            check_config_owner: false,
            allowed_refclock_drivers: vec!["PHC".to_string()],
            ..Default::default()
        };
        let findings = audit_by_kind(NtpConfigKind::Chrony, content, &config, &config_path);
        assert!(
            findings
                .iter()
                .all(|f| f.kind != "chrony_refclock_unexpected"),
            "allowed drivers must not produce findings"
        );
    }

    #[test]
    fn test_audit_by_kind_ntp_does_not_trigger_chrony_refclock() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("ntp.conf");
        let content = "server 0.pool.ntp.org iburst\nrestrict default ignore\ndriftfile /var/ntp.drift\nrefclock SHM 0\n";

        let config = NtpConfigMonitorConfig {
            check_keys_file_owner: false,
            check_config_owner: false,
            ..Default::default()
        };
        let findings = audit_by_kind(NtpConfigKind::Ntp, content, &config, &config_path);
        assert!(
            findings
                .iter()
                .all(|f| f.kind != "chrony_refclock_unexpected"),
            "ntp.conf path should not dispatch chrony-specific refclock audit"
        );
    }

    #[test]
    fn test_audit_by_kind_ntp_does_not_trigger_chrony_sample_counts() {
        // NtpConfigKind::Ntp アームでは chrony 専用ルールはディスパッチされない
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("ntp.conf");
        let content = "server 0.pool.ntp.org iburst\nrestrict default ignore\ndriftfile /var/ntp.drift\nmaxsamples 2\n";

        let config = NtpConfigMonitorConfig {
            check_keys_file_owner: false,
            check_config_owner: false,
            ..Default::default()
        };
        let findings = audit_by_kind(NtpConfigKind::Ntp, content, &config, &config_path);
        assert!(
            findings
                .iter()
                .all(|f| f.kind != "chrony_maxsamples_too_low"
                    && f.kind != "chrony_minsamples_exceeds_maxsamples"
                    && f.kind != "chrony_leapsectz_missing")
        );
    }

    // ------------------------------------------------------------------
    // audit_chrony_rtcsync_missing
    // ------------------------------------------------------------------
    #[test]
    fn test_audit_chrony_rtcsync_missing_detects() {
        let content = "pool 2.pool.ntp.org iburst\nmakestep 1.0 3\n";
        let findings = audit_chrony_rtcsync_missing(content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "chrony_rtcsync_missing");
        assert!(matches!(findings[0].severity, Severity::Warning));
    }

    #[test]
    fn test_audit_chrony_rtcsync_set_no_finding() {
        // 引数なしの `rtcsync` だけでも設定済みとして扱う
        let content = "pool foo\nrtcsync\n";
        let findings = audit_chrony_rtcsync_missing(content);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_chrony_rtcsync_with_trailing_content_set() {
        // 行頭トークン一致なら `rtcsync` ディレクティブが見つかったとみなす
        let content = "pool foo\nrtcsync # enable linux rtc sync\n";
        let findings = audit_chrony_rtcsync_missing(content);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_chrony_rtcsync_comment_does_not_count() {
        // コメント化された行は `find_keyword_lines` で無視される
        let content = "# rtcsync\nserver foo\n";
        let findings = audit_chrony_rtcsync_missing(content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "chrony_rtcsync_missing");
    }

    // ------------------------------------------------------------------
    // audit_chrony_rtcfile_absolute
    // ------------------------------------------------------------------
    #[test]
    fn test_audit_chrony_rtcfile_absent_no_finding() {
        let content = "server foo\n";
        let findings = audit_chrony_rtcfile_absolute(content);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_chrony_rtcfile_absolute_ok() {
        let content = "rtcfile /var/lib/chrony/rtc\n";
        let findings = audit_chrony_rtcfile_absolute(content);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_chrony_rtcfile_relative_detects() {
        let content = "rtcfile rtc.drift\n";
        let findings = audit_chrony_rtcfile_absolute(content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "chrony_rtcfile_not_absolute");
        assert!(matches!(findings[0].severity, Severity::Info));
        assert!(findings[0].message.contains("rtc.drift"));
    }

    #[test]
    fn test_audit_chrony_rtcfile_empty_value_detects() {
        let content = "rtcfile \n";
        let findings = audit_chrony_rtcfile_absolute(content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "chrony_rtcfile_not_absolute");
    }

    #[test]
    fn test_audit_chrony_rtcfile_multiple_lines() {
        // 複数行ある場合は各行を個別に評価する
        let content = "rtcfile ./rel\nrtcfile /abs/ok\nrtcfile another_rel\n";
        let findings = audit_chrony_rtcfile_absolute(content);
        assert_eq!(findings.len(), 2);
        assert!(
            findings
                .iter()
                .all(|f| f.kind == "chrony_rtcfile_not_absolute")
        );
    }

    // ------------------------------------------------------------------
    // audit_by_kind: rtcsync / rtcfile フラグの有効/無効切替
    // ------------------------------------------------------------------
    #[test]
    fn test_audit_by_kind_rtcsync_flag_toggle() {
        // rtcsync なし & その他の新規ルールを発火させない最小 chrony 設定
        let content = "pool foo\nmakestep 1.0 3\nleapsectz right/UTC\n";
        let path = Path::new("/etc/chrony/chrony.conf");

        let mut config = NtpConfigMonitorConfig {
            check_config_owner: false,
            check_keys_file_owner: false,
            ..Default::default()
        };
        let findings = audit_by_kind(NtpConfigKind::Chrony, content, &config, path);
        assert!(
            findings.iter().any(|f| f.kind == "chrony_rtcsync_missing"),
            "rtcsync audit should fire by default"
        );

        config.check_chrony_rtcsync = false;
        let findings = audit_by_kind(NtpConfigKind::Chrony, content, &config, path);
        assert!(
            findings.iter().all(|f| f.kind != "chrony_rtcsync_missing"),
            "disabling check_chrony_rtcsync suppresses the finding"
        );
    }

    #[test]
    fn test_audit_by_kind_rtcfile_flag_toggle() {
        // rtcsync 設定済み (rtcsync missing を抑止) & rtcfile 相対パス
        let content = "pool foo\nmakestep 1.0 3\nleapsectz right/UTC\nrtcsync\nrtcfile rel.rtc\n";
        let path = Path::new("/etc/chrony/chrony.conf");

        let mut config = NtpConfigMonitorConfig {
            check_config_owner: false,
            check_keys_file_owner: false,
            ..Default::default()
        };
        let findings = audit_by_kind(NtpConfigKind::Chrony, content, &config, path);
        assert!(
            findings
                .iter()
                .any(|f| f.kind == "chrony_rtcfile_not_absolute"),
            "rtcfile audit should fire when path is relative"
        );

        config.check_chrony_rtcfile = false;
        let findings = audit_by_kind(NtpConfigKind::Chrony, content, &config, path);
        assert!(
            findings
                .iter()
                .all(|f| f.kind != "chrony_rtcfile_not_absolute"),
            "disabling check_chrony_rtcfile suppresses the finding"
        );
    }

    #[test]
    fn test_audit_by_kind_ntp_does_not_trigger_chrony_rtcsync_or_rtcfile() {
        // NtpConfigKind::Ntp アームでは chrony 専用ルールはディスパッチされない
        let content = "server 0.pool.ntp.org iburst\nrestrict default ignore\ndriftfile /var/ntp.drift\nrtcfile rel.rtc\n";
        let path = Path::new("/etc/ntp.conf");
        let config = NtpConfigMonitorConfig {
            check_keys_file_owner: false,
            check_config_owner: false,
            ..Default::default()
        };
        let findings = audit_by_kind(NtpConfigKind::Ntp, content, &config, path);
        assert!(
            findings
                .iter()
                .all(|f| f.kind != "chrony_rtcsync_missing"
                    && f.kind != "chrony_rtcfile_not_absolute"),
            "ntp.conf path should not dispatch chrony-specific rtc audits"
        );
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

    #[test]
    fn test_inotify_config_enabled_by_default() {
        let config = NtpConfigMonitorConfig::default();
        assert!(config.use_inotify);
        assert_eq!(config.inotify_debounce_ms, 500);
    }

    #[tokio::test]
    async fn test_start_and_stop_with_inotify_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chrony.conf");
        std::fs::write(&path, "pool 2.pool.ntp.org iburst\nmakestep 1.0 3\n").unwrap();

        let config = NtpConfigMonitorConfig {
            config_paths: vec![path.to_string_lossy().to_string()],
            scan_interval_secs: 3600,
            use_inotify: false,
            ..Default::default()
        };
        let mut module = NtpConfigMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        let handle = module.start().await.unwrap();
        module.stop().await.unwrap();
        let _ = handle.await;
        assert!(cancel_token.is_cancelled());
    }

    #[test]
    fn test_setup_inotify_registers_parent_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chrony.conf");
        std::fs::write(&path, "pool 2.pool.ntp.org iburst\n").unwrap();

        let config_paths = vec![path.to_string_lossy().to_string()];
        let (_inotify, watch_map) =
            NtpConfigMonitorModule::setup_inotify(&config_paths, &[]).unwrap();

        assert_eq!(watch_map.len(), 1);
        assert!(watch_map.values().any(|p| p == dir.path()));
    }

    #[test]
    fn test_setup_inotify_deduplicates_shared_parent() {
        // 複数ファイルが同じ親ディレクトリに属する場合、watch は 1 つだけになる
        let dir = tempfile::tempdir().unwrap();
        let path1 = dir.path().join("chrony.conf");
        let path2 = dir.path().join("ntp.conf");
        std::fs::write(&path1, "pool 2.pool.ntp.org iburst\n").unwrap();
        std::fs::write(&path2, "server pool.ntp.org\n").unwrap();

        let config_paths = vec![
            path1.to_string_lossy().to_string(),
            path2.to_string_lossy().to_string(),
        ];
        let (_inotify, watch_map) =
            NtpConfigMonitorModule::setup_inotify(&config_paths, &[]).unwrap();

        assert_eq!(watch_map.len(), 1);
    }

    #[test]
    fn test_setup_inotify_skips_missing_parent() {
        // 存在しない親ディレクトリは watch に登録されない
        let config_paths = vec!["/nonexistent-xyz-zettai/ntp.conf".to_string()];
        let (_inotify, watch_map) =
            NtpConfigMonitorModule::setup_inotify(&config_paths, &[]).unwrap();
        assert!(watch_map.is_empty());
    }

    #[test]
    fn test_debounce_logic_skips_within_window() {
        let mut debounce_map: HashMap<PathBuf, Instant> = HashMap::new();
        let debounce_duration = Duration::from_millis(500);
        let path = PathBuf::from("/etc/chrony/chrony.conf");

        let now = Instant::now();
        debounce_map.insert(path.clone(), now);

        let should_skip = debounce_map
            .get(&path)
            .is_some_and(|last_time| now.duration_since(*last_time) < debounce_duration);
        assert!(should_skip);
    }

    #[test]
    fn test_debounce_logic_allows_after_expiry() {
        let mut debounce_map: HashMap<PathBuf, Instant> = HashMap::new();
        let debounce_duration = Duration::from_millis(500);
        let path = PathBuf::from("/etc/chrony/chrony.conf");

        let past = Instant::now() - Duration::from_secs(1);
        debounce_map.insert(path.clone(), past);

        let now = Instant::now();
        let should_skip = debounce_map
            .get(&path)
            .is_some_and(|last_time| now.duration_since(*last_time) < debounce_duration);
        assert!(!should_skip);
    }

    #[test]
    fn test_scan_and_publish_adds_detection_field_periodic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chrony.conf");
        std::fs::write(&path, "pool 2.pool.ntp.org iburst\nmakestep 1.0 3\n").unwrap();
        let path_str = path.to_string_lossy().to_string();

        let config = NtpConfigMonitorConfig {
            config_paths: vec![path_str.clone()],
            ..Default::default()
        };
        let event_bus = EventBus::new(16);
        let mut rx = event_bus.subscribe();
        let mut previous: BTreeMap<String, Option<String>> = BTreeMap::new();
        // ベースラインとして旧ハッシュを入れておく
        previous.insert(path_str.clone(), Some("00".to_string()));

        NtpConfigMonitorModule::scan_and_publish(
            &path_str,
            None,
            "main",
            &config,
            &Some(event_bus),
            &mut previous,
            "periodic_scan",
        );

        let event = rx.try_recv().unwrap();
        assert_eq!(event.event_type, "ntp_config_changed");
        let details = event.details.as_ref().unwrap();
        assert!(details.contains("detection=periodic_scan"));
        assert!(details.contains("source=main"));
    }

    #[test]
    fn test_scan_and_publish_adds_detection_field_inotify() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chrony.conf");
        std::fs::write(&path, "pool 2.pool.ntp.org iburst\nmakestep 1.0 3\n").unwrap();
        let path_str = path.to_string_lossy().to_string();

        let config = NtpConfigMonitorConfig {
            config_paths: vec![path_str.clone()],
            ..Default::default()
        };
        let event_bus = EventBus::new(16);
        let mut rx = event_bus.subscribe();
        let mut previous: BTreeMap<String, Option<String>> = BTreeMap::new();
        previous.insert(path_str.clone(), Some("00".to_string()));

        NtpConfigMonitorModule::scan_and_publish(
            &path_str,
            None,
            "main",
            &config,
            &Some(event_bus),
            &mut previous,
            "inotify",
        );

        let event = rx.try_recv().unwrap();
        assert_eq!(event.event_type, "ntp_config_changed");
        let details = event.details.as_ref().unwrap();
        assert!(details.contains("detection=inotify"));
        assert!(details.contains("source=main"));
    }

    #[test]
    fn test_scan_and_publish_removal_detection_field() {
        // 以前存在していたファイルが消失した場合は ntp_config_removed に detection が付く
        let path_str = "/tmp/nonexistent-ntp-zettai-349.conf".to_string();
        let config = NtpConfigMonitorConfig {
            config_paths: vec![path_str.clone()],
            ..Default::default()
        };
        let event_bus = EventBus::new(16);
        let mut rx = event_bus.subscribe();
        let mut previous: BTreeMap<String, Option<String>> = BTreeMap::new();
        previous.insert(path_str.clone(), Some("aabb".to_string()));

        NtpConfigMonitorModule::scan_and_publish(
            &path_str,
            None,
            "main",
            &config,
            &Some(event_bus),
            &mut previous,
            "inotify",
        );

        let event = rx.try_recv().unwrap();
        assert_eq!(event.event_type, "ntp_config_removed");
        let details = event.details.as_ref().unwrap();
        assert!(details.contains("detection=inotify"));
        assert!(details.contains("source=main"));
    }

    #[tokio::test]
    async fn test_inotify_detects_file_modification() {
        // 実際に inotify 経由で変更検知イベントが発行されることを確認する統合テスト
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chrony.conf");
        std::fs::write(&path, "pool 2.pool.ntp.org iburst\nmakestep 1.0 3\n").unwrap();

        let config = NtpConfigMonitorConfig {
            config_paths: vec![path.to_string_lossy().to_string()],
            scan_interval_secs: 3600,
            use_inotify: true,
            inotify_debounce_ms: 10,
            ..Default::default()
        };
        let event_bus = EventBus::new(64);
        let mut rx = event_bus.subscribe();
        let mut module = NtpConfigMonitorModule::new(config, Some(event_bus));
        module.init().unwrap();
        let handle = module.start().await.unwrap();

        // inotify watch が確立するまで待つ
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        // ファイルを書き換える（CLOSE_WRITE が発火）
        std::fs::write(&path, "pool 1.pool.ntp.org iburst\nmakestep 1.0 3\n").unwrap();

        // inotify イベント検知・scan_and_publish 完了まで待つ
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        module.stop().await.unwrap();
        let _ = handle.await;

        // detection=inotify を含む ntp_config_changed が発行されるはず
        let mut found_inotify = false;
        while let Ok(event) = rx.try_recv() {
            if event.event_type == "ntp_config_changed"
                && event
                    .details
                    .as_ref()
                    .is_some_and(|d| d.contains("detection=inotify"))
            {
                found_inotify = true;
                break;
            }
        }
        assert!(
            found_inotify,
            "detection=inotify を含む ntp_config_changed イベントが発行されませんでした"
        );
    }

    #[test]
    fn test_parse_chrony_dropin_specs_confdir_absolute() {
        let content = "confdir /etc/chrony/conf.d\n";
        let specs = parse_chrony_dropin_specs(content, Path::new("/etc/chrony"));
        assert_eq!(specs.len(), 1);
        assert!(
            matches!(&specs[0], ChronyDropinSpec::ConfDir(p) if p == Path::new("/etc/chrony/conf.d"))
        );
    }

    #[test]
    fn test_parse_chrony_dropin_specs_sourcedir_absolute() {
        let content = "sourcedir /etc/chrony/sources.d\n";
        let specs = parse_chrony_dropin_specs(content, Path::new("/etc/chrony"));
        assert_eq!(specs.len(), 1);
        assert!(
            matches!(&specs[0], ChronyDropinSpec::SourceDir(p) if p == Path::new("/etc/chrony/sources.d"))
        );
    }

    #[test]
    fn test_parse_chrony_dropin_specs_include_glob() {
        let content = "include /etc/chrony/conf.d/*.conf\n";
        let specs = parse_chrony_dropin_specs(content, Path::new("/etc/chrony"));
        assert_eq!(specs.len(), 1);
        assert!(
            matches!(&specs[0], ChronyDropinSpec::Include(p) if p == Path::new("/etc/chrony/conf.d/*.conf"))
        );
    }

    #[test]
    fn test_parse_chrony_dropin_specs_relative_path_resolved() {
        let content = "confdir conf.d\n";
        let specs = parse_chrony_dropin_specs(content, Path::new("/etc/chrony"));
        assert_eq!(specs.len(), 1);
        assert!(
            matches!(&specs[0], ChronyDropinSpec::ConfDir(p) if p == Path::new("/etc/chrony/conf.d"))
        );
    }

    #[test]
    fn test_parse_chrony_dropin_specs_ignores_comments_and_keywords() {
        // `keys` や他のキーワードは無視し、`include` などのみ拾う
        let content =
            "# confdir commented\nkeys /etc/chrony/keys\ninclude /etc/chrony/extra.conf\n";
        let specs = parse_chrony_dropin_specs(content, Path::new("/etc/chrony"));
        assert_eq!(specs.len(), 1);
        assert!(
            matches!(&specs[0], ChronyDropinSpec::Include(p) if p == Path::new("/etc/chrony/extra.conf"))
        );
    }

    #[test]
    fn test_parse_chrony_dropin_specs_multiple_directives() {
        let content = "confdir /a\nsourcedir /b\ninclude /c/*.conf\n";
        let specs = parse_chrony_dropin_specs(content, Path::new("/etc/chrony"));
        assert_eq!(specs.len(), 3);
    }

    #[test]
    fn test_expand_dropin_spec_confdir_lists_conf_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("10-pool.conf"), "pool a.pool.ntp.org\n").unwrap();
        std::fs::write(dir.path().join("20-other.conf"), "server b.example.org\n").unwrap();
        // *.conf 以外は無視される
        std::fs::write(dir.path().join("ignored.sources"), "pool c\n").unwrap();
        std::fs::write(dir.path().join("README"), "readme\n").unwrap();

        let spec = ChronyDropinSpec::ConfDir(dir.path().to_path_buf());
        let mut remaining = 10usize;
        let (files, dirs) = expand_dropin_spec(&spec, &mut remaining);
        assert_eq!(files.len(), 2, "expected 2 *.conf files, got {:?}", files);
        assert_eq!(dirs.len(), 1);
        assert_eq!(dirs[0], dir.path());
        assert!(
            files
                .iter()
                .all(|p| p.extension().and_then(|s| s.to_str()) == Some("conf"))
        );
    }

    #[test]
    fn test_expand_dropin_spec_sourcedir_lists_sources_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("upstream.sources"), "pool a\n").unwrap();
        std::fs::write(dir.path().join("skip.conf"), "server b\n").unwrap();

        let spec = ChronyDropinSpec::SourceDir(dir.path().to_path_buf());
        let mut remaining = 10usize;
        let (files, _) = expand_dropin_spec(&spec, &mut remaining);
        assert_eq!(files.len(), 1);
        assert_eq!(
            files[0].extension().and_then(|s| s.to_str()),
            Some("sources")
        );
    }

    #[test]
    fn test_expand_dropin_spec_confdir_respects_remaining_limit() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..5 {
            std::fs::write(dir.path().join(format!("{}-test.conf", i)), "server a\n").unwrap();
        }
        let spec = ChronyDropinSpec::ConfDir(dir.path().to_path_buf());
        let mut remaining = 2usize;
        let (files, _) = expand_dropin_spec(&spec, &mut remaining);
        assert!(files.len() <= 2);
        assert_eq!(remaining, 0);
    }

    #[test]
    fn test_expand_dropin_spec_include_glob_expands() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.conf"), "server a\n").unwrap();
        std::fs::write(dir.path().join("b.conf"), "server b\n").unwrap();

        let pattern = dir.path().join("*.conf");
        let spec = ChronyDropinSpec::Include(pattern);
        let mut remaining = 10usize;
        let (files, dirs) = expand_dropin_spec(&spec, &mut remaining);
        assert_eq!(files.len(), 2);
        assert!(dirs.iter().any(|d| d == dir.path()));
    }

    #[test]
    fn test_expand_dropin_spec_include_fixed_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("local.conf");
        std::fs::write(&file, "server a\n").unwrap();

        let spec = ChronyDropinSpec::Include(file.clone());
        let mut remaining = 10usize;
        let (files, dirs) = expand_dropin_spec(&spec, &mut remaining);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0], file);
        assert!(dirs.iter().any(|d| d == dir.path()));
    }

    #[test]
    fn test_expand_dropin_spec_confdir_missing_returns_empty() {
        let spec = ChronyDropinSpec::ConfDir(PathBuf::from("/nonexistent-zettai-ntp-351"));
        let mut remaining = 10usize;
        let (files, dirs) = expand_dropin_spec(&spec, &mut remaining);
        assert!(files.is_empty());
        assert!(dirs.is_empty());
    }

    #[test]
    fn test_discover_chrony_dropins_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let dropin_dir = dir.path().join("conf.d");
        std::fs::create_dir(&dropin_dir).unwrap();
        std::fs::write(dropin_dir.join("10-pool.conf"), "pool a.pool.ntp.org\n").unwrap();

        let main = dir.path().join("chrony.conf");
        std::fs::write(
            &main,
            format!(
                "pool b.pool.ntp.org iburst\nmakestep 1.0 3\nconfdir {}\n",
                dropin_dir.display()
            ),
        )
        .unwrap();

        let (files, watch_dirs) = discover_chrony_dropins(&[main.as_path()], 64);
        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("10-pool.conf"));
        assert!(watch_dirs.iter().any(|d| d == &dropin_dir));
    }

    #[test]
    fn test_discover_chrony_dropins_honors_max_files() {
        let dir = tempfile::tempdir().unwrap();
        let dropin_dir = dir.path().join("conf.d");
        std::fs::create_dir(&dropin_dir).unwrap();
        for i in 0..10 {
            std::fs::write(
                dropin_dir.join(format!("{}-p.conf", i)),
                "pool a.pool.ntp.org\n",
            )
            .unwrap();
        }
        let main = dir.path().join("chrony.conf");
        std::fs::write(&main, format!("confdir {}\n", dropin_dir.display())).unwrap();

        let (files, _) = discover_chrony_dropins(&[main.as_path()], 3);
        assert!(
            files.len() <= 3,
            "expected at most 3 files, got {}",
            files.len()
        );
    }

    #[test]
    fn test_discover_chrony_dropins_skips_non_chrony_configs() {
        // ntp.conf / timesyncd.conf は confdir ディレクティブを持たないので発見されない
        let dir = tempfile::tempdir().unwrap();
        let ntp = dir.path().join("ntp.conf");
        std::fs::write(&ntp, "server a\nincludefile /etc/ntp/ntp.conf.local\n").unwrap();
        let (files, dirs) = discover_chrony_dropins(&[ntp.as_path()], 64);
        assert!(files.is_empty());
        assert!(dirs.is_empty());
    }

    #[tokio::test]
    async fn test_discover_dropins_for_disabled_check() {
        let dir = tempfile::tempdir().unwrap();
        let main = dir.path().join("chrony.conf");
        let dropin_dir = dir.path().join("conf.d");
        std::fs::create_dir(&dropin_dir).unwrap();
        std::fs::write(dropin_dir.join("x.conf"), "server a\n").unwrap();
        std::fs::write(&main, format!("confdir {}\n", dropin_dir.display())).unwrap();

        let config = NtpConfigMonitorConfig {
            config_paths: vec![main.to_string_lossy().to_string()],
            check_chrony_dropin: false,
            ..Default::default()
        };
        let (files, dirs) = NtpConfigMonitorModule::discover_dropins_for(&config);
        assert!(files.is_empty());
        assert!(dirs.is_empty());
    }

    #[test]
    fn test_scan_and_publish_dropin_source_tagged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("10-pool.conf");
        std::fs::write(&path, "pool a.pool.ntp.org iburst\n").unwrap();
        let path_str = path.to_string_lossy().to_string();

        let config = NtpConfigMonitorConfig::default();
        let event_bus = EventBus::new(16);
        let mut rx = event_bus.subscribe();
        let mut previous: BTreeMap<String, Option<String>> = BTreeMap::new();
        previous.insert(path_str.clone(), Some("dead".to_string()));

        NtpConfigMonitorModule::scan_and_publish(
            &path_str,
            Some(NtpConfigKind::Chrony),
            "dropin",
            &config,
            &Some(event_bus),
            &mut previous,
            "inotify",
        );

        let event = rx.try_recv().unwrap();
        assert_eq!(event.event_type, "ntp_config_changed");
        let details = event.details.as_ref().unwrap();
        assert!(details.contains("source=dropin"));
    }

    #[tokio::test]
    async fn test_inotify_detects_new_dropin_creation() {
        // chrony.conf に confdir を記述しておき、後から新規ドロップインを作成した際に
        // ntp_config_appeared / insecure_setting が発行されることを検証する
        let dir = tempfile::tempdir().unwrap();
        let dropin_dir = dir.path().join("conf.d");
        std::fs::create_dir(&dropin_dir).unwrap();
        let main = dir.path().join("chrony.conf");
        std::fs::write(
            &main,
            format!(
                "pool b.pool.ntp.org iburst\nmakestep 1.0 3\nconfdir {}\n",
                dropin_dir.display()
            ),
        )
        .unwrap();

        let config = NtpConfigMonitorConfig {
            config_paths: vec![main.to_string_lossy().to_string()],
            scan_interval_secs: 3600,
            use_inotify: true,
            inotify_debounce_ms: 10,
            check_chrony_dropin: true,
            ..Default::default()
        };
        let event_bus = EventBus::new(64);
        let mut rx = event_bus.subscribe();
        let mut module = NtpConfigMonitorModule::new(config, Some(event_bus));
        module.init().unwrap();
        let handle = module.start().await.unwrap();

        // inotify watch が確立するまで待つ
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        // 新規ドロップインを作成
        let new_dropin = dropin_dir.join("99-attacker.conf");
        std::fs::write(&new_dropin, "pool evil.example.com\n").unwrap();

        // 検知まで待つ
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        module.stop().await.unwrap();
        let _ = handle.await;

        // ntp_config_appeared イベントで source=dropin を期待する
        let mut found = false;
        while let Ok(event) = rx.try_recv() {
            if event.event_type == "ntp_config_appeared"
                && event
                    .details
                    .as_ref()
                    .is_some_and(|d| d.contains("source=dropin") && d.contains("99-attacker.conf"))
            {
                found = true;
                break;
            }
        }
        assert!(
            found,
            "新規 chrony ドロップイン作成時に source=dropin の ntp_config_appeared イベントが発行されませんでした"
        );
    }

    #[test]
    fn test_setup_inotify_with_extra_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let conf_d = dir.path().join("conf.d");
        std::fs::create_dir(&conf_d).unwrap();
        let main = dir.path().join("chrony.conf");
        std::fs::write(&main, "pool a\n").unwrap();

        let config_paths = vec![main.to_string_lossy().to_string()];
        let extra_dirs = vec![conf_d.clone()];
        let (_inotify, watch_map) =
            NtpConfigMonitorModule::setup_inotify(&config_paths, &extra_dirs).unwrap();

        assert_eq!(watch_map.len(), 2);
        assert!(watch_map.values().any(|p| p == dir.path()));
        assert!(watch_map.values().any(|p| p == &conf_d));
    }
}
