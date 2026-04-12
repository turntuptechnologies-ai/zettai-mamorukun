//! パッケージ整合性検証モジュール
//!
//! パッケージマネージャーの検証機能を使って、インストール済みパッケージのファイルが
//! 改ざんされていないか定期的にチェックする。
//!
//! 対応パッケージマネージャー:
//! - dpkg (Debian/Ubuntu): `dpkg --verify` コマンド
//! - rpm (RHEL/CentOS/Fedora): `rpm -Va` コマンド

use crate::config::PackageVerifyConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::BTreeMap;
use tokio_util::sync::CancellationToken;

/// パッケージマネージャーの種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackageManager {
    /// dpkg (Debian/Ubuntu)
    Dpkg,
    /// rpm (RHEL/CentOS/Fedora)
    Rpm,
}

/// パッケージ検証の失敗情報
#[derive(Debug, Clone, PartialEq)]
struct VerificationFailure {
    /// ファイルパス
    path: String,
    /// パッケージ名（rpm の場合のみ取得可能）
    package: Option<String>,
    /// サイズ変更
    size_changed: bool,
    /// チェックサム不一致（MD5）
    checksum_mismatch: bool,
    /// mtime 変更
    mtime_changed: bool,
    /// パーミッション変更
    mode_changed: bool,
    /// オーナー変更
    owner_changed: bool,
    /// グループ変更
    group_changed: bool,
    /// conffile かどうか
    is_conffile: bool,
    /// ファイルが欠落
    missing: bool,
}

/// 利用可能なパッケージマネージャーを検出する
///
/// `which` コマンドで dpkg / rpm の存在を確認する。両方ある場合は dpkg を優先する。
fn detect_package_manager() -> Option<PackageManager> {
    if std::process::Command::new("which")
        .arg("dpkg")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
    {
        return Some(PackageManager::Dpkg);
    }
    if std::process::Command::new("which")
        .arg("rpm")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
    {
        return Some(PackageManager::Rpm);
    }
    None
}

/// dpkg --verify の出力をパースする
///
/// 出力形式: `??5??????  c /etc/foo.conf`
/// - 9文字のフラグ: 位置 0=size, 2=checksum(5=MD5)
/// - 各位置が `.` なら変更なし、`?` は不明、それ以外は変更あり
/// - `c` は conffile フラグ
fn parse_dpkg_verify_output(output: &str) -> Vec<VerificationFailure> {
    let mut failures = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // dpkg --verify 形式: "??5??????  c /path/to/file" or "??5??????   /path/to/file"
        // 最小長: 9文字のフラグ + 少なくとも空白 + パス
        if line.len() < 12 {
            continue;
        }

        let flags = &line[..9];
        let rest = &line[9..];

        // conffile フラグとパスを抽出
        let (is_conffile, path) = parse_conffile_and_path(rest);

        if path.is_empty() {
            continue;
        }

        // missing 判定: すべてのフラグが '?' の場合はファイルが欠落している可能性
        let all_question = flags.chars().all(|c| c == '?');

        failures.push(VerificationFailure {
            path: path.to_string(),
            package: None,
            size_changed: flags
                .as_bytes()
                .first()
                .is_some_and(|&b| b != b'.' && b != b'?'),
            checksum_mismatch: flags.as_bytes().get(2).is_some_and(|&b| b == b'5'),
            mtime_changed: false,
            mode_changed: false,
            owner_changed: false,
            group_changed: false,
            is_conffile,
            missing: all_question,
        });
    }

    failures
}

/// conffile フラグとパスを抽出するヘルパー
fn parse_conffile_and_path(rest: &str) -> (bool, &str) {
    let trimmed = rest.trim_start();
    if let Some(after_c) = trimmed.strip_prefix('c') {
        if after_c.starts_with(' ') || after_c.starts_with('\t') {
            (true, after_c.trim_start())
        } else {
            // 'c' の後に空白がない場合はパスの一部
            (false, trimmed)
        }
    } else {
        (false, trimmed)
    }
}

/// rpm -Va の出力をパースする
///
/// 出力形式: `S.5....T.  c /etc/bar.conf` または `missing   c /etc/baz.conf`
/// - S=size, M=mode, 5=md5, D=device, L=link, U=user, G=group, T=mtime, P=capabilities
/// - `missing` は特別扱い
fn parse_rpm_va_output(output: &str) -> Vec<VerificationFailure> {
    let mut failures = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // missing 行の特別処理
        if let Some(rest) = line.strip_prefix("missing") {
            let (is_conffile, path) = parse_conffile_and_path(rest);
            if !path.is_empty() {
                failures.push(VerificationFailure {
                    path: path.to_string(),
                    package: None,
                    size_changed: false,
                    checksum_mismatch: false,
                    mtime_changed: false,
                    mode_changed: false,
                    owner_changed: false,
                    group_changed: false,
                    is_conffile,
                    missing: true,
                });
            }
            continue;
        }

        // 通常行: 9文字のフラグ + 空白 + [c ] + パス
        if line.len() < 12 {
            continue;
        }

        let flags = &line[..9];
        let rest = &line[9..];

        let (is_conffile, path) = parse_conffile_and_path(rest);

        if path.is_empty() {
            continue;
        }

        failures.push(VerificationFailure {
            path: path.to_string(),
            package: None,
            size_changed: flags.as_bytes().first().is_some_and(|&b| b == b'S'),
            checksum_mismatch: flags.as_bytes().get(2).is_some_and(|&b| b == b'5'),
            mtime_changed: flags.as_bytes().get(7).is_some_and(|&b| b == b'T'),
            mode_changed: flags.as_bytes().get(1).is_some_and(|&b| b == b'M'),
            owner_changed: flags.as_bytes().get(5).is_some_and(|&b| b == b'U'),
            group_changed: flags.as_bytes().get(6).is_some_and(|&b| b == b'G'),
            is_conffile,
            missing: false,
        });
    }

    failures
}

/// 除外フィルタを適用する
fn apply_exclusions(
    failures: &[VerificationFailure],
    exclude_paths: &[String],
    exclude_packages: &[String],
) -> Vec<VerificationFailure> {
    failures
        .iter()
        .filter(|f| {
            // パスの前方一致でフィルタ
            if exclude_paths.iter().any(|p| f.path.starts_with(p)) {
                return false;
            }
            // パッケージ名でフィルタ
            if let Some(ref pkg) = f.package
                && exclude_packages.iter().any(|p| p == pkg)
            {
                return false;
            }
            true
        })
        .cloned()
        .collect()
}

/// 検証失敗の重大度を判定する
fn determine_severity(failure: &VerificationFailure) -> Severity {
    if failure.missing {
        return Severity::Warning;
    }
    if failure.checksum_mismatch {
        if failure.is_conffile {
            return Severity::Info;
        }
        return Severity::Warning;
    }
    Severity::Info
}

/// 検証失敗のイベントタイプを判定する
fn determine_event_type(failure: &VerificationFailure) -> &'static str {
    if failure.missing {
        return "package_file_missing";
    }
    if failure.checksum_mismatch {
        if failure.is_conffile {
            return "package_conffile_modified";
        }
        return "package_file_tampered";
    }
    "package_file_changed"
}

/// パッケージ検証コマンドを実行する
fn run_verification(manager: PackageManager) -> Result<String, String> {
    let output = match manager {
        PackageManager::Dpkg => std::process::Command::new("dpkg")
            .arg("--verify")
            .output()
            .map_err(|e| format!("dpkg --verify の実行に失敗しました: {}", e))?,
        PackageManager::Rpm => std::process::Command::new("rpm")
            .arg("-Va")
            .output()
            .map_err(|e| format!("rpm -Va の実行に失敗しました: {}", e))?,
    };

    // dpkg --verify と rpm -Va はファイルの不一致がある場合に非ゼロで終了するため、
    // 終了コードではなく stderr が空でないかつ stdout も空の場合のみエラーとする
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if stdout.is_empty() && !stderr.is_empty() {
        return Err(format!("検証コマンドがエラーを出力しました: {}", stderr));
    }

    Ok(stdout)
}

/// パッケージ整合性検証モジュール
///
/// パッケージマネージャーの検証コマンドを使って、インストール済みパッケージの
/// ファイルが改ざんされていないか定期的にチェックする。
pub struct PackageVerifyModule {
    config: PackageVerifyConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
    package_manager: Option<PackageManager>,
}

impl PackageVerifyModule {
    /// 新しいパッケージ整合性検証モジュールを作成する
    pub fn new(config: PackageVerifyConfig, event_bus: Option<EventBus>) -> Self {
        Self {
            config,
            cancel_token: CancellationToken::new(),
            event_bus,
            package_manager: None,
        }
    }

    /// キャンセルトークンのクローンを返す
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    /// 1回のスキャンを実行し、検証失敗のリストを返す
    fn run_scan(
        manager: PackageManager,
        config: &PackageVerifyConfig,
    ) -> Result<Vec<VerificationFailure>, String> {
        let output = run_verification(manager)?;

        let failures = match manager {
            PackageManager::Dpkg => parse_dpkg_verify_output(&output),
            PackageManager::Rpm => parse_rpm_va_output(&output),
        };

        let filtered = apply_exclusions(&failures, &config.exclude_paths, &config.exclude_packages);

        Ok(filtered)
    }

    /// 検証失敗をイベントとして発行する
    fn publish_failures(event_bus: &EventBus, failures: &[VerificationFailure]) {
        for failure in failures {
            let severity = determine_severity(failure);
            let event_type = determine_event_type(failure);

            let message = match event_type {
                "package_file_tampered" => {
                    format!("パッケージファイルの改ざんを検知しました: {}", failure.path)
                }
                "package_conffile_modified" => {
                    format!("パッケージ設定ファイルが変更されています: {}", failure.path)
                }
                "package_file_missing" => {
                    format!("パッケージファイルが欠落しています: {}", failure.path)
                }
                _ => {
                    format!("パッケージファイルに変更があります: {}", failure.path)
                }
            };

            let mut details_parts = vec![format!("path={}", failure.path)];
            if failure.size_changed {
                details_parts.push("size=changed".to_string());
            }
            if failure.checksum_mismatch {
                details_parts.push("checksum=mismatch".to_string());
            }
            if failure.mtime_changed {
                details_parts.push("mtime=changed".to_string());
            }
            if failure.mode_changed {
                details_parts.push("mode=changed".to_string());
            }
            if failure.owner_changed {
                details_parts.push("owner=changed".to_string());
            }
            if failure.group_changed {
                details_parts.push("group=changed".to_string());
            }
            if failure.is_conffile {
                details_parts.push("conffile=true".to_string());
            }
            if failure.missing {
                details_parts.push("missing=true".to_string());
            }
            if let Some(ref pkg) = failure.package {
                details_parts.push(format!("package={}", pkg));
            }

            event_bus.publish(
                SecurityEvent::new(event_type, severity, "package_verify", message)
                    .with_details(details_parts.join(", ")),
            );
        }
    }
}

impl Module for PackageVerifyModule {
    fn name(&self) -> &str {
        "package_verify"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        self.package_manager = detect_package_manager();

        if self.package_manager.is_none() {
            tracing::warn!(
                "dpkg / rpm コマンドが見つかりません。パッケージ整合性検証モジュールは動作しません"
            );
        }

        tracing::info!(
            interval_secs = self.config.interval_secs,
            package_manager = ?self.package_manager,
            exclude_paths = ?self.config.exclude_paths,
            exclude_packages = ?self.config.exclude_packages,
            "パッケージ整合性検証モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        let manager = match self.package_manager {
            Some(m) => m,
            None => {
                tracing::warn!(
                    "パッケージマネージャーが検出されないため、スキャンをスキップします"
                );
                let cancel_token = self.cancel_token.clone();
                return Ok(tokio::spawn(async move {
                    cancel_token.cancelled().await;
                }));
            }
        };

        let interval_secs = self.config.interval_secs;
        let config = self.config.clone();
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            // 最初の tick は即座に発火するのでスキップ
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("パッケージ整合性検証モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        match Self::run_scan(manager, &config) {
                            Ok(failures) => {
                                if failures.is_empty() {
                                    tracing::debug!("パッケージ検証: 問題なし");
                                } else {
                                    tracing::info!(
                                        count = failures.len(),
                                        "パッケージ検証: {}件の問題を検知しました",
                                        failures.len()
                                    );
                                    if let Some(ref bus) = event_bus {
                                        Self::publish_failures(bus, &failures);
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "パッケージ検証の実行に失敗しました");
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

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();

        let manager = match self.package_manager {
            Some(m) => m,
            None => {
                let duration = start.elapsed();
                return Ok(InitialScanResult {
                    items_scanned: 0,
                    issues_found: 0,
                    duration,
                    summary: "パッケージマネージャーが検出されませんでした".to_string(),
                    snapshot: BTreeMap::new(),
                });
            }
        };

        match Self::run_scan(manager, &self.config) {
            Ok(failures) => {
                let issues_found = failures.len();
                let duration = start.elapsed();
                let mut snapshot = BTreeMap::new();
                for failure in &failures {
                    let status = if failure.missing {
                        "missing".to_string()
                    } else if failure.checksum_mismatch {
                        "checksum_mismatch".to_string()
                    } else {
                        "changed".to_string()
                    };
                    snapshot.insert(failure.path.clone(), status);
                }

                Ok(InitialScanResult {
                    items_scanned: 1,
                    issues_found,
                    duration,
                    summary: format!("パッケージ検証を実行しました（問題: {}件）", issues_found),
                    snapshot,
                })
            }
            Err(e) => {
                let duration = start.elapsed();
                Ok(InitialScanResult {
                    items_scanned: 0,
                    issues_found: 0,
                    duration,
                    summary: format!("パッケージ検証の実行に失敗しました: {}", e),
                    snapshot: BTreeMap::new(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dpkg_verify_output() {
        let output = "??5??????  c /etc/foo.conf\n..5......   /usr/bin/bar\n";
        let failures = parse_dpkg_verify_output(output);
        assert_eq!(failures.len(), 2);

        assert_eq!(failures[0].path, "/etc/foo.conf");
        assert!(failures[0].is_conffile);
        assert!(failures[0].checksum_mismatch);
        assert!(!failures[0].size_changed); // '?' is not a size change indicator

        assert_eq!(failures[1].path, "/usr/bin/bar");
        assert!(!failures[1].is_conffile);
        assert!(failures[1].checksum_mismatch);
    }

    #[test]
    fn test_parse_rpm_va_output() {
        let output = "S.5....T.  c /etc/bar.conf\n..5......   /usr/lib/libfoo.so\n";
        let failures = parse_rpm_va_output(output);
        assert_eq!(failures.len(), 2);

        assert_eq!(failures[0].path, "/etc/bar.conf");
        assert!(failures[0].is_conffile);
        assert!(failures[0].size_changed);
        assert!(failures[0].checksum_mismatch);
        assert!(failures[0].mtime_changed);

        assert_eq!(failures[1].path, "/usr/lib/libfoo.so");
        assert!(!failures[1].is_conffile);
        assert!(failures[1].checksum_mismatch);
        assert!(!failures[1].size_changed);
        assert!(!failures[1].mtime_changed);
    }

    #[test]
    fn test_parse_rpm_missing() {
        let output = "missing    c /etc/baz.conf\nmissing     /usr/bin/gone\n";
        let failures = parse_rpm_va_output(output);
        assert_eq!(failures.len(), 2);

        assert_eq!(failures[0].path, "/etc/baz.conf");
        assert!(failures[0].missing);
        assert!(failures[0].is_conffile);

        assert_eq!(failures[1].path, "/usr/bin/gone");
        assert!(failures[1].missing);
        assert!(!failures[1].is_conffile);
    }

    #[test]
    fn test_exclude_paths() {
        let failures = vec![
            VerificationFailure {
                path: "/usr/share/doc/foo/README".to_string(),
                package: None,
                size_changed: false,
                checksum_mismatch: true,
                mtime_changed: false,
                mode_changed: false,
                owner_changed: false,
                group_changed: false,
                is_conffile: false,
                missing: false,
            },
            VerificationFailure {
                path: "/etc/foo.conf".to_string(),
                package: None,
                size_changed: false,
                checksum_mismatch: true,
                mtime_changed: false,
                mode_changed: false,
                owner_changed: false,
                group_changed: false,
                is_conffile: true,
                missing: false,
            },
        ];

        let filtered = apply_exclusions(&failures, &["/usr/share/doc/".to_string()], &[]);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].path, "/etc/foo.conf");
    }

    #[test]
    fn test_exclude_packages() {
        let failures = vec![
            VerificationFailure {
                path: "/usr/bin/foo".to_string(),
                package: Some("foo-pkg".to_string()),
                size_changed: false,
                checksum_mismatch: true,
                mtime_changed: false,
                mode_changed: false,
                owner_changed: false,
                group_changed: false,
                is_conffile: false,
                missing: false,
            },
            VerificationFailure {
                path: "/usr/bin/bar".to_string(),
                package: Some("bar-pkg".to_string()),
                size_changed: false,
                checksum_mismatch: true,
                mtime_changed: false,
                mode_changed: false,
                owner_changed: false,
                group_changed: false,
                is_conffile: false,
                missing: false,
            },
        ];

        let filtered = apply_exclusions(&failures, &[], &["foo-pkg".to_string()]);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].path, "/usr/bin/bar");
    }

    #[test]
    fn test_severity_determination() {
        // チェックサム不一致(非conffile) -> Warning
        let tampered = VerificationFailure {
            path: "/usr/bin/foo".to_string(),
            package: None,
            size_changed: false,
            checksum_mismatch: true,
            mtime_changed: false,
            mode_changed: false,
            owner_changed: false,
            group_changed: false,
            is_conffile: false,
            missing: false,
        };
        assert!(matches!(determine_severity(&tampered), Severity::Warning));

        // チェックサム不一致(conffile) -> Info
        let conffile_modified = VerificationFailure {
            path: "/etc/foo.conf".to_string(),
            package: None,
            size_changed: false,
            checksum_mismatch: true,
            mtime_changed: false,
            mode_changed: false,
            owner_changed: false,
            group_changed: false,
            is_conffile: true,
            missing: false,
        };
        assert!(matches!(
            determine_severity(&conffile_modified),
            Severity::Info
        ));

        // ファイル欠落 -> Warning
        let missing = VerificationFailure {
            path: "/usr/bin/bar".to_string(),
            package: None,
            size_changed: false,
            checksum_mismatch: false,
            mtime_changed: false,
            mode_changed: false,
            owner_changed: false,
            group_changed: false,
            is_conffile: false,
            missing: true,
        };
        assert!(matches!(determine_severity(&missing), Severity::Warning));

        // その他の変更 -> Info
        let changed = VerificationFailure {
            path: "/usr/lib/foo.so".to_string(),
            package: None,
            size_changed: true,
            checksum_mismatch: false,
            mtime_changed: false,
            mode_changed: false,
            owner_changed: false,
            group_changed: false,
            is_conffile: false,
            missing: false,
        };
        assert!(matches!(determine_severity(&changed), Severity::Info));
    }

    #[test]
    fn test_module_name() {
        let config = PackageVerifyConfig::default();
        let module = PackageVerifyModule::new(config, None);
        assert_eq!(module.name(), "package_verify");
    }

    #[test]
    fn test_init_zero_interval() {
        let config = PackageVerifyConfig {
            interval_secs: 0,
            ..Default::default()
        };
        let mut module = PackageVerifyModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let config = PackageVerifyConfig::default();
        let mut module = PackageVerifyModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let config = PackageVerifyConfig::default();
        let module = PackageVerifyModule::new(config, None);
        let result = module.initial_scan().await;
        assert!(result.is_ok());
        let scan = result.unwrap();
        assert!(scan.summary.contains("パッケージ"));
    }

    #[test]
    fn test_parse_dpkg_empty_output() {
        let failures = parse_dpkg_verify_output("");
        assert!(failures.is_empty());

        let failures = parse_dpkg_verify_output("\n\n");
        assert!(failures.is_empty());
    }

    #[test]
    fn test_parse_rpm_empty_output() {
        let failures = parse_rpm_va_output("");
        assert!(failures.is_empty());

        let failures = parse_rpm_va_output("\n\n");
        assert!(failures.is_empty());
    }
}
