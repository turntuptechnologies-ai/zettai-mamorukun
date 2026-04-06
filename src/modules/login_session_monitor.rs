//! ログインセッション監視モジュール
//!
//! `/var/run/utmp` および `/var/log/wtmp` を定期的にスキャンし、
//! 不審なログインセッションを検知してアラートを発行する。
//!
//! 検知対象:
//! - 新規ログインセッション（Info）
//! - root 直接ログイン（Critical）
//! - 同一ユーザーの過剰な同時セッション（Warning）
//! - 不審な時間帯のログイン（Warning）

use crate::config::LoginSessionMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::BTreeMap;
use std::path::Path;
use tokio_util::sync::CancellationToken;

/// utmp レコードサイズ（Linux x86_64: 384 バイト）
const UTMP_RECORD_SIZE: usize = 384;

/// USER_PROCESS を示す ut_type 値
const USER_PROCESS: i32 = 7;

/// utmp レコードから抽出されたセッション情報
#[derive(Debug, Clone, PartialEq)]
struct SessionInfo {
    /// ユーザー名
    user: String,
    /// ターミナル名（例: "pts/0"）
    line: String,
    /// リモートホスト名
    host: String,
    /// プロセス ID
    pid: i32,
    /// ログイン時刻（Unix タイムスタンプ秒）
    login_time: i32,
}

/// スキャンパラメータ
#[derive(Clone)]
struct ScanParams {
    utmp_path: String,
    alert_root_login: bool,
    max_concurrent_sessions: u32,
    alert_suspicious_hours: bool,
    suspicious_hours_start: u32,
    suspicious_hours_end: u32,
}

/// ログインセッション監視モジュール
pub struct LoginSessionMonitorModule {
    config: LoginSessionMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl LoginSessionMonitorModule {
    /// 新しいログインセッション監視モジュールを作成する
    pub fn new(config: LoginSessionMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// バイト配列から null 終端文字列を抽出する
    fn extract_string(bytes: &[u8]) -> String {
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..end]).to_string()
    }

    /// utmp ファイルのバイナリデータからセッション情報を解析する
    fn parse_utmp_records(data: &[u8]) -> Vec<SessionInfo> {
        let mut sessions = Vec::new();
        let mut offset = 0;

        while offset + UTMP_RECORD_SIZE <= data.len() {
            let record = &data[offset..offset + UTMP_RECORD_SIZE];

            // ut_type: i32 at offset 0
            let ut_type = i32::from_le_bytes([record[0], record[1], record[2], record[3]]);

            if ut_type == USER_PROCESS {
                // ut_pid: i32 at offset 4
                let pid = i32::from_le_bytes([record[4], record[5], record[6], record[7]]);

                // ut_line: [u8; 32] at offset 8
                let line = Self::extract_string(&record[8..40]);

                // ut_user: [u8; 32] at offset 44
                let user = Self::extract_string(&record[44..76]);

                // ut_host: [u8; 256] at offset 76
                let host = Self::extract_string(&record[76..332]);

                // ut_tv_sec: i32 at offset 340
                let login_time =
                    i32::from_le_bytes([record[340], record[341], record[342], record[343]]);

                if !user.is_empty() {
                    sessions.push(SessionInfo {
                        user,
                        line,
                        host,
                        pid,
                        login_time,
                    });
                }
            }

            offset += UTMP_RECORD_SIZE;
        }

        sessions
    }

    /// utmp ファイルを読み取り、アクティブなセッション一覧を返す
    fn read_sessions(utmp_path: &Path) -> Vec<SessionInfo> {
        match std::fs::read(utmp_path) {
            Ok(data) => Self::parse_utmp_records(&data),
            Err(e) => {
                tracing::debug!(
                    path = %utmp_path.display(),
                    error = %e,
                    "utmp ファイルの読み取りに失敗しました"
                );
                Vec::new()
            }
        }
    }

    /// 前回のセッション一覧と比較して新規セッションを検出する
    fn detect_new_sessions<'a>(
        current: &'a [SessionInfo],
        previous: &[SessionInfo],
    ) -> Vec<&'a SessionInfo> {
        current
            .iter()
            .filter(|s| {
                !previous
                    .iter()
                    .any(|p| p.pid == s.pid && p.line == s.line && p.user == s.user)
            })
            .collect()
    }

    /// 同一ユーザーの同時セッション数をカウントする
    fn count_user_sessions(sessions: &[SessionInfo]) -> BTreeMap<String, u32> {
        let mut counts = BTreeMap::new();
        for session in sessions {
            *counts.entry(session.user.clone()).or_insert(0) += 1;
        }
        counts
    }

    /// 指定された時刻が不審な時間帯に該当するかチェックする
    fn is_suspicious_hour(hour: u32, start: u32, end: u32) -> bool {
        if start <= end {
            hour >= start && hour < end
        } else {
            // 日付をまたぐ場合（例: 22時〜6時）
            hour >= start || hour < end
        }
    }

    /// セッション一覧をスキャンし、イベントを発行する
    fn scan_sessions(
        params: &ScanParams,
        previous_sessions: &[SessionInfo],
        event_bus: &Option<EventBus>,
    ) -> (Vec<SessionInfo>, usize, usize, BTreeMap<String, String>) {
        let utmp_path = Path::new(&params.utmp_path);
        let current_sessions = Self::read_sessions(utmp_path);
        let new_sessions = Self::detect_new_sessions(&current_sessions, previous_sessions);

        let items_scanned = current_sessions.len();
        let mut issues_found: usize = 0;
        let mut snapshot = BTreeMap::new();

        // スナップショットを構築
        for session in &current_sessions {
            let key = format!("{}:{}:{}", session.user, session.line, session.pid);
            snapshot.insert(
                key,
                format!(
                    "user={} line={} host={} time={}",
                    session.user, session.line, session.host, session.login_time
                ),
            );
        }

        // 新規セッションの検知
        for session in &new_sessions {
            let host_info = if session.host.is_empty() {
                "ローカル".to_string()
            } else {
                session.host.clone()
            };

            // root 直接ログインの検知
            if params.alert_root_login && session.user == "root" {
                issues_found += 1;
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "login_root_direct",
                            Severity::Critical,
                            "login_session_monitor",
                            format!(
                                "root 直接ログインを検知しました: ターミナル={}, ホスト={}",
                                session.line, host_info,
                            ),
                        )
                        .with_details(format!(
                            "pid={} line={} host={}",
                            session.pid, session.line, session.host,
                        )),
                    );
                }
            }

            // 不審な時間帯のチェック
            if params.alert_suspicious_hours && session.login_time > 0 {
                // login_time から時刻を抽出
                let hour = ((session.login_time % 86400) / 3600) as u32;
                if Self::is_suspicious_hour(
                    hour,
                    params.suspicious_hours_start,
                    params.suspicious_hours_end,
                ) {
                    issues_found += 1;
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "login_suspicious_hour",
                                Severity::Warning,
                                "login_session_monitor",
                                format!(
                                    "不審な時間帯のログインを検知しました: ユーザー={}, 時刻={}時台, ターミナル={}, ホスト={}",
                                    session.user, hour, session.line, host_info,
                                ),
                            )
                            .with_details(format!(
                                "user={} hour={} line={} host={}",
                                session.user, hour, session.line, session.host,
                            )),
                        );
                    }
                }
            }

            // 新規セッション通知（root 以外、または root 検知が無効の場合）
            if !(params.alert_root_login && session.user == "root")
                && let Some(bus) = event_bus
            {
                bus.publish(
                    SecurityEvent::new(
                        "login_new_session",
                        Severity::Info,
                        "login_session_monitor",
                        format!(
                            "新規ログインセッションを検知しました: ユーザー={}, ターミナル={}, ホスト={}",
                            session.user, session.line, host_info,
                        ),
                    )
                    .with_details(format!(
                        "pid={} user={} line={} host={}",
                        session.pid, session.user, session.line, session.host,
                    )),
                );
            }
        }

        // 同時セッション数の超過チェック
        let user_counts = Self::count_user_sessions(&current_sessions);
        for (user, count) in &user_counts {
            if *count > params.max_concurrent_sessions {
                issues_found += 1;
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "login_excessive_sessions",
                            Severity::Warning,
                            "login_session_monitor",
                            format!(
                                "同一ユーザーの過剰な同時セッションを検知しました: ユーザー={}, セッション数={}, 閾値={}",
                                user, count, params.max_concurrent_sessions,
                            ),
                        )
                        .with_details(format!(
                            "user={} count={} threshold={}",
                            user, count, params.max_concurrent_sessions,
                        )),
                    );
                }
            }
        }

        (current_sessions, items_scanned, issues_found, snapshot)
    }
}

impl Module for LoginSessionMonitorModule {
    fn name(&self) -> &str {
        "login_session_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.check_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "check_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        let utmp_path = Path::new(&self.config.utmp_path);
        if !utmp_path.exists() {
            tracing::warn!(
                path = %utmp_path.display(),
                "utmp ファイルが存在しません"
            );
        }

        tracing::info!(
            utmp_path = %self.config.utmp_path,
            wtmp_path = %self.config.wtmp_path,
            check_interval_secs = self.config.check_interval_secs,
            alert_root_login = self.config.alert_root_login,
            max_concurrent_sessions = self.config.max_concurrent_sessions,
            "ログインセッション監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<(), AppError> {
        let params = ScanParams {
            utmp_path: self.config.utmp_path.clone(),
            alert_root_login: self.config.alert_root_login,
            max_concurrent_sessions: self.config.max_concurrent_sessions,
            alert_suspicious_hours: self.config.alert_suspicious_hours,
            suspicious_hours_start: self.config.suspicious_hours_start,
            suspicious_hours_end: self.config.suspicious_hours_end,
        };
        let check_interval_secs = self.config.check_interval_secs;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        // 初回スキャン — 現在のセッションをベースラインとして記録
        let path = Path::new(&params.utmp_path);
        let initial_sessions = Self::read_sessions(path);
        tracing::info!(
            sessions = initial_sessions.len(),
            "ログインセッションの初回スキャンが完了しました"
        );

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(check_interval_secs));
            // 最初の tick は即座に発火するのでスキップ
            interval.tick().await;

            let mut previous_sessions = initial_sessions;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("ログインセッション監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let (current_sessions, items_scanned, issues_found, _snapshot) =
                            LoginSessionMonitorModule::scan_sessions(
                                &params,
                                &previous_sessions,
                                &event_bus,
                            );
                        previous_sessions = current_sessions;
                        tracing::debug!(
                            items_scanned = items_scanned,
                            issues_found = issues_found,
                            "ログインセッションの定期スキャンが完了しました"
                        );
                    }
                }
            }
        });

        Ok(())
    }

    async fn stop(&mut self) -> Result<(), AppError> {
        self.cancel_token.cancel();
        Ok(())
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();

        let params = ScanParams {
            utmp_path: self.config.utmp_path.clone(),
            alert_root_login: self.config.alert_root_login,
            max_concurrent_sessions: self.config.max_concurrent_sessions,
            alert_suspicious_hours: self.config.alert_suspicious_hours,
            suspicious_hours_start: self.config.suspicious_hours_start,
            suspicious_hours_end: self.config.suspicious_hours_end,
        };
        let (_, items_scanned, issues_found, snapshot) =
            Self::scan_sessions(&params, &[], &self.event_bus);

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "ログインセッション {}件をスキャンしました（問題: {}件）",
                items_scanned, issues_found,
            ),
            snapshot,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// テスト用の utmp レコードを作成する
    fn create_utmp_record(
        ut_type: i32,
        pid: i32,
        line: &str,
        user: &str,
        host: &str,
        tv_sec: i32,
    ) -> Vec<u8> {
        let mut record = vec![0u8; UTMP_RECORD_SIZE];

        // ut_type at offset 0
        record[0..4].copy_from_slice(&ut_type.to_le_bytes());

        // ut_pid at offset 4
        record[4..8].copy_from_slice(&pid.to_le_bytes());

        // ut_line at offset 8 (32 bytes)
        let line_bytes = line.as_bytes();
        let len = line_bytes.len().min(31);
        record[8..8 + len].copy_from_slice(&line_bytes[..len]);

        // ut_user at offset 44 (32 bytes)
        let user_bytes = user.as_bytes();
        let len = user_bytes.len().min(31);
        record[44..44 + len].copy_from_slice(&user_bytes[..len]);

        // ut_host at offset 76 (256 bytes)
        let host_bytes = host.as_bytes();
        let len = host_bytes.len().min(255);
        record[76..76 + len].copy_from_slice(&host_bytes[..len]);

        // ut_tv_sec at offset 340
        record[340..344].copy_from_slice(&tv_sec.to_le_bytes());

        record
    }

    #[test]
    fn test_parse_utmp_single_record() {
        let data = create_utmp_record(
            USER_PROCESS,
            1234,
            "pts/0",
            "testuser",
            "192.168.1.1",
            1700000000,
        );
        let sessions = LoginSessionMonitorModule::parse_utmp_records(&data);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].user, "testuser");
        assert_eq!(sessions[0].line, "pts/0");
        assert_eq!(sessions[0].host, "192.168.1.1");
        assert_eq!(sessions[0].pid, 1234);
        assert_eq!(sessions[0].login_time, 1700000000);
    }

    #[test]
    fn test_parse_utmp_multiple_records() {
        let mut data =
            create_utmp_record(USER_PROCESS, 1000, "pts/0", "alice", "10.0.0.1", 1700000000);
        data.extend(create_utmp_record(
            USER_PROCESS,
            2000,
            "pts/1",
            "bob",
            "10.0.0.2",
            1700000100,
        ));
        let sessions = LoginSessionMonitorModule::parse_utmp_records(&data);
        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions[0].user, "alice");
        assert_eq!(sessions[1].user, "bob");
    }

    #[test]
    fn test_parse_utmp_skips_non_user_process() {
        // ut_type=1 (RUN_LVL) should be skipped
        let mut data = create_utmp_record(1, 0, "", "runlevel", "", 0);
        data.extend(create_utmp_record(
            USER_PROCESS,
            1234,
            "pts/0",
            "testuser",
            "",
            1700000000,
        ));
        let sessions = LoginSessionMonitorModule::parse_utmp_records(&data);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].user, "testuser");
    }

    #[test]
    fn test_parse_utmp_empty_data() {
        let sessions = LoginSessionMonitorModule::parse_utmp_records(&[]);
        assert!(sessions.is_empty());
    }

    #[test]
    fn test_parse_utmp_partial_record() {
        // Data shorter than one record should be ignored
        let data = vec![0u8; 100];
        let sessions = LoginSessionMonitorModule::parse_utmp_records(&data);
        assert!(sessions.is_empty());
    }

    #[test]
    fn test_detect_new_sessions() {
        let prev = vec![SessionInfo {
            user: "alice".to_string(),
            line: "pts/0".to_string(),
            host: "10.0.0.1".to_string(),
            pid: 1000,
            login_time: 1700000000,
        }];
        let current = vec![
            SessionInfo {
                user: "alice".to_string(),
                line: "pts/0".to_string(),
                host: "10.0.0.1".to_string(),
                pid: 1000,
                login_time: 1700000000,
            },
            SessionInfo {
                user: "bob".to_string(),
                line: "pts/1".to_string(),
                host: "10.0.0.2".to_string(),
                pid: 2000,
                login_time: 1700000100,
            },
        ];
        let new_sessions = LoginSessionMonitorModule::detect_new_sessions(&current, &prev);
        assert_eq!(new_sessions.len(), 1);
        assert_eq!(new_sessions[0].user, "bob");
    }

    #[test]
    fn test_detect_new_sessions_all_new() {
        let current = vec![SessionInfo {
            user: "alice".to_string(),
            line: "pts/0".to_string(),
            host: "".to_string(),
            pid: 1000,
            login_time: 1700000000,
        }];
        let new_sessions = LoginSessionMonitorModule::detect_new_sessions(&current, &[]);
        assert_eq!(new_sessions.len(), 1);
    }

    #[test]
    fn test_detect_new_sessions_none_new() {
        let sessions = vec![SessionInfo {
            user: "alice".to_string(),
            line: "pts/0".to_string(),
            host: "".to_string(),
            pid: 1000,
            login_time: 1700000000,
        }];
        let new_sessions = LoginSessionMonitorModule::detect_new_sessions(&sessions, &sessions);
        assert!(new_sessions.is_empty());
    }

    #[test]
    fn test_count_user_sessions() {
        let sessions = vec![
            SessionInfo {
                user: "alice".to_string(),
                line: "pts/0".to_string(),
                host: "".to_string(),
                pid: 1000,
                login_time: 0,
            },
            SessionInfo {
                user: "alice".to_string(),
                line: "pts/1".to_string(),
                host: "".to_string(),
                pid: 1001,
                login_time: 0,
            },
            SessionInfo {
                user: "bob".to_string(),
                line: "pts/2".to_string(),
                host: "".to_string(),
                pid: 2000,
                login_time: 0,
            },
        ];
        let counts = LoginSessionMonitorModule::count_user_sessions(&sessions);
        assert_eq!(counts.get("alice"), Some(&2));
        assert_eq!(counts.get("bob"), Some(&1));
    }

    #[test]
    fn test_suspicious_hour_normal_range() {
        // 0時〜6時が不審な時間帯
        assert!(LoginSessionMonitorModule::is_suspicious_hour(0, 0, 6));
        assert!(LoginSessionMonitorModule::is_suspicious_hour(3, 0, 6));
        assert!(LoginSessionMonitorModule::is_suspicious_hour(5, 0, 6));
        assert!(!LoginSessionMonitorModule::is_suspicious_hour(6, 0, 6));
        assert!(!LoginSessionMonitorModule::is_suspicious_hour(12, 0, 6));
        assert!(!LoginSessionMonitorModule::is_suspicious_hour(23, 0, 6));
    }

    #[test]
    fn test_suspicious_hour_wrap_around() {
        // 22時〜6時が不審な時間帯（日付をまたぐ）
        assert!(LoginSessionMonitorModule::is_suspicious_hour(22, 22, 6));
        assert!(LoginSessionMonitorModule::is_suspicious_hour(23, 22, 6));
        assert!(LoginSessionMonitorModule::is_suspicious_hour(0, 22, 6));
        assert!(LoginSessionMonitorModule::is_suspicious_hour(3, 22, 6));
        assert!(!LoginSessionMonitorModule::is_suspicious_hour(6, 22, 6));
        assert!(!LoginSessionMonitorModule::is_suspicious_hour(12, 22, 6));
        assert!(!LoginSessionMonitorModule::is_suspicious_hour(21, 22, 6));
    }

    #[test]
    fn test_extract_string_null_terminated() {
        let bytes = b"hello\0world";
        assert_eq!(LoginSessionMonitorModule::extract_string(bytes), "hello");
    }

    #[test]
    fn test_extract_string_no_null() {
        let bytes = b"hello";
        assert_eq!(LoginSessionMonitorModule::extract_string(bytes), "hello");
    }

    #[test]
    fn test_extract_string_empty() {
        let bytes = b"\0rest";
        assert_eq!(LoginSessionMonitorModule::extract_string(bytes), "");
    }

    fn make_scan_params(
        utmp_path: &str,
        alert_root: bool,
        max_sessions: u32,
        alert_hours: bool,
        hours_start: u32,
        hours_end: u32,
    ) -> ScanParams {
        ScanParams {
            utmp_path: utmp_path.to_string(),
            alert_root_login: alert_root,
            max_concurrent_sessions: max_sessions,
            alert_suspicious_hours: alert_hours,
            suspicious_hours_start: hours_start,
            suspicious_hours_end: hours_end,
        }
    }

    #[test]
    fn test_scan_sessions_root_login() {
        let tmp_dir = std::env::temp_dir();
        let utmp_path = tmp_dir.join("test_utmp_root");
        let data = create_utmp_record(USER_PROCESS, 1234, "pts/0", "root", "10.0.0.1", 1700050000);
        std::fs::write(&utmp_path, &data).unwrap();

        let params = make_scan_params(&utmp_path.to_string_lossy(), true, 3, false, 0, 6);
        let (sessions, items, issues, _snapshot) =
            LoginSessionMonitorModule::scan_sessions(&params, &[], &None);

        assert_eq!(sessions.len(), 1);
        assert_eq!(items, 1);
        assert_eq!(issues, 1); // root login detected

        std::fs::remove_file(&utmp_path).ok();
    }

    #[test]
    fn test_scan_sessions_concurrent_threshold() {
        let tmp_dir = std::env::temp_dir();
        let utmp_path = tmp_dir.join("test_utmp_concurrent");

        let mut data = Vec::new();
        for i in 0..4 {
            data.extend(create_utmp_record(
                USER_PROCESS,
                1000 + i,
                &format!("pts/{}", i),
                "alice",
                "",
                1700050000,
            ));
        }
        std::fs::write(&utmp_path, &data).unwrap();

        let params = make_scan_params(&utmp_path.to_string_lossy(), false, 3, false, 0, 6);
        let (_sessions, _items, issues, _snapshot) =
            LoginSessionMonitorModule::scan_sessions(&params, &[], &None);

        assert_eq!(issues, 1); // exceeded concurrent session threshold

        std::fs::remove_file(&utmp_path).ok();
    }

    #[test]
    fn test_scan_sessions_suspicious_hours() {
        let tmp_dir = std::env::temp_dir();
        let utmp_path = tmp_dir.join("test_utmp_suspicious");

        // login_time = 3600 * 3 = 10800 => 3:00 AM (UTC)
        let data = create_utmp_record(USER_PROCESS, 1234, "pts/0", "alice", "", 10800);
        std::fs::write(&utmp_path, &data).unwrap();

        let params = make_scan_params(&utmp_path.to_string_lossy(), false, 10, true, 0, 6);
        let (_sessions, _items, issues, _snapshot) =
            LoginSessionMonitorModule::scan_sessions(&params, &[], &None);

        assert_eq!(issues, 1); // suspicious hour login

        std::fs::remove_file(&utmp_path).ok();
    }

    #[test]
    fn test_scan_sessions_nonexistent_file() {
        let params = make_scan_params(
            "/tmp/nonexistent_utmp_test_file_12345",
            false,
            3,
            false,
            0,
            6,
        );
        let (sessions, items, issues, snapshot) =
            LoginSessionMonitorModule::scan_sessions(&params, &[], &None);
        assert!(sessions.is_empty());
        assert_eq!(items, 0);
        assert_eq!(issues, 0);
        assert!(snapshot.is_empty());
    }

    #[test]
    fn test_config_defaults() {
        let config = LoginSessionMonitorConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.check_interval_secs, 30);
        assert_eq!(config.utmp_path, "/var/run/utmp");
        assert_eq!(config.wtmp_path, "/var/log/wtmp");
        assert!(config.alert_root_login);
        assert_eq!(config.max_concurrent_sessions, 3);
        assert_eq!(config.suspicious_hours_start, 0);
        assert_eq!(config.suspicious_hours_end, 6);
        assert!(!config.alert_suspicious_hours);
    }

    #[test]
    fn test_module_name() {
        let config = LoginSessionMonitorConfig::default();
        let module = LoginSessionMonitorModule::new(config, None);
        assert_eq!(module.name(), "login_session_monitor");
    }

    #[test]
    fn test_module_init_zero_interval() {
        let config = LoginSessionMonitorConfig {
            enabled: true,
            check_interval_secs: 0,
            ..LoginSessionMonitorConfig::default()
        };
        let mut module = LoginSessionMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_module_init_success() {
        let config = LoginSessionMonitorConfig::default();
        let mut module = LoginSessionMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_module_start_stop() {
        let config = LoginSessionMonitorConfig {
            enabled: true,
            utmp_path: "/tmp/nonexistent_utmp_start_stop_test".to_string(),
            ..LoginSessionMonitorConfig::default()
        };
        let mut module = LoginSessionMonitorModule::new(config, None);
        module.init().unwrap();
        let result = module.start().await;
        assert!(result.is_ok());
        let result = module.stop().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_initial_scan_empty() {
        let config = LoginSessionMonitorConfig {
            utmp_path: "/tmp/nonexistent_utmp_initial_scan_test".to_string(),
            ..LoginSessionMonitorConfig::default()
        };
        let module = LoginSessionMonitorModule::new(config, None);
        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
        assert!(result.snapshot.is_empty());
    }

    #[tokio::test]
    async fn test_initial_scan_with_sessions() {
        let tmp_dir = std::env::temp_dir();
        let utmp_path = tmp_dir.join("test_utmp_initial_scan");

        let mut data =
            create_utmp_record(USER_PROCESS, 1000, "pts/0", "alice", "10.0.0.1", 1700050000);
        data.extend(create_utmp_record(
            USER_PROCESS,
            2000,
            "pts/1",
            "bob",
            "",
            1700050100,
        ));
        std::fs::write(&utmp_path, &data).unwrap();

        let config = LoginSessionMonitorConfig {
            utmp_path: utmp_path.to_string_lossy().to_string(),
            alert_root_login: false,
            ..LoginSessionMonitorConfig::default()
        };
        let module = LoginSessionMonitorModule::new(config, None);
        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 2);
        assert_eq!(result.snapshot.len(), 2);

        std::fs::remove_file(&utmp_path).ok();
    }
}
