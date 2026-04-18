//! セキュリティスコアリング

use crate::config::ScoringConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::{broadcast, watch};

/// 外部から参照可能なセキュリティスコアデータ
#[derive(Debug, Clone, Default, Serialize)]
pub struct SharedSecurityScore {
    /// 総合スコア（0〜100）
    pub overall_score: u32,
    /// グレード（A〜F）
    pub grade: String,
    /// カテゴリ別スコア
    pub categories: HashMap<String, CategoryScore>,
    /// サマリー
    pub summary: ScoreSummary,
    /// 評価日時（ISO 8601）
    pub evaluated_at: String,
}

/// カテゴリ別スコア
#[derive(Debug, Clone, Default, Serialize)]
pub struct CategoryScore {
    /// スコア（0〜100）
    pub score: u32,
    /// グレード（A〜F）
    pub grade: String,
    /// 検知された問題数
    pub issues: u32,
}

/// スコアサマリー
#[derive(Debug, Clone, Default, Serialize)]
pub struct ScoreSummary {
    /// 総イベント数
    pub total_events: u64,
    /// CRITICAL イベント数
    pub critical: u64,
    /// WARNING イベント数（high として扱う）
    pub high: u64,
    /// 未使用（API 互換のため 0 固定）
    pub medium: u64,
    /// 未使用（0 固定）
    pub low: u64,
    /// INFO イベント数
    pub info: u64,
}

/// スコアリングランタイム設定（ホットリロード用）
#[derive(Debug, Clone)]
pub struct ScoringRuntimeConfig {
    /// スコア更新インターバル（秒）
    pub interval_secs: u64,
    /// カテゴリ別重み付け
    pub category_weights: HashMap<String, f64>,
}

/// セキュリティスコアラー
pub struct SecurityScorer {
    receiver: broadcast::Receiver<SecurityEvent>,
    interval: Duration,
    config_receiver: watch::Receiver<ScoringRuntimeConfig>,
    shared_score: Arc<StdMutex<SharedSecurityScore>>,
    category_weights: HashMap<String, f64>,
}

impl SecurityScorer {
    /// 設定とイベントバスから SecurityScorer を構築する
    pub fn new(
        config: &ScoringConfig,
        event_bus: &EventBus,
    ) -> (
        Self,
        watch::Sender<ScoringRuntimeConfig>,
        Arc<StdMutex<SharedSecurityScore>>,
    ) {
        let interval_secs = config.interval_secs;
        let runtime_config = ScoringRuntimeConfig {
            interval_secs,
            category_weights: config.category_weights.clone(),
        };
        let (config_sender, config_receiver) = watch::channel(runtime_config);
        let shared_score = Arc::new(StdMutex::new(SharedSecurityScore::default()));
        (
            Self {
                receiver: event_bus.subscribe(),
                interval: Duration::from_secs(interval_secs),
                config_receiver,
                shared_score: Arc::clone(&shared_score),
                category_weights: config.category_weights.clone(),
            },
            config_sender,
            shared_score,
        )
    }

    /// 非同期タスクとしてスコアラーを起動する
    pub fn spawn(self) {
        let shared_score = self.shared_score;
        let category_weights = self.category_weights;
        tokio::spawn(async move {
            Self::run_loop(
                self.receiver,
                self.interval,
                self.config_receiver,
                shared_score,
                category_weights,
            )
            .await;
        });
    }

    async fn run_loop(
        mut receiver: broadcast::Receiver<SecurityEvent>,
        interval: Duration,
        mut config_receiver: watch::Receiver<ScoringRuntimeConfig>,
        shared_score: Arc<StdMutex<SharedSecurityScore>>,
        mut category_weights: HashMap<String, f64>,
    ) {
        let mut category_critical: HashMap<String, u64> = HashMap::new();
        let mut category_warning: HashMap<String, u64> = HashMap::new();
        let mut total_events: u64 = 0;
        let mut critical_count: u64 = 0;
        let mut warning_count: u64 = 0;
        let mut info_count: u64 = 0;

        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await;

        loop {
            tokio::select! {
                result = receiver.recv() => {
                    match result {
                        Ok(event) => {
                            total_events += 1;
                            let category = categorize_module(&event.source_module).to_string();
                            match event.severity {
                                Severity::Critical => {
                                    critical_count += 1;
                                    *category_critical.entry(category).or_insert(0) += 1;
                                }
                                Severity::Warning => {
                                    warning_count += 1;
                                    *category_warning.entry(category).or_insert(0) += 1;
                                }
                                Severity::Info => {
                                    info_count += 1;
                                }
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(
                                skipped = n,
                                "スコアラー: {} 件のイベントをスキップ（遅延）",
                                n
                            );
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            tracing::info!("イベントバスが閉じられました。スコアラーを終了します");
                            break;
                        }
                    }
                }
                _ = ticker.tick() => {
                    update_shared_score(
                        &shared_score,
                        &category_critical,
                        &category_warning,
                        &category_weights,
                        total_events,
                        critical_count,
                        warning_count,
                        info_count,
                    );
                }
                result = config_receiver.changed() => {
                    match result {
                        Ok(()) => {
                            let new_config = config_receiver.borrow_and_update().clone();
                            let new_interval = Duration::from_secs(new_config.interval_secs);
                            tracing::info!(
                                old_interval_secs = interval.as_secs(),
                                new_interval_secs = new_config.interval_secs,
                                "スコアラー: 設定をリロードしました"
                            );
                            category_weights = new_config.category_weights;
                            ticker = tokio::time::interval(new_interval);
                            ticker.tick().await;
                        }
                        Err(_) => {
                            tracing::info!("設定チャネルが閉じられました。スコアラーを終了します");
                            break;
                        }
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn update_shared_score(
    shared_score: &Arc<StdMutex<SharedSecurityScore>>,
    category_critical: &HashMap<String, u64>,
    category_warning: &HashMap<String, u64>,
    category_weights: &HashMap<String, f64>,
    total_events: u64,
    critical_count: u64,
    warning_count: u64,
    info_count: u64,
) {
    let all_categories = [
        "network",
        "filesystem",
        "process",
        "auth",
        "kernel",
        "system",
    ];

    let mut categories = HashMap::new();
    let mut weighted_sum: f64 = 0.0;
    let mut weight_total: f64 = 0.0;

    for &cat in &all_categories {
        let cat_critical = category_critical.get(cat).copied().unwrap_or(0);
        let cat_warning = category_warning.get(cat).copied().unwrap_or(0);
        let score = calculate_score(cat_critical, cat_warning);
        let grade = grade_from_score(score).to_string();
        let issues = (cat_critical + cat_warning) as u32;

        let weight = category_weights.get(cat).copied().unwrap_or(1.0);
        weighted_sum += score as f64 * weight;
        weight_total += weight;

        categories.insert(
            cat.to_string(),
            CategoryScore {
                score,
                grade,
                issues,
            },
        );
    }

    let overall_score = if weight_total > 0.0 {
        (weighted_sum / weight_total).round() as u32
    } else {
        100
    };
    let overall_score = overall_score.min(100);
    let grade = grade_from_score(overall_score).to_string();

    let now = chrono_now_iso8601();

    if let Ok(mut s) = shared_score.lock() {
        s.overall_score = overall_score;
        s.grade = grade;
        s.categories = categories;
        s.summary = ScoreSummary {
            total_events,
            critical: critical_count,
            high: warning_count,
            medium: 0,
            low: 0,
            info: info_count,
        };
        s.evaluated_at = now;
    }
}

fn calculate_score(critical_count: u64, warning_count: u64) -> u32 {
    let penalty = (critical_count.min(2) * 20 + warning_count.min(3) * 10) as u32;
    100u32.saturating_sub(penalty)
}

fn grade_from_score(score: u32) -> &'static str {
    match score {
        90..=100 => "A",
        75..=89 => "B",
        60..=74 => "C",
        40..=59 => "D",
        _ => "F",
    }
}

fn categorize_module(module_name: &str) -> &'static str {
    match module_name {
        "network_monitor"
        | "network_interface_monitor"
        | "network_traffic_monitor"
        | "listening_port_monitor"
        | "dns_monitor"
        | "dns_query_monitor"
        | "ssh_brute_force"
        | "firewall_monitor"
        | "proc_net_monitor"
        | "backdoor_detector"
        | "unix_socket_monitor"
        | "abstract_socket_monitor" => "network",

        "file_integrity" | "inotify_monitor" | "log_tamper" | "xattr_monitor" | "mount_monitor"
        | "tmp_exec_monitor" | "shm_monitor" | "suid_sgid_monitor" | "honeypot_monitor" => {
            "filesystem"
        }

        "process_monitor"
        | "process_tree_monitor"
        | "process_exec_monitor"
        | "process_cgroup_monitor"
        | "process_cmdline_monitor"
        | "hidden_process_monitor"
        | "privilege_escalation_monitor"
        | "ptrace_monitor"
        | "proc_maps_monitor"
        | "proc_environ_monitor"
        | "fd_monitor"
        | "fileless_exec_monitor"
        | "dynamic_library_monitor" => "process",

        "user_account"
        | "group_monitor"
        | "login_session_monitor"
        | "ssh_key_monitor"
        | "sshd_config_monitor"
        | "sudoers_monitor"
        | "pam_monitor"
        | "security_files_monitor" => "auth",

        "kernel_module"
        | "kernel_params"
        | "kernel_taint_monitor"
        | "kernel_cmdline_monitor"
        | "kallsyms_monitor"
        | "ebpf_monitor"
        | "livepatch_monitor"
        | "seccomp_monitor"
        | "capabilities_monitor"
        | "mac_monitor"
        | "initramfs_monitor"
        | "bootloader_monitor"
        | "cgroup_monitor" => "kernel",

        _ => "system",
    }
}

fn chrono_now_iso8601() -> String {
    let now = std::time::SystemTime::now();
    let duration = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    let days = secs / 86400;
    let day_secs = secs % 86400;
    let hours = day_secs / 3600;
    let minutes = (day_secs % 3600) / 60;
    let seconds = day_secs % 60;

    // Simple date calculation from epoch days
    let mut y = 1970i64;
    let mut remaining_days = days as i64;

    loop {
        let year_days = if is_leap_year(y) { 366 } else { 365 };
        if remaining_days < year_days {
            break;
        }
        remaining_days -= year_days;
        y += 1;
    }

    let month_days: [i64; 12] = if is_leap_year(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut m = 0;
    for (i, &md) in month_days.iter().enumerate() {
        if remaining_days < md {
            m = i;
            break;
        }
        remaining_days -= md;
    }

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m + 1,
        remaining_days + 1,
        hours,
        minutes,
        seconds
    )
}

fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_score() {
        assert_eq!(calculate_score(0, 0), 100);
        assert_eq!(calculate_score(1, 0), 80);
        assert_eq!(calculate_score(2, 0), 60);
        assert_eq!(calculate_score(0, 1), 90);
        assert_eq!(calculate_score(0, 3), 70);
        assert_eq!(calculate_score(2, 3), 30);
        // Capped at min(2) and min(3)
        assert_eq!(calculate_score(5, 5), 30);
        assert_eq!(calculate_score(10, 10), 30);
    }

    #[test]
    fn test_grade_from_score() {
        assert_eq!(grade_from_score(100), "A");
        assert_eq!(grade_from_score(95), "A");
        assert_eq!(grade_from_score(90), "A");
        assert_eq!(grade_from_score(89), "B");
        assert_eq!(grade_from_score(75), "B");
        assert_eq!(grade_from_score(74), "C");
        assert_eq!(grade_from_score(60), "C");
        assert_eq!(grade_from_score(59), "D");
        assert_eq!(grade_from_score(40), "D");
        assert_eq!(grade_from_score(39), "F");
        assert_eq!(grade_from_score(0), "F");
    }

    #[test]
    fn test_categorize_module() {
        assert_eq!(categorize_module("network_monitor"), "network");
        assert_eq!(categorize_module("ssh_brute_force"), "network");
        assert_eq!(categorize_module("file_integrity"), "filesystem");
        assert_eq!(categorize_module("inotify_monitor"), "filesystem");
        assert_eq!(categorize_module("process_monitor"), "process");
        assert_eq!(categorize_module("ptrace_monitor"), "process");
        assert_eq!(categorize_module("user_account"), "auth");
        assert_eq!(categorize_module("pam_monitor"), "auth");
        assert_eq!(categorize_module("kernel_module"), "kernel");
        assert_eq!(categorize_module("ebpf_monitor"), "kernel");
        assert_eq!(categorize_module("systemd_service"), "system");
        assert_eq!(categorize_module("cron_monitor"), "system");
        assert_eq!(categorize_module("unknown_module"), "system");
    }

    #[test]
    fn test_security_scorer_new() {
        let config = ScoringConfig::default();
        let bus = EventBus::new(16);
        let (scorer, _sender, _shared) = SecurityScorer::new(&config, &bus);
        assert_eq!(scorer.interval, Duration::from_secs(300));
    }

    #[tokio::test]
    async fn test_security_scorer_receives_events() {
        let bus = EventBus::new(16);
        let config = ScoringConfig {
            enabled: true,
            interval_secs: 1,
            category_weights: HashMap::new(),
        };
        let (scorer, _sender, shared) = SecurityScorer::new(&config, &bus);
        scorer.spawn();

        bus.publish(SecurityEvent::new(
            "test_event",
            Severity::Critical,
            "network_monitor",
            "テストイベント",
        ));
        bus.publish(SecurityEvent::new(
            "test_event",
            Severity::Warning,
            "file_integrity",
            "テストイベント",
        ));
        bus.publish(SecurityEvent::new(
            "test_event",
            Severity::Info,
            "process_monitor",
            "テストイベント",
        ));

        // イベント処理とスコア更新を待つ
        tokio::time::sleep(Duration::from_millis(200)).await;
        // ticker が発火するまで待つ
        tokio::time::sleep(Duration::from_secs(1)).await;

        let s = shared.lock().unwrap();
        assert!(s.overall_score <= 100);
        assert!(!s.grade.is_empty());
        assert_eq!(s.summary.critical, 1);
        assert_eq!(s.summary.high, 1);
        assert_eq!(s.summary.info, 1);
        assert_eq!(s.summary.total_events, 3);
    }

    #[test]
    fn test_shared_security_score_default() {
        let score = SharedSecurityScore::default();
        assert_eq!(score.overall_score, 0);
        assert_eq!(score.grade, "");
        assert!(score.categories.is_empty());
        assert_eq!(score.summary.total_events, 0);
        assert_eq!(score.summary.critical, 0);
        assert_eq!(score.summary.high, 0);
        assert_eq!(score.summary.medium, 0);
        assert_eq!(score.summary.low, 0);
        assert_eq!(score.summary.info, 0);
        assert_eq!(score.evaluated_at, "");
    }

    #[test]
    fn test_shared_security_score_serialize() {
        let mut score = SharedSecurityScore {
            overall_score: 85,
            grade: "B".to_string(),
            ..Default::default()
        };
        score.summary.total_events = 10;
        score.summary.critical = 1;
        score.summary.high = 2;

        let json = serde_json::to_string(&score).unwrap();
        assert!(json.contains("\"overall_score\":85"));
        assert!(json.contains("\"grade\":\"B\""));
        assert!(json.contains("\"total_events\":10"));
    }

    #[test]
    fn test_chrono_now_iso8601_format() {
        let ts = chrono_now_iso8601();
        // ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ
        assert!(ts.ends_with('Z'));
        assert!(ts.contains('T'));
        assert_eq!(ts.len(), 20);
    }
}
