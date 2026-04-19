use crate::encryption::EncryptionConfig;
use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// アプリケーション全体の設定
#[derive(Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct AppConfig {
    /// 一般設定
    #[serde(default)]
    pub general: GeneralConfig,

    /// デーモン動作設定
    #[serde(default)]
    pub daemon: DaemonConfig,

    /// モジュール設定
    #[serde(default)]
    pub modules: ModulesConfig,

    /// ヘルスチェック設定
    #[serde(default)]
    pub health: HealthConfig,

    /// イベントバス設定
    #[serde(default)]
    pub event_bus: EventBusConfig,

    /// アクションエンジン設定
    #[serde(default)]
    pub actions: ActionConfig,

    /// メトリクス収集設定
    #[serde(default)]
    pub metrics: MetricsConfig,

    /// モジュール実行統計設定
    #[serde(default)]
    pub module_stats: ModuleStatsConfig,

    /// ステータスサーバー設定
    #[serde(default)]
    pub status: StatusConfig,

    /// 起動時スキャン設定
    #[serde(default)]
    pub startup_scan: StartupScanConfig,

    /// イベントストア設定
    #[serde(default)]
    pub event_store: EventStoreConfig,

    /// イベントストリーム設定
    #[serde(default)]
    pub event_stream: EventStreamConfig,

    /// 相関分析エンジン設定
    #[serde(default)]
    pub correlation: CorrelationConfig,

    /// モジュールウォッチドッグ設定
    #[serde(default)]
    pub module_watchdog: ModuleWatchdogConfig,

    /// Syslog 転送設定
    #[serde(default)]
    pub syslog: SyslogConfig,

    /// アラートルール DSL 設定
    #[serde(default)]
    pub alert_rules: AlertRulesConfig,

    /// Prometheus メトリクスエクスポーター設定
    #[serde(default)]
    pub prometheus: PrometheusConfig,

    /// REST API サーバー設定
    #[serde(default)]
    pub api: ApiConfig,

    /// セキュリティスコアリング設定
    #[serde(default)]
    pub scoring: ScoringConfig,

    /// 暗号化設定
    #[serde(default)]
    pub encryption: Option<EncryptionConfig>,
}

/// デーモン動作設定
#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct DaemonConfig {
    /// シャットダウンタイムアウト（秒）
    #[serde(default = "DaemonConfig::default_shutdown_timeout_secs")]
    pub shutdown_timeout_secs: u64,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            shutdown_timeout_secs: Self::default_shutdown_timeout_secs(),
        }
    }
}

impl DaemonConfig {
    fn default_shutdown_timeout_secs() -> u64 {
        30
    }
}

/// 起動時セキュリティスキャン設定
#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct StartupScanConfig {
    /// 起動時スキャンの有効/無効（デフォルト: true）
    #[serde(default = "StartupScanConfig::default_enabled")]
    pub enabled: bool,
    /// スキャン全体のタイムアウト（秒、デフォルト: 60）
    #[serde(default = "StartupScanConfig::default_timeout_secs")]
    pub timeout_secs: u64,
    /// スキャン結果の永続化の有効/無効（デフォルト: true）
    #[serde(default = "StartupScanConfig::default_persist_state")]
    pub persist_state: bool,
    /// スキャン状態ファイルのパス
    #[serde(default = "StartupScanConfig::default_state_file")]
    pub state_file: String,
}

impl Default for StartupScanConfig {
    fn default() -> Self {
        Self {
            enabled: Self::default_enabled(),
            timeout_secs: Self::default_timeout_secs(),
            persist_state: Self::default_persist_state(),
            state_file: Self::default_state_file(),
        }
    }
}

impl StartupScanConfig {
    fn default_enabled() -> bool {
        true
    }

    fn default_timeout_secs() -> u64 {
        60
    }

    fn default_persist_state() -> bool {
        true
    }

    fn default_state_file() -> String {
        "/var/lib/zettai-mamorukun/scan_state.json".to_string()
    }
}

/// 一般設定
#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct GeneralConfig {
    /// ログレベル（trace, debug, info, warn, error）
    #[serde(default = "GeneralConfig::default_log_level")]
    pub log_level: String,

    /// journald への構造化ログ送信の有効/無効
    #[serde(default = "GeneralConfig::default_journald_enabled")]
    pub journald_enabled: bool,

    /// journald カスタムフィールドのプレフィックス
    ///
    /// SecurityEvent の各フィールドが `{PREFIX}_EVENT_TYPE`, `{PREFIX}_SEVERITY` 等の
    /// 名前で journald に送信される。`journalctl {PREFIX}_SEVERITY=CRITICAL` のように
    /// フィルタリングに使用できる。
    #[serde(default = "GeneralConfig::default_journald_field_prefix")]
    pub journald_field_prefix: String,
}

/// モジュール設定
#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq)]
pub struct ModulesConfig {
    /// ファイル整合性監視モジュールの設定
    #[serde(default)]
    pub file_integrity: FileIntegrityConfig,

    /// プロセス異常検知モジュールの設定
    #[serde(default)]
    pub process_monitor: ProcessMonitorConfig,

    /// カーネルモジュール監視モジュールの設定
    #[serde(default)]
    pub kernel_module: KernelModuleConfig,

    /// auditd ログ統合モジュールの設定
    #[serde(default)]
    pub auditd_monitor: AuditdMonitorConfig,

    /// at/batch ジョブ監視モジュールの設定
    #[serde(default)]
    pub at_job_monitor: AtJobMonitorConfig,

    /// Cron ジョブ改ざん検知モジュールの設定
    #[serde(default)]
    pub cron_monitor: CronMonitorConfig,

    /// ユーザーアカウント監視モジュールの設定
    #[serde(default)]
    pub user_account: UserAccountConfig,

    /// ログファイル改ざん検知モジュールの設定
    #[serde(default)]
    pub log_tamper: LogTamperConfig,

    /// systemd サービス監視モジュールの設定
    #[serde(default)]
    pub systemd_service: SystemdServiceConfig,

    /// systemd タイマー監視モジュールの設定
    #[serde(default)]
    pub systemd_timer_monitor: SystemdTimerMonitorConfig,

    /// ファイアウォールルール監視モジュールの設定
    #[serde(default)]
    pub firewall_monitor: FirewallMonitorConfig,

    /// DNS設定改ざん検知モジュールの設定
    #[serde(default)]
    pub dns_monitor: DnsMonitorConfig,

    /// ネットワーク名前解決監視モジュールの設定
    #[serde(default)]
    pub dns_query_monitor: DnsQueryMonitorConfig,

    /// SSH公開鍵ファイル監視モジュールの設定
    #[serde(default)]
    pub ssh_key_monitor: SshKeyMonitorConfig,

    /// マウントポイント監視モジュールの設定
    #[serde(default)]
    pub mount_monitor: MountMonitorConfig,

    /// シェル設定ファイル監視モジュールの設定
    #[serde(default)]
    pub shell_config_monitor: ShellConfigMonitorConfig,

    /// 一時ディレクトリ実行ファイル検知モジュールの設定
    #[serde(default)]
    pub tmp_exec_monitor: TmpExecMonitorConfig,

    /// sudoers ファイル監視モジュールの設定
    #[serde(default)]
    pub sudoers_monitor: SudoersMonitorConfig,

    /// SUID/SGID ファイル監視モジュールの設定
    #[serde(default)]
    pub suid_sgid_monitor: SuidSgidMonitorConfig,

    /// SSH ブルートフォース検知モジュールの設定
    #[serde(default)]
    pub ssh_brute_force: SshBruteForceConfig,

    /// SSH 設定セキュリティ監査モジュールの設定
    #[serde(default)]
    pub sshd_config_monitor: SshdConfigMonitorConfig,

    /// NTP / 時刻同期設定監視モジュールの設定
    #[serde(default)]
    pub ntp_config_monitor: NtpConfigMonitorConfig,

    /// パッケージ整合性検証モジュールの設定
    #[serde(default)]
    pub package_verify: PackageVerifyConfig,

    /// パッケージリポジトリ改ざん検知モジュールの設定
    #[serde(default)]
    pub pkg_repo_monitor: PkgRepoMonitorConfig,

    /// 環境変数・LD_PRELOAD 監視モジュールの設定
    #[serde(default)]
    pub ld_preload_monitor: LdPreloadMonitorConfig,

    /// ネットワーク接続監視モジュールの設定
    #[serde(default)]
    pub network_monitor: NetworkMonitorConfig,

    /// PAM 設定監視モジュールの設定
    #[serde(default)]
    pub pam_monitor: PamMonitorConfig,

    /// /etc/security/ 監視モジュールの設定
    #[serde(default)]
    pub security_files_monitor: SecurityFilesMonitorConfig,

    /// SELinux / AppArmor 監視モジュールの設定
    #[serde(default)]
    pub mac_monitor: MacMonitorConfig,

    /// Linux capabilities 監視モジュールの設定
    #[serde(default)]
    pub capabilities_monitor: CapabilitiesMonitorConfig,

    /// コンテナ・名前空間検知モジュールの設定
    #[serde(default)]
    pub container_namespace: ContainerNamespaceConfig,

    /// cgroup v2 リソース制限監視モジュールの設定
    #[serde(default)]
    pub cgroup_monitor: CgroupMonitorConfig,

    /// カーネルパラメータ監視モジュールの設定
    #[serde(default)]
    pub kernel_params: KernelParamsConfig,

    /// カーネル taint フラグ監視モジュールの設定
    #[serde(default)]
    pub kernel_taint_monitor: KernelTaintMonitorConfig,

    /// /proc/net/ 監視モジュールの設定
    #[serde(default)]
    pub proc_net_monitor: ProcNetMonitorConfig,

    /// seccomp プロファイル監視モジュールの設定
    #[serde(default)]
    pub seccomp_monitor: SeccompMonitorConfig,

    /// USB デバイス監視モジュールの設定
    #[serde(default)]
    pub usb_monitor: UsbMonitorConfig,

    /// リスニングポート監視モジュールの設定
    #[serde(default)]
    pub listening_port_monitor: ListeningPortMonitorConfig,

    /// ファイルディスクリプタ監視モジュールの設定
    #[serde(default)]
    pub fd_monitor: FdMonitorConfig,

    /// ネットワークインターフェース監視モジュールの設定
    #[serde(default)]
    pub network_interface_monitor: NetworkInterfaceMonitorConfig,

    /// ネットワークトラフィック異常検知モジュールの設定
    #[serde(default)]
    pub network_traffic_monitor: NetworkTrafficMonitorConfig,

    /// 環境変数インジェクション検知モジュールの設定
    #[serde(default)]
    pub env_injection_monitor: EnvInjectionMonitorConfig,

    /// 共有メモリ（/dev/shm）監視モジュールの設定
    #[serde(default)]
    pub shm_monitor: ShmMonitorConfig,

    /// プロセスツリー監視モジュールの設定
    #[serde(default)]
    pub process_tree_monitor: ProcessTreeMonitorConfig,

    /// ファイルシステム xattr 監視モジュールの設定
    #[serde(default)]
    pub xattr_monitor: XattrMonitorConfig,

    /// inotify ベースのリアルタイムファイル変更検知モジュールの設定
    #[serde(default)]
    pub inotify_monitor: InotifyMonitorConfig,

    /// プロセス起動監視モジュールの設定
    #[serde(default)]
    pub process_exec_monitor: ProcessExecMonitorConfig,

    /// TLS 証明書有効期限監視モジュールの設定
    #[serde(default)]
    pub tls_cert_monitor: TlsCertMonitorConfig,

    /// ログインセッション監視モジュールの設定
    #[serde(default)]
    pub login_session_monitor: LoginSessionMonitorConfig,

    /// プロセスメモリマップ監視モジュールの設定
    #[serde(default)]
    pub proc_maps_monitor: ProcMapsMonitorConfig,

    /// ptrace 検知モジュールの設定
    #[serde(default)]
    pub ptrace_monitor: PtraceMonitorConfig,

    /// カーネルシンボルテーブル監視モジュールの設定
    #[serde(default)]
    pub kallsyms_monitor: KallsymsMonitorConfig,

    /// コアダンプ設定監視モジュールの設定
    #[serde(default)]
    pub coredump_monitor: CoredumpMonitorConfig,

    /// eBPF プログラム監視モジュールの設定
    #[serde(default)]
    pub ebpf_monitor: EbpfMonitorConfig,

    /// D-Bus シグナル監視モジュールの設定
    #[serde(default)]
    pub dbus_monitor: DbusMonitorConfig,

    /// スワップ / tmpfs 監視モジュールの設定
    #[serde(default)]
    pub swap_tmpfs_monitor: SwapTmpfsMonitorConfig,

    /// UNIX ソケット監視モジュールの設定
    #[serde(default)]
    pub unix_socket_monitor: UnixSocketMonitorConfig,

    /// プロセス cgroup 逸脱検知モジュールの設定
    #[serde(default)]
    pub process_cgroup_monitor: ProcessCgroupMonitorConfig,

    /// 抽象ソケット名前空間監視モジュールの設定
    #[serde(default)]
    pub abstract_socket_monitor: AbstractSocketMonitorConfig,

    /// IPC 監視モジュールの設定
    #[serde(default)]
    pub ipc_monitor: IpcMonitorConfig,

    /// プロセス権限昇格検知モジュールの設定
    #[serde(default)]
    pub privilege_escalation_monitor: PrivilegeEscalationMonitorConfig,

    /// バックドア検知モジュールの設定
    #[serde(default)]
    pub backdoor_detector: BackdoorDetectorConfig,

    /// TLS 証明書チェーン検証モジュールの設定
    #[serde(default)]
    pub cert_chain_monitor: CertChainMonitorConfig,

    /// namespaces 詳細監視モジュールの設定
    #[serde(default)]
    pub namespace_monitor: NamespaceMonitorConfig,

    /// プロセス環境変数スナップショット監視モジュールの設定
    #[serde(default)]
    pub proc_environ_monitor: ProcEnvironMonitorConfig,

    /// グループポリシー監視モジュールの設定
    #[serde(default)]
    pub group_monitor: GroupMonitorConfig,

    /// プロセス起動コマンドライン監視モジュールの設定
    #[serde(default)]
    pub process_cmdline_monitor: ProcessCmdlineMonitorConfig,

    /// ブートローダー整合性監視モジュールの設定
    #[serde(default)]
    pub bootloader_monitor: BootloaderMonitorConfig,

    /// プロセス隠蔽検知モジュールの設定
    #[serde(default)]
    pub hidden_process_monitor: HiddenProcessMonitorConfig,

    /// ハニーポットファイル（カナリアトークン）監視モジュールの設定
    #[serde(default)]
    pub honeypot_monitor: HoneypotMonitorConfig,

    /// initramfs 整合性監視モジュールの設定
    #[serde(default)]
    pub initramfs_monitor: InitramfsMonitorConfig,

    /// カーネルコマンドライン実行時監視モジュールの設定
    #[serde(default)]
    pub kernel_cmdline_monitor: KernelCmdlineMonitorConfig,

    /// ファイルレス実行検知モジュールの設定
    #[serde(default)]
    pub fileless_exec_monitor: FilelessExecMonitorConfig,

    /// カーネルライブパッチ監視モジュールの設定
    #[serde(default)]
    pub livepatch_monitor: LivepatchMonitorConfig,

    /// systemd ジャーナルパターン監視モジュールの設定
    #[serde(default)]
    pub journal_pattern_monitor: JournalPatternMonitorConfig,

    /// キーロガー検知モジュールの設定
    #[serde(default)]
    pub keylogger_detector: KeyloggerDetectorConfig,

    /// 動的ライブラリインジェクション検知モジュールの設定
    #[serde(default)]
    pub dynamic_library_monitor: DynamicLibraryMonitorConfig,
}

/// ファイル整合性監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct FileIntegrityConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "FileIntegrityConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象パスのリスト
    #[serde(default)]
    pub watch_paths: Vec<PathBuf>,

    /// HMAC-SHA256 キー（設定時は HMAC-SHA256、未設定時は SHA-256 を使用）
    #[serde(default)]
    pub hmac_key: Option<String>,
}

impl FileIntegrityConfig {
    fn default_scan_interval_secs() -> u64 {
        300
    }
}

impl Default for FileIntegrityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_paths: Vec::new(),
            hmac_key: None,
        }
    }
}

/// プロセス異常検知モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct ProcessMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "ProcessMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 不審とみなすパスのリスト
    #[serde(default = "ProcessMonitorConfig::default_suspicious_paths")]
    pub suspicious_paths: Vec<PathBuf>,
}

impl ProcessMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        60
    }

    fn default_suspicious_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/tmp"),
            PathBuf::from("/dev/shm"),
            PathBuf::from("/var/tmp"),
        ]
    }
}

impl Default for ProcessMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            suspicious_paths: Self::default_suspicious_paths(),
        }
    }
}

/// カーネルモジュール監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct KernelModuleConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "KernelModuleConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,
}

impl KernelModuleConfig {
    fn default_scan_interval_secs() -> u64 {
        120
    }
}

impl Default for KernelModuleConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
        }
    }
}

/// auditd ログ統合モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct AuditdMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// チェック間隔（秒）
    #[serde(default = "AuditdMonitorConfig::default_check_interval_secs")]
    pub check_interval_secs: u64,

    /// auditd ログファイルのパス
    #[serde(default = "AuditdMonitorConfig::default_log_path")]
    pub log_path: PathBuf,

    /// 監視対象のイベントタイプリスト
    #[serde(default = "AuditdMonitorConfig::default_watch_types")]
    pub watch_types: Vec<String>,
}

impl AuditdMonitorConfig {
    fn default_check_interval_secs() -> u64 {
        30
    }

    fn default_log_path() -> PathBuf {
        PathBuf::from("/var/log/audit/audit.log")
    }

    fn default_watch_types() -> Vec<String> {
        vec![
            "EXECVE".to_string(),
            "SYSCALL".to_string(),
            "USER_AUTH".to_string(),
            "USER_LOGIN".to_string(),
            "AVC".to_string(),
            "ANOMALY".to_string(),
        ]
    }
}

impl Default for AuditdMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            check_interval_secs: Self::default_check_interval_secs(),
            log_path: Self::default_log_path(),
            watch_types: Self::default_watch_types(),
        }
    }
}

/// at/batch ジョブ監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct AtJobMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "AtJobMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象パスのリスト
    #[serde(default = "AtJobMonitorConfig::default_watch_paths")]
    pub watch_paths: Vec<PathBuf>,
}

impl AtJobMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        120
    }

    fn default_watch_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/var/spool/at"),
            PathBuf::from("/var/spool/cron/atjobs"),
            PathBuf::from("/etc/at.allow"),
            PathBuf::from("/etc/at.deny"),
        ]
    }
}

impl Default for AtJobMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_paths: Self::default_watch_paths(),
        }
    }
}

/// Cron ジョブ改ざん検知モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct CronMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "CronMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象パスのリスト
    #[serde(default = "CronMonitorConfig::default_watch_paths")]
    pub watch_paths: Vec<PathBuf>,

    /// inotify によるリアルタイム検知の有効/無効
    #[serde(default = "CronMonitorConfig::default_true")]
    pub use_inotify: bool,

    /// inotify デバウンス時間（ミリ秒）
    #[serde(default = "CronMonitorConfig::default_inotify_debounce_ms")]
    pub inotify_debounce_ms: u64,
}

impl CronMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        120
    }

    fn default_watch_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/etc/crontab"),
            PathBuf::from("/etc/cron.d"),
            PathBuf::from("/etc/cron.hourly"),
            PathBuf::from("/etc/cron.daily"),
            PathBuf::from("/etc/cron.weekly"),
            PathBuf::from("/etc/cron.monthly"),
            PathBuf::from("/var/spool/cron/crontabs"),
        ]
    }

    fn default_true() -> bool {
        true
    }

    fn default_inotify_debounce_ms() -> u64 {
        500
    }
}

impl Default for CronMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_paths: Self::default_watch_paths(),
            use_inotify: Self::default_true(),
            inotify_debounce_ms: Self::default_inotify_debounce_ms(),
        }
    }
}

/// ユーザーアカウント監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct UserAccountConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "UserAccountConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// passwd ファイルのパス
    #[serde(default = "UserAccountConfig::default_passwd_path")]
    pub passwd_path: PathBuf,

    /// group ファイルのパス
    #[serde(default = "UserAccountConfig::default_group_path")]
    pub group_path: PathBuf,
}

impl UserAccountConfig {
    fn default_scan_interval_secs() -> u64 {
        60
    }

    fn default_passwd_path() -> PathBuf {
        PathBuf::from("/etc/passwd")
    }

    fn default_group_path() -> PathBuf {
        PathBuf::from("/etc/group")
    }
}

impl Default for UserAccountConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            passwd_path: Self::default_passwd_path(),
            group_path: Self::default_group_path(),
        }
    }
}

/// ログファイル改ざん検知モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct LogTamperConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "LogTamperConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象パスのリスト
    #[serde(default = "LogTamperConfig::default_watch_paths")]
    pub watch_paths: Vec<PathBuf>,

    /// logrotate によるファイル変更を誤検知しないようにする
    #[serde(default = "LogTamperConfig::default_logrotate_aware")]
    pub logrotate_aware: bool,

    /// logrotate 検知後のイベント抑制時間（秒）
    #[serde(default = "LogTamperConfig::default_logrotate_suppression_secs")]
    pub logrotate_suppression_secs: u64,
}

impl LogTamperConfig {
    fn default_scan_interval_secs() -> u64 {
        30
    }

    fn default_watch_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/var/log/syslog"),
            PathBuf::from("/var/log/auth.log"),
            PathBuf::from("/var/log/kern.log"),
            PathBuf::from("/var/log/messages"),
        ]
    }

    fn default_logrotate_aware() -> bool {
        true
    }

    fn default_logrotate_suppression_secs() -> u64 {
        300
    }
}

impl Default for LogTamperConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_paths: Self::default_watch_paths(),
            logrotate_aware: Self::default_logrotate_aware(),
            logrotate_suppression_secs: Self::default_logrotate_suppression_secs(),
        }
    }
}

/// systemd サービス監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct SystemdServiceConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "SystemdServiceConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象パスのリスト
    #[serde(default = "SystemdServiceConfig::default_watch_paths")]
    pub watch_paths: Vec<PathBuf>,
}

impl SystemdServiceConfig {
    fn default_scan_interval_secs() -> u64 {
        120
    }

    fn default_watch_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/etc/systemd/system/"),
            PathBuf::from("/usr/lib/systemd/system/"),
            PathBuf::from("/usr/local/lib/systemd/system/"),
        ]
    }
}

impl Default for SystemdServiceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_paths: Self::default_watch_paths(),
        }
    }
}

/// systemd タイマー監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct SystemdTimerMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "SystemdTimerMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象ディレクトリのリスト
    #[serde(default = "SystemdTimerMonitorConfig::default_timer_dirs")]
    pub timer_dirs: Vec<PathBuf>,

    /// 不審と判定するインターバルの閾値（秒）
    #[serde(default = "SystemdTimerMonitorConfig::default_min_interval_warn_seconds")]
    pub min_interval_warn_seconds: u64,
}

impl SystemdTimerMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        30
    }

    fn default_timer_dirs() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/etc/systemd/system/"),
            PathBuf::from("/usr/lib/systemd/system/"),
            PathBuf::from("/run/systemd/system/"),
        ]
    }

    fn default_min_interval_warn_seconds() -> u64 {
        60
    }
}

impl Default for SystemdTimerMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            timer_dirs: Self::default_timer_dirs(),
            min_interval_warn_seconds: Self::default_min_interval_warn_seconds(),
        }
    }
}

/// DNS設定改ざん検知モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct DnsMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "DnsMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象パスのリスト
    #[serde(default = "DnsMonitorConfig::default_watch_paths")]
    pub watch_paths: Vec<PathBuf>,
}

impl DnsMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        30
    }

    fn default_watch_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/etc/resolv.conf"),
            PathBuf::from("/etc/hosts"),
        ]
    }
}

impl Default for DnsMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_paths: Self::default_watch_paths(),
        }
    }
}

/// ネットワーク名前解決監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct DnsQueryMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "DnsQueryMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// DNS 接続数閾値（この値以上で警告）
    #[serde(default = "DnsQueryMonitorConfig::default_query_rate_threshold")]
    pub query_rate_threshold: u64,

    /// 不明 DNS サーバ検知の有効/無効
    #[serde(default = "DnsQueryMonitorConfig::default_unknown_dns_server_detection")]
    pub unknown_dns_server_detection: bool,

    /// tx_queue 異常閾値（DNS トンネリング検知）
    #[serde(default = "DnsQueryMonitorConfig::default_tx_queue_threshold")]
    pub tx_queue_threshold: u64,

    /// ホワイトリストアドレス
    #[serde(default)]
    pub whitelist_addresses: Vec<String>,
}

impl DnsQueryMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        30
    }

    fn default_query_rate_threshold() -> u64 {
        100
    }

    fn default_unknown_dns_server_detection() -> bool {
        true
    }

    fn default_tx_queue_threshold() -> u64 {
        4096
    }
}

impl Default for DnsQueryMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            query_rate_threshold: Self::default_query_rate_threshold(),
            unknown_dns_server_detection: Self::default_unknown_dns_server_detection(),
            tx_queue_threshold: Self::default_tx_queue_threshold(),
            whitelist_addresses: Vec::new(),
        }
    }
}

/// ファイアウォールルール監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct FirewallMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "FirewallMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象パスのリスト
    #[serde(default = "FirewallMonitorConfig::default_watch_paths")]
    pub watch_paths: Vec<PathBuf>,
}

impl FirewallMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        60
    }

    fn default_watch_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/proc/net/ip_tables_names"),
            PathBuf::from("/proc/net/ip6_tables_names"),
            PathBuf::from("/proc/net/ip_tables_targets"),
            PathBuf::from("/proc/net/ip_tables_matches"),
            PathBuf::from("/proc/net/ip6_tables_targets"),
            PathBuf::from("/proc/net/ip6_tables_matches"),
        ]
    }
}

impl Default for FirewallMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_paths: Self::default_watch_paths(),
        }
    }
}

/// SSH公開鍵ファイル監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct SshKeyMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "SshKeyMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象の authorized_keys ファイルパスのリスト
    #[serde(default = "SshKeyMonitorConfig::default_watch_paths")]
    pub watch_paths: Vec<PathBuf>,
}

impl SshKeyMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        120
    }

    fn default_watch_paths() -> Vec<PathBuf> {
        vec![PathBuf::from("/root/.ssh/authorized_keys")]
    }
}

impl Default for SshKeyMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_paths: Self::default_watch_paths(),
        }
    }
}

/// TLS 証明書有効期限監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct TlsCertMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// チェック間隔（秒）
    #[serde(default = "TlsCertMonitorConfig::default_check_interval_secs")]
    pub check_interval_secs: u64,

    /// 監視対象ディレクトリのリスト
    #[serde(default = "TlsCertMonitorConfig::default_watch_dirs")]
    pub watch_dirs: Vec<PathBuf>,

    /// 警告を発行する残日数の閾値
    #[serde(default = "TlsCertMonitorConfig::default_warning_days")]
    pub warning_days: u32,

    /// 重大アラートを発行する残日数の閾値
    #[serde(default = "TlsCertMonitorConfig::default_critical_days")]
    pub critical_days: u32,

    /// 対象ファイル拡張子
    #[serde(default = "TlsCertMonitorConfig::default_file_extensions")]
    pub file_extensions: Vec<String>,
}

impl TlsCertMonitorConfig {
    fn default_check_interval_secs() -> u64 {
        3600
    }

    fn default_watch_dirs() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/etc/ssl/certs"),
            PathBuf::from("/etc/pki/tls/certs"),
        ]
    }

    fn default_warning_days() -> u32 {
        30
    }

    fn default_critical_days() -> u32 {
        7
    }

    fn default_file_extensions() -> Vec<String> {
        vec![".pem".to_string(), ".crt".to_string(), ".cer".to_string()]
    }
}

impl Default for TlsCertMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            check_interval_secs: Self::default_check_interval_secs(),
            watch_dirs: Self::default_watch_dirs(),
            warning_days: Self::default_warning_days(),
            critical_days: Self::default_critical_days(),
            file_extensions: Self::default_file_extensions(),
        }
    }
}

/// ログインセッション監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct LoginSessionMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// チェック間隔（秒）
    #[serde(default = "LoginSessionMonitorConfig::default_check_interval_secs")]
    pub check_interval_secs: u64,

    /// utmp ファイルパス
    #[serde(default = "LoginSessionMonitorConfig::default_utmp_path")]
    pub utmp_path: String,

    /// wtmp ファイルパス
    #[serde(default = "LoginSessionMonitorConfig::default_wtmp_path")]
    pub wtmp_path: String,

    /// root 直接ログインの検知を有効化
    #[serde(default = "LoginSessionMonitorConfig::default_alert_root_login")]
    pub alert_root_login: bool,

    /// 同一ユーザーの最大同時セッション数
    #[serde(default = "LoginSessionMonitorConfig::default_max_concurrent_sessions")]
    pub max_concurrent_sessions: u32,

    /// 不審な時間帯の開始時刻（0-23）
    #[serde(default)]
    pub suspicious_hours_start: u32,

    /// 不審な時間帯の終了時刻（0-23）
    #[serde(default = "LoginSessionMonitorConfig::default_suspicious_hours_end")]
    pub suspicious_hours_end: u32,

    /// 不審な時間帯のログイン検知を有効化
    #[serde(default)]
    pub alert_suspicious_hours: bool,
}

impl LoginSessionMonitorConfig {
    fn default_check_interval_secs() -> u64 {
        30
    }

    fn default_utmp_path() -> String {
        "/var/run/utmp".to_string()
    }

    fn default_wtmp_path() -> String {
        "/var/log/wtmp".to_string()
    }

    fn default_alert_root_login() -> bool {
        true
    }

    fn default_max_concurrent_sessions() -> u32 {
        3
    }

    fn default_suspicious_hours_end() -> u32 {
        6
    }
}

impl Default for LoginSessionMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            check_interval_secs: Self::default_check_interval_secs(),
            utmp_path: Self::default_utmp_path(),
            wtmp_path: Self::default_wtmp_path(),
            alert_root_login: Self::default_alert_root_login(),
            max_concurrent_sessions: Self::default_max_concurrent_sessions(),
            suspicious_hours_start: 0,
            suspicious_hours_end: Self::default_suspicious_hours_end(),
            alert_suspicious_hours: false,
        }
    }
}

/// プロセスメモリマップ監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct ProcMapsMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "ProcMapsMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 不審なパスのリスト（これらのパスからのライブラリロードを検知する）
    #[serde(default = "ProcMapsMonitorConfig::default_suspicious_paths")]
    pub suspicious_paths: Vec<String>,

    /// 削除済みファイルからのマッピングを検知するか
    #[serde(default = "ProcMapsMonitorConfig::default_true")]
    pub detect_deleted_mappings: bool,

    /// RWX 権限を持つ匿名メモリ領域を検知するか
    #[serde(default = "ProcMapsMonitorConfig::default_true")]
    pub detect_rwx_anonymous: bool,

    /// 隠しファイルからのライブラリロードを検知するか
    #[serde(default = "ProcMapsMonitorConfig::default_true")]
    pub detect_hidden_libraries: bool,

    /// 除外するプロセス名のリスト
    #[serde(default)]
    pub exclude_processes: Vec<String>,

    /// 除外するライブラリパスのリスト
    #[serde(default)]
    pub exclude_paths: Vec<String>,
}

impl ProcMapsMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        60
    }

    fn default_suspicious_paths() -> Vec<String> {
        vec![
            "/tmp".to_string(),
            "/dev/shm".to_string(),
            "/var/tmp".to_string(),
        ]
    }

    fn default_true() -> bool {
        true
    }
}

impl Default for ProcMapsMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            suspicious_paths: Self::default_suspicious_paths(),
            detect_deleted_mappings: true,
            detect_rwx_anonymous: true,
            detect_hidden_libraries: true,
            exclude_processes: Vec::new(),
            exclude_paths: Vec::new(),
        }
    }
}

/// マウントポイント監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct MountMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "MountMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// マウント情報ファイルのパス
    #[serde(default = "MountMonitorConfig::default_mounts_path")]
    pub mounts_path: PathBuf,
}

impl MountMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        30
    }

    fn default_mounts_path() -> PathBuf {
        PathBuf::from("/proc/mounts")
    }
}

impl Default for MountMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            mounts_path: Self::default_mounts_path(),
        }
    }
}

/// シェル設定ファイル監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct ShellConfigMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "ShellConfigMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象のシェル設定ファイルパスのリスト
    #[serde(default = "ShellConfigMonitorConfig::default_watch_paths")]
    pub watch_paths: Vec<PathBuf>,
}

impl ShellConfigMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        120
    }

    fn default_watch_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/etc/profile"),
            PathBuf::from("/etc/bash.bashrc"),
            PathBuf::from("/etc/environment"),
            PathBuf::from("/root/.bashrc"),
            PathBuf::from("/root/.profile"),
        ]
    }
}

impl Default for ShellConfigMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_paths: Self::default_watch_paths(),
        }
    }
}

/// 一時ディレクトリ実行ファイル検知モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct TmpExecMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "TmpExecMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象ディレクトリのリスト
    #[serde(default = "TmpExecMonitorConfig::default_watch_dirs")]
    pub watch_dirs: Vec<PathBuf>,
}

impl TmpExecMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        60
    }

    fn default_watch_dirs() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/tmp"),
            PathBuf::from("/dev/shm"),
            PathBuf::from("/var/tmp"),
        ]
    }
}

impl Default for TmpExecMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_dirs: Self::default_watch_dirs(),
        }
    }
}

/// sudoers ファイル監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct SudoersMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "SudoersMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象パスのリスト（ファイルまたはディレクトリ）
    #[serde(default = "SudoersMonitorConfig::default_watch_paths")]
    pub watch_paths: Vec<PathBuf>,
}

impl SudoersMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        120
    }

    fn default_watch_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/etc/sudoers"),
            PathBuf::from("/etc/sudoers.d"),
        ]
    }
}

impl Default for SudoersMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_paths: Self::default_watch_paths(),
        }
    }
}

/// PAM 設定監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct PamMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "PamMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象パスのリスト（ファイルまたはディレクトリ）
    #[serde(default = "PamMonitorConfig::default_watch_paths")]
    pub watch_paths: Vec<PathBuf>,
}

impl PamMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        120
    }

    fn default_watch_paths() -> Vec<PathBuf> {
        vec![PathBuf::from("/etc/pam.d")]
    }
}

impl Default for PamMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_paths: Self::default_watch_paths(),
        }
    }
}

/// /etc/security/ 監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct SecurityFilesMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "SecurityFilesMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象パスのリスト（ファイルまたはディレクトリ）
    #[serde(default = "SecurityFilesMonitorConfig::default_watch_paths")]
    pub watch_paths: Vec<PathBuf>,
}

impl SecurityFilesMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        120
    }

    fn default_watch_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/etc/security/limits.conf"),
            PathBuf::from("/etc/security/limits.d"),
            PathBuf::from("/etc/security/access.conf"),
            PathBuf::from("/etc/security/namespace.conf"),
            PathBuf::from("/etc/security/group.conf"),
            PathBuf::from("/etc/security/time.conf"),
            PathBuf::from("/etc/security/pam_env.conf"),
            PathBuf::from("/etc/security/faillock.conf"),
            PathBuf::from("/etc/security/pwquality.conf"),
        ]
    }
}

impl Default for SecurityFilesMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_paths: Self::default_watch_paths(),
        }
    }
}

/// SUID/SGID ファイル監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct SuidSgidMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "SuidSgidMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象ディレクトリのリスト
    #[serde(default = "SuidSgidMonitorConfig::default_watch_dirs")]
    pub watch_dirs: Vec<PathBuf>,
}

impl SuidSgidMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        300
    }

    fn default_watch_dirs() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/usr/bin"),
            PathBuf::from("/usr/sbin"),
            PathBuf::from("/usr/local/bin"),
            PathBuf::from("/usr/local/sbin"),
        ]
    }
}

impl Default for SuidSgidMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_dirs: Self::default_watch_dirs(),
        }
    }
}

/// SSH ブルートフォース検知モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct SshBruteForceConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "SshBruteForceConfig::default_interval_secs")]
    pub interval_secs: u64,

    /// 認証ログファイルのパス
    #[serde(default = "SshBruteForceConfig::default_auth_log_path")]
    pub auth_log_path: PathBuf,

    /// 認証失敗の閾値
    #[serde(default = "SshBruteForceConfig::default_max_failures")]
    pub max_failures: u32,

    /// 時間窓（秒）
    #[serde(default = "SshBruteForceConfig::default_time_window_secs")]
    pub time_window_secs: u64,
}

impl SshBruteForceConfig {
    fn default_interval_secs() -> u64 {
        30
    }

    fn default_auth_log_path() -> PathBuf {
        PathBuf::from("/var/log/auth.log")
    }

    fn default_max_failures() -> u32 {
        5
    }

    fn default_time_window_secs() -> u64 {
        300
    }
}

impl Default for SshBruteForceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: Self::default_interval_secs(),
            auth_log_path: Self::default_auth_log_path(),
            max_failures: Self::default_max_failures(),
            time_window_secs: Self::default_time_window_secs(),
        }
    }
}

/// パッケージリポジトリ改ざん検知モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct PkgRepoMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "PkgRepoMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象パスのリスト（ファイルまたはディレクトリ）
    #[serde(default = "PkgRepoMonitorConfig::default_watch_paths")]
    pub watch_paths: Vec<PathBuf>,
}

impl PkgRepoMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        120
    }

    fn default_watch_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/etc/apt/sources.list"),
            PathBuf::from("/etc/apt/sources.list.d"),
            PathBuf::from("/etc/yum.repos.d"),
        ]
    }
}

impl Default for PkgRepoMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_paths: Self::default_watch_paths(),
        }
    }
}

/// 環境変数・LD_PRELOAD 監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct LdPreloadMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "LdPreloadMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象パスのリスト
    #[serde(default = "LdPreloadMonitorConfig::default_watch_paths")]
    pub watch_paths: Vec<PathBuf>,
}

impl LdPreloadMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        60
    }

    fn default_watch_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/etc/ld.so.preload"),
            PathBuf::from("/etc/environment"),
            PathBuf::from("/etc/ld.so.conf"),
            PathBuf::from("/etc/ld.so.conf.d"),
        ]
    }
}

impl Default for LdPreloadMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_paths: Self::default_watch_paths(),
        }
    }
}

/// ネットワーク接続監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct NetworkMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// 監視間隔（秒）
    #[serde(default = "NetworkMonitorConfig::default_interval_secs")]
    pub interval_secs: u64,

    /// 不審ポートリスト
    #[serde(default = "NetworkMonitorConfig::default_suspicious_ports")]
    pub suspicious_ports: Vec<u16>,

    /// 接続数閾値
    #[serde(default = "NetworkMonitorConfig::default_max_connections")]
    pub max_connections: u32,

    /// IPv6 監視の有効/無効
    #[serde(default = "NetworkMonitorConfig::default_enable_ipv6")]
    pub enable_ipv6: bool,
}

impl NetworkMonitorConfig {
    fn default_interval_secs() -> u64 {
        30
    }

    fn default_suspicious_ports() -> Vec<u16> {
        vec![4444, 5555, 6666, 8888, 1337]
    }

    fn default_max_connections() -> u32 {
        1000
    }

    fn default_enable_ipv6() -> bool {
        true
    }
}

impl Default for NetworkMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: Self::default_interval_secs(),
            suspicious_ports: Self::default_suspicious_ports(),
            max_connections: Self::default_max_connections(),
            enable_ipv6: Self::default_enable_ipv6(),
        }
    }
}

/// SELinux / AppArmor 監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct MacMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "MacMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// SELinux 設定ファイルのパスリスト
    #[serde(default = "MacMonitorConfig::default_selinux_config_paths")]
    pub selinux_config_paths: Vec<PathBuf>,

    /// SELinux ポリシーディレクトリのリスト
    #[serde(default = "MacMonitorConfig::default_selinux_policy_dirs")]
    pub selinux_policy_dirs: Vec<PathBuf>,

    /// SELinux enforce ファイルのパス
    #[serde(default = "MacMonitorConfig::default_selinux_enforce_path")]
    pub selinux_enforce_path: PathBuf,

    /// AppArmor 設定パスのリスト
    #[serde(default = "MacMonitorConfig::default_apparmor_config_paths")]
    pub apparmor_config_paths: Vec<PathBuf>,

    /// AppArmor profiles ファイルのパス
    #[serde(default = "MacMonitorConfig::default_apparmor_profiles_path")]
    pub apparmor_profiles_path: PathBuf,
}

impl MacMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        30
    }

    fn default_selinux_config_paths() -> Vec<PathBuf> {
        vec![PathBuf::from("/etc/selinux/config")]
    }

    fn default_selinux_policy_dirs() -> Vec<PathBuf> {
        vec![PathBuf::from("/etc/selinux")]
    }

    fn default_selinux_enforce_path() -> PathBuf {
        PathBuf::from("/sys/fs/selinux/enforce")
    }

    fn default_apparmor_config_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/etc/apparmor"),
            PathBuf::from("/etc/apparmor.d"),
        ]
    }

    fn default_apparmor_profiles_path() -> PathBuf {
        PathBuf::from("/sys/kernel/security/apparmor/profiles")
    }
}

impl Default for MacMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            selinux_config_paths: Self::default_selinux_config_paths(),
            selinux_policy_dirs: Self::default_selinux_policy_dirs(),
            selinux_enforce_path: Self::default_selinux_enforce_path(),
            apparmor_config_paths: Self::default_apparmor_config_paths(),
            apparmor_profiles_path: Self::default_apparmor_profiles_path(),
        }
    }
}

/// Linux capabilities 監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct CapabilitiesMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "CapabilitiesMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 危険と見なす capabilities のビット番号リスト
    #[serde(default = "CapabilitiesMonitorConfig::default_dangerous_caps")]
    pub dangerous_caps: Vec<u8>,

    /// ホワイトリスト（除外するプロセス名）
    #[serde(default = "CapabilitiesMonitorConfig::default_whitelist_processes")]
    pub whitelist_processes: Vec<String>,
}

impl CapabilitiesMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        60
    }

    fn default_dangerous_caps() -> Vec<u8> {
        vec![
            1,  // CAP_DAC_OVERRIDE
            6,  // CAP_SETGID
            7,  // CAP_SETUID
            12, // CAP_NET_ADMIN
            13, // CAP_NET_RAW
            16, // CAP_SYS_MODULE
            19, // CAP_SYS_PTRACE
            21, // CAP_SYS_ADMIN
        ]
    }

    fn default_whitelist_processes() -> Vec<String> {
        vec![
            "systemd".to_string(),
            "systemd-journal".to_string(),
            "systemd-udevd".to_string(),
            "systemd-logind".to_string(),
            "systemd-resolve".to_string(),
            "systemd-timesyn".to_string(),
            "systemd-network".to_string(),
            "networkd-dispat".to_string(),
            "dbus-daemon".to_string(),
            "polkitd".to_string(),
        ]
    }
}

impl Default for CapabilitiesMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            dangerous_caps: Self::default_dangerous_caps(),
            whitelist_processes: Self::default_whitelist_processes(),
        }
    }
}

/// コンテナ・名前空間検知モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct ContainerNamespaceConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "ContainerNamespaceConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象の名前空間リスト
    #[serde(default = "ContainerNamespaceConfig::default_watch_namespaces")]
    pub watch_namespaces: Vec<String>,

    /// コンテナ環境マーカーのチェックを行うか
    #[serde(default = "ContainerNamespaceConfig::default_check_container_env")]
    pub check_container_env: bool,
}

impl ContainerNamespaceConfig {
    fn default_scan_interval_secs() -> u64 {
        30
    }

    fn default_watch_namespaces() -> Vec<String> {
        vec![
            "mnt".to_string(),
            "pid".to_string(),
            "net".to_string(),
            "ipc".to_string(),
            "uts".to_string(),
            "user".to_string(),
            "cgroup".to_string(),
        ]
    }

    fn default_check_container_env() -> bool {
        true
    }
}

impl Default for ContainerNamespaceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_namespaces: Self::default_watch_namespaces(),
            check_container_env: Self::default_check_container_env(),
        }
    }
}

/// cgroup v2 リソース制限監視設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct CgroupMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "CgroupMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// cgroup v2 ファイルシステムのベースパス
    #[serde(default = "CgroupMonitorConfig::default_cgroup_path")]
    pub cgroup_path: String,

    /// 再帰スキャンの最大深さ
    #[serde(default = "CgroupMonitorConfig::default_max_depth")]
    pub max_depth: usize,

    /// 監視対象の cgroup ファイル名リスト
    #[serde(default = "CgroupMonitorConfig::default_watch_files")]
    pub watch_files: Vec<String>,
}

impl CgroupMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        30
    }

    fn default_cgroup_path() -> String {
        "/sys/fs/cgroup".to_string()
    }

    fn default_max_depth() -> usize {
        5
    }

    fn default_watch_files() -> Vec<String> {
        vec![
            "memory.max".to_string(),
            "memory.high".to_string(),
            "cpu.max".to_string(),
            "pids.max".to_string(),
            "io.max".to_string(),
        ]
    }
}

impl Default for CgroupMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            cgroup_path: Self::default_cgroup_path(),
            max_depth: Self::default_max_depth(),
            watch_files: Self::default_watch_files(),
        }
    }
}

/// カーネルパラメータ監視ルール
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct KernelParamRule {
    /// パラメータのパス（例: "kernel/kptr_restrict"）
    pub path: String,

    /// 最小値（この値未満で Critical）
    #[serde(default)]
    pub min_value: Option<i64>,

    /// 期待値（不一致で Warning）
    #[serde(default)]
    pub expected_value: Option<String>,
}

/// カーネルパラメータ監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct KernelParamsConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "KernelParamsConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// proc/sys のベースパス
    #[serde(default = "KernelParamsConfig::default_proc_sys_path")]
    pub proc_sys_path: String,

    /// 監視対象パラメータルール
    #[serde(default = "KernelParamsConfig::default_watch_params")]
    pub watch_params: Vec<KernelParamRule>,
}

impl KernelParamsConfig {
    fn default_scan_interval_secs() -> u64 {
        60
    }

    fn default_proc_sys_path() -> String {
        "/proc/sys".to_string()
    }

    fn default_watch_params() -> Vec<KernelParamRule> {
        vec![
            KernelParamRule {
                path: "kernel/kptr_restrict".to_string(),
                min_value: Some(1),
                expected_value: None,
            },
            KernelParamRule {
                path: "kernel/dmesg_restrict".to_string(),
                min_value: Some(1),
                expected_value: None,
            },
            KernelParamRule {
                path: "kernel/randomize_va_space".to_string(),
                min_value: Some(2),
                expected_value: None,
            },
            KernelParamRule {
                path: "kernel/sysrq".to_string(),
                min_value: None,
                expected_value: None,
            },
            KernelParamRule {
                path: "kernel/unprivileged_bpf_disabled".to_string(),
                min_value: Some(1),
                expected_value: None,
            },
            KernelParamRule {
                path: "kernel/yama/ptrace_scope".to_string(),
                min_value: Some(1),
                expected_value: None,
            },
            KernelParamRule {
                path: "kernel/perf_event_paranoid".to_string(),
                min_value: Some(2),
                expected_value: None,
            },
            KernelParamRule {
                path: "kernel/core_pattern".to_string(),
                min_value: None,
                expected_value: None,
            },
        ]
    }
}

impl Default for KernelParamsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            proc_sys_path: Self::default_proc_sys_path(),
            watch_params: Self::default_watch_params(),
        }
    }
}

/// カーネル taint フラグ監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct KernelTaintMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "KernelTaintMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// taint ファイルのパス
    #[serde(default = "KernelTaintMonitorConfig::default_tainted_path")]
    pub tainted_path: String,

    /// 起動時スキャンで issues_found に計上しないビット番号
    #[serde(default = "KernelTaintMonitorConfig::default_ignore_initial_bits")]
    pub ignore_initial_bits: Vec<u8>,

    /// ビット番号ごとの Severity 上書き（"Info"/"Warning"/"High"/"Critical"）
    #[serde(default)]
    pub severity_overrides: std::collections::BTreeMap<u8, String>,
}

impl KernelTaintMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        60
    }

    fn default_tainted_path() -> String {
        "/proc/sys/kernel/tainted".to_string()
    }

    fn default_ignore_initial_bits() -> Vec<u8> {
        vec![15, 17]
    }
}

impl Default for KernelTaintMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            tainted_path: Self::default_tainted_path(),
            ignore_initial_bits: Self::default_ignore_initial_bits(),
            severity_overrides: std::collections::BTreeMap::new(),
        }
    }
}

/// /proc/net/ 監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct ProcNetMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "ProcNetMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// /proc/net/route のパス
    #[serde(default = "ProcNetMonitorConfig::default_route_path")]
    pub route_path: String,

    /// /proc/net/arp のパス
    #[serde(default = "ProcNetMonitorConfig::default_arp_path")]
    pub arp_path: String,
}

impl ProcNetMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        30
    }

    fn default_route_path() -> String {
        "/proc/net/route".to_string()
    }

    fn default_arp_path() -> String {
        "/proc/net/arp".to_string()
    }
}

impl Default for ProcNetMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            route_path: Self::default_route_path(),
            arp_path: Self::default_arp_path(),
        }
    }
}

/// seccomp プロファイル監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct SeccompMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "SeccompMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象プロセス名のリスト
    #[serde(default = "SeccompMonitorConfig::default_watched_processes")]
    pub watched_processes: Vec<String>,
}

impl SeccompMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        30
    }

    fn default_watched_processes() -> Vec<String> {
        vec![
            "sshd".to_string(),
            "nginx".to_string(),
            "apache2".to_string(),
            "postgres".to_string(),
            "mysqld".to_string(),
            "dockerd".to_string(),
            "containerd".to_string(),
            "named".to_string(),
            "unbound".to_string(),
            "haproxy".to_string(),
        ]
    }
}

impl Default for SeccompMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watched_processes: Self::default_watched_processes(),
        }
    }
}

/// USB デバイス監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct UsbMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "UsbMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// USB デバイスディレクトリのパス
    #[serde(default = "UsbMonitorConfig::default_devices_path")]
    pub devices_path: PathBuf,
}

impl UsbMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        10
    }

    fn default_devices_path() -> PathBuf {
        PathBuf::from("/sys/bus/usb/devices")
    }
}

impl Default for UsbMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            devices_path: Self::default_devices_path(),
        }
    }
}

/// リスニングポート監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct ListeningPortMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "ListeningPortMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 許可ポートリスト（"プロトコル:ポート番号" 形式）
    ///
    /// 例: ["tcp:22", "tcp:80", "tcp:443", "udp:53"]
    /// 空の場合はホワイトリストを適用しない（変更検知のみ）
    #[serde(default)]
    pub allowed_ports: Vec<String>,

    /// IPv6 監視の有効/無効
    #[serde(default = "ListeningPortMonitorConfig::default_enable_ipv6")]
    pub enable_ipv6: bool,

    /// /proc/net/tcp のパス
    #[serde(default = "ListeningPortMonitorConfig::default_tcp_path")]
    pub tcp_path: String,

    /// /proc/net/tcp6 のパス
    #[serde(default = "ListeningPortMonitorConfig::default_tcp6_path")]
    pub tcp6_path: String,

    /// /proc/net/udp のパス
    #[serde(default = "ListeningPortMonitorConfig::default_udp_path")]
    pub udp_path: String,

    /// /proc/net/udp6 のパス
    #[serde(default = "ListeningPortMonitorConfig::default_udp6_path")]
    pub udp6_path: String,
}

impl ListeningPortMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        30
    }

    fn default_enable_ipv6() -> bool {
        true
    }

    fn default_tcp_path() -> String {
        "/proc/net/tcp".to_string()
    }

    fn default_tcp6_path() -> String {
        "/proc/net/tcp6".to_string()
    }

    fn default_udp_path() -> String {
        "/proc/net/udp".to_string()
    }

    fn default_udp6_path() -> String {
        "/proc/net/udp6".to_string()
    }
}

impl Default for ListeningPortMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            allowed_ports: Vec::new(),
            enable_ipv6: Self::default_enable_ipv6(),
            tcp_path: Self::default_tcp_path(),
            tcp6_path: Self::default_tcp6_path(),
            udp_path: Self::default_udp_path(),
            udp6_path: Self::default_udp6_path(),
        }
    }
}

/// ファイルディスクリプタ監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct FdMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "FdMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// プロセスあたりの最大 fd 数（これを超えると Warning）
    #[serde(default = "FdMonitorConfig::default_max_fd_per_process")]
    pub max_fd_per_process: usize,

    /// /proc ディレクトリのパス
    #[serde(default = "FdMonitorConfig::default_proc_path")]
    pub proc_path: PathBuf,

    /// ホワイトリストプロセス名（これらのプロセスは検知対象外）
    #[serde(default)]
    pub whitelist_processes: Vec<String>,
}

impl FdMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        60
    }

    fn default_max_fd_per_process() -> usize {
        1024
    }

    fn default_proc_path() -> PathBuf {
        PathBuf::from("/proc")
    }
}

impl Default for FdMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            max_fd_per_process: Self::default_max_fd_per_process(),
            proc_path: Self::default_proc_path(),
            whitelist_processes: Vec::new(),
        }
    }
}

/// ネットワークインターフェース監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct NetworkInterfaceMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "NetworkInterfaceMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 無視するインターフェース名のリスト
    #[serde(default = "NetworkInterfaceMonitorConfig::default_ignore_interfaces")]
    pub ignore_interfaces: Vec<String>,

    /// /sys/class/net/ ディレクトリのパス
    #[serde(default = "NetworkInterfaceMonitorConfig::default_sys_class_net_path")]
    pub sys_class_net_path: PathBuf,
}

impl NetworkInterfaceMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        30
    }

    fn default_ignore_interfaces() -> Vec<String> {
        vec!["lo".to_string()]
    }

    fn default_sys_class_net_path() -> PathBuf {
        PathBuf::from("/sys/class/net")
    }
}

impl Default for NetworkInterfaceMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            ignore_interfaces: Self::default_ignore_interfaces(),
            sys_class_net_path: Self::default_sys_class_net_path(),
        }
    }
}

/// ネットワークトラフィック異常検知モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct NetworkTrafficMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "NetworkTrafficMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 無視するインターフェース名のリスト
    #[serde(default = "NetworkTrafficMonitorConfig::default_ignore_interfaces")]
    pub ignore_interfaces: Vec<String>,

    /// /proc/net/dev ファイルのパス
    #[serde(default = "NetworkTrafficMonitorConfig::default_proc_net_dev_path")]
    pub proc_net_dev_path: PathBuf,

    /// バイト数/秒の閾値（受信+送信の合計）
    #[serde(default = "NetworkTrafficMonitorConfig::default_threshold_bytes_per_sec")]
    pub threshold_bytes_per_sec: u64,

    /// パケット数/秒の閾値（受信+送信の合計）
    #[serde(default = "NetworkTrafficMonitorConfig::default_threshold_packets_per_sec")]
    pub threshold_packets_per_sec: u64,

    /// エラー数/秒の閾値（受信+送信の合計）
    #[serde(default = "NetworkTrafficMonitorConfig::default_threshold_errors_per_sec")]
    pub threshold_errors_per_sec: u64,

    /// ドロップ数/秒の閾値（受信+送信の合計）
    #[serde(default = "NetworkTrafficMonitorConfig::default_threshold_drops_per_sec")]
    pub threshold_drops_per_sec: u64,
}

impl NetworkTrafficMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        30
    }

    fn default_ignore_interfaces() -> Vec<String> {
        vec!["lo".to_string()]
    }

    fn default_proc_net_dev_path() -> PathBuf {
        PathBuf::from("/proc/net/dev")
    }

    fn default_threshold_bytes_per_sec() -> u64 {
        104_857_600 // 100 MB/s
    }

    fn default_threshold_packets_per_sec() -> u64 {
        100_000 // 100k packets/s
    }

    fn default_threshold_errors_per_sec() -> u64 {
        10
    }

    fn default_threshold_drops_per_sec() -> u64 {
        10
    }
}

impl Default for NetworkTrafficMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            ignore_interfaces: Self::default_ignore_interfaces(),
            proc_net_dev_path: Self::default_proc_net_dev_path(),
            threshold_bytes_per_sec: Self::default_threshold_bytes_per_sec(),
            threshold_packets_per_sec: Self::default_threshold_packets_per_sec(),
            threshold_errors_per_sec: Self::default_threshold_errors_per_sec(),
            threshold_drops_per_sec: Self::default_threshold_drops_per_sec(),
        }
    }
}

/// 環境変数インジェクション検知モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct EnvInjectionMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "EnvInjectionMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 除外プロセス名リスト
    #[serde(default = "EnvInjectionMonitorConfig::default_exclude_processes")]
    pub exclude_processes: Vec<String>,

    /// 不審パスとみなすディレクトリのリスト
    #[serde(default = "EnvInjectionMonitorConfig::default_suspicious_paths")]
    pub suspicious_paths: Vec<String>,

    /// 追加の危険環境変数名
    #[serde(default)]
    pub extra_dangerous_vars: Vec<String>,

    /// proxy 変数の検知を有効にするか
    #[serde(default = "EnvInjectionMonitorConfig::default_check_proxy_vars")]
    pub check_proxy_vars: bool,
}

impl EnvInjectionMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        60
    }

    fn default_exclude_processes() -> Vec<String> {
        vec![
            "java".to_string(),
            "gradle".to_string(),
            "mvn".to_string(),
            "node".to_string(),
            "npm".to_string(),
            "python3".to_string(),
            "ruby".to_string(),
            "perl".to_string(),
        ]
    }

    fn default_suspicious_paths() -> Vec<String> {
        vec![
            "/tmp".to_string(),
            "/dev/shm".to_string(),
            "/var/tmp".to_string(),
            ".".to_string(),
        ]
    }

    fn default_check_proxy_vars() -> bool {
        true
    }
}

impl Default for EnvInjectionMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            exclude_processes: Self::default_exclude_processes(),
            suspicious_paths: Self::default_suspicious_paths(),
            extra_dangerous_vars: Vec::new(),
            check_proxy_vars: Self::default_check_proxy_vars(),
        }
    }
}

/// 共有メモリ（/dev/shm）監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct ShmMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "ShmMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象ディレクトリのパス
    #[serde(default = "ShmMonitorConfig::default_watch_dir")]
    pub watch_dir: PathBuf,

    /// 大容量ファイルと判定する閾値（MB）
    #[serde(default = "ShmMonitorConfig::default_large_file_threshold_mb")]
    pub large_file_threshold_mb: u64,
}

impl ShmMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        30
    }

    fn default_watch_dir() -> PathBuf {
        PathBuf::from("/dev/shm")
    }

    fn default_large_file_threshold_mb() -> u64 {
        10
    }
}

impl Default for ShmMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_dir: Self::default_watch_dir(),
            large_file_threshold_mb: Self::default_large_file_threshold_mb(),
        }
    }
}

/// 不審なプロセスツリーパターンの定義
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct SuspiciousTreePattern {
    /// 親プロセス名の正規表現パターン
    pub parent: String,
    /// 子プロセス名の正規表現パターン
    pub child: String,
    /// パターンの説明
    pub description: String,
}

/// プロセスツリー監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct ProcessTreeMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "ProcessTreeMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// プロセスツリーの最大深度
    #[serde(default = "ProcessTreeMonitorConfig::default_max_depth")]
    pub max_depth: usize,

    /// 不審な親子関係パターン
    #[serde(default = "ProcessTreeMonitorConfig::default_suspicious_patterns")]
    pub suspicious_patterns: Vec<SuspiciousTreePattern>,

    /// 除外パス
    #[serde(default)]
    pub whitelist_paths: Vec<PathBuf>,
}

impl ProcessTreeMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        60
    }

    fn default_max_depth() -> usize {
        10
    }

    fn default_suspicious_patterns() -> Vec<SuspiciousTreePattern> {
        vec![
            SuspiciousTreePattern {
                parent: "nginx|httpd|apache2".to_string(),
                child: "sh|bash|dash|zsh|fish".to_string(),
                description: "Web サーバからのシェル起動".to_string(),
            },
            SuspiciousTreePattern {
                parent: "mysqld|postgres|mongod".to_string(),
                child: "sh|bash|dash|zsh|fish".to_string(),
                description: "データベースからのシェル起動".to_string(),
            },
            SuspiciousTreePattern {
                parent: "nginx|httpd|apache2".to_string(),
                child: "python[23]?|perl|ruby|php".to_string(),
                description: "Web サーバからのインタプリタ起動".to_string(),
            },
        ]
    }
}

impl Default for ProcessTreeMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            max_depth: Self::default_max_depth(),
            suspicious_patterns: Self::default_suspicious_patterns(),
            whitelist_paths: Vec::new(),
        }
    }
}

/// フ���イルシステム xattr（��張属性）監視モジュ��ルの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct XattrMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "XattrMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象パスのリスト
    #[serde(default = "XattrMonitorConfig::default_watch_paths")]
    pub watch_paths: Vec<PathBuf>,

    /// 監視対象の xattr 名前空間のリスト
    #[serde(default = "XattrMonitorConfig::default_namespaces")]
    pub namespaces: Vec<String>,
}

impl XattrMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        300
    }

    fn default_watch_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/etc"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/usr/sbin"),
            PathBuf::from("/usr/local/bin"),
        ]
    }

    fn default_namespaces() -> Vec<String> {
        vec![
            "security".to_string(),
            "system".to_string(),
            "user".to_string(),
        ]
    }
}

impl Default for XattrMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_paths: Self::default_watch_paths(),
            namespaces: Self::default_namespaces(),
        }
    }
}

/// inotify ベースのリアルタイムファイル変更検知モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct InotifyMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// 監視対象パスのリスト
    #[serde(default = "InotifyMonitorConfig::default_watch_paths")]
    pub watch_paths: Vec<PathBuf>,

    /// 再帰的監視の有効/無効（サブディレクトリも監視するか）
    #[serde(default = "InotifyMonitorConfig::default_recursive")]
    pub recursive: bool,

    /// 除外パターン（glob）のリスト
    #[serde(default)]
    pub exclude_patterns: Vec<String>,

    /// inotify watch の最大数
    #[serde(default = "InotifyMonitorConfig::default_max_watches")]
    pub max_watches: u32,

    /// デバウンス時間（ミリ秒）
    #[serde(default = "InotifyMonitorConfig::default_debounce_ms")]
    pub debounce_ms: u64,
}

impl InotifyMonitorConfig {
    fn default_watch_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/etc"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/usr/sbin"),
        ]
    }

    fn default_recursive() -> bool {
        true
    }

    fn default_max_watches() -> u32 {
        65536
    }

    fn default_debounce_ms() -> u64 {
        100
    }
}

impl Default for InotifyMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            watch_paths: Self::default_watch_paths(),
            recursive: Self::default_recursive(),
            exclude_patterns: Vec::new(),
            max_watches: Self::default_max_watches(),
            debounce_ms: Self::default_debounce_ms(),
        }
    }
}

/// プロセス起動監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct ProcessExecMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "ProcessExecMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 不審とみなすパスのリスト
    #[serde(default = "ProcessExecMonitorConfig::default_suspicious_paths")]
    pub suspicious_paths: Vec<PathBuf>,

    /// 不審なコマンドパターン（正規表現）のリスト
    #[serde(default = "ProcessExecMonitorConfig::default_suspicious_commands")]
    pub suspicious_commands: Vec<String>,

    /// 許可リスト（このパスのプロセスは無視）
    #[serde(default)]
    pub allowed_processes: Vec<String>,
}

impl ProcessExecMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        3
    }

    pub(crate) fn default_suspicious_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/tmp"),
            PathBuf::from("/dev/shm"),
            PathBuf::from("/var/tmp"),
        ]
    }

    pub(crate) fn default_suspicious_commands() -> Vec<String> {
        vec![
            r"nc\s+.*-e".to_string(),
            r"ncat\s+.*-e".to_string(),
            r"bash\s+-i\s+>&\s+/dev/tcp".to_string(),
            r"python[23]?\s+-c\s+.*socket".to_string(),
            r"perl\s+-e\s+.*socket".to_string(),
            r"ruby\s+-e\s+.*socket".to_string(),
            r"curl\s+.*\|\s*sh".to_string(),
            r"wget\s+.*\|\s*sh".to_string(),
        ]
    }
}

impl Default for ProcessExecMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            suspicious_paths: Self::default_suspicious_paths(),
            suspicious_commands: Self::default_suspicious_commands(),
            allowed_processes: Vec::new(),
        }
    }
}

/// アクションエンジン設定
#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq)]
pub struct ActionConfig {
    /// アクションエンジンの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// アクションルールのリスト
    #[serde(default)]
    pub rules: Vec<ActionRuleConfig>,

    /// レートリミット設定（未設定時はレートリミットなし）
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,

    /// ダイジェスト通知設定
    #[serde(default)]
    pub digest: Option<DigestConfig>,
}

/// レートリミット設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct RateLimitConfig {
    /// コマンド実行のレート制限
    pub command: Option<BucketConfig>,
    /// Webhook 送信のレート制限
    pub webhook: Option<BucketConfig>,
}

/// トークンバケット設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct BucketConfig {
    /// バケット容量（バースト許容数）
    pub max_tokens: u64,
    /// 補充トークン数
    pub refill_amount: u64,
    /// 補充間隔（秒）
    pub refill_interval_secs: u64,
}

/// アクションルールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct ActionRuleConfig {
    /// ルール名
    pub name: String,
    /// Severity フィルタ
    pub severity: Option<String>,
    /// モジュール名フィルタ
    pub module: Option<String>,
    /// アクション種別（"log", "command", "webhook"）
    pub action: String,
    /// 実行コマンド
    pub command: Option<String>,
    /// コマンドタイムアウト（秒）
    #[serde(default = "ActionRuleConfig::default_timeout_secs")]
    pub timeout_secs: u64,
    /// Webhook URL
    pub url: Option<String>,
    /// HTTP メソッド（デフォルト: POST）
    #[serde(default)]
    pub method: Option<String>,
    /// HTTP ヘッダー
    #[serde(default)]
    pub headers: Option<std::collections::HashMap<String, String>>,
    /// ボディテンプレート
    pub body_template: Option<String>,
    /// リトライ回数（デフォルト: 3）
    pub max_retries: Option<u32>,
}

impl ActionRuleConfig {
    fn default_timeout_secs() -> u64 {
        30
    }
}

/// ダイジェスト通知設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct DigestConfig {
    /// ダイジェスト通知の有効/無効
    #[serde(default)]
    pub enabled: bool,
    /// ダイジェスト集約間隔（秒）
    #[serde(default = "DigestConfig::default_interval_secs")]
    pub interval_secs: u64,
    /// ダイジェスト通知の最小イベント数
    #[serde(default = "DigestConfig::default_min_events")]
    pub min_events: usize,
    /// ダイジェスト通知用 Webhook URL
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// HTTP メソッド
    #[serde(default = "DigestConfig::default_method")]
    pub method: String,
    /// HTTP ヘッダー
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
    /// ボディテンプレート
    pub body_template: Option<String>,
    /// リトライ回数
    #[serde(default = "DigestConfig::default_max_retries")]
    pub max_retries: u32,
}

impl Default for DigestConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: Self::default_interval_secs(),
            min_events: Self::default_min_events(),
            webhook_url: None,
            method: Self::default_method(),
            headers: std::collections::HashMap::new(),
            body_template: None,
            max_retries: Self::default_max_retries(),
        }
    }
}

impl DigestConfig {
    fn default_interval_secs() -> u64 {
        300
    }

    fn default_min_events() -> usize {
        2
    }

    fn default_method() -> String {
        "POST".to_string()
    }

    fn default_max_retries() -> u32 {
        3
    }
}

/// ヘルスチェック設定
#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct HealthConfig {
    /// ハートビートを有効にするか
    #[serde(default = "HealthConfig::default_enabled")]
    pub enabled: bool,

    /// ハートビートのインターバル（秒）
    #[serde(default = "HealthConfig::default_interval")]
    pub heartbeat_interval_secs: u64,
}

impl HealthConfig {
    fn default_enabled() -> bool {
        true
    }

    fn default_interval() -> u64 {
        60
    }
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            enabled: Self::default_enabled(),
            heartbeat_interval_secs: Self::default_interval(),
        }
    }
}

/// モジュールウォッチドッグ設定
#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct ModuleWatchdogConfig {
    /// ウォッチドッグを有効にするか
    #[serde(default = "ModuleWatchdogConfig::default_enabled")]
    pub enabled: bool,
    /// ヘルスチェックインターバル（秒）
    #[serde(default = "ModuleWatchdogConfig::default_check_interval_secs")]
    pub check_interval_secs: u64,
    /// 異常停止時の自動再起動
    #[serde(default = "ModuleWatchdogConfig::default_auto_restart")]
    pub auto_restart: bool,
    /// 最大再起動回数
    #[serde(default = "ModuleWatchdogConfig::default_max_restarts")]
    pub max_restarts: u32,
    /// 再起動クールダウン（秒）
    #[serde(default = "ModuleWatchdogConfig::default_restart_cooldown_secs")]
    pub restart_cooldown_secs: u64,
}

impl ModuleWatchdogConfig {
    fn default_enabled() -> bool {
        true
    }

    fn default_check_interval_secs() -> u64 {
        30
    }

    fn default_auto_restart() -> bool {
        true
    }

    fn default_max_restarts() -> u32 {
        3
    }

    fn default_restart_cooldown_secs() -> u64 {
        60
    }
}

impl Default for ModuleWatchdogConfig {
    fn default() -> Self {
        Self {
            enabled: Self::default_enabled(),
            check_interval_secs: Self::default_check_interval_secs(),
            auto_restart: Self::default_auto_restart(),
            max_restarts: Self::default_max_restarts(),
            restart_cooldown_secs: Self::default_restart_cooldown_secs(),
        }
    }
}

/// Syslog TLS 設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct SyslogTlsConfig {
    /// CA 証明書ファイルパス（PEM 形式）
    #[serde(default)]
    pub ca_cert_path: Option<String>,

    /// ホスト名検証の有効/無効（デフォルト: true）
    #[serde(default = "SyslogTlsConfig::default_verify_hostname")]
    pub verify_hostname: bool,

    /// クライアント証明書ファイルパス（PEM 形式、mTLS 用）
    #[serde(default)]
    pub client_cert_path: Option<String>,

    /// クライアント秘密鍵ファイルパス（PEM 形式、mTLS 用）
    #[serde(default)]
    pub client_key_path: Option<String>,
}

impl SyslogTlsConfig {
    fn default_verify_hostname() -> bool {
        true
    }
}

impl Default for SyslogTlsConfig {
    fn default() -> Self {
        Self {
            ca_cert_path: None,
            verify_hostname: true,
            client_cert_path: None,
            client_key_path: None,
        }
    }
}

/// Syslog 転送設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct SyslogConfig {
    /// Syslog 転送の有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// プロトコル（"udp", "tcp", or "tls"）
    #[serde(default = "SyslogConfig::default_protocol")]
    pub protocol: String,

    /// Syslog サーバのアドレス
    #[serde(default = "SyslogConfig::default_server")]
    pub server: String,

    /// Syslog サーバのポート
    #[serde(default = "SyslogConfig::default_port")]
    pub port: u16,

    /// Syslog facility（"auth", "authpriv", "daemon", "local0"-"local7" 等）
    #[serde(default = "SyslogConfig::default_facility")]
    pub facility: String,

    /// ホスト名（空文字の場合はシステムから自動取得）
    #[serde(default)]
    pub hostname: String,

    /// アプリケーション名
    #[serde(default = "SyslogConfig::default_app_name")]
    pub app_name: String,

    /// TLS 設定
    #[serde(default)]
    pub tls: SyslogTlsConfig,
}

impl SyslogConfig {
    fn default_protocol() -> String {
        "udp".to_string()
    }

    fn default_server() -> String {
        "127.0.0.1".to_string()
    }

    fn default_port() -> u16 {
        514
    }

    fn default_facility() -> String {
        "local0".to_string()
    }

    fn default_app_name() -> String {
        "zettai-mamorukun".to_string()
    }
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            protocol: Self::default_protocol(),
            server: Self::default_server(),
            port: Self::default_port(),
            facility: Self::default_facility(),
            hostname: String::new(),
            app_name: Self::default_app_name(),
            tls: SyslogTlsConfig::default(),
        }
    }
}

/// イベントフィルタリング設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Default)]
pub struct EventFilterConfig {
    /// イベントを抑制する正規表現パターンのリスト
    #[serde(default)]
    pub exclude_patterns: Vec<String>,

    /// マッチした場合のみイベントを発行する正規表現パターンのリスト
    /// 空の場合は全イベントを通過させる
    #[serde(default)]
    pub include_patterns: Vec<String>,

    /// 指定した Severity 以上のイベントのみ発行
    #[serde(default)]
    pub min_severity: Option<String>,
}

/// イベントバス設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct EventBusConfig {
    /// イベントバスの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// ブロードキャストチャネルの容量
    #[serde(default = "EventBusConfig::default_channel_capacity")]
    pub channel_capacity: usize,

    /// イベントデバウンス間隔（秒）— 0 でデバウンス無効
    #[serde(default = "EventBusConfig::default_debounce_secs")]
    pub debounce_secs: u64,

    /// モジュールごとのイベントフィルタリング設定
    #[serde(default)]
    pub filters: HashMap<String, EventFilterConfig>,
}

impl EventBusConfig {
    fn default_channel_capacity() -> usize {
        1024
    }

    fn default_debounce_secs() -> u64 {
        30
    }
}

impl Default for EventBusConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            channel_capacity: Self::default_channel_capacity(),
            debounce_secs: Self::default_debounce_secs(),
            filters: HashMap::new(),
        }
    }
}

/// メトリクス収集の設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct MetricsConfig {
    /// メトリクス収集の有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// サマリーログ出力インターバル（秒）
    #[serde(default = "MetricsConfig::default_interval_secs")]
    pub interval_secs: u64,
}

impl MetricsConfig {
    fn default_interval_secs() -> u64 {
        60
    }
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: Self::default_interval_secs(),
        }
    }
}

/// モジュール実行統計の設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct ModuleStatsConfig {
    /// モジュール統計収集の有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// サマリーログ出力インターバル（秒）。0 の場合は定期ログを出力しない
    #[serde(default = "ModuleStatsConfig::default_log_interval_secs")]
    pub log_interval_secs: u64,
}

impl ModuleStatsConfig {
    fn default_log_interval_secs() -> u64 {
        300
    }
}

impl Default for ModuleStatsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            log_interval_secs: Self::default_log_interval_secs(),
        }
    }
}

/// モジュール別イベント保持ポリシー
#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct RetentionPolicy {
    /// INFO イベントの保持期間（日数）。0 でグローバル設定を使用
    #[serde(default)]
    pub retention_days: u64,
    /// WARNING イベントの保持期間（日数）。0 でグローバル設定を使用
    #[serde(default)]
    pub retention_days_warning: u64,
    /// CRITICAL イベントの保持期間（日数）。0 でグローバル設定を使用
    #[serde(default)]
    pub retention_days_critical: u64,
}

/// イベントストア（SQLite 永続化）設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct EventStoreConfig {
    /// イベントストアの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// SQLite データベースファイルパス
    #[serde(default = "EventStoreConfig::default_database_path")]
    pub database_path: String,

    /// イベント保持期間（日数）
    #[serde(default = "EventStoreConfig::default_retention_days")]
    pub retention_days: u64,

    /// バッチ挿入サイズ
    #[serde(default = "EventStoreConfig::default_batch_size")]
    pub batch_size: usize,

    /// バッチフラッシュ間隔（秒）
    #[serde(default = "EventStoreConfig::default_batch_interval_secs")]
    pub batch_interval_secs: u64,

    /// クリーンアップ実行間隔（時間）
    #[serde(default = "EventStoreConfig::default_cleanup_interval_hours")]
    pub cleanup_interval_hours: u64,

    /// CRITICAL イベントの保持期間（日数）
    /// 0 の場合は retention_days と同じ値を使用する
    #[serde(default = "EventStoreConfig::default_retention_days_critical")]
    pub retention_days_critical: u64,

    /// WARNING イベントの保持期間（日数）
    /// 0 の場合は retention_days と同じ値を使用する
    #[serde(default)]
    pub retention_days_warning: u64,

    /// モジュール別イベント保持ポリシー
    #[serde(default)]
    pub retention_policies: HashMap<String, RetentionPolicy>,

    /// ストレージ上限（MB）
    /// DB ファイルサイズがこの値を超えた場合、古い INFO → WARNING → CRITICAL の順で削除する
    /// 0 の場合は上限なし
    #[serde(default)]
    pub max_storage_mb: u64,

    /// アーカイブ機能の有効/無効
    #[serde(default)]
    pub archive_enabled: bool,

    /// アーカイブ対象とするイベントの経過日数
    #[serde(default = "EventStoreConfig::default_archive_after_days")]
    pub archive_after_days: u64,

    /// アーカイブファイルの保存先ディレクトリ
    #[serde(default = "EventStoreConfig::default_archive_dir")]
    pub archive_dir: String,

    /// アーカイブ実行間隔（時間）
    #[serde(default = "EventStoreConfig::default_archive_interval_hours")]
    pub archive_interval_hours: u64,

    /// アーカイブファイルの gzip 圧縮の有効/無効
    #[serde(default = "EventStoreConfig::default_archive_compress")]
    pub archive_compress: bool,

    /// アーカイブローテーションの有効/無効
    #[serde(default)]
    pub archive_rotation_enabled: bool,

    /// アーカイブファイルの最大保持日数（0 で無制限）
    #[serde(default = "EventStoreConfig::default_archive_max_age_days")]
    pub archive_max_age_days: u64,

    /// アーカイブディレクトリの合計サイズ上限（MB、0 で無制限）
    #[serde(default)]
    pub archive_max_total_mb: u64,

    /// アーカイブファイルの最大保持数（0 で無制限）
    #[serde(default)]
    pub archive_max_files: u64,
}

impl EventStoreConfig {
    fn default_database_path() -> String {
        "/var/lib/zettai-mamorukun/events.db".to_string()
    }
    fn default_retention_days() -> u64 {
        90
    }
    fn default_batch_size() -> usize {
        100
    }
    fn default_batch_interval_secs() -> u64 {
        5
    }
    fn default_cleanup_interval_hours() -> u64 {
        24
    }
    fn default_retention_days_critical() -> u64 {
        365
    }
    fn default_archive_after_days() -> u64 {
        30
    }
    fn default_archive_dir() -> String {
        "/var/lib/zettai-mamorukun/archive".to_string()
    }
    fn default_archive_interval_hours() -> u64 {
        24
    }
    fn default_archive_compress() -> bool {
        true
    }
    fn default_archive_max_age_days() -> u64 {
        365
    }
}

impl Default for EventStoreConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            database_path: Self::default_database_path(),
            retention_days: Self::default_retention_days(),
            batch_size: Self::default_batch_size(),
            batch_interval_secs: Self::default_batch_interval_secs(),
            cleanup_interval_hours: Self::default_cleanup_interval_hours(),
            retention_days_critical: Self::default_retention_days_critical(),
            retention_days_warning: 0,
            retention_policies: HashMap::new(),
            max_storage_mb: 0,
            archive_enabled: false,
            archive_after_days: Self::default_archive_after_days(),
            archive_dir: Self::default_archive_dir(),
            archive_interval_hours: Self::default_archive_interval_hours(),
            archive_compress: Self::default_archive_compress(),
            archive_rotation_enabled: false,
            archive_max_age_days: Self::default_archive_max_age_days(),
            archive_max_total_mb: 0,
            archive_max_files: 0,
        }
    }
}

/// ステータスサーバー設定
#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct StatusConfig {
    /// ステータスサーバーの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// Unix ソケットのパス
    #[serde(default = "StatusConfig::default_socket_path")]
    pub socket_path: String,
}

impl StatusConfig {
    fn default_enabled() -> bool {
        false
    }

    fn default_socket_path() -> String {
        "/var/run/zettai-mamorukun/status.sock".to_string()
    }
}

impl Default for StatusConfig {
    fn default() -> Self {
        Self {
            enabled: Self::default_enabled(),
            socket_path: Self::default_socket_path(),
        }
    }
}

/// イベントストリーム設定
#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct EventStreamConfig {
    /// イベントストリームの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// Unix ソケットのパス
    #[serde(default = "EventStreamConfig::default_socket_path")]
    pub socket_path: String,

    /// クライアントごとの送信バッファサイズ
    #[serde(default = "EventStreamConfig::default_buffer_size")]
    pub buffer_size: usize,
}

impl EventStreamConfig {
    fn default_socket_path() -> String {
        "/var/run/zettai-mamorukun/event_stream.sock".to_string()
    }

    fn default_buffer_size() -> usize {
        256
    }
}

impl Default for EventStreamConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            socket_path: Self::default_socket_path(),
            buffer_size: Self::default_buffer_size(),
        }
    }
}

/// 相関分析エンジン設定
#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct CorrelationConfig {
    /// 相関分析エンジンの有効/無効（デフォルト: false）
    #[serde(default)]
    pub enabled: bool,

    /// イベントウィンドウの保持期間（秒、デフォルト: 600 = 10分）
    #[serde(default = "CorrelationConfig::default_window_secs")]
    pub window_secs: u64,

    /// ウィンドウ内の最大イベント保持数（デフォルト: 10000）
    #[serde(default = "CorrelationConfig::default_max_events")]
    pub max_events: usize,

    /// クリーンアップ間隔（秒、デフォルト: 30）
    #[serde(default = "CorrelationConfig::default_cleanup_interval_secs")]
    pub cleanup_interval_secs: u64,

    /// 相関ルールのリスト
    #[serde(default)]
    pub rules: Vec<CorrelationRuleConfig>,

    /// プリセットルールの有効/無効（デフォルト: true）
    #[serde(default = "CorrelationConfig::default_enable_presets")]
    pub enable_presets: bool,

    /// 無効にするプリセットのリスト
    #[serde(default)]
    pub disabled_presets: Vec<String>,
}

impl CorrelationConfig {
    fn default_window_secs() -> u64 {
        600
    }

    fn default_max_events() -> usize {
        10_000
    }

    fn default_cleanup_interval_secs() -> u64 {
        30
    }

    fn default_enable_presets() -> bool {
        true
    }
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            window_secs: Self::default_window_secs(),
            max_events: Self::default_max_events(),
            cleanup_interval_secs: Self::default_cleanup_interval_secs(),
            rules: Vec::new(),
            enable_presets: Self::default_enable_presets(),
            disabled_presets: Vec::new(),
        }
    }
}

/// 相関ルール設定
#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct CorrelationRuleConfig {
    /// ルール名（一意識別子）
    pub name: String,

    /// ルールの説明
    pub description: String,

    /// ルールの各ステップ（順序付き）
    pub steps: Vec<CorrelationStepConfig>,

    /// 全ステップが完了すべき時間窓（秒）
    /// 未設定の場合は CorrelationConfig の window_secs を使用
    pub within_secs: Option<u64>,
}

/// 相関ルールのステップ設定
#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct CorrelationStepConfig {
    /// ステップ名（ログ出力用）
    pub name: String,

    /// マッチ対象のイベント種別（正規表現）
    pub event_type: String,

    /// マッチ対象のソースモジュール（正規表現、オプション）
    pub source_module: Option<String>,

    /// マッチ対象の最小重要度（オプション）
    pub min_severity: Option<String>,
}

impl GeneralConfig {
    fn default_log_level() -> String {
        "info".to_string()
    }

    fn default_journald_enabled() -> bool {
        true
    }

    fn default_journald_field_prefix() -> String {
        "ZETTAI".to_string()
    }
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            log_level: Self::default_log_level(),
            journald_enabled: Self::default_journald_enabled(),
            journald_field_prefix: Self::default_journald_field_prefix(),
        }
    }
}

impl AppConfig {
    /// 設定ファイルの値を検証する。エラーがあればすべて収集して返す。
    pub fn validate(&self) -> Result<(), AppError> {
        let mut errors = Vec::new();

        // general.log_level の検証
        let valid_log_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_log_levels.contains(&self.general.log_level.as_str()) {
            errors.push(format!(
                "general.log_level: 無効な値 '{}' (有効値: {})",
                self.general.log_level,
                valid_log_levels.join(", ")
            ));
        }

        // general.journald_field_prefix の検証
        if self.general.journald_field_prefix.is_empty() {
            errors.push("general.journald_field_prefix: 空文字列は指定できません".to_string());
        } else if !self
            .general
            .journald_field_prefix
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        {
            errors.push(format!(
                "general.journald_field_prefix: 大文字英数字とアンダースコアのみ使用できます (現在値: '{}')",
                self.general.journald_field_prefix
            ));
        }

        // health 設定の検証
        if self.health.heartbeat_interval_secs == 0 {
            errors.push(
                "health.heartbeat_interval_secs: 0 より大きい値を指定してください".to_string(),
            );
        }

        // event_bus 設定の検証
        if self.event_bus.channel_capacity == 0 {
            errors.push("event_bus.channel_capacity: 0 より大きい値を指定してください".to_string());
        }

        // metrics 設定の検証
        if self.metrics.enabled && self.metrics.interval_secs == 0 {
            errors.push("metrics.interval_secs: 0 より大きい値を指定してください".to_string());
        }

        // event_store 設定の検証
        if self.event_store.enabled {
            if self.event_store.database_path.is_empty() {
                errors.push("event_store.database_path: 空文字列は指定できません".to_string());
            }
            if self.event_store.retention_days == 0 {
                errors.push(
                    "event_store.retention_days: 0 より大きい値を指定してください".to_string(),
                );
            }
            if self.event_store.batch_interval_secs == 0 {
                errors.push(
                    "event_store.batch_interval_secs: 0 より大きい値を指定してください".to_string(),
                );
            }
            if self.event_store.retention_days_critical != 0
                && self.event_store.retention_days_critical < self.event_store.retention_days
            {
                errors.push(
                    "event_store.retention_days_critical: retention_days 以上の値を指定してください（0 で無効化）".to_string(),
                );
            }
            if self.event_store.retention_days_warning != 0
                && self.event_store.retention_days_warning < self.event_store.retention_days
            {
                tracing::warn!(
                    retention_days_warning = self.event_store.retention_days_warning,
                    retention_days = self.event_store.retention_days,
                    "event_store.retention_days_warning が retention_days より小さい値です"
                );
            }
            for (module_name, policy) in &self.event_store.retention_policies {
                if policy.retention_days_warning != 0
                    && policy.retention_days != 0
                    && policy.retention_days_warning < policy.retention_days
                {
                    tracing::warn!(
                        module = %module_name,
                        retention_days_warning = policy.retention_days_warning,
                        retention_days = policy.retention_days,
                        "event_store.retention_policies.{}: retention_days_warning が retention_days より小さい値です",
                        module_name
                    );
                }
                if policy.retention_days_critical != 0
                    && policy.retention_days != 0
                    && policy.retention_days_critical < policy.retention_days
                {
                    tracing::warn!(
                        module = %module_name,
                        retention_days_critical = policy.retention_days_critical,
                        retention_days = policy.retention_days,
                        "event_store.retention_policies.{}: retention_days_critical が retention_days より小さい値です",
                        module_name
                    );
                }
            }
        }

        // event_stream 設定の検証
        if self.event_stream.enabled && self.event_stream.buffer_size == 0 {
            errors.push("event_stream.buffer_size: 0 より大きい値を指定してください".to_string());
        }

        // correlation 設定の検証
        if self.correlation.enabled {
            if self.correlation.window_secs == 0 {
                errors
                    .push("correlation.window_secs: 0 より大きい値を指定してください".to_string());
            }
            if self.correlation.max_events == 0 {
                errors.push("correlation.max_events: 0 より大きい値を指定してください".to_string());
            }
            if self.correlation.cleanup_interval_secs == 0 {
                errors.push(
                    "correlation.cleanup_interval_secs: 0 より大きい値を指定してください"
                        .to_string(),
                );
            }
            for (i, rule) in self.correlation.rules.iter().enumerate() {
                if rule.name.is_empty() {
                    errors.push(format!(
                        "correlation.rules[{}].name: 空文字列は指定できません",
                        i
                    ));
                }
                if rule.steps.is_empty() {
                    errors.push(format!(
                        "correlation.rules[{}].steps: 少なくとも1つのステップが必要です",
                        i
                    ));
                }
                for (j, step) in rule.steps.iter().enumerate() {
                    if step.event_type.is_empty() {
                        errors.push(format!(
                            "correlation.rules[{}].steps[{}].event_type: 空文字列は指定できません",
                            i, j
                        ));
                    }
                    if let Some(ref sev) = step.min_severity {
                        let valid_severities = ["info", "warning", "critical"];
                        if !valid_severities.contains(&sev.to_lowercase().as_str()) {
                            errors.push(format!(
                                "correlation.rules[{}].steps[{}].min_severity: 無効な値 '{}' (有効値: info, warning, critical)",
                                i, j, sev
                            ));
                        }
                    }
                }
            }
        }

        // 各モジュールの interval 検証
        Self::validate_interval(
            self.modules.file_integrity.scan_interval_secs,
            "modules.file_integrity.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.process_monitor.scan_interval_secs,
            "modules.process_monitor.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.kernel_module.scan_interval_secs,
            "modules.kernel_module.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.at_job_monitor.scan_interval_secs,
            "modules.at_job_monitor.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.cron_monitor.scan_interval_secs,
            "modules.cron_monitor.scan_interval_secs",
            &mut errors,
        );
        if !(10..=60000).contains(&self.modules.cron_monitor.inotify_debounce_ms) {
            errors.push(
                "modules.cron_monitor.inotify_debounce_ms: 10〜60000 の範囲で指定してください"
                    .to_string(),
            );
        }
        Self::validate_interval(
            self.modules.user_account.scan_interval_secs,
            "modules.user_account.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.log_tamper.scan_interval_secs,
            "modules.log_tamper.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.systemd_service.scan_interval_secs,
            "modules.systemd_service.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.systemd_timer_monitor.scan_interval_secs,
            "modules.systemd_timer_monitor.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.firewall_monitor.scan_interval_secs,
            "modules.firewall_monitor.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.dns_monitor.scan_interval_secs,
            "modules.dns_monitor.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.dns_query_monitor.scan_interval_secs,
            "modules.dns_query_monitor.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.ssh_key_monitor.scan_interval_secs,
            "modules.ssh_key_monitor.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.mount_monitor.scan_interval_secs,
            "modules.mount_monitor.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.shell_config_monitor.scan_interval_secs,
            "modules.shell_config_monitor.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.tmp_exec_monitor.scan_interval_secs,
            "modules.tmp_exec_monitor.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.sudoers_monitor.scan_interval_secs,
            "modules.sudoers_monitor.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.pam_monitor.scan_interval_secs,
            "modules.pam_monitor.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.security_files_monitor.scan_interval_secs,
            "modules.security_files_monitor.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.suid_sgid_monitor.scan_interval_secs,
            "modules.suid_sgid_monitor.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.ssh_brute_force.interval_secs,
            "modules.ssh_brute_force.interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.network_monitor.interval_secs,
            "modules.network_monitor.interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.pkg_repo_monitor.scan_interval_secs,
            "modules.pkg_repo_monitor.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.ld_preload_monitor.scan_interval_secs,
            "modules.ld_preload_monitor.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.ebpf_monitor.scan_interval_secs,
            "modules.ebpf_monitor.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.fileless_exec_monitor.scan_interval_secs,
            "modules.fileless_exec_monitor.scan_interval_secs",
            &mut errors,
        );

        // network_monitor 固有の検証
        if self.modules.network_monitor.max_connections == 0 {
            errors.push(
                "modules.network_monitor.max_connections: 0 より大きい値を指定してください"
                    .to_string(),
            );
        }

        // ssh_brute_force 固有の検証
        if self.modules.ssh_brute_force.max_failures == 0 {
            errors.push(
                "modules.ssh_brute_force.max_failures: 0 より大きい値を指定してください"
                    .to_string(),
            );
        }
        if self.modules.ssh_brute_force.time_window_secs == 0 {
            errors.push(
                "modules.ssh_brute_force.time_window_secs: 0 より大きい値を指定してください"
                    .to_string(),
            );
        }

        // actions.rules の検証
        let valid_actions = ["log", "command", "webhook"];
        let valid_severities = ["Critical", "High", "Warning", "Info"];
        for (i, rule) in self.actions.rules.iter().enumerate() {
            let prefix = format!("actions.rules[{}] ({})", i, rule.name);

            if !valid_actions.contains(&rule.action.as_str()) {
                errors.push(format!(
                    "{}: 無効なアクション種別 '{}' (有効値: {})",
                    prefix,
                    rule.action,
                    valid_actions.join(", ")
                ));
            }

            if let Some(ref severity) = rule.severity
                && !valid_severities.contains(&severity.as_str())
            {
                errors.push(format!(
                    "{}: 無効な severity '{}' (有効値: {})",
                    prefix,
                    severity,
                    valid_severities.join(", ")
                ));
            }

            if rule.action == "command" && rule.command.is_none() {
                errors.push(format!(
                    "{}: action が 'command' の場合、command フィールドは必須です",
                    prefix
                ));
            }

            if rule.action == "webhook" && rule.url.is_none() {
                errors.push(format!(
                    "{}: action が 'webhook' の場合、url フィールドは必須です",
                    prefix
                ));
            }
        }

        // module_watchdog 設定の検証
        if self.module_watchdog.check_interval_secs == 0 {
            errors.push(
                "module_watchdog.check_interval_secs: 0 より大きい値を指定してください".to_string(),
            );
        }
        if self.module_watchdog.restart_cooldown_secs == 0 {
            errors.push(
                "module_watchdog.restart_cooldown_secs: 0 より大きい値を指定してください"
                    .to_string(),
            );
        }

        // status 設定の検証
        if self.status.enabled && self.status.socket_path.is_empty() {
            errors.push("status.socket_path: 空文字列は指定できません".to_string());
        }

        // syslog 設定の検証
        if self.syslog.enabled {
            let valid_protocols = ["udp", "tcp", "tls"];
            if !valid_protocols.contains(&self.syslog.protocol.as_str()) {
                errors.push(format!(
                    "syslog.protocol: 無効な値 '{}' (有効値: udp, tcp, tls)",
                    self.syslog.protocol
                ));
            }
            if self.syslog.server.is_empty() {
                errors.push("syslog.server: 空文字列は指定できません".to_string());
            }
            if self.syslog.port == 0 {
                errors.push("syslog.port: 0 より大きい値を指定してください".to_string());
            }
            let valid_facilities = [
                "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron",
                "authpriv", "ftp", "local0", "local1", "local2", "local3", "local4", "local5",
                "local6", "local7",
            ];
            if !valid_facilities.contains(&self.syslog.facility.as_str()) {
                errors.push(format!(
                    "syslog.facility: 無効な値 '{}' (有効値: {})",
                    self.syslog.facility,
                    valid_facilities.join(", ")
                ));
            }
            if self.syslog.app_name.is_empty() {
                errors.push("syslog.app_name: 空文字列は指定できません".to_string());
            }
        }

        // alert_rules の検証
        if self.alert_rules.enabled {
            let valid_condition_types = ["threshold", "field_match", "compound"];
            let valid_alert_actions = ["log", "command", "webhook"];
            let valid_alert_fields = [
                "event_type",
                "source_module",
                "message",
                "details",
                "severity",
            ];
            for (i, rule) in self.alert_rules.rules.iter().enumerate() {
                let prefix = format!("alert_rules.rules[{}] ({})", i, rule.name);
                if !valid_condition_types.contains(&rule.condition_type.as_str()) {
                    errors.push(format!(
                        "{}: 無効な condition_type '{}' (有効値: {})",
                        prefix,
                        rule.condition_type,
                        valid_condition_types.join(", ")
                    ));
                }
                if !valid_alert_actions.contains(&rule.action.as_str()) {
                    errors.push(format!(
                        "{}: 無効な action '{}' (有効値: {})",
                        prefix,
                        rule.action,
                        valid_alert_actions.join(", ")
                    ));
                }
                if rule.condition_type == "threshold" {
                    if rule.threshold_count.is_none() {
                        errors.push(format!(
                            "{}: condition_type が 'threshold' の場合、threshold_count は必須です",
                            prefix
                        ));
                    }
                    if rule.window_secs.is_none() {
                        errors.push(format!(
                            "{}: condition_type が 'threshold' の場合、window_secs は必須です",
                            prefix
                        ));
                    }
                }
                if rule.condition_type == "field_match" {
                    if rule.field.is_none() {
                        errors.push(format!(
                            "{}: condition_type が 'field_match' の場合、field は必須です",
                            prefix
                        ));
                    } else if let Some(ref f) = rule.field
                        && !valid_alert_fields.contains(&f.as_str())
                    {
                        errors.push(format!(
                            "{}: 無効な field '{}' (有効値: {})",
                            prefix,
                            f,
                            valid_alert_fields.join(", ")
                        ));
                    }
                    if rule.pattern.is_none() {
                        errors.push(format!(
                            "{}: condition_type が 'field_match' の場合、pattern は必須です",
                            prefix
                        ));
                    }
                }
                if rule.condition_type == "compound" {
                    if rule.operator.is_none() {
                        errors.push(format!(
                            "{}: condition_type が 'compound' の場合、operator は必須です",
                            prefix
                        ));
                    } else if let Some(ref op) = rule.operator
                        && op != "and"
                        && op != "or"
                    {
                        errors.push(format!(
                            "{}: 無効な operator '{}' (有効値: and, or)",
                            prefix, op
                        ));
                    }
                    if rule.conditions.is_empty() {
                        errors.push(format!(
                            "{}: condition_type が 'compound' の場合、conditions は必須です",
                            prefix
                        ));
                    }
                }
                if rule.action == "command" && rule.command.is_none() {
                    errors.push(format!(
                        "{}: action が 'command' の場合、command フィールドは必須です",
                        prefix
                    ));
                }
                if rule.action == "webhook" && rule.url.is_none() {
                    errors.push(format!(
                        "{}: action が 'webhook' の場合、url フィールドは必須です",
                        prefix
                    ));
                }
            }
        }

        // rate_limit の検証
        if let Some(ref rate_limit) = self.actions.rate_limit {
            if let Some(ref cmd) = rate_limit.command {
                Self::validate_bucket_config(cmd, "actions.rate_limit.command", &mut errors);
            }
            if let Some(ref wh) = rate_limit.webhook {
                Self::validate_bucket_config(wh, "actions.rate_limit.webhook", &mut errors);
            }
        }

        // prometheus の検証
        if self.prometheus.enabled && self.prometheus.port == 0 {
            errors.push("prometheus.port: 0 より大きい値を指定してください".to_string());
        }
        if self.prometheus.enabled && self.prometheus.bind_address.is_empty() {
            errors.push("prometheus.bind_address: 空文字列は指定できません".to_string());
        }

        // api の検証
        if self.api.enabled && self.api.port == 0 {
            errors.push("api.port: 0 より大きい値を指定してください".to_string());
        }
        if self.api.enabled && self.api.bind_address.is_empty() {
            errors.push("api.bind_address: 空文字列は指定できません".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            let count = errors.len();
            Err(AppError::ConfigValidation { count, errors })
        }
    }

    /// interval 値が 0 でないことを検証するヘルパー
    fn validate_interval(value: u64, field_name: &str, errors: &mut Vec<String>) {
        if value == 0 {
            errors.push(format!("{}: 0 より大きい値を指定してください", field_name));
        }
    }

    /// トークンバケット設定の値を検証するヘルパー
    fn validate_bucket_config(config: &BucketConfig, prefix: &str, errors: &mut Vec<String>) {
        if config.max_tokens == 0 {
            errors.push(format!(
                "{}.max_tokens: 0 より大きい値を指定してください",
                prefix
            ));
        }
        if config.refill_amount == 0 {
            errors.push(format!(
                "{}.refill_amount: 0 より大きい値を指定してください",
                prefix
            ));
        }
        if config.refill_interval_secs == 0 {
            errors.push(format!(
                "{}.refill_interval_secs: 0 より大きい値を指定してください",
                prefix
            ));
        }
    }

    /// 有効なモジュール数をカウントする
    pub fn count_enabled_modules(&self) -> usize {
        let m = &self.modules;
        [
            m.file_integrity.enabled,
            m.process_monitor.enabled,
            m.kernel_module.enabled,
            m.at_job_monitor.enabled,
            m.cron_monitor.enabled,
            m.user_account.enabled,
            m.log_tamper.enabled,
            m.systemd_service.enabled,
            m.systemd_timer_monitor.enabled,
            m.firewall_monitor.enabled,
            m.dns_monitor.enabled,
            m.dns_query_monitor.enabled,
            m.ssh_key_monitor.enabled,
            m.mount_monitor.enabled,
            m.shell_config_monitor.enabled,
            m.tmp_exec_monitor.enabled,
            m.sudoers_monitor.enabled,
            m.pam_monitor.enabled,
            m.security_files_monitor.enabled,
            m.suid_sgid_monitor.enabled,
            m.ssh_brute_force.enabled,
            m.pkg_repo_monitor.enabled,
            m.ld_preload_monitor.enabled,
            m.network_monitor.enabled,
            m.group_monitor.enabled,
            m.process_cmdline_monitor.enabled,
        ]
        .iter()
        .filter(|&&e| e)
        .count()
    }

    /// デフォルト設定との差分を検出する。変更されたフィールドのパスと（デフォルト値, 現在値）のペアを返す。
    pub fn diff_from_default(&self) -> Vec<(String, String, String)> {
        // unwrap safety: AppConfig は Serialize を実装しており、シリアライズは常に成功する
        let default_value: toml::Value = toml::Value::try_from(Self::default()).unwrap();
        let current_value: toml::Value = toml::Value::try_from(self).unwrap();

        let mut diffs = Vec::new();
        Self::collect_diffs(&default_value, &current_value, "", &mut diffs);
        diffs
    }

    /// TOML 値を再帰的に比較し、差分を収集する
    fn collect_diffs(
        default: &toml::Value,
        current: &toml::Value,
        path: &str,
        diffs: &mut Vec<(String, String, String)>,
    ) {
        match (default, current) {
            (toml::Value::Table(d_table), toml::Value::Table(c_table)) => {
                for (key, d_val) in d_table {
                    let full_path = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{}.{}", path, key)
                    };

                    if let Some(c_val) = c_table.get(key)
                        && d_val != c_val
                    {
                        if d_val.is_table() && c_val.is_table() {
                            Self::collect_diffs(d_val, c_val, &full_path, diffs);
                        } else {
                            diffs.push((
                                full_path,
                                Self::format_value(d_val),
                                Self::format_value(c_val),
                            ));
                        }
                    }
                }

                for (key, c_val) in c_table {
                    if !d_table.contains_key(key) {
                        let full_path = if path.is_empty() {
                            key.clone()
                        } else {
                            format!("{}.{}", path, key)
                        };
                        diffs.push((full_path, "(なし)".to_string(), Self::format_value(c_val)));
                    }
                }
            }
            _ => {
                if default != current {
                    diffs.push((
                        path.to_string(),
                        Self::format_value(default),
                        Self::format_value(current),
                    ));
                }
            }
        }
    }

    /// TOML 値を表示用の文字列に変換する
    fn format_value(value: &toml::Value) -> String {
        match value {
            toml::Value::String(s) => format!("\"{}\"", s),
            toml::Value::Integer(i) => i.to_string(),
            toml::Value::Float(f) => f.to_string(),
            toml::Value::Boolean(b) => b.to_string(),
            toml::Value::Array(arr) => {
                let items: Vec<String> = arr.iter().map(Self::format_value).collect();
                format!("[{}]", items.join(", "))
            }
            toml::Value::Table(_) => "(テーブル)".to_string(),
            toml::Value::Datetime(dt) => dt.to_string(),
        }
    }

    /// 設定ファイルを読み込む。ファイルが存在しない場合はデフォルト設定を返す。
    pub fn load(path: &Path) -> Result<Self, AppError> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(path).map_err(|e| AppError::ConfigRead {
            path: path.to_path_buf(),
            source: e,
        })?;

        let content = crate::encryption::decrypt_config_content(&content)?;

        toml::from_str(&content).map_err(|e| AppError::ConfigParse {
            path: path.to_path_buf(),
            source: e,
        })
    }
}

/// ptrace 検知モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct PtraceMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "PtraceMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 許可するトレーサーのプロセス名リスト（ホワイトリスト）
    #[serde(default)]
    pub whitelist_tracers: Vec<String>,
}

impl PtraceMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        30
    }
}

impl Default for PtraceMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            whitelist_tracers: Vec::new(),
        }
    }
}

/// アラートルール DSL 設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Default)]
pub struct AlertRulesConfig {
    /// 有効/無効
    #[serde(default)]
    pub enabled: bool,
    /// ルールリスト
    #[serde(default)]
    pub rules: Vec<AlertRuleConfig>,
}

/// アラートルール設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct AlertRuleConfig {
    /// ルール名
    pub name: String,
    /// ルールの説明
    #[serde(default)]
    pub description: Option<String>,
    /// 条件タイプ（"threshold" | "field_match" | "compound"）
    pub condition_type: String,
    /// threshold: 閾値件数
    pub threshold_count: Option<u64>,
    /// threshold: 時間窓（秒）
    pub window_secs: Option<u64>,
    /// イベント種別フィルタ
    pub event_type: Option<String>,
    /// Severity フィルタ
    pub severity_filter: Option<String>,
    /// モジュール名フィルタ
    pub module_filter: Option<String>,
    /// field_match: 対象フィールド
    pub field: Option<String>,
    /// field_match: 正規表現パターン
    pub pattern: Option<String>,
    /// compound: 論理演算子（"and" | "or"）
    pub operator: Option<String>,
    /// compound: サブ条件リスト
    #[serde(default)]
    pub conditions: Vec<AlertSubConditionConfig>,
    /// アクション種別（"log" | "command" | "webhook"）
    pub action: String,
    /// 実行コマンド（action が "command" の場合）
    pub command: Option<String>,
    /// タイムアウト（秒）
    #[serde(default = "default_alert_timeout")]
    pub timeout_secs: u64,
    /// Webhook URL
    pub url: Option<String>,
    /// HTTP メソッド
    pub method: Option<String>,
    /// HTTP ヘッダー
    #[serde(default)]
    pub headers: Option<std::collections::HashMap<String, String>>,
    /// ボディテンプレート
    pub body_template: Option<String>,
    /// リトライ回数
    pub max_retries: Option<u32>,
}

/// アラートサブ条件設定（compound 用）
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct AlertSubConditionConfig {
    /// 条件タイプ
    pub condition_type: String,
    /// threshold: 閾値件数
    pub threshold_count: Option<u64>,
    /// threshold: 時間窓（秒）
    pub window_secs: Option<u64>,
    /// イベント種別フィルタ
    pub event_type: Option<String>,
    /// Severity フィルタ
    pub severity_filter: Option<String>,
    /// モジュール名フィルタ
    pub module_filter: Option<String>,
    /// field_match: 対象フィールド
    pub field: Option<String>,
    /// field_match: 正規表現パターン
    pub pattern: Option<String>,
}

fn default_alert_timeout() -> u64 {
    30
}

/// カーネルシンボルテーブル監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct KallsymsMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "KallsymsMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,
}

impl KallsymsMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        300
    }
}

impl Default for KallsymsMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
        }
    }
}

/// カーネルライブパッチ監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct LivepatchMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "LivepatchMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// /sys/kernel/livepatch パス（テスト用にオーバーライド可能）
    #[serde(default = "LivepatchMonitorConfig::default_sys_path")]
    pub sys_path: String,

    /// /proc パス（テスト用にオーバーライド可能）
    #[serde(default = "LivepatchMonitorConfig::default_proc_path")]
    pub proc_path: String,
}

impl LivepatchMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        60
    }

    fn default_sys_path() -> String {
        "/sys/kernel/livepatch".to_string()
    }

    fn default_proc_path() -> String {
        "/proc".to_string()
    }
}

impl Default for LivepatchMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            sys_path: Self::default_sys_path(),
            proc_path: Self::default_proc_path(),
        }
    }
}

/// コアダンプ設定監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct CoredumpMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "CoredumpMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// /proc パス（テスト用にオーバーライド可能）
    #[serde(default = "CoredumpMonitorConfig::default_proc_path")]
    pub proc_path: String,
}

impl CoredumpMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        30
    }

    fn default_proc_path() -> String {
        "/proc".to_string()
    }
}

impl Default for CoredumpMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            proc_path: Self::default_proc_path(),
        }
    }
}

/// eBPF プログラム監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct EbpfMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "EbpfMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// /proc パス（テスト用にオーバーライド可能）
    #[serde(default = "EbpfMonitorConfig::default_proc_path")]
    pub proc_path: String,

    /// 許可するプログラム名のリスト
    #[serde(default)]
    pub allowed_programs: Vec<String>,
}

impl EbpfMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        30
    }

    fn default_proc_path() -> String {
        "/proc".to_string()
    }
}

impl Default for EbpfMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            proc_path: Self::default_proc_path(),
            allowed_programs: vec![],
        }
    }
}

/// D-Bus シグナル監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct DbusMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "DbusMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// systemd ユニット状態変更を監視する
    #[serde(default = "DbusMonitorConfig::default_watch_systemd")]
    pub watch_systemd: bool,

    /// D-Bus バス名の出現・消失を監視する
    #[serde(default = "DbusMonitorConfig::default_watch_bus_names")]
    pub watch_bus_names: bool,
}

impl DbusMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        30
    }

    fn default_watch_systemd() -> bool {
        true
    }

    fn default_watch_bus_names() -> bool {
        true
    }
}

impl Default for DbusMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_systemd: Self::default_watch_systemd(),
            watch_bus_names: Self::default_watch_bus_names(),
        }
    }
}

/// スワップ / tmpfs 監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct SwapTmpfsMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "SwapTmpfsMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// tmpfs 使用量の閾値（%）
    #[serde(default = "SwapTmpfsMonitorConfig::default_tmpfs_usage_threshold_percent")]
    pub tmpfs_usage_threshold_percent: u64,

    /// tmpfs 上の実行ファイルをスキャンするか
    #[serde(default = "SwapTmpfsMonitorConfig::default_scan_executables")]
    pub scan_executables: bool,

    /// 除外する tmpfs マウントポイント（他モジュールとの棲み分け用）
    #[serde(default = "SwapTmpfsMonitorConfig::default_exclude_paths")]
    pub exclude_paths: Vec<String>,

    /// /proc パス（通常は変更不要）
    #[serde(default = "SwapTmpfsMonitorConfig::default_proc_path")]
    pub proc_path: String,
}

impl SwapTmpfsMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        30
    }

    fn default_tmpfs_usage_threshold_percent() -> u64 {
        80
    }

    fn default_scan_executables() -> bool {
        true
    }

    fn default_exclude_paths() -> Vec<String> {
        vec!["/dev/shm".to_string()]
    }

    fn default_proc_path() -> String {
        "/proc".to_string()
    }
}

impl Default for SwapTmpfsMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            tmpfs_usage_threshold_percent: Self::default_tmpfs_usage_threshold_percent(),
            scan_executables: Self::default_scan_executables(),
            exclude_paths: Self::default_exclude_paths(),
            proc_path: Self::default_proc_path(),
        }
    }
}

/// UNIX ソケット監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct UnixSocketMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "UnixSocketMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象ディレクトリ
    #[serde(default = "UnixSocketMonitorConfig::default_watch_dirs")]
    pub watch_dirs: Vec<String>,

    /// 既知の正常なソケットパス（ベースライン）
    #[serde(default = "UnixSocketMonitorConfig::default_known_sockets")]
    pub known_sockets: Vec<String>,

    /// /proc パス（テスト用に変更可能）
    #[serde(default = "UnixSocketMonitorConfig::default_proc_path")]
    pub proc_path: String,
}

impl UnixSocketMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        30
    }

    fn default_watch_dirs() -> Vec<String> {
        vec![
            "/run".to_string(),
            "/tmp".to_string(),
            "/var/run".to_string(),
            "/var/tmp".to_string(),
        ]
    }

    fn default_known_sockets() -> Vec<String> {
        vec![
            "/run/dbus/system_bus_socket".to_string(),
            "/run/systemd/private".to_string(),
        ]
    }

    fn default_proc_path() -> String {
        "/proc".to_string()
    }
}

impl Default for UnixSocketMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_dirs: Self::default_watch_dirs(),
            known_sockets: Self::default_known_sockets(),
            proc_path: Self::default_proc_path(),
        }
    }
}

/// プロセス cgroup 逸脱検知モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct ProcessCgroupMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "ProcessCgroupMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象プロセス名のフィルタ（空の場合は全プロセス）
    #[serde(default)]
    pub watch_process_names: Vec<String>,

    /// ホワイトリスト cgroup パターン（正規表現）
    #[serde(default)]
    pub whitelist_patterns: Vec<String>,

    /// ルート cgroup（"/"）への移動検知
    #[serde(default = "ProcessCgroupMonitorConfig::default_detect_root_cgroup_escape")]
    pub detect_root_cgroup_escape: bool,
}

impl ProcessCgroupMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        30
    }

    fn default_detect_root_cgroup_escape() -> bool {
        true
    }
}

impl Default for ProcessCgroupMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_process_names: Vec::new(),
            whitelist_patterns: Vec::new(),
            detect_root_cgroup_escape: Self::default_detect_root_cgroup_escape(),
        }
    }
}

/// 抽象ソケット名前空間監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct AbstractSocketMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "AbstractSocketMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 許可パターン — これらにマッチしない抽象ソケットを検知
    #[serde(default = "AbstractSocketMonitorConfig::default_allowed_patterns")]
    pub allowed_patterns: Vec<String>,

    /// バースト検知閾値（1スキャンサイクル内で新規出現がこの数を超えたら警告）
    #[serde(default = "AbstractSocketMonitorConfig::default_burst_threshold")]
    pub burst_threshold: usize,

    /// /proc パス（テスト用に変更可能）
    #[serde(default = "AbstractSocketMonitorConfig::default_proc_path")]
    pub proc_path: String,
}

impl AbstractSocketMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        30
    }

    fn default_allowed_patterns() -> Vec<String> {
        vec![
            "@/tmp/.X11-unix/*".to_string(),
            "@/tmp/.ICE-unix/*".to_string(),
            "@/run/dbus-*".to_string(),
            "@/run/systemd/*".to_string(),
            "@/run/user/*/bus".to_string(),
            "@/run/user/*/at-spi*".to_string(),
        ]
    }

    fn default_burst_threshold() -> usize {
        10
    }

    fn default_proc_path() -> String {
        "/proc".to_string()
    }
}

impl Default for AbstractSocketMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            allowed_patterns: Self::default_allowed_patterns(),
            burst_threshold: Self::default_burst_threshold(),
            proc_path: Self::default_proc_path(),
        }
    }
}

/// IPC 監視モジュールの設定
///
/// System V IPC（共有メモリ、セマフォ、メッセージキュー）を監視する。
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct IpcMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "IpcMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 過度に緩いパーミッション（0o666 等）を検知するか
    #[serde(default = "IpcMonitorConfig::default_alert_on_world_accessible")]
    pub alert_on_world_accessible: bool,

    /// 大容量共有メモリセグメントの閾値（バイト）
    #[serde(default = "IpcMonitorConfig::default_alert_on_large_shm_bytes")]
    pub alert_on_large_shm_bytes: u64,

    /// セマフォセット数の警告閾値
    #[serde(default = "IpcMonitorConfig::default_alert_on_high_semaphore_count")]
    pub alert_on_high_semaphore_count: u64,

    /// メッセージキュー数の警告閾値
    #[serde(default = "IpcMonitorConfig::default_alert_on_high_msg_queue_count")]
    pub alert_on_high_msg_queue_count: u64,

    /// /proc/sysvipc パス（テスト用に変更可能）
    #[serde(default = "IpcMonitorConfig::default_proc_sysvipc_path")]
    pub proc_sysvipc_path: PathBuf,
}

impl IpcMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        60
    }

    fn default_alert_on_world_accessible() -> bool {
        true
    }

    fn default_alert_on_large_shm_bytes() -> u64 {
        104_857_600 // 100MB
    }

    fn default_alert_on_high_semaphore_count() -> u64 {
        100
    }

    fn default_alert_on_high_msg_queue_count() -> u64 {
        50
    }

    fn default_proc_sysvipc_path() -> PathBuf {
        PathBuf::from("/proc/sysvipc")
    }
}

impl Default for IpcMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            alert_on_world_accessible: Self::default_alert_on_world_accessible(),
            alert_on_large_shm_bytes: Self::default_alert_on_large_shm_bytes(),
            alert_on_high_semaphore_count: Self::default_alert_on_high_semaphore_count(),
            alert_on_high_msg_queue_count: Self::default_alert_on_high_msg_queue_count(),
            proc_sysvipc_path: Self::default_proc_sysvipc_path(),
        }
    }
}

/// プロセス権限昇格検知モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct PrivilegeEscalationMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "PrivilegeEscalationMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視除外プロセス名
    #[serde(default = "PrivilegeEscalationMonitorConfig::default_whitelist_processes")]
    pub whitelist_processes: Vec<String>,

    /// /proc パス（テスト用に変更可能）
    #[serde(default = "PrivilegeEscalationMonitorConfig::default_proc_path")]
    pub proc_path: PathBuf,
}

impl PrivilegeEscalationMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        5
    }

    fn default_whitelist_processes() -> Vec<String> {
        vec![
            "su".to_string(),
            "sudo".to_string(),
            "polkitd".to_string(),
            "pkexec".to_string(),
            "login".to_string(),
            "sshd".to_string(),
            "cron".to_string(),
            "crond".to_string(),
            "systemd".to_string(),
        ]
    }

    fn default_proc_path() -> PathBuf {
        PathBuf::from("/proc")
    }
}

impl Default for PrivilegeEscalationMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            whitelist_processes: Self::default_whitelist_processes(),
            proc_path: Self::default_proc_path(),
        }
    }
}

/// バックドア検知モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct BackdoorDetectorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "BackdoorDetectorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 許可ポート番号リスト
    ///
    /// このリストに含まれるポートでリッスンしているソケットはアラート対象外
    #[serde(default)]
    pub allowed_ports: Vec<u16>,

    /// 許可プロセス名リスト
    ///
    /// このリストに含まれるプロセス名でリッスンしているソケットはアラート対象外
    #[serde(default)]
    pub allowed_processes: Vec<String>,

    /// ループバックアドレスのリッスンもアラートするか
    ///
    /// false の場合、127.0.0.1 / ::1 のみでリッスンしているソケットはアラート対象外
    #[serde(default = "BackdoorDetectorConfig::default_alert_on_loopback")]
    pub alert_on_loopback: bool,

    /// /proc/net/tcp のパス（テスト用に変更可能）
    #[serde(default = "BackdoorDetectorConfig::default_tcp_path")]
    pub tcp_path: String,

    /// /proc/net/tcp6 のパス（テスト用に変更可能）
    #[serde(default = "BackdoorDetectorConfig::default_tcp6_path")]
    pub tcp6_path: String,

    /// /proc パス（テスト用に変更可能）
    #[serde(default = "BackdoorDetectorConfig::default_proc_path")]
    pub proc_path: String,
}

impl BackdoorDetectorConfig {
    fn default_scan_interval_secs() -> u64 {
        30
    }

    fn default_alert_on_loopback() -> bool {
        false
    }

    fn default_tcp_path() -> String {
        "/proc/net/tcp".to_string()
    }

    fn default_tcp6_path() -> String {
        "/proc/net/tcp6".to_string()
    }

    fn default_proc_path() -> String {
        "/proc".to_string()
    }
}

impl Default for BackdoorDetectorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            allowed_ports: Vec::new(),
            allowed_processes: Vec::new(),
            alert_on_loopback: Self::default_alert_on_loopback(),
            tcp_path: Self::default_tcp_path(),
            tcp6_path: Self::default_tcp6_path(),
            proc_path: Self::default_proc_path(),
        }
    }
}

/// TLS 証明書チェーン検証モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct CertChainMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// チェック間隔（秒）
    #[serde(default = "CertChainMonitorConfig::default_check_interval_secs")]
    pub check_interval_secs: u64,

    /// 監視対象ディレクトリのリスト
    #[serde(default = "CertChainMonitorConfig::default_watch_dirs")]
    pub watch_dirs: Vec<PathBuf>,

    /// 対象ファイル拡張子
    #[serde(default = "CertChainMonitorConfig::default_file_extensions")]
    pub file_extensions: Vec<String>,

    /// 信頼済み CA 証明書の格納ディレクトリ
    #[serde(default = "CertChainMonitorConfig::default_trusted_ca_dirs")]
    pub trusted_ca_dirs: Vec<PathBuf>,
}

impl CertChainMonitorConfig {
    fn default_check_interval_secs() -> u64 {
        3600
    }

    fn default_watch_dirs() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/etc/ssl/certs"),
            PathBuf::from("/etc/pki/tls/certs"),
        ]
    }

    fn default_file_extensions() -> Vec<String> {
        vec![".pem".to_string(), ".crt".to_string(), ".cer".to_string()]
    }

    fn default_trusted_ca_dirs() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/etc/ssl/certs"),
            PathBuf::from("/etc/pki/ca-trust/extracted/pem"),
        ]
    }
}

impl Default for CertChainMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            check_interval_secs: Self::default_check_interval_secs(),
            watch_dirs: Self::default_watch_dirs(),
            file_extensions: Self::default_file_extensions(),
            trusted_ca_dirs: Self::default_trusted_ca_dirs(),
        }
    }
}

/// namespaces 詳細監視モジュール設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct NamespaceMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "NamespaceMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象の名前空間リスト
    #[serde(default = "NamespaceMonitorConfig::default_watch_namespaces")]
    pub watch_namespaces: Vec<String>,

    /// 除外プロセス名リスト
    #[serde(default = "NamespaceMonitorConfig::default_exclude_processes")]
    pub exclude_processes: Vec<String>,

    /// init namespace と異なる namespace を持つ新規プロセスをアラートするか
    #[serde(default = "NamespaceMonitorConfig::default_alert_on_new_ns")]
    pub alert_on_new_ns: bool,
}

impl NamespaceMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        30
    }

    fn default_watch_namespaces() -> Vec<String> {
        vec![
            "pid".to_string(),
            "net".to_string(),
            "mnt".to_string(),
            "uts".to_string(),
            "ipc".to_string(),
            "user".to_string(),
        ]
    }

    fn default_exclude_processes() -> Vec<String> {
        vec![
            "containerd".to_string(),
            "dockerd".to_string(),
            "podman".to_string(),
            "lxc-start".to_string(),
        ]
    }

    fn default_alert_on_new_ns() -> bool {
        true
    }
}

impl Default for NamespaceMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_namespaces: Self::default_watch_namespaces(),
            exclude_processes: Self::default_exclude_processes(),
            alert_on_new_ns: Self::default_alert_on_new_ns(),
        }
    }
}

/// プロセス環境変数スナップショット監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct ProcEnvironMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "ProcEnvironMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 存在自体が危険な環境変数名リスト
    #[serde(default = "ProcEnvironMonitorConfig::default_suspicious_vars")]
    pub suspicious_vars: Vec<String>,

    /// PATH 内の不審ディレクトリリスト
    #[serde(default = "ProcEnvironMonitorConfig::default_suspicious_path_dirs")]
    pub suspicious_path_dirs: Vec<String>,

    /// リバースシェルパターンを検査するコマンド変数リスト
    #[serde(default = "ProcEnvironMonitorConfig::default_suspicious_commands")]
    pub suspicious_commands: Vec<String>,

    /// 不審パスを検査するライブラリパス変数リスト
    #[serde(default = "ProcEnvironMonitorConfig::default_library_path_vars")]
    pub library_path_vars: Vec<String>,

    /// 監視対象のプロキシ変数リスト
    #[serde(default = "ProcEnvironMonitorConfig::default_proxy_vars")]
    pub proxy_vars: Vec<String>,

    /// ホワイトリスト（正規表現パターン、"PID:変数名=値" に対してマッチ）
    #[serde(default)]
    pub whitelist_patterns: Vec<String>,

    /// カーネルスレッドをスキップするか
    #[serde(default = "ProcEnvironMonitorConfig::default_skip_kernel_threads")]
    pub skip_kernel_threads: bool,
}

impl ProcEnvironMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        60
    }

    fn default_suspicious_vars() -> Vec<String> {
        vec![
            "LD_PRELOAD".to_string(),
            "LD_LIBRARY_PATH".to_string(),
            "LD_AUDIT".to_string(),
            "LD_DEBUG".to_string(),
            "LD_PROFILE".to_string(),
        ]
    }

    fn default_suspicious_path_dirs() -> Vec<String> {
        vec![
            "/tmp".to_string(),
            "/dev/shm".to_string(),
            "/var/tmp".to_string(),
            "/run/shm".to_string(),
        ]
    }

    fn default_suspicious_commands() -> Vec<String> {
        vec!["PROMPT_COMMAND".to_string()]
    }

    fn default_library_path_vars() -> Vec<String> {
        vec![
            "PYTHONPATH".to_string(),
            "RUBYLIB".to_string(),
            "PERL5LIB".to_string(),
            "NODE_PATH".to_string(),
            "CLASSPATH".to_string(),
        ]
    }

    fn default_proxy_vars() -> Vec<String> {
        vec![
            "http_proxy".to_string(),
            "https_proxy".to_string(),
            "HTTP_PROXY".to_string(),
            "HTTPS_PROXY".to_string(),
        ]
    }

    fn default_skip_kernel_threads() -> bool {
        true
    }
}

impl Default for ProcEnvironMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            suspicious_vars: Self::default_suspicious_vars(),
            suspicious_path_dirs: Self::default_suspicious_path_dirs(),
            suspicious_commands: Self::default_suspicious_commands(),
            library_path_vars: Self::default_library_path_vars(),
            proxy_vars: Self::default_proxy_vars(),
            whitelist_patterns: Vec::new(),
            skip_kernel_threads: Self::default_skip_kernel_threads(),
        }
    }
}

/// グループポリシー監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct GroupMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "GroupMonitorConfig::default_interval_secs")]
    pub interval_secs: u64,

    /// /etc/group ファイルのパス
    #[serde(default = "GroupMonitorConfig::default_group_path")]
    pub group_path: PathBuf,

    /// /etc/gshadow ファイルのパス
    #[serde(default = "GroupMonitorConfig::default_gshadow_path")]
    pub gshadow_path: PathBuf,

    /// 特権グループ名リスト（これらへのメンバー追加は Critical severity）
    #[serde(default = "GroupMonitorConfig::default_privileged_groups")]
    pub privileged_groups: Vec<String>,
}

impl GroupMonitorConfig {
    fn default_interval_secs() -> u64 {
        60
    }

    fn default_group_path() -> PathBuf {
        PathBuf::from("/etc/group")
    }

    fn default_gshadow_path() -> PathBuf {
        PathBuf::from("/etc/gshadow")
    }

    fn default_privileged_groups() -> Vec<String> {
        vec![
            "sudo".to_string(),
            "wheel".to_string(),
            "docker".to_string(),
            "adm".to_string(),
            "root".to_string(),
            "shadow".to_string(),
            "disk".to_string(),
        ]
    }
}

impl Default for GroupMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: Self::default_interval_secs(),
            group_path: Self::default_group_path(),
            gshadow_path: Self::default_gshadow_path(),
            privileged_groups: Self::default_privileged_groups(),
        }
    }
}

/// プロセス起動コマンドライン監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct ProcessCmdlineMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "ProcessCmdlineMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// ユーザー定義の追加検知パターン（正規表現）
    #[serde(default)]
    pub extra_patterns: Vec<String>,

    /// 除外パターン（正規表現、マッチしたコマンドラインを検知対象から除外）
    #[serde(default)]
    pub exclude_patterns: Vec<String>,
}

impl ProcessCmdlineMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        30
    }
}

impl Default for ProcessCmdlineMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            extra_patterns: Vec::new(),
            exclude_patterns: Vec::new(),
        }
    }
}

/// ブートローダー整合性監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct BootloaderMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "BootloaderMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象の GRUB 設定ファイルパス
    #[serde(default = "BootloaderMonitorConfig::default_grub_paths")]
    pub grub_paths: Vec<PathBuf>,

    /// EFI パーティション上の GRUB 設定を探索するディレクトリ
    #[serde(default = "BootloaderMonitorConfig::default_efi_grub_dirs")]
    pub efi_grub_dirs: Vec<PathBuf>,

    /// カーネルコマンドライン変更のアラート有効/無効
    #[serde(default = "BootloaderMonitorConfig::default_alert_on_cmdline_changes")]
    pub alert_on_cmdline_changes: bool,
}

impl BootloaderMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        300
    }

    fn default_grub_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/boot/grub/grub.cfg"),
            PathBuf::from("/boot/grub2/grub.cfg"),
            PathBuf::from("/etc/default/grub"),
            PathBuf::from("/boot/grub/custom.cfg"),
        ]
    }

    fn default_efi_grub_dirs() -> Vec<PathBuf> {
        vec![PathBuf::from("/boot/efi/EFI")]
    }

    fn default_alert_on_cmdline_changes() -> bool {
        true
    }
}

impl Default for BootloaderMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            grub_paths: Self::default_grub_paths(),
            efi_grub_dirs: Self::default_efi_grub_dirs(),
            alert_on_cmdline_changes: Self::default_alert_on_cmdline_changes(),
        }
    }
}

/// initramfs 整合性監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct InitramfsMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "InitramfsMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象のファイルパスパターン（glob）
    #[serde(default = "InitramfsMonitorConfig::default_paths")]
    pub paths: Vec<String>,
}

impl InitramfsMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        300
    }

    fn default_paths() -> Vec<String> {
        vec![
            "/boot/initrd.img-*".to_string(),
            "/boot/initramfs-*".to_string(),
        ]
    }
}

impl Default for InitramfsMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            paths: Self::default_paths(),
        }
    }
}

/// カーネルコマンドライン実行時監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct KernelCmdlineMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "KernelCmdlineMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// kexec_loaded のチェックを行うか
    #[serde(default = "KernelCmdlineMonitorConfig::default_check_kexec_loaded")]
    pub check_kexec_loaded: bool,

    /// 不審パラメータのリスト
    #[serde(default = "KernelCmdlineMonitorConfig::default_suspicious_params")]
    pub suspicious_params: Vec<String>,

    /// /proc/cmdline のパス（テスト用にカスタマイズ可能）
    #[serde(default = "KernelCmdlineMonitorConfig::default_proc_cmdline_path")]
    pub proc_cmdline_path: String,

    /// /sys/kernel/kexec_loaded のパス（テスト用にカスタマイズ可能）
    #[serde(default = "KernelCmdlineMonitorConfig::default_kexec_loaded_path")]
    pub kexec_loaded_path: String,
}

impl KernelCmdlineMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        30
    }

    fn default_check_kexec_loaded() -> bool {
        true
    }

    fn default_suspicious_params() -> Vec<String> {
        vec![
            "selinux=0".to_string(),
            "apparmor=0".to_string(),
            "security=none".to_string(),
            "ima_appraise=off".to_string(),
            "module.sig_enforce=0".to_string(),
            "init=/bin/sh".to_string(),
            "init=/bin/bash".to_string(),
            "single".to_string(),
            "debug".to_string(),
            "earlyprintk".to_string(),
        ]
    }

    fn default_proc_cmdline_path() -> String {
        "/proc/cmdline".to_string()
    }

    fn default_kexec_loaded_path() -> String {
        "/sys/kernel/kexec_loaded".to_string()
    }
}

impl Default for KernelCmdlineMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            check_kexec_loaded: Self::default_check_kexec_loaded(),
            suspicious_params: Self::default_suspicious_params(),
            proc_cmdline_path: Self::default_proc_cmdline_path(),
            kexec_loaded_path: Self::default_kexec_loaded_path(),
        }
    }
}

/// ファイルレス実行検知モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct FilelessExecMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "FilelessExecMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 検知除外パス（exe パスの前方一致）
    #[serde(default)]
    pub exclude_paths: Vec<String>,

    /// 検知除外 UID
    #[serde(default)]
    pub exclude_uids: Vec<u32>,
}

impl FilelessExecMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        30
    }
}

impl Default for FilelessExecMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            exclude_paths: Vec::new(),
            exclude_uids: Vec::new(),
        }
    }
}

/// プロセス隠蔽検知モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct HiddenProcessMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "HiddenProcessMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// スキャン対象の最大 PID（None の場合は /proc/sys/kernel/pid_max から取得）
    #[serde(default)]
    pub scan_max_pid: Option<u32>,

    /// スキャン対象外の PID リスト
    #[serde(default)]
    pub skip_pids: Vec<u32>,

    /// バッチサイズ（CPU 負荷軽減のためバッチ処理）
    #[serde(default = "HiddenProcessMonitorConfig::default_scan_batch_size")]
    pub scan_batch_size: u32,

    /// 再確認回数（false positive 対策）
    #[serde(default = "HiddenProcessMonitorConfig::default_recheck_count")]
    pub recheck_count: u32,
}

impl HiddenProcessMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        300
    }

    fn default_scan_batch_size() -> u32 {
        1000
    }

    fn default_recheck_count() -> u32 {
        3
    }
}

impl Default for HiddenProcessMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            scan_max_pid: None,
            skip_pids: Vec::new(),
            scan_batch_size: Self::default_scan_batch_size(),
            recheck_count: Self::default_recheck_count(),
        }
    }
}

/// ハニーポットファイル（カナリアトークン）監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct HoneypotMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// 監視対象のデコイファイル・ディレクトリのリスト
    #[serde(default)]
    pub watch_paths: Vec<PathBuf>,

    /// 再帰的監視の有効/無効（ディレクトリ配下も監視するか）
    #[serde(default)]
    pub recursive: bool,

    /// デバウンス時間（ミリ秒）
    #[serde(default = "HoneypotMonitorConfig::default_debounce_ms")]
    pub debounce_ms: u64,

    /// ヘルスチェック間隔（秒）
    #[serde(default = "HoneypotMonitorConfig::default_health_check_interval_secs")]
    pub health_check_interval_secs: u64,
}

impl HoneypotMonitorConfig {
    fn default_debounce_ms() -> u64 {
        500
    }

    fn default_health_check_interval_secs() -> u64 {
        300
    }
}

impl Default for HoneypotMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            watch_paths: Vec::new(),
            recursive: false,
            debounce_ms: Self::default_debounce_ms(),
            health_check_interval_secs: Self::default_health_check_interval_secs(),
        }
    }
}

/// ジャーナルパターン定義
///
/// マッチングに使用する正規表現パターンと重要度を定義する。
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct JournalPattern {
    /// パターン名
    pub name: String,
    /// 正規表現パターン
    pub pattern: String,
    /// 重要度（info / warning / critical）
    #[serde(default = "JournalPattern::default_severity")]
    pub severity: String,
    /// ユニットフィルター（指定時はそのユニットのエントリのみ対象）
    #[serde(default)]
    pub unit_filter: Option<String>,
}

impl JournalPattern {
    fn default_severity() -> String {
        "warning".to_string()
    }
}

/// systemd ジャーナルパターン監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct JournalPatternMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "JournalPatternMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 1回のスキャンで処理する最大エントリ数
    #[serde(default = "JournalPatternMonitorConfig::default_max_entries_per_scan")]
    pub max_entries_per_scan: usize,

    /// journalctl コマンドのパス
    #[serde(default = "JournalPatternMonitorConfig::default_journalctl_path")]
    pub journalctl_path: String,

    /// プリセットパターンを使用するかどうか
    #[serde(default = "JournalPatternMonitorConfig::default_use_preset_patterns")]
    pub use_preset_patterns: bool,

    /// カスタムパターン
    #[serde(default)]
    pub custom_patterns: Vec<JournalPattern>,
}

impl JournalPatternMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        30
    }

    fn default_max_entries_per_scan() -> usize {
        1000
    }

    fn default_journalctl_path() -> String {
        "/usr/bin/journalctl".to_string()
    }

    fn default_use_preset_patterns() -> bool {
        true
    }
}

impl Default for JournalPatternMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            max_entries_per_scan: Self::default_max_entries_per_scan(),
            journalctl_path: Self::default_journalctl_path(),
            use_preset_patterns: Self::default_use_preset_patterns(),
            custom_patterns: Vec::new(),
        }
    }
}

/// キーロガー検知モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct KeyloggerDetectorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "KeyloggerDetectorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 許可プロセスリスト（ホワイトリスト）
    #[serde(default = "KeyloggerDetectorConfig::default_allowed_processes")]
    pub allowed_processes: Vec<String>,
}

impl KeyloggerDetectorConfig {
    fn default_scan_interval_secs() -> u64 {
        30
    }

    fn default_allowed_processes() -> Vec<String> {
        vec![
            "Xorg".to_string(),
            "gnome-shell".to_string(),
            "kwin_wayland".to_string(),
            "sway".to_string(),
            "systemd-logind".to_string(),
            "libinput".to_string(),
            "mutter".to_string(),
            "weston".to_string(),
            "Hyprland".to_string(),
        ]
    }
}

impl Default for KeyloggerDetectorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            allowed_processes: Self::default_allowed_processes(),
        }
    }
}

/// SSH 設定セキュリティ監査モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct SshdConfigMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "SshdConfigMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象の sshd_config ファイルパス
    #[serde(default = "SshdConfigMonitorConfig::default_config_paths")]
    pub config_paths: Vec<String>,

    /// PermitRootLogin チェックの有効/無効
    #[serde(default = "SshdConfigMonitorConfig::default_true")]
    pub check_permit_root_login: bool,

    /// PasswordAuthentication チェックの有効/無効
    #[serde(default = "SshdConfigMonitorConfig::default_true")]
    pub check_password_authentication: bool,

    /// PermitEmptyPasswords チェックの有効/無効
    #[serde(default = "SshdConfigMonitorConfig::default_true")]
    pub check_permit_empty_passwords: bool,

    /// Protocol バージョンチェックの有効/無効
    #[serde(default = "SshdConfigMonitorConfig::default_true")]
    pub check_protocol_version: bool,

    /// X11Forwarding チェックの有効/無効
    #[serde(default = "SshdConfigMonitorConfig::default_true")]
    pub check_x11_forwarding: bool,

    /// StrictModes チェックの有効/無効
    #[serde(default = "SshdConfigMonitorConfig::default_true")]
    pub check_strict_modes: bool,

    /// MaxAuthTries チェックの有効/無効
    #[serde(default = "SshdConfigMonitorConfig::default_true")]
    pub check_max_auth_tries: bool,

    /// MaxAuthTries の閾値
    #[serde(default = "SshdConfigMonitorConfig::default_max_auth_tries_threshold")]
    pub max_auth_tries_threshold: u32,

    /// GatewayPorts チェックの有効/無効
    #[serde(default = "SshdConfigMonitorConfig::default_true")]
    pub check_gateway_ports: bool,

    /// PermitTunnel チェックの有効/無効
    #[serde(default = "SshdConfigMonitorConfig::default_true")]
    pub check_permit_tunnel: bool,

    /// Include ディレクティブの再帰的展開
    #[serde(default = "SshdConfigMonitorConfig::default_true")]
    pub follow_includes: bool,

    /// ファイルサイズ上限（バイト）
    #[serde(default = "SshdConfigMonitorConfig::default_max_file_size_bytes")]
    pub max_file_size_bytes: u64,
}

impl SshdConfigMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        300
    }

    fn default_config_paths() -> Vec<String> {
        vec!["/etc/ssh/sshd_config".to_string()]
    }

    fn default_true() -> bool {
        true
    }

    fn default_max_auth_tries_threshold() -> u32 {
        6
    }

    fn default_max_file_size_bytes() -> u64 {
        1_048_576
    }
}

impl Default for SshdConfigMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            config_paths: Self::default_config_paths(),
            check_permit_root_login: true,
            check_password_authentication: true,
            check_permit_empty_passwords: true,
            check_protocol_version: true,
            check_x11_forwarding: true,
            check_strict_modes: true,
            check_max_auth_tries: true,
            max_auth_tries_threshold: Self::default_max_auth_tries_threshold(),
            check_gateway_ports: true,
            check_permit_tunnel: true,
            follow_includes: true,
            max_file_size_bytes: Self::default_max_file_size_bytes(),
        }
    }
}

/// NTP / 時刻同期設定監視モジュールの設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct NtpConfigMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "NtpConfigMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象の NTP / 時刻同期設定ファイルパス
    #[serde(default = "NtpConfigMonitorConfig::default_config_paths")]
    pub config_paths: Vec<String>,

    /// 危険な設定（NTP サーバ未設定、makestep 未設定など）の監査を有効化
    #[serde(default = "NtpConfigMonitorConfig::default_true")]
    pub audit_enabled: bool,

    /// chrony の `allow` ディレクティブによるネットワーク公開を検知
    #[serde(default = "NtpConfigMonitorConfig::default_true")]
    pub check_chrony_allow: bool,

    /// chrony の `bindcmdaddress` が公開アドレス（0.0.0.0 / :: / *）を検知
    #[serde(default = "NtpConfigMonitorConfig::default_true")]
    pub check_chrony_bindcmdaddress: bool,

    /// ntp.conf の `restrict default` 欠如を検知
    #[serde(default = "NtpConfigMonitorConfig::default_true")]
    pub check_ntp_restrict: bool,

    /// `driftfile` が絶対パスでない場合を検知
    #[serde(default = "NtpConfigMonitorConfig::default_true")]
    pub check_driftfile_absolute: bool,

    /// chrony の `cmdport` / `port` が既定値（cmdport=323 / port=123）から
    /// 変更されている場合を検知
    #[serde(default = "NtpConfigMonitorConfig::default_true")]
    pub check_chrony_cmdport_port: bool,

    /// chrony の `ntpsigndsocket` が world-writable な一時領域
    /// （/tmp/ / /var/tmp/ / /dev/shm/）を指す場合を検知
    #[serde(default = "NtpConfigMonitorConfig::default_true")]
    pub check_ntpsigndsocket: bool,

    /// chrony.conf / ntp.conf の `keys` ディレクティブが指定されているが
    /// ファイルが存在しない場合（NTP 認証が事実上無効化されている可能性）を検知
    #[serde(default = "NtpConfigMonitorConfig::default_true")]
    pub check_keys_file_presence: bool,

    /// `keys` で指定された鍵ファイルが world-readable / world-writable な
    /// 過剰パーミッションを持つ場合を検知（共有鍵漏洩リスク）
    #[serde(default = "NtpConfigMonitorConfig::default_true")]
    pub check_keys_file_permissions: bool,

    /// chrony で `keys` を設定しているのに `trustedkey` が未設定の場合を検知
    /// （NTP 認証が形骸化している状態）
    #[serde(default = "NtpConfigMonitorConfig::default_true")]
    pub check_chrony_trustedkey: bool,

    /// chrony で `keys` を設定しているのに `authselectmode require` が
    /// 指定されていない場合を検知（認証失敗時に非認証同期へフォールバック可能）
    #[serde(default = "NtpConfigMonitorConfig::default_true")]
    pub check_chrony_authselectmode: bool,

    /// NTP 設定ファイル自体の所有者 uid / gid が許容リストに含まれない場合を検知
    /// （root 以外が所有する設定ファイルは権限昇格の足場として悪用されうる）
    #[serde(default = "NtpConfigMonitorConfig::default_true")]
    pub check_config_owner: bool,

    /// `keys` で指定された鍵ファイルの所有者 uid / gid が許容リストに含まれない
    /// 場合を検知（共有鍵の所有者改ざんは認証設定の書き換えを容易にする）
    #[serde(default = "NtpConfigMonitorConfig::default_true")]
    pub check_keys_file_owner: bool,

    /// chrony の `leapsectz` 未設定を検知（閏秒情報ソースが指定されていない場合 Info）
    #[serde(default = "NtpConfigMonitorConfig::default_true")]
    pub check_chrony_leapsectz: bool,

    /// chrony の `maxsamples` / `minsamples` サンプル数設定の整合性を検知
    /// - `0 < maxsamples < maxsamples_min_threshold` の過少設定を Warning
    /// - `minsamples > maxsamples`（両方設定かつ maxsamples != 0）の設定矛盾を Warning
    #[serde(default = "NtpConfigMonitorConfig::default_true")]
    pub check_chrony_sample_counts: bool,

    /// `maxsamples_too_low` 判定の下限閾値（既定: 4）
    /// chrony の NTP フィルタアルゴリズムは通常 4 以上のサンプルで安定動作する
    #[serde(default = "NtpConfigMonitorConfig::default_maxsamples_min_threshold")]
    pub maxsamples_min_threshold: u32,

    /// 所有者監査で許容する uid 一覧（デフォルトは `[0]` = root のみ）
    /// Debian の chrony パッケージのように `_chrony` 所有が正常なディストリでは
    /// 該当 uid を追加する
    #[serde(default = "NtpConfigMonitorConfig::default_allowed_uids")]
    pub allowed_owner_uids: Vec<u32>,

    /// 所有者監査で許容する gid 一覧（デフォルトは `[0]` = root のみ）
    #[serde(default = "NtpConfigMonitorConfig::default_allowed_gids")]
    pub allowed_owner_gids: Vec<u32>,

    /// ファイルサイズ上限（バイト）
    #[serde(default = "NtpConfigMonitorConfig::default_max_file_size_bytes")]
    pub max_file_size_bytes: u64,
}

impl NtpConfigMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        300
    }

    fn default_config_paths() -> Vec<String> {
        vec![
            "/etc/systemd/timesyncd.conf".to_string(),
            "/etc/ntp.conf".to_string(),
            "/etc/chrony/chrony.conf".to_string(),
            "/etc/chrony.conf".to_string(),
        ]
    }

    fn default_true() -> bool {
        true
    }

    fn default_allowed_uids() -> Vec<u32> {
        vec![0]
    }

    fn default_allowed_gids() -> Vec<u32> {
        vec![0]
    }

    fn default_max_file_size_bytes() -> u64 {
        1_048_576
    }

    fn default_maxsamples_min_threshold() -> u32 {
        4
    }
}

impl Default for NtpConfigMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            config_paths: Self::default_config_paths(),
            audit_enabled: true,
            check_chrony_allow: true,
            check_chrony_bindcmdaddress: true,
            check_ntp_restrict: true,
            check_driftfile_absolute: true,
            check_chrony_cmdport_port: true,
            check_ntpsigndsocket: true,
            check_keys_file_presence: true,
            check_keys_file_permissions: true,
            check_chrony_trustedkey: true,
            check_chrony_authselectmode: true,
            check_config_owner: true,
            check_keys_file_owner: true,
            check_chrony_leapsectz: true,
            check_chrony_sample_counts: true,
            maxsamples_min_threshold: Self::default_maxsamples_min_threshold(),
            allowed_owner_uids: Self::default_allowed_uids(),
            allowed_owner_gids: Self::default_allowed_gids(),
            max_file_size_bytes: Self::default_max_file_size_bytes(),
        }
    }
}

/// パッケージ整合性検証モジュールの設定
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct PackageVerifyConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// 検証間隔（秒）
    #[serde(default = "PackageVerifyConfig::default_interval_secs")]
    pub interval_secs: u64,

    /// 除外パッケージ名リスト
    #[serde(default)]
    pub exclude_packages: Vec<String>,

    /// 除外パスパターンリスト（前方一致）
    #[serde(default)]
    pub exclude_paths: Vec<String>,
}

impl PackageVerifyConfig {
    fn default_interval_secs() -> u64 {
        3600
    }
}

impl Default for PackageVerifyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: Self::default_interval_secs(),
            exclude_packages: Vec::new(),
            exclude_paths: Vec::new(),
        }
    }
}

/// 動的ライブラリインジェクション検知モジュールの設定
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct DynamicLibraryMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "DynamicLibraryMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 不審なパスのリスト
    #[serde(default = "DynamicLibraryMonitorConfig::default_suspicious_paths")]
    pub suspicious_paths: Vec<String>,

    /// 除外する PID のリスト
    #[serde(default)]
    pub ignore_pids: Vec<u32>,

    /// 除外するライブラリパターン（正規表現）
    #[serde(default)]
    pub ignore_libraries: Vec<String>,

    /// 全プロセスを監視するか（false の場合は root プロセスのみ）
    #[serde(default)]
    pub monitor_all_processes: bool,
}

impl DynamicLibraryMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        60
    }

    fn default_suspicious_paths() -> Vec<String> {
        vec![
            "/tmp".to_string(),
            "/dev/shm".to_string(),
            "/var/tmp".to_string(),
        ]
    }
}

impl Default for DynamicLibraryMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            suspicious_paths: Self::default_suspicious_paths(),
            ignore_pids: Vec::new(),
            ignore_libraries: Vec::new(),
            monitor_all_processes: false,
        }
    }
}

/// Prometheus mTLS 設定
#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct PrometheusMtlsConfig {
    /// mTLS の有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// クライアント CA 証明書ファイルのパス（PEM 形式）
    #[serde(default)]
    pub client_ca_file: String,

    /// クライアント認証モード（"required" または "optional"）
    #[serde(default = "PrometheusMtlsConfig::default_client_auth_mode")]
    pub client_auth_mode: String,
}

impl PrometheusMtlsConfig {
    fn default_client_auth_mode() -> String {
        "required".to_string()
    }
}

impl Default for PrometheusMtlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            client_ca_file: String::new(),
            client_auth_mode: Self::default_client_auth_mode(),
        }
    }
}

/// Prometheus TLS 設定
#[derive(Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct PrometheusTlsConfig {
    /// TLS の有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// 証明書ファイルのパス（PEM 形式）
    #[serde(default)]
    pub cert_file: String,

    /// 秘密鍵ファイルのパス（PEM 形式）
    #[serde(default)]
    pub key_file: String,

    /// mTLS（クライアント証明書認証）設定
    #[serde(default)]
    pub mtls: PrometheusMtlsConfig,
}

/// Prometheus メトリクスエクスポーター設定
#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct PrometheusConfig {
    /// Prometheus エクスポーターの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// バインドアドレス
    #[serde(default = "PrometheusConfig::default_bind_address")]
    pub bind_address: String,

    /// リスニングポート
    #[serde(default = "PrometheusConfig::default_port")]
    pub port: u16,

    /// TLS 設定
    #[serde(default)]
    pub tls: PrometheusTlsConfig,
}

impl PrometheusConfig {
    fn default_bind_address() -> String {
        "127.0.0.1".to_string()
    }

    fn default_port() -> u16 {
        9100
    }
}

impl Default for PrometheusConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: Self::default_bind_address(),
            port: Self::default_port(),
            tls: PrometheusTlsConfig::default(),
        }
    }
}

/// API トークンのロール
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ApiRole {
    /// 参照系エンドポイントのみアクセス可能
    ReadOnly,
    /// 全エンドポイントにアクセス可能
    Admin,
}

impl ApiRole {
    /// このロールが要求されたロール以上の権限を持つか判定する
    pub fn has_permission(&self, required: &ApiRole) -> bool {
        match (self, required) {
            (ApiRole::Admin, _) => true,
            (ApiRole::ReadOnly, ApiRole::ReadOnly) => true,
            (ApiRole::ReadOnly, ApiRole::Admin) => false,
        }
    }
}

/// API トークン設定
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ApiTokenConfig {
    /// トークン名（識別用）
    pub name: String,
    /// SHA-256 ハッシュ（`sha256:` プレフィックス付き hex 文字列）
    pub token_hash: String,
    /// ロール
    pub role: ApiRole,
}

/// API レートリミット設定
#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct ApiRateLimitConfig {
    /// レートリミットの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// 1秒あたりの最大リクエスト数
    #[serde(default = "ApiRateLimitConfig::default_max_requests_per_second")]
    pub max_requests_per_second: f64,

    /// バースト許容数
    #[serde(default = "ApiRateLimitConfig::default_burst_size")]
    pub burst_size: u32,

    /// クリーンアップ間隔（秒）
    #[serde(default = "ApiRateLimitConfig::default_cleanup_interval_secs")]
    pub cleanup_interval_secs: u64,
}

impl ApiRateLimitConfig {
    fn default_max_requests_per_second() -> f64 {
        10.0
    }

    fn default_burst_size() -> u32 {
        20
    }

    fn default_cleanup_interval_secs() -> u64 {
        60
    }
}

impl Default for ApiRateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_requests_per_second: Self::default_max_requests_per_second(),
            burst_size: Self::default_burst_size(),
            cleanup_interval_secs: Self::default_cleanup_interval_secs(),
        }
    }
}

/// WebSocket イベントストリーミング設定
#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct WebSocketConfig {
    /// WebSocket の有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// 最大同時接続数
    #[serde(default = "WebSocketConfig::default_max_connections")]
    pub max_connections: usize,

    /// Ping 送信間隔（秒）
    #[serde(default = "WebSocketConfig::default_ping_interval_secs")]
    pub ping_interval_secs: u64,

    /// アイドルタイムアウト（秒）
    #[serde(default = "WebSocketConfig::default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,

    /// イベントバッファサイズ
    #[serde(default = "WebSocketConfig::default_buffer_size")]
    pub buffer_size: usize,
}

impl WebSocketConfig {
    fn default_max_connections() -> usize {
        10
    }

    fn default_ping_interval_secs() -> u64 {
        30
    }

    fn default_idle_timeout_secs() -> u64 {
        300
    }

    fn default_buffer_size() -> usize {
        128
    }
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_connections: Self::default_max_connections(),
            ping_interval_secs: Self::default_ping_interval_secs(),
            idle_timeout_secs: Self::default_idle_timeout_secs(),
            buffer_size: Self::default_buffer_size(),
        }
    }
}

/// REST API mTLS（クライアント証明書認証）設定
///
/// REST API の TLS 設定にネストする形で mTLS を構成する。
/// Syslog モジュールではフラット構造（`client_ca_file` 等が直接 TLS 設定に並ぶ）だが、
/// REST API では TLS 自体がオプショナルなサブテーブルであるため、
/// mTLS をさらにネストすることで設定の階層構造を明確にしている。
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ApiMtlsConfig {
    /// mTLS の有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// クライアント CA 証明書ファイルのパス（PEM 形式）
    #[serde(default)]
    pub client_ca_file: String,

    /// クライアント認証モード（"required" または "optional"）
    #[serde(default = "ApiMtlsConfig::default_client_auth_mode")]
    pub client_auth_mode: String,
}

impl ApiMtlsConfig {
    fn default_client_auth_mode() -> String {
        "required".to_string()
    }
}

impl Default for ApiMtlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            client_ca_file: String::new(),
            client_auth_mode: Self::default_client_auth_mode(),
        }
    }
}

/// REST API TLS 設定
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
pub struct ApiTlsConfig {
    /// TLS の有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// 証明書ファイルのパス（PEM 形式）
    #[serde(default)]
    pub cert_file: String,

    /// 秘密鍵ファイルのパス（PEM 形式）
    #[serde(default)]
    pub key_file: String,

    /// mTLS（クライアント証明書認証）設定
    #[serde(default)]
    pub mtls: ApiMtlsConfig,
}

/// REST API サーバー設定
#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct ApiConfig {
    /// REST API サーバーの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// バインドアドレス
    #[serde(default = "ApiConfig::default_bind_address")]
    pub bind_address: String,

    /// リスニングポート
    #[serde(default = "ApiConfig::default_port")]
    pub port: u16,

    /// API トークン設定（空の場合は認証なしで動作）
    #[serde(default)]
    pub tokens: Vec<ApiTokenConfig>,

    /// レートリミット設定
    #[serde(default)]
    pub rate_limit: ApiRateLimitConfig,

    /// WebSocket イベントストリーミング設定
    #[serde(default)]
    pub websocket: WebSocketConfig,

    /// CORS 設定
    #[serde(default)]
    pub cors: CorsConfig,

    /// OpenAPI スキーマエンドポイントの有効/無効
    #[serde(default = "ApiConfig::default_openapi_enabled")]
    pub openapi_enabled: bool,

    /// デフォルトページサイズ
    #[serde(default = "ApiConfig::default_page_size")]
    pub default_page_size: u32,

    /// 最大ページサイズ
    #[serde(default = "ApiConfig::default_max_page_size")]
    pub max_page_size: u32,

    /// バッチ操作の最大件数
    #[serde(default = "ApiConfig::default_batch_max_size")]
    pub batch_max_size: u32,

    /// リクエストボディの最大サイズ（バイト）
    #[serde(default = "ApiConfig::default_max_request_body_size")]
    pub max_request_body_size: usize,

    /// アクセスログの有効/無効
    #[serde(default = "ApiConfig::default_access_log")]
    pub access_log: bool,

    /// TLS 設定
    #[serde(default)]
    pub tls: ApiTlsConfig,
}

impl ApiConfig {
    fn default_bind_address() -> String {
        "127.0.0.1".to_string()
    }

    fn default_port() -> u16 {
        9201
    }

    fn default_openapi_enabled() -> bool {
        true
    }

    fn default_page_size() -> u32 {
        50
    }

    fn default_max_page_size() -> u32 {
        200
    }

    fn default_batch_max_size() -> u32 {
        1000
    }

    fn default_max_request_body_size() -> usize {
        1_048_576
    }

    fn default_access_log() -> bool {
        true
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: Self::default_bind_address(),
            port: Self::default_port(),
            tokens: Vec::new(),
            rate_limit: ApiRateLimitConfig::default(),
            websocket: WebSocketConfig::default(),
            cors: CorsConfig::default(),
            openapi_enabled: Self::default_openapi_enabled(),
            default_page_size: Self::default_page_size(),
            max_page_size: Self::default_max_page_size(),
            batch_max_size: Self::default_batch_max_size(),
            max_request_body_size: Self::default_max_request_body_size(),
            access_log: Self::default_access_log(),
            tls: ApiTlsConfig::default(),
        }
    }
}

impl Clone for ApiConfig {
    fn clone(&self) -> Self {
        Self {
            enabled: self.enabled,
            bind_address: self.bind_address.clone(),
            port: self.port,
            tokens: self.tokens.clone(),
            rate_limit: self.rate_limit.clone(),
            websocket: self.websocket.clone(),
            cors: self.cors.clone(),
            openapi_enabled: self.openapi_enabled,
            default_page_size: self.default_page_size,
            max_page_size: self.max_page_size,
            batch_max_size: self.batch_max_size,
            max_request_body_size: self.max_request_body_size,
            access_log: self.access_log,
            tls: self.tls.clone(),
        }
    }
}

/// セキュリティスコアリング設定
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct ScoringConfig {
    /// スコアリングの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スコア更新インターバル（秒）
    #[serde(default = "ScoringConfig::default_interval_secs")]
    pub interval_secs: u64,

    /// カテゴリ別の重み付け（デフォルト: 各1.0）
    #[serde(default)]
    pub category_weights: HashMap<String, f64>,
}

impl ScoringConfig {
    fn default_interval_secs() -> u64 {
        300
    }
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: Self::default_interval_secs(),
            category_weights: HashMap::new(),
        }
    }
}

/// CORS 設定
#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct CorsConfig {
    /// CORS の有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// 許可するオリジン（空の場合は全オリジン "*" を許可）
    #[serde(default)]
    pub allowed_origins: Vec<String>,

    /// 許可する HTTP メソッド
    #[serde(default = "CorsConfig::default_allowed_methods")]
    pub allowed_methods: Vec<String>,

    /// 許可するリクエストヘッダー
    #[serde(default = "CorsConfig::default_allowed_headers")]
    pub allowed_headers: Vec<String>,

    /// クレデンシャル送信の許可
    #[serde(default)]
    pub allow_credentials: bool,

    /// プリフライトキャッシュ秒数
    #[serde(default = "CorsConfig::default_max_age")]
    pub max_age: u64,
}

impl CorsConfig {
    fn default_allowed_methods() -> Vec<String> {
        vec!["GET".to_string(), "POST".to_string(), "OPTIONS".to_string()]
    }

    fn default_allowed_headers() -> Vec<String> {
        vec![
            "Content-Type".to_string(),
            "Authorization".to_string(),
            "X-API-Token".to_string(),
        ]
    }

    fn default_max_age() -> u64 {
        86400
    }
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_origins: Vec::new(),
            allowed_methods: Self::default_allowed_methods(),
            allowed_headers: Self::default_allowed_headers(),
            allow_credentials: false,
            max_age: Self::default_max_age(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_parse_valid_toml() {
        let toml_str = r#"
[general]
log_level = "debug"

[modules]
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.general.log_level, "debug");
    }

    #[test]
    fn test_parse_empty_toml() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert_eq!(config.general.log_level, "info");
    }

    #[test]
    fn test_load_nonexistent_file() {
        let config = AppConfig::load(Path::new("/tmp/nonexistent-zettai-config.toml")).unwrap();
        assert_eq!(config.general.log_level, "info");
    }

    #[test]
    fn test_load_invalid_toml() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "invalid = [[[toml").unwrap();
        let result = AppConfig::load(tmpfile.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_health_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(config.health.enabled);
        assert_eq!(config.health.heartbeat_interval_secs, 60);
    }

    #[test]
    fn test_health_config_custom() {
        let toml_str = r#"
[health]
enabled = false
heartbeat_interval_secs = 30
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.health.enabled);
        assert_eq!(config.health.heartbeat_interval_secs, 30);
    }

    #[test]
    fn test_load_valid_file() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(
            tmpfile,
            r#"
[general]
log_level = "warn"
"#
        )
        .unwrap();
        let config = AppConfig::load(tmpfile.path()).unwrap();
        assert_eq!(config.general.log_level, "warn");
    }

    #[test]
    fn test_cron_monitor_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(!config.modules.cron_monitor.enabled);
        assert_eq!(config.modules.cron_monitor.scan_interval_secs, 120);
        assert_eq!(config.modules.cron_monitor.watch_paths.len(), 7);
        assert!(config.modules.cron_monitor.use_inotify);
        assert_eq!(config.modules.cron_monitor.inotify_debounce_ms, 500);
    }

    #[test]
    fn test_cron_monitor_config_custom() {
        let toml_str = r#"
[modules.cron_monitor]
enabled = true
scan_interval_secs = 60
watch_paths = ["/etc/crontab", "/etc/cron.d"]
use_inotify = false
inotify_debounce_ms = 200
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.modules.cron_monitor.enabled);
        assert_eq!(config.modules.cron_monitor.scan_interval_secs, 60);
        assert_eq!(config.modules.cron_monitor.watch_paths.len(), 2);
        assert!(!config.modules.cron_monitor.use_inotify);
        assert_eq!(config.modules.cron_monitor.inotify_debounce_ms, 200);
    }

    #[test]
    fn test_systemd_service_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(!config.modules.systemd_service.enabled);
        assert_eq!(config.modules.systemd_service.scan_interval_secs, 120);
        assert_eq!(config.modules.systemd_service.watch_paths.len(), 3);
    }

    #[test]
    fn test_systemd_service_config_custom() {
        let toml_str = r#"
[modules.systemd_service]
enabled = true
scan_interval_secs = 60
watch_paths = ["/etc/systemd/system/"]
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.modules.systemd_service.enabled);
        assert_eq!(config.modules.systemd_service.scan_interval_secs, 60);
        assert_eq!(config.modules.systemd_service.watch_paths.len(), 1);
    }

    #[test]
    fn test_dns_monitor_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(!config.modules.dns_monitor.enabled);
        assert_eq!(config.modules.dns_monitor.scan_interval_secs, 30);
        assert_eq!(config.modules.dns_monitor.watch_paths.len(), 2);
    }

    #[test]
    fn test_dns_monitor_config_custom() {
        let toml_str = r#"
[modules.dns_monitor]
enabled = true
scan_interval_secs = 15
watch_paths = ["/etc/resolv.conf"]
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.modules.dns_monitor.enabled);
        assert_eq!(config.modules.dns_monitor.scan_interval_secs, 15);
        assert_eq!(config.modules.dns_monitor.watch_paths.len(), 1);
    }

    #[test]
    fn test_firewall_monitor_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(!config.modules.firewall_monitor.enabled);
        assert_eq!(config.modules.firewall_monitor.scan_interval_secs, 60);
        assert_eq!(config.modules.firewall_monitor.watch_paths.len(), 6);
    }

    #[test]
    fn test_firewall_monitor_config_custom() {
        let toml_str = r#"
[modules.firewall_monitor]
enabled = true
scan_interval_secs = 30
watch_paths = ["/proc/net/ip_tables_names", "/proc/net/ip6_tables_names"]
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.modules.firewall_monitor.enabled);
        assert_eq!(config.modules.firewall_monitor.scan_interval_secs, 30);
        assert_eq!(config.modules.firewall_monitor.watch_paths.len(), 2);
    }

    #[test]
    fn test_ssh_key_monitor_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(!config.modules.ssh_key_monitor.enabled);
        assert_eq!(config.modules.ssh_key_monitor.scan_interval_secs, 120);
        assert_eq!(config.modules.ssh_key_monitor.watch_paths.len(), 1);
        assert_eq!(
            config.modules.ssh_key_monitor.watch_paths[0],
            PathBuf::from("/root/.ssh/authorized_keys")
        );
    }

    #[test]
    fn test_ssh_key_monitor_config_custom() {
        let toml_str = r#"
[modules.ssh_key_monitor]
enabled = true
scan_interval_secs = 60
watch_paths = ["/root/.ssh/authorized_keys", "/home/admin/.ssh/authorized_keys"]
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.modules.ssh_key_monitor.enabled);
        assert_eq!(config.modules.ssh_key_monitor.scan_interval_secs, 60);
        assert_eq!(config.modules.ssh_key_monitor.watch_paths.len(), 2);
    }

    #[test]
    fn test_mount_monitor_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(!config.modules.mount_monitor.enabled);
        assert_eq!(config.modules.mount_monitor.scan_interval_secs, 30);
        assert_eq!(
            config.modules.mount_monitor.mounts_path,
            PathBuf::from("/proc/mounts")
        );
    }

    #[test]
    fn test_mount_monitor_config_custom() {
        let toml_str = r#"
[modules.mount_monitor]
enabled = true
scan_interval_secs = 15
mounts_path = "/proc/self/mounts"
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.modules.mount_monitor.enabled);
        assert_eq!(config.modules.mount_monitor.scan_interval_secs, 15);
        assert_eq!(
            config.modules.mount_monitor.mounts_path,
            PathBuf::from("/proc/self/mounts")
        );
    }

    #[test]
    fn test_tmp_exec_monitor_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(!config.modules.tmp_exec_monitor.enabled);
        assert_eq!(config.modules.tmp_exec_monitor.scan_interval_secs, 60);
        assert_eq!(config.modules.tmp_exec_monitor.watch_dirs.len(), 3);
    }

    #[test]
    fn test_tmp_exec_monitor_config_custom() {
        let toml_str = r#"
[modules.tmp_exec_monitor]
enabled = true
scan_interval_secs = 30
watch_dirs = ["/tmp", "/dev/shm"]
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.modules.tmp_exec_monitor.enabled);
        assert_eq!(config.modules.tmp_exec_monitor.scan_interval_secs, 30);
        assert_eq!(config.modules.tmp_exec_monitor.watch_dirs.len(), 2);
    }

    #[test]
    fn test_shell_config_monitor_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(!config.modules.shell_config_monitor.enabled);
        assert_eq!(config.modules.shell_config_monitor.scan_interval_secs, 120);
        assert_eq!(config.modules.shell_config_monitor.watch_paths.len(), 5);
    }

    #[test]
    fn test_shell_config_monitor_config_custom() {
        let toml_str = r#"
[modules.shell_config_monitor]
enabled = true
scan_interval_secs = 60
watch_paths = ["/etc/profile", "/etc/bash.bashrc"]
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.modules.shell_config_monitor.enabled);
        assert_eq!(config.modules.shell_config_monitor.scan_interval_secs, 60);
        assert_eq!(config.modules.shell_config_monitor.watch_paths.len(), 2);
    }

    #[test]
    fn test_sudoers_monitor_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(!config.modules.sudoers_monitor.enabled);
        assert_eq!(config.modules.sudoers_monitor.scan_interval_secs, 120);
        assert_eq!(config.modules.sudoers_monitor.watch_paths.len(), 2);
    }

    #[test]
    fn test_sudoers_monitor_config_custom() {
        let toml_str = r#"
[modules.sudoers_monitor]
enabled = true
scan_interval_secs = 60
watch_paths = ["/etc/sudoers"]
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.modules.sudoers_monitor.enabled);
        assert_eq!(config.modules.sudoers_monitor.scan_interval_secs, 60);
        assert_eq!(config.modules.sudoers_monitor.watch_paths.len(), 1);
    }

    #[test]
    fn test_suid_sgid_monitor_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(!config.modules.suid_sgid_monitor.enabled);
        assert_eq!(config.modules.suid_sgid_monitor.scan_interval_secs, 300);
        assert_eq!(config.modules.suid_sgid_monitor.watch_dirs.len(), 4);
    }

    #[test]
    fn test_suid_sgid_monitor_config_custom() {
        let toml_str = r#"
[modules.suid_sgid_monitor]
enabled = true
scan_interval_secs = 120
watch_dirs = ["/usr/bin", "/usr/sbin"]
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.modules.suid_sgid_monitor.enabled);
        assert_eq!(config.modules.suid_sgid_monitor.scan_interval_secs, 120);
        assert_eq!(config.modules.suid_sgid_monitor.watch_dirs.len(), 2);
    }

    #[test]
    fn test_action_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(!config.actions.enabled);
        assert!(config.actions.rules.is_empty());
    }

    #[test]
    fn test_action_config_custom() {
        let toml_str = r#"
[actions]
enabled = true

[[actions.rules]]
name = "critical_log"
severity = "Critical"
action = "log"

[[actions.rules]]
name = "alert_command"
severity = "Warning"
module = "file_integrity"
action = "command"
command = "/usr/local/bin/alert.sh '{{message}}'"
timeout_secs = 10
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.actions.enabled);
        assert_eq!(config.actions.rules.len(), 2);
        assert_eq!(config.actions.rules[0].name, "critical_log");
        assert_eq!(
            config.actions.rules[0].severity,
            Some("Critical".to_string())
        );
        assert_eq!(config.actions.rules[0].action, "log");
        assert!(config.actions.rules[0].command.is_none());
        assert_eq!(config.actions.rules[0].timeout_secs, 30); // default
        assert_eq!(config.actions.rules[1].name, "alert_command");
        assert_eq!(config.actions.rules[1].timeout_secs, 10);
        assert!(config.actions.rules[1].command.is_some());
    }

    #[test]
    fn test_event_bus_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(!config.event_bus.enabled);
        assert_eq!(config.event_bus.channel_capacity, 1024);
    }

    #[test]
    fn test_event_bus_config_custom() {
        let toml_str = r#"
[event_bus]
enabled = true
channel_capacity = 512
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.event_bus.enabled);
        assert_eq!(config.event_bus.channel_capacity, 512);
    }

    #[test]
    fn test_metrics_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(!config.metrics.enabled);
        assert_eq!(config.metrics.interval_secs, 60);
    }

    #[test]
    fn test_metrics_config_custom() {
        let toml_str = r#"
[metrics]
enabled = true
interval_secs = 300
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.metrics.enabled);
        assert_eq!(config.metrics.interval_secs, 300);
    }

    #[test]
    fn test_network_monitor_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(!config.modules.network_monitor.enabled);
        assert_eq!(config.modules.network_monitor.interval_secs, 30);
        assert_eq!(
            config.modules.network_monitor.suspicious_ports,
            vec![4444, 5555, 6666, 8888, 1337]
        );
        assert_eq!(config.modules.network_monitor.max_connections, 1000);
    }

    #[test]
    fn test_network_monitor_config_custom() {
        let toml_str = r#"
[modules.network_monitor]
enabled = true
interval_secs = 60
suspicious_ports = [1234, 5678]
max_connections = 500
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.modules.network_monitor.enabled);
        assert_eq!(config.modules.network_monitor.interval_secs, 60);
        assert_eq!(
            config.modules.network_monitor.suspicious_ports,
            vec![1234, 5678]
        );
        assert_eq!(config.modules.network_monitor.max_connections, 500);
    }

    #[test]
    fn test_modules_config_partial_eq_detects_change() {
        let config1 = ModulesConfig::default();
        let config2 = ModulesConfig::default();
        assert_eq!(config1, config2);

        let mut config3 = ModulesConfig::default();
        config3.dns_monitor.scan_interval_secs = 999;
        assert_ne!(config1, config3);
    }

    #[test]
    fn test_modules_config_partial_eq_enabled_flag() {
        let config1 = ModulesConfig::default();
        let mut config2 = ModulesConfig::default();
        config2.file_integrity.enabled = true;
        assert_ne!(config1, config2);
    }

    #[test]
    fn test_app_config_partial_eq() {
        let config1 = AppConfig::default();
        let config2 = AppConfig::default();
        assert_eq!(config1, config2);

        let mut config3 = AppConfig::default();
        config3.general.log_level = "debug".to_string();
        assert_ne!(config1, config3);
    }

    #[test]
    fn test_load_invalid_toml_returns_parse_error() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "this is not valid toml {{{{").unwrap();
        let result = AppConfig::load(tmpfile.path());
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("設定ファイルのパースに失敗"));
    }

    #[test]
    fn test_validate_default_config_is_valid() {
        let config = AppConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_invalid_log_level() {
        let mut config = AppConfig::default();
        config.general.log_level = "verbose".to_string();
        let result = config.validate();
        assert!(result.is_err());
        if let Err(AppError::ConfigValidation { errors, .. }) = result {
            assert_eq!(errors.len(), 1);
            assert!(errors[0].contains("general.log_level"));
            assert!(errors[0].contains("verbose"));
        }
    }

    #[test]
    fn test_validate_journald_field_prefix_default_is_valid() {
        let config = AppConfig::default();
        assert_eq!(config.general.journald_field_prefix, "ZETTAI");
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_journald_field_prefix_custom_valid() {
        let mut config = AppConfig::default();
        config.general.journald_field_prefix = "MY_APP".to_string();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_journald_field_prefix_empty() {
        let mut config = AppConfig::default();
        config.general.journald_field_prefix = "".to_string();
        let result = config.validate();
        assert!(result.is_err());
        if let Err(AppError::ConfigValidation { errors, .. }) = result {
            assert!(errors.iter().any(|e| e.contains("journald_field_prefix")));
        }
    }

    #[test]
    fn test_validate_journald_field_prefix_lowercase_invalid() {
        let mut config = AppConfig::default();
        config.general.journald_field_prefix = "zettai".to_string();
        let result = config.validate();
        assert!(result.is_err());
        if let Err(AppError::ConfigValidation { errors, .. }) = result {
            assert!(errors.iter().any(|e| e.contains("journald_field_prefix")));
        }
    }

    #[test]
    fn test_validate_journald_field_prefix_with_special_chars_invalid() {
        let mut config = AppConfig::default();
        config.general.journald_field_prefix = "ZETTAI-APP".to_string();
        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_zero_heartbeat_interval() {
        let mut config = AppConfig::default();
        config.health.heartbeat_interval_secs = 0;
        let result = config.validate();
        assert!(result.is_err());
        if let Err(AppError::ConfigValidation { errors, .. }) = result {
            assert!(
                errors
                    .iter()
                    .any(|e| e.contains("health.heartbeat_interval_secs"))
            );
        }
    }

    #[test]
    fn test_validate_zero_channel_capacity() {
        let mut config = AppConfig::default();
        config.event_bus.channel_capacity = 0;
        let result = config.validate();
        assert!(result.is_err());
        if let Err(AppError::ConfigValidation { errors, .. }) = result {
            assert!(
                errors
                    .iter()
                    .any(|e| e.contains("event_bus.channel_capacity"))
            );
        }
    }

    #[test]
    fn test_validate_zero_module_interval() {
        let mut config = AppConfig::default();
        config.modules.file_integrity.scan_interval_secs = 0;
        let result = config.validate();
        assert!(result.is_err());
        if let Err(AppError::ConfigValidation { errors, .. }) = result {
            assert!(
                errors
                    .iter()
                    .any(|e| e.contains("modules.file_integrity.scan_interval_secs"))
            );
        }
    }

    #[test]
    fn test_validate_invalid_action_type() {
        let mut config = AppConfig::default();
        config.actions.rules.push(ActionRuleConfig {
            name: "test_rule".to_string(),
            severity: None,
            module: None,
            action: "invalid".to_string(),
            command: None,
            timeout_secs: 30,
            url: None,
            method: None,
            headers: None,
            body_template: None,
            max_retries: None,
        });
        let result = config.validate();
        assert!(result.is_err());
        if let Err(AppError::ConfigValidation { errors, .. }) = result {
            assert!(errors.iter().any(|e| e.contains("無効なアクション種別")));
        }
    }

    #[test]
    fn test_validate_invalid_severity() {
        let mut config = AppConfig::default();
        config.actions.rules.push(ActionRuleConfig {
            name: "test_rule".to_string(),
            severity: Some("Unknown".to_string()),
            module: None,
            action: "log".to_string(),
            command: None,
            timeout_secs: 30,
            url: None,
            method: None,
            headers: None,
            body_template: None,
            max_retries: None,
        });
        let result = config.validate();
        assert!(result.is_err());
        if let Err(AppError::ConfigValidation { errors, .. }) = result {
            assert!(errors.iter().any(|e| e.contains("無効な severity")));
        }
    }

    #[test]
    fn test_validate_command_action_without_command() {
        let mut config = AppConfig::default();
        config.actions.rules.push(ActionRuleConfig {
            name: "test_rule".to_string(),
            severity: None,
            module: None,
            action: "command".to_string(),
            command: None,
            timeout_secs: 30,
            url: None,
            method: None,
            headers: None,
            body_template: None,
            max_retries: None,
        });
        let result = config.validate();
        assert!(result.is_err());
        if let Err(AppError::ConfigValidation { errors, .. }) = result {
            assert!(
                errors
                    .iter()
                    .any(|e| e.contains("command フィールドは必須"))
            );
        }
    }

    #[test]
    fn test_validate_webhook_action_without_url() {
        let mut config = AppConfig::default();
        config.actions.rules.push(ActionRuleConfig {
            name: "test_rule".to_string(),
            severity: None,
            module: None,
            action: "webhook".to_string(),
            command: None,
            timeout_secs: 30,
            url: None,
            method: None,
            headers: None,
            body_template: None,
            max_retries: None,
        });
        let result = config.validate();
        assert!(result.is_err());
        if let Err(AppError::ConfigValidation { errors, .. }) = result {
            assert!(errors.iter().any(|e| e.contains("url フィールドは必須")));
        }
    }

    #[test]
    fn test_validate_valid_action_rules() {
        let mut config = AppConfig::default();
        config.actions.rules.push(ActionRuleConfig {
            name: "log_rule".to_string(),
            severity: Some("Critical".to_string()),
            module: None,
            action: "log".to_string(),
            command: None,
            timeout_secs: 30,
            url: None,
            method: None,
            headers: None,
            body_template: None,
            max_retries: None,
        });
        config.actions.rules.push(ActionRuleConfig {
            name: "cmd_rule".to_string(),
            severity: Some("Warning".to_string()),
            module: None,
            action: "command".to_string(),
            command: Some("/bin/echo test".to_string()),
            timeout_secs: 30,
            url: None,
            method: None,
            headers: None,
            body_template: None,
            max_retries: None,
        });
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_rate_limit_zero_values() {
        let mut config = AppConfig::default();
        config.actions.rate_limit = Some(RateLimitConfig {
            command: Some(BucketConfig {
                max_tokens: 0,
                refill_amount: 5,
                refill_interval_secs: 60,
            }),
            webhook: None,
        });
        let result = config.validate();
        assert!(result.is_err());
        if let Err(AppError::ConfigValidation { errors, .. }) = result {
            assert!(
                errors
                    .iter()
                    .any(|e| e.contains("actions.rate_limit.command.max_tokens"))
            );
        }
    }

    #[test]
    fn test_validate_multiple_errors() {
        let mut config = AppConfig::default();
        config.general.log_level = "invalid".to_string();
        config.health.heartbeat_interval_secs = 0;
        config.event_bus.channel_capacity = 0;
        let result = config.validate();
        assert!(result.is_err());
        if let Err(AppError::ConfigValidation { count, errors }) = result {
            assert_eq!(count, 3);
            assert_eq!(errors.len(), 3);
        }
    }

    #[test]
    fn test_validate_zero_max_connections() {
        let mut config = AppConfig::default();
        config.modules.network_monitor.max_connections = 0;
        let result = config.validate();
        assert!(result.is_err());
        if let Err(AppError::ConfigValidation { errors, .. }) = result {
            assert!(
                errors
                    .iter()
                    .any(|e| e.contains("network_monitor.max_connections"))
            );
        }
    }

    #[test]
    fn test_validate_zero_max_failures() {
        let mut config = AppConfig::default();
        config.modules.ssh_brute_force.max_failures = 0;
        let result = config.validate();
        assert!(result.is_err());
        if let Err(AppError::ConfigValidation { errors, .. }) = result {
            assert!(
                errors
                    .iter()
                    .any(|e| e.contains("ssh_brute_force.max_failures"))
            );
        }
    }

    #[test]
    fn test_count_enabled_modules_none() {
        let config = AppConfig::default();
        assert_eq!(config.count_enabled_modules(), 0);
    }

    #[test]
    fn test_count_enabled_modules_some() {
        let mut config = AppConfig::default();
        config.modules.file_integrity.enabled = true;
        config.modules.dns_monitor.enabled = true;
        config.modules.network_monitor.enabled = true;
        assert_eq!(config.count_enabled_modules(), 3);
    }

    #[test]
    fn test_validate_metrics_zero_interval_when_enabled() {
        let mut config = AppConfig::default();
        config.metrics.enabled = true;
        config.metrics.interval_secs = 0;
        let result = config.validate();
        assert!(result.is_err());
        if let Err(AppError::ConfigValidation { errors, .. }) = result {
            assert!(errors.iter().any(|e| e.contains("metrics.interval_secs")));
        }
    }

    #[test]
    fn test_validate_metrics_zero_interval_when_disabled() {
        let mut config = AppConfig::default();
        config.metrics.enabled = false;
        config.metrics.interval_secs = 0;
        // メトリクスが無効なら interval_secs = 0 は許容
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_status_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(!config.status.enabled);
        assert_eq!(
            config.status.socket_path,
            "/var/run/zettai-mamorukun/status.sock"
        );
    }

    #[test]
    fn test_status_config_custom() {
        let toml_str = r#"
[status]
enabled = true
socket_path = "/tmp/custom.sock"
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.status.enabled);
        assert_eq!(config.status.socket_path, "/tmp/custom.sock");
    }

    #[test]
    fn test_validate_status_empty_socket_path() {
        let mut config = AppConfig::default();
        config.status.enabled = true;
        config.status.socket_path = String::new();
        let result = config.validate();
        assert!(result.is_err());
        if let Err(AppError::ConfigValidation { errors, .. }) = result {
            assert!(errors.iter().any(|e| e.contains("status.socket_path")));
        }
    }

    #[test]
    fn test_validate_status_disabled_empty_socket_path_ok() {
        let mut config = AppConfig::default();
        config.status.enabled = false;
        config.status.socket_path = String::new();
        // ステータスが無効なら空パスは許容
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_diff_from_default_no_changes() {
        let config = AppConfig::default();
        let diffs = config.diff_from_default();
        assert!(diffs.is_empty());
    }

    #[test]
    fn test_diff_from_default_log_level_changed() {
        let mut config = AppConfig::default();
        config.general.log_level = "debug".to_string();
        let diffs = config.diff_from_default();
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].0, "general.log_level");
        assert_eq!(diffs[0].1, "\"info\"");
        assert_eq!(diffs[0].2, "\"debug\"");
    }

    #[test]
    fn test_diff_from_default_module_enabled() {
        let mut config = AppConfig::default();
        config.modules.file_integrity.enabled = true;
        config.modules.file_integrity.scan_interval_secs = 60;
        let diffs = config.diff_from_default();
        assert_eq!(diffs.len(), 2);
        let paths: Vec<&str> = diffs.iter().map(|d| d.0.as_str()).collect();
        assert!(paths.contains(&"modules.file_integrity.enabled"));
        assert!(paths.contains(&"modules.file_integrity.scan_interval_secs"));
    }

    #[test]
    fn test_diff_from_default_multiple_sections() {
        let mut config = AppConfig::default();
        config.general.log_level = "warn".to_string();
        config.health.heartbeat_interval_secs = 30;
        config.event_bus.enabled = true;
        let diffs = config.diff_from_default();
        assert_eq!(diffs.len(), 3);
    }

    #[test]
    fn test_diff_from_default_boolean_change() {
        let mut config = AppConfig::default();
        config.health.enabled = false;
        let diffs = config.diff_from_default();
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].0, "health.enabled");
        assert_eq!(diffs[0].1, "true");
        assert_eq!(diffs[0].2, "false");
    }

    #[test]
    fn test_diff_from_default_serialization_roundtrip() {
        let config = AppConfig::default();
        // unwrap safety: テストコード
        let value: toml::Value = toml::Value::try_from(&config).unwrap();
        let roundtrip: AppConfig = value.try_into().unwrap();
        assert_eq!(config, roundtrip);
    }

    #[test]
    fn test_module_watchdog_config_defaults() {
        let config = ModuleWatchdogConfig::default();
        assert!(config.enabled);
        assert_eq!(config.check_interval_secs, 30);
        assert!(config.auto_restart);
        assert_eq!(config.max_restarts, 3);
        assert_eq!(config.restart_cooldown_secs, 60);
    }

    #[test]
    fn test_module_watchdog_config_parse_toml() {
        let toml_str = r#"
[module_watchdog]
enabled = false
check_interval_secs = 10
auto_restart = false
max_restarts = 5
restart_cooldown_secs = 120
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.module_watchdog.enabled);
        assert_eq!(config.module_watchdog.check_interval_secs, 10);
        assert!(!config.module_watchdog.auto_restart);
        assert_eq!(config.module_watchdog.max_restarts, 5);
        assert_eq!(config.module_watchdog.restart_cooldown_secs, 120);
    }

    #[test]
    fn test_module_watchdog_config_parse_toml_defaults() {
        let toml_str = "";
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.module_watchdog.enabled);
        assert_eq!(config.module_watchdog.check_interval_secs, 30);
        assert!(config.module_watchdog.auto_restart);
        assert_eq!(config.module_watchdog.max_restarts, 3);
        assert_eq!(config.module_watchdog.restart_cooldown_secs, 60);
    }

    #[test]
    fn test_validate_module_watchdog_zero_check_interval() {
        let mut config = AppConfig::default();
        config.module_watchdog.check_interval_secs = 0;
        let result = config.validate();
        assert!(result.is_err());
        if let Err(AppError::ConfigValidation { errors, .. }) = result {
            assert!(
                errors
                    .iter()
                    .any(|e| e.contains("module_watchdog.check_interval_secs"))
            );
        }
    }

    #[test]
    fn test_validate_module_watchdog_zero_restart_cooldown() {
        let mut config = AppConfig::default();
        config.module_watchdog.restart_cooldown_secs = 0;
        let result = config.validate();
        assert!(result.is_err());
        if let Err(AppError::ConfigValidation { errors, .. }) = result {
            assert!(
                errors
                    .iter()
                    .any(|e| e.contains("module_watchdog.restart_cooldown_secs"))
            );
        }
    }

    #[test]
    fn test_validate_module_watchdog_valid_config() {
        let config = AppConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_diff_from_default_module_watchdog_changed() {
        let mut config = AppConfig::default();
        config.module_watchdog.check_interval_secs = 10;
        let diffs = config.diff_from_default();
        assert!(
            diffs
                .iter()
                .any(|d| d.0 == "module_watchdog.check_interval_secs")
        );
    }

    #[test]
    fn test_cors_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(!config.api.cors.enabled);
        assert!(config.api.cors.allowed_origins.is_empty());
        assert_eq!(
            config.api.cors.allowed_methods,
            vec!["GET", "POST", "OPTIONS"]
        );
        assert_eq!(
            config.api.cors.allowed_headers,
            vec!["Content-Type", "Authorization", "X-API-Token"]
        );
        assert!(!config.api.cors.allow_credentials);
        assert_eq!(config.api.cors.max_age, 86400);
    }

    #[test]
    fn test_cors_config_custom() {
        let toml_str = r#"
[api.cors]
enabled = true
allowed_origins = ["https://example.com", "https://app.example.com"]
allowed_methods = ["GET", "POST", "PUT"]
allowed_headers = ["Content-Type", "X-Custom"]
allow_credentials = true
max_age = 3600
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.api.cors.enabled);
        assert_eq!(config.api.cors.allowed_origins.len(), 2);
        assert_eq!(config.api.cors.allowed_origins[0], "https://example.com");
        assert!(config.api.cors.allow_credentials);
        assert_eq!(config.api.cors.max_age, 3600);
    }

    #[test]
    fn test_prometheus_tls_config_deserialize() {
        let toml_str = r#"
[prometheus]
enabled = true
bind_address = "0.0.0.0"
port = 9100

[prometheus.tls]
enabled = true
cert_file = "/etc/certs/prometheus.crt"
key_file = "/etc/certs/prometheus.key"

[prometheus.tls.mtls]
enabled = true
client_ca_file = "/etc/certs/client-ca.crt"
client_auth_mode = "optional"
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.prometheus.tls.enabled);
        assert_eq!(config.prometheus.tls.cert_file, "/etc/certs/prometheus.crt");
        assert_eq!(config.prometheus.tls.key_file, "/etc/certs/prometheus.key");
        assert!(config.prometheus.tls.mtls.enabled);
        assert_eq!(
            config.prometheus.tls.mtls.client_ca_file,
            "/etc/certs/client-ca.crt"
        );
        assert_eq!(config.prometheus.tls.mtls.client_auth_mode, "optional");
    }

    #[test]
    fn test_retention_policy_deserialization() {
        let toml_str = r#"
[event_store]
enabled = true
retention_days = 90
retention_days_warning = 180
retention_days_critical = 365

[event_store.retention_policies.file_integrity]
retention_days = 120
retention_days_warning = 240
retention_days_critical = 365

[event_store.retention_policies.ssh_brute_force]
retention_days = 30
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.event_store.retention_days, 90);
        assert_eq!(config.event_store.retention_days_warning, 180);
        assert_eq!(config.event_store.retention_days_critical, 365);
        assert_eq!(config.event_store.retention_policies.len(), 2);

        let fi_policy = config
            .event_store
            .retention_policies
            .get("file_integrity")
            .unwrap();
        assert_eq!(fi_policy.retention_days, 120);
        assert_eq!(fi_policy.retention_days_warning, 240);
        assert_eq!(fi_policy.retention_days_critical, 365);

        let ssh_policy = config
            .event_store
            .retention_policies
            .get("ssh_brute_force")
            .unwrap();
        assert_eq!(ssh_policy.retention_days, 30);
        assert_eq!(ssh_policy.retention_days_warning, 0);
        assert_eq!(ssh_policy.retention_days_critical, 0);
    }

    #[test]
    fn test_prometheus_tls_config_defaults_when_omitted() {
        let toml_str = r#"
[prometheus]
enabled = true
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.prometheus.tls.enabled);
        assert!(config.prometheus.tls.cert_file.is_empty());
        assert!(config.prometheus.tls.key_file.is_empty());
        assert!(!config.prometheus.tls.mtls.enabled);
        assert_eq!(config.prometheus.tls.mtls.client_auth_mode, "required");
    }
}
