use crate::config::AppConfig;
use std::fmt;

/// 設定プロファイル種別
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileKind {
    /// 最小限の監視（開発・テスト環境向け）
    Minimal,
    /// Web サーバ向け
    Webserver,
    /// DB サーバ向け
    Database,
    /// 全モジュール有効（本番・高セキュリティ環境向け）
    Full,
}

/// プロファイル情報
pub struct ProfileInfo {
    /// プロファイル種別
    pub kind: ProfileKind,
    /// プロファイル名（CLI で指定する文字列）
    pub name: &'static str,
    /// プロファイルの説明
    pub description: &'static str,
    /// 有効化されるモジュール数の目安
    pub module_count: &'static str,
}

/// 全プロファイル一覧
const PROFILES: &[ProfileInfo] = &[
    ProfileInfo {
        kind: ProfileKind::Minimal,
        name: "minimal",
        description: "最小限の監視（開発・テスト環境向け）",
        module_count: "8",
    },
    ProfileInfo {
        kind: ProfileKind::Webserver,
        name: "webserver",
        description: "Web サーバ向け（TLS・ネットワーク・ファイル変更監視を強化）",
        module_count: "20",
    },
    ProfileInfo {
        kind: ProfileKind::Database,
        name: "database",
        description: "DB サーバ向け（権限・アクセス制御・FD 監視を強化）",
        module_count: "18",
    },
    ProfileInfo {
        kind: ProfileKind::Full,
        name: "full",
        description: "全モジュール有効（本番・高セキュリティ環境向け）",
        module_count: "60",
    },
];

impl ProfileKind {
    /// 文字列からプロファイル種別をパースする
    pub fn from_name(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "minimal" => Some(Self::Minimal),
            "webserver" => Some(Self::Webserver),
            "database" => Some(Self::Database),
            "full" => Some(Self::Full),
            _ => None,
        }
    }

    /// 全プロファイル一覧を返す
    pub fn all_profiles() -> &'static [ProfileInfo] {
        PROFILES
    }

    /// プロファイルに基づいた AppConfig を生成する
    pub fn build_config(self) -> AppConfig {
        let mut config = AppConfig::default();

        // 全プロファイル共通: インフラ設定を有効化
        config.event_bus.enabled = true;
        config.health.enabled = true;
        config.metrics.enabled = true;

        match self {
            Self::Minimal => self.apply_minimal(&mut config),
            Self::Webserver => {
                self.apply_minimal(&mut config);
                self.apply_webserver(&mut config);
            }
            Self::Database => {
                self.apply_minimal(&mut config);
                self.apply_database(&mut config);
            }
            Self::Full => self.apply_full(&mut config),
        }

        config
    }

    fn apply_minimal(self, config: &mut AppConfig) {
        config.modules.file_integrity.enabled = true;
        config.modules.process_monitor.enabled = true;
        config.modules.user_account.enabled = true;
        config.modules.log_tamper.enabled = true;
        config.modules.ssh_brute_force.enabled = true;
        config.modules.listening_port_monitor.enabled = true;
        config.modules.tmp_exec_monitor.enabled = true;
        config.modules.network_monitor.enabled = true;
    }

    fn apply_webserver(self, config: &mut AppConfig) {
        // インフラ強化
        config.event_store.enabled = true;
        config.correlation.enabled = true;
        config.startup_scan.enabled = true;
        config.status.enabled = true;

        // Web サーバ向けモジュール
        config.modules.tls_cert_monitor.enabled = true;
        config.modules.cert_chain_monitor.enabled = true;
        config.modules.firewall_monitor.enabled = true;
        config.modules.network_traffic_monitor.enabled = true;
        config.modules.network_interface_monitor.enabled = true;
        config.modules.backdoor_detector.enabled = true;
        config.modules.shell_config_monitor.enabled = true;
        config.modules.sudoers_monitor.enabled = true;
        config.modules.process_tree_monitor.enabled = true;
        config.modules.process_exec_monitor.enabled = true;
        config.modules.inotify_monitor.enabled = true;
        config.modules.login_session_monitor.enabled = true;
    }

    fn apply_database(self, config: &mut AppConfig) {
        // インフラ強化
        config.event_store.enabled = true;
        config.correlation.enabled = true;
        config.startup_scan.enabled = true;
        config.status.enabled = true;

        // DB サーバ向けモジュール
        config.modules.pam_monitor.enabled = true;
        config.modules.security_files_monitor.enabled = true;
        config.modules.sudoers_monitor.enabled = true;
        config.modules.privilege_escalation_monitor.enabled = true;
        config.modules.fd_monitor.enabled = true;
        config.modules.firewall_monitor.enabled = true;
        config.modules.backdoor_detector.enabled = true;
        config.modules.login_session_monitor.enabled = true;
        config.modules.proc_environ_monitor.enabled = true;
        config.modules.ld_preload_monitor.enabled = true;
    }

    fn apply_full(self, config: &mut AppConfig) {
        // 全インフラ設定を有効化
        config.event_store.enabled = true;
        config.correlation.enabled = true;
        config.startup_scan.enabled = true;
        config.status.enabled = true;
        config.event_stream.enabled = true;
        config.actions.enabled = true;
        config.module_watchdog.enabled = true;

        // 全モジュールを有効化
        config.modules.file_integrity.enabled = true;
        config.modules.process_monitor.enabled = true;
        config.modules.kernel_module.enabled = true;
        config.modules.auditd_monitor.enabled = true;
        config.modules.at_job_monitor.enabled = true;
        config.modules.cron_monitor.enabled = true;
        config.modules.user_account.enabled = true;
        config.modules.log_tamper.enabled = true;
        config.modules.systemd_service.enabled = true;
        config.modules.systemd_timer_monitor.enabled = true;
        config.modules.firewall_monitor.enabled = true;
        config.modules.dns_monitor.enabled = true;
        config.modules.ssh_key_monitor.enabled = true;
        config.modules.mount_monitor.enabled = true;
        config.modules.shell_config_monitor.enabled = true;
        config.modules.tmp_exec_monitor.enabled = true;
        config.modules.sudoers_monitor.enabled = true;
        config.modules.suid_sgid_monitor.enabled = true;
        config.modules.ssh_brute_force.enabled = true;
        config.modules.pkg_repo_monitor.enabled = true;
        config.modules.ld_preload_monitor.enabled = true;
        config.modules.network_monitor.enabled = true;
        config.modules.pam_monitor.enabled = true;
        config.modules.security_files_monitor.enabled = true;
        config.modules.mac_monitor.enabled = true;
        config.modules.capabilities_monitor.enabled = true;
        config.modules.container_namespace.enabled = true;
        config.modules.cgroup_monitor.enabled = true;
        config.modules.kernel_params.enabled = true;
        config.modules.kernel_taint_monitor.enabled = true;
        config.modules.proc_net_monitor.enabled = true;
        config.modules.seccomp_monitor.enabled = true;
        config.modules.usb_monitor.enabled = true;
        config.modules.listening_port_monitor.enabled = true;
        config.modules.fd_monitor.enabled = true;
        config.modules.network_interface_monitor.enabled = true;
        config.modules.network_traffic_monitor.enabled = true;
        config.modules.env_injection_monitor.enabled = true;
        config.modules.shm_monitor.enabled = true;
        config.modules.process_tree_monitor.enabled = true;
        config.modules.xattr_monitor.enabled = true;
        config.modules.inotify_monitor.enabled = true;
        config.modules.process_exec_monitor.enabled = true;
        config.modules.tls_cert_monitor.enabled = true;
        config.modules.login_session_monitor.enabled = true;
        config.modules.proc_maps_monitor.enabled = true;
        config.modules.ptrace_monitor.enabled = true;
        config.modules.kallsyms_monitor.enabled = true;
        config.modules.coredump_monitor.enabled = true;
        config.modules.ebpf_monitor.enabled = true;
        config.modules.dbus_monitor.enabled = true;
        config.modules.swap_tmpfs_monitor.enabled = true;
        config.modules.unix_socket_monitor.enabled = true;
        config.modules.process_cgroup_monitor.enabled = true;
        config.modules.abstract_socket_monitor.enabled = true;
        config.modules.ipc_monitor.enabled = true;
        config.modules.privilege_escalation_monitor.enabled = true;
        config.modules.backdoor_detector.enabled = true;
        config.modules.cert_chain_monitor.enabled = true;
        config.modules.namespace_monitor.enabled = true;
        config.modules.proc_environ_monitor.enabled = true;
        config.modules.group_monitor.enabled = true;
        config.modules.process_cmdline_monitor.enabled = true;
        config.modules.bootloader_monitor.enabled = true;
        config.modules.hidden_process_monitor.enabled = true;
        config.modules.initramfs_monitor.enabled = true;
        config.modules.kernel_cmdline_monitor.enabled = true;
        config.modules.fileless_exec_monitor.enabled = true;
        config.modules.livepatch_monitor.enabled = true;
        config.modules.journal_pattern_monitor.enabled = true;
        config.modules.keylogger_detector.enabled = true;
    }
}

impl fmt::Display for ProfileKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Minimal => "minimal",
            Self::Webserver => "webserver",
            Self::Database => "database",
            Self::Full => "full",
        };
        write!(f, "{}", name)
    }
}

/// プロファイルに基づいた設定ファイルの TOML 文字列を生成する
pub fn generate_config_toml(profile: ProfileKind) -> Result<String, toml::ser::Error> {
    let config = profile.build_config();
    let toml_str = toml::to_string_pretty(&config)?;

    let header = format!(
        "# zettai-mamorukun 設定ファイル\n\
         # プロファイル: {}\n\
         # 生成コマンド: zettai-mamorukun init --profile {}\n\
         #\n\
         # 各モジュールの enabled を true/false で切り替えて有効・無効を制御できます。\n\
         # 詳細は https://github.com/turntuptechnologies-ai/zettai-mamorukun を参照してください。\n\n",
        profile, profile,
    );

    Ok(format!("{}{}", header, toml_str))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_from_name() {
        assert_eq!(
            ProfileKind::from_name("minimal"),
            Some(ProfileKind::Minimal)
        );
        assert_eq!(
            ProfileKind::from_name("webserver"),
            Some(ProfileKind::Webserver)
        );
        assert_eq!(
            ProfileKind::from_name("database"),
            Some(ProfileKind::Database)
        );
        assert_eq!(ProfileKind::from_name("full"), Some(ProfileKind::Full));
        assert_eq!(
            ProfileKind::from_name("MINIMAL"),
            Some(ProfileKind::Minimal)
        );
        assert_eq!(ProfileKind::from_name("unknown"), None);
    }

    #[test]
    fn test_profile_display() {
        assert_eq!(format!("{}", ProfileKind::Minimal), "minimal");
        assert_eq!(format!("{}", ProfileKind::Full), "full");
    }

    #[test]
    fn test_all_profiles() {
        let profiles = ProfileKind::all_profiles();
        assert_eq!(profiles.len(), 4);
        assert_eq!(profiles[0].name, "minimal");
        assert_eq!(profiles[3].name, "full");
    }

    #[test]
    fn test_minimal_profile_modules() {
        let config = ProfileKind::Minimal.build_config();
        assert!(config.modules.file_integrity.enabled);
        assert!(config.modules.process_monitor.enabled);
        assert!(config.modules.user_account.enabled);
        assert!(config.modules.log_tamper.enabled);
        assert!(config.modules.ssh_brute_force.enabled);
        assert!(config.modules.listening_port_monitor.enabled);
        assert!(config.modules.tmp_exec_monitor.enabled);
        assert!(config.modules.network_monitor.enabled);
        // minimal では無効
        assert!(!config.modules.tls_cert_monitor.enabled);
        assert!(!config.modules.kernel_module.enabled);
        // インフラ
        assert!(config.event_bus.enabled);
        assert!(config.health.enabled);
        assert!(config.metrics.enabled);
    }

    #[test]
    fn test_webserver_profile_includes_minimal() {
        let config = ProfileKind::Webserver.build_config();
        // minimal のモジュールも有効
        assert!(config.modules.file_integrity.enabled);
        assert!(config.modules.ssh_brute_force.enabled);
        // webserver 固有
        assert!(config.modules.tls_cert_monitor.enabled);
        assert!(config.modules.cert_chain_monitor.enabled);
        assert!(config.modules.firewall_monitor.enabled);
        assert!(config.modules.inotify_monitor.enabled);
        // webserver には含まれない
        assert!(!config.modules.kernel_module.enabled);
    }

    #[test]
    fn test_database_profile_includes_minimal() {
        let config = ProfileKind::Database.build_config();
        // minimal のモジュールも有効
        assert!(config.modules.file_integrity.enabled);
        // database 固有
        assert!(config.modules.pam_monitor.enabled);
        assert!(config.modules.fd_monitor.enabled);
        assert!(config.modules.privilege_escalation_monitor.enabled);
        // database には含まれない
        assert!(!config.modules.tls_cert_monitor.enabled);
    }

    #[test]
    fn test_full_profile_all_modules() {
        let config = ProfileKind::Full.build_config();
        // 全モジュールが有効であることをスポットチェック
        assert!(config.modules.file_integrity.enabled);
        assert!(config.modules.kernel_module.enabled);
        assert!(config.modules.tls_cert_monitor.enabled);
        assert!(config.modules.keylogger_detector.enabled);
        assert!(config.modules.bootloader_monitor.enabled);
        assert!(config.modules.fileless_exec_monitor.enabled);
        // 全インフラも有効
        assert!(config.event_store.enabled);
        assert!(config.correlation.enabled);
        assert!(config.status.enabled);
        assert!(config.event_stream.enabled);
        assert!(config.actions.enabled);
        assert!(config.module_watchdog.enabled);
    }

    #[test]
    fn test_generate_config_toml() {
        let toml_str = generate_config_toml(ProfileKind::Minimal).unwrap();
        assert!(toml_str.contains("# プロファイル: minimal"));
        assert!(toml_str.contains("[modules.file_integrity]"));
        // パースし直してバリデーション
        let config: AppConfig = toml::from_str(
            toml_str
                .lines()
                .filter(|l| !l.starts_with('#'))
                .collect::<Vec<_>>()
                .join("\n")
                .as_str(),
        )
        .unwrap();
        assert!(config.modules.file_integrity.enabled);
    }

    #[test]
    fn test_generated_config_validates() {
        for profile_info in ProfileKind::all_profiles() {
            let config = profile_info.kind.build_config();
            assert!(
                config.validate().is_ok(),
                "プロファイル {} のバリデーションに失敗",
                profile_info.name
            );
        }
    }
}
