//! コンテナエスケープ検知モジュール
//!
//! コンテナ内からのブレイクアウト試行を検知する。
//!
//! 検知対象:
//! - cgroup 内のコンテナ環境変化
//! - 特権ケーパビリティを持つプロセスの検出
//! - Docker ソケットのコンテナ内マウント検知
//! - nsenter/unshare 等の名前空間操作コマンドの実行検知

use crate::config::ContainerEscapeConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::Module;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;

/// 全ケーパビリティが有効な状態を示すビットマスク（hex）
/// CAP_LAST_CAP が 40 の場合: (1 << 41) - 1 = 0x1ffffffffff
const FULL_CAPS_THRESHOLD: u64 = 0x0000003fffffffff;

/// プロセスのケーパビリティ情報
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessCapInfo {
    pid: u32,
    name: String,
    cap_eff: u64,
}

/// コンテナエスケープ検知モジュール
///
/// `/proc` ファイルシステムを定期スキャンし、コンテナエスケープの兆候を検知する。
pub struct ContainerEscapeModule {
    config: ContainerEscapeConfig,
    event_bus: Option<EventBus>,
    cancel_token: CancellationToken,
}

impl ContainerEscapeModule {
    /// 新しいコンテナエスケープ検知モジュールを作成する
    pub fn new(config: ContainerEscapeConfig, event_bus: Option<EventBus>) -> Self {
        Self {
            config,
            event_bus,
            cancel_token: CancellationToken::new(),
        }
    }

    /// キャンセルトークンのクローンを返す
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    /// `/proc/<pid>/cgroup` を読み取り、コンテナ内プロセスかどうかを判定するためのキーワードを検出する
    fn parse_cgroup_for_container(content: &str) -> bool {
        for line in content.lines() {
            let lower = line.to_lowercase();
            if lower.contains("docker")
                || lower.contains("kubepods")
                || lower.contains("containerd")
                || lower.contains("lxc")
                || lower.contains("/system.slice/containerd.service")
            {
                return true;
            }
        }
        false
    }

    /// `/proc/<pid>/status` から CapEff（実効ケーパビリティ）を読み取る
    fn parse_cap_eff(status_content: &str) -> Option<u64> {
        for line in status_content.lines() {
            if let Some(hex_str) = line.strip_prefix("CapEff:\t") {
                let hex_str = hex_str.trim();
                return u64::from_str_radix(hex_str, 16).ok();
            }
        }
        None
    }

    /// 特権ケーパビリティを持つプロセスかどうかを判定する
    fn is_privileged(cap_eff: u64) -> bool {
        cap_eff >= FULL_CAPS_THRESHOLD
    }

    /// `/proc/<pid>/status` からプロセス名を読み取る
    fn parse_process_name(status_content: &str) -> String {
        for line in status_content.lines() {
            if let Some(name) = line.strip_prefix("Name:\t") {
                return name.trim().to_string();
            }
        }
        "unknown".to_string()
    }

    /// `/proc` をスキャンして PID ディレクトリ一覧を返す
    fn list_pids() -> Vec<u32> {
        let mut pids = Vec::new();
        let proc_dir = match std::fs::read_dir("/proc") {
            Ok(dir) => dir,
            Err(_) => return pids,
        };

        for entry in proc_dir.flatten() {
            if let Some(name) = entry.file_name().to_str()
                && let Ok(pid) = name.parse::<u32>()
            {
                pids.push(pid);
            }
        }
        pids
    }

    /// 特権ケーパビリティを持つプロセス一覧を取得する
    fn scan_privileged_processes() -> Vec<ProcessCapInfo> {
        let mut results = Vec::new();
        for pid in Self::list_pids() {
            let status_path = PathBuf::from(format!("/proc/{}/status", pid));
            let status_content = match std::fs::read_to_string(&status_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            if let Some(cap_eff) = Self::parse_cap_eff(&status_content)
                && Self::is_privileged(cap_eff)
            {
                let name = Self::parse_process_name(&status_content);
                results.push(ProcessCapInfo { pid, name, cap_eff });
            }
        }
        results
    }

    /// Docker ソケットがマウントされたコンテナを検知する
    ///
    /// `/proc/mounts` を確認し、docker.sock がバインドマウントされているか検出する
    fn check_docker_socket_mount(docker_socket_path: &Path) -> bool {
        let mounts_content = match std::fs::read_to_string("/proc/mounts") {
            Ok(c) => c,
            Err(_) => return false,
        };

        let socket_str = docker_socket_path.to_string_lossy();
        for line in mounts_content.lines() {
            // マウントエントリの中に docker socket パスが含まれるか確認
            if line.contains(socket_str.as_ref()) {
                return true;
            }
        }
        false
    }

    /// nsenter/unshare 等の名前空間操作コマンドを実行中のプロセスを検知する
    fn scan_namespace_commands(suspicious_commands: &[String]) -> Vec<(u32, String)> {
        let mut found = Vec::new();
        for pid in Self::list_pids() {
            let cmdline_path = PathBuf::from(format!("/proc/{}/cmdline", pid));
            let cmdline = match std::fs::read_to_string(&cmdline_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            // cmdline はヌル文字区切り
            let cmd = cmdline.replace('\0', " ");
            let cmd_lower = cmd.to_lowercase();

            for suspicious in suspicious_commands {
                if cmd_lower.contains(&suspicious.to_lowercase()) {
                    found.push((pid, cmd.trim().to_string()));
                    break;
                }
            }
        }
        found
    }

    /// cgroup の変化を検知する（ベースラインと比較）
    fn scan_cgroup_changes(
        baseline: &HashMap<u32, bool>,
    ) -> (HashMap<u32, bool>, Vec<(u32, String)>) {
        let mut current = HashMap::new();
        let mut new_containers = Vec::new();

        for pid in Self::list_pids() {
            let cgroup_path = PathBuf::from(format!("/proc/{}/cgroup", pid));
            let content = match std::fs::read_to_string(&cgroup_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let is_container = Self::parse_cgroup_for_container(&content);
            current.insert(pid, is_container);

            // 新規のコンテナプロセスを検知
            if is_container && !baseline.contains_key(&pid) {
                let status_path = PathBuf::from(format!("/proc/{}/status", pid));
                let name = match std::fs::read_to_string(&status_path) {
                    Ok(s) => Self::parse_process_name(&s),
                    Err(_) => "unknown".to_string(),
                };
                new_containers.push((pid, name));
            }
        }

        (current, new_containers)
    }
}

impl Module for ContainerEscapeModule {
    fn name(&self) -> &str {
        "container_escape"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            docker_socket_path = %self.config.docker_socket_path.display(),
            suspicious_commands = ?self.config.suspicious_commands,
            "コンテナエスケープ検知モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<(), AppError> {
        // 初回スキャンでベースライン作成
        let privileged_baseline: HashSet<u32> = Self::scan_privileged_processes()
            .iter()
            .map(|p| p.pid)
            .collect();
        tracing::info!(
            privileged_count = privileged_baseline.len(),
            "特権プロセスのベースラインスキャンが完了しました"
        );

        // cgroup ベースライン
        let mut cgroup_baseline = HashMap::new();
        for pid in Self::list_pids() {
            let cgroup_path = PathBuf::from(format!("/proc/{}/cgroup", pid));
            if let Ok(content) = std::fs::read_to_string(&cgroup_path) {
                let is_container = Self::parse_cgroup_for_container(&content);
                cgroup_baseline.insert(pid, is_container);
            }
        }

        let scan_interval_secs = self.config.scan_interval_secs;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();
        let docker_socket_path = self.config.docker_socket_path.clone();
        let suspicious_commands = self.config.suspicious_commands.clone();

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            // 最初の tick は即座に発火するのでスキップ
            interval.tick().await;

            let mut privileged_baseline = privileged_baseline;
            let mut cgroup_baseline = cgroup_baseline;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("コンテナエスケープ検知モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        // 1. 特権プロセスの検知
                        let current_privileged = ContainerEscapeModule::scan_privileged_processes();
                        for proc_info in &current_privileged {
                            if !privileged_baseline.contains(&proc_info.pid) {
                                tracing::warn!(
                                    pid = proc_info.pid,
                                    name = %proc_info.name,
                                    cap_eff = format!("0x{:x}", proc_info.cap_eff),
                                    "新規特権プロセスを検知しました"
                                );
                                if let Some(ref bus) = event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            "privileged_process_detected",
                                            Severity::Warning,
                                            "container_escape",
                                            format!(
                                                "新規特権プロセスを検知しました: PID={}, name={}",
                                                proc_info.pid, proc_info.name
                                            ),
                                        )
                                        .with_details(format!(
                                            "pid={}, name={}, cap_eff=0x{:x}",
                                            proc_info.pid, proc_info.name, proc_info.cap_eff
                                        )),
                                    );
                                }
                            }
                        }
                        privileged_baseline = current_privileged.iter().map(|p| p.pid).collect();

                        // 2. Docker ソケットマウントの検知
                        if ContainerEscapeModule::check_docker_socket_mount(&docker_socket_path) {
                            tracing::warn!(
                                socket_path = %docker_socket_path.display(),
                                "Docker ソケットのマウントを検知しました"
                            );
                            if let Some(ref bus) = event_bus {
                                bus.publish(
                                    SecurityEvent::new(
                                        "docker_socket_mounted",
                                        Severity::Critical,
                                        "container_escape",
                                        format!(
                                            "Docker ソケットのマウントを検知しました: {}",
                                            docker_socket_path.display()
                                        ),
                                    )
                                    .with_details(docker_socket_path.display().to_string()),
                                );
                            }
                        }

                        // 3. 名前空間操作コマンドの検知
                        let ns_commands = ContainerEscapeModule::scan_namespace_commands(&suspicious_commands);
                        for (pid, cmd) in &ns_commands {
                            tracing::warn!(
                                pid = pid,
                                command = %cmd,
                                "名前空間操作コマンドの実行を検知しました"
                            );
                            if let Some(ref bus) = event_bus {
                                bus.publish(
                                    SecurityEvent::new(
                                        "namespace_command_detected",
                                        Severity::Critical,
                                        "container_escape",
                                        format!(
                                            "名前空間操作コマンドの実行を検知しました: PID={}, cmd={}",
                                            pid, cmd
                                        ),
                                    )
                                    .with_details(format!("pid={}, cmd={}", pid, cmd)),
                                );
                            }
                        }

                        // 4. cgroup 変化の検知
                        let (new_cgroup, new_containers) =
                            ContainerEscapeModule::scan_cgroup_changes(&cgroup_baseline);
                        for (pid, name) in &new_containers {
                            tracing::warn!(
                                pid = pid,
                                name = %name,
                                "新規コンテナプロセスを検知しました"
                            );
                            if let Some(ref bus) = event_bus {
                                bus.publish(
                                    SecurityEvent::new(
                                        "new_container_process",
                                        Severity::Info,
                                        "container_escape",
                                        format!(
                                            "新規コンテナプロセスを検知しました: PID={}, name={}",
                                            pid, name
                                        ),
                                    )
                                    .with_details(format!("pid={}, name={}", pid, name)),
                                );
                            }
                        }
                        cgroup_baseline = new_cgroup;
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cgroup_for_container_docker() {
        let content = "12:memory:/docker/abc123def456\n11:cpu:/docker/abc123def456\n";
        assert!(ContainerEscapeModule::parse_cgroup_for_container(content));
    }

    #[test]
    fn test_parse_cgroup_for_container_kubepods() {
        let content = "12:memory:/kubepods/burstable/pod-abc\n";
        assert!(ContainerEscapeModule::parse_cgroup_for_container(content));
    }

    #[test]
    fn test_parse_cgroup_for_container_containerd() {
        let content = "0::/system.slice/containerd.service/kubepods-abc\n";
        assert!(ContainerEscapeModule::parse_cgroup_for_container(content));
    }

    #[test]
    fn test_parse_cgroup_for_container_lxc() {
        let content = "12:memory:/lxc/my-container\n";
        assert!(ContainerEscapeModule::parse_cgroup_for_container(content));
    }

    #[test]
    fn test_parse_cgroup_for_container_host() {
        let content = "12:memory:/\n11:cpu:/\n0::/init.scope\n";
        assert!(!ContainerEscapeModule::parse_cgroup_for_container(content));
    }

    #[test]
    fn test_parse_cgroup_empty() {
        assert!(!ContainerEscapeModule::parse_cgroup_for_container(""));
    }

    #[test]
    fn test_parse_cap_eff_full() {
        let status = "Name:\tinit\nCapEff:\t0000003fffffffff\n";
        let cap = ContainerEscapeModule::parse_cap_eff(status);
        assert_eq!(cap, Some(0x0000003fffffffff));
    }

    #[test]
    fn test_parse_cap_eff_limited() {
        let status = "Name:\tbash\nCapEff:\t0000000000000000\n";
        let cap = ContainerEscapeModule::parse_cap_eff(status);
        assert_eq!(cap, Some(0));
    }

    #[test]
    fn test_parse_cap_eff_missing() {
        let status = "Name:\tbash\nCapInh:\t0000000000000000\n";
        let cap = ContainerEscapeModule::parse_cap_eff(status);
        assert!(cap.is_none());
    }

    #[test]
    fn test_is_privileged_full_caps() {
        assert!(ContainerEscapeModule::is_privileged(0x0000003fffffffff));
    }

    #[test]
    fn test_is_privileged_no_caps() {
        assert!(!ContainerEscapeModule::is_privileged(0));
    }

    #[test]
    fn test_is_privileged_partial_caps() {
        assert!(!ContainerEscapeModule::is_privileged(0x00000000a80425fb));
    }

    #[test]
    fn test_parse_process_name() {
        let status = "Name:\tnginx\nUmask:\t0022\nState:\tS (sleeping)\n";
        assert_eq!(ContainerEscapeModule::parse_process_name(status), "nginx");
    }

    #[test]
    fn test_parse_process_name_missing() {
        let status = "Umask:\t0022\nState:\tS (sleeping)\n";
        assert_eq!(ContainerEscapeModule::parse_process_name(status), "unknown");
    }

    #[test]
    fn test_init_zero_interval() {
        let config = ContainerEscapeConfig {
            enabled: true,
            scan_interval_secs: 0,
            docker_socket_path: PathBuf::from("/var/run/docker.sock"),
            suspicious_commands: vec![],
        };
        let mut module = ContainerEscapeModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_init_valid() {
        let config = ContainerEscapeConfig {
            enabled: true,
            scan_interval_secs: 60,
            docker_socket_path: PathBuf::from("/var/run/docker.sock"),
            suspicious_commands: vec!["nsenter".to_string()],
        };
        let mut module = ContainerEscapeModule::new(config, None);
        let result = module.init();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let config = ContainerEscapeConfig {
            enabled: true,
            scan_interval_secs: 3600,
            docker_socket_path: PathBuf::from("/tmp/nonexistent-docker.sock"),
            suspicious_commands: vec!["nsenter".to_string()],
        };
        let mut module = ContainerEscapeModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[test]
    fn test_list_pids_returns_some() {
        // /proc が存在する環境でのみテスト
        if PathBuf::from("/proc").exists() {
            let pids = ContainerEscapeModule::list_pids();
            assert!(!pids.is_empty());
            // PID 1 は必ず存在する
            assert!(pids.contains(&1));
        }
    }

    #[test]
    fn test_scan_cgroup_changes_empty_baseline() {
        if PathBuf::from("/proc").exists() {
            let baseline = HashMap::new();
            let (current, _new_containers) = ContainerEscapeModule::scan_cgroup_changes(&baseline);
            // 少なくとも PID 1 は存在するはず
            assert!(!current.is_empty());
        }
    }

    #[test]
    fn test_check_docker_socket_mount_nonexistent() {
        let path = PathBuf::from("/tmp/nonexistent-docker-test.sock");
        // マウントされていないパスの場合 false
        let result = ContainerEscapeModule::check_docker_socket_mount(&path);
        assert!(!result);
    }

    #[test]
    fn test_scan_namespace_commands_empty() {
        let cmds: Vec<String> = vec![];
        let result = ContainerEscapeModule::scan_namespace_commands(&cmds);
        assert!(result.is_empty());
    }

    #[test]
    fn test_scan_namespace_commands_nonexistent() {
        let cmds = vec!["zzz_nonexistent_command_zzz".to_string()];
        let result = ContainerEscapeModule::scan_namespace_commands(&cmds);
        assert!(result.is_empty());
    }
}
