use std::path::Path;
use zettai_mamorukun::config::AppConfig;
use zettai_mamorukun::core::health::HealthChecker;

#[test]
fn test_config_default_when_file_missing() {
    let config = AppConfig::load(Path::new("/tmp/nonexistent-zettai-config.toml")).unwrap();
    assert_eq!(config.general.log_level, "info");
}

#[test]
fn test_binary_help() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_zettai-mamorukun"))
        .arg("--help")
        .output()
        .expect("バイナリの実行に失敗しました");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("サイバー攻撃防御デーモン"));
}

#[test]
fn test_health_checker_integration() {
    let checker = HealthChecker::new();
    let status = checker.status();
    // 統合テストでの基本的な動作確認
    assert!(status.uptime_secs < 60);
    // Linux 環境では VmRSS が取得できる
    assert!(status.memory_rss_kb.is_some());
    assert!(status.memory_rss_kb.unwrap() > 0);
}

#[test]
fn test_config_with_health_section() {
    use std::io::Write;
    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
    write!(
        tmpfile,
        r#"
[general]
log_level = "debug"

[health]
enabled = true
heartbeat_interval_secs = 10
"#
    )
    .unwrap();
    let config = AppConfig::load(tmpfile.path()).unwrap();
    assert!(config.health.enabled);
    assert_eq!(config.health.heartbeat_interval_secs, 10);
}

#[test]
fn test_config_with_file_integrity_section() {
    use std::io::Write;
    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
    write!(
        tmpfile,
        r#"
[general]
log_level = "info"

[modules.file_integrity]
enabled = true
scan_interval_secs = 60
watch_paths = ["/tmp"]
"#
    )
    .unwrap();
    let config = AppConfig::load(tmpfile.path()).unwrap();
    assert!(config.modules.file_integrity.enabled);
    assert_eq!(config.modules.file_integrity.scan_interval_secs, 60);
    assert_eq!(config.modules.file_integrity.watch_paths.len(), 1);
}

#[test]
fn test_config_with_process_monitor_section() {
    use std::io::Write;
    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
    write!(
        tmpfile,
        r#"
[modules.process_monitor]
enabled = true
scan_interval_secs = 30
suspicious_paths = ["/tmp", "/dev/shm"]
"#
    )
    .unwrap();
    let config = AppConfig::load(tmpfile.path()).unwrap();
    assert!(config.modules.process_monitor.enabled);
    assert_eq!(config.modules.process_monitor.scan_interval_secs, 30);
    assert_eq!(config.modules.process_monitor.suspicious_paths.len(), 2);
}

#[test]
fn test_config_with_kernel_module_section() {
    use std::io::Write;
    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
    write!(
        tmpfile,
        r#"
[modules.kernel_module]
enabled = true
scan_interval_secs = 60
"#
    )
    .unwrap();
    let config = AppConfig::load(tmpfile.path()).unwrap();
    assert!(config.modules.kernel_module.enabled);
    assert_eq!(config.modules.kernel_module.scan_interval_secs, 60);
}

#[test]
fn test_config_kernel_module_disabled_by_default() {
    let config = AppConfig::load(Path::new("/tmp/nonexistent-zettai-config.toml")).unwrap();
    assert!(!config.modules.kernel_module.enabled);
    assert_eq!(config.modules.kernel_module.scan_interval_secs, 120);
}

#[test]
fn test_config_process_monitor_disabled_by_default() {
    let config = AppConfig::load(Path::new("/tmp/nonexistent-zettai-config.toml")).unwrap();
    assert!(!config.modules.process_monitor.enabled);
    assert_eq!(config.modules.process_monitor.scan_interval_secs, 60);
    assert_eq!(config.modules.process_monitor.suspicious_paths.len(), 3);
}

#[test]
fn test_config_with_cron_monitor_section() {
    use std::io::Write;
    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
    write!(
        tmpfile,
        r#"
[modules.cron_monitor]
enabled = true
scan_interval_secs = 60
watch_paths = ["/etc/crontab", "/etc/cron.d"]
"#
    )
    .unwrap();
    let config = AppConfig::load(tmpfile.path()).unwrap();
    assert!(config.modules.cron_monitor.enabled);
    assert_eq!(config.modules.cron_monitor.scan_interval_secs, 60);
    assert_eq!(config.modules.cron_monitor.watch_paths.len(), 2);
}

#[test]
fn test_config_cron_monitor_disabled_by_default() {
    let config = AppConfig::load(Path::new("/tmp/nonexistent-zettai-config.toml")).unwrap();
    assert!(!config.modules.cron_monitor.enabled);
    assert_eq!(config.modules.cron_monitor.scan_interval_secs, 120);
    assert_eq!(config.modules.cron_monitor.watch_paths.len(), 7);
}

#[test]
fn test_config_with_user_account_section() {
    use std::io::Write;
    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
    write!(
        tmpfile,
        r#"
[modules.user_account]
enabled = true
scan_interval_secs = 30
passwd_path = "/etc/passwd"
group_path = "/etc/group"
"#
    )
    .unwrap();
    let config = AppConfig::load(tmpfile.path()).unwrap();
    assert!(config.modules.user_account.enabled);
    assert_eq!(config.modules.user_account.scan_interval_secs, 30);
    assert_eq!(
        config.modules.user_account.passwd_path,
        std::path::PathBuf::from("/etc/passwd")
    );
    assert_eq!(
        config.modules.user_account.group_path,
        std::path::PathBuf::from("/etc/group")
    );
}

#[test]
fn test_config_user_account_disabled_by_default() {
    let config = AppConfig::load(Path::new("/tmp/nonexistent-zettai-config.toml")).unwrap();
    assert!(!config.modules.user_account.enabled);
    assert_eq!(config.modules.user_account.scan_interval_secs, 60);
    assert_eq!(
        config.modules.user_account.passwd_path,
        std::path::PathBuf::from("/etc/passwd")
    );
    assert_eq!(
        config.modules.user_account.group_path,
        std::path::PathBuf::from("/etc/group")
    );
}

#[test]
fn test_config_with_log_tamper_section() {
    use std::io::Write;
    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
    write!(
        tmpfile,
        r#"
[modules.log_tamper]
enabled = true
scan_interval_secs = 15
watch_paths = ["/var/log/syslog", "/var/log/auth.log"]
"#
    )
    .unwrap();
    let config = AppConfig::load(tmpfile.path()).unwrap();
    assert!(config.modules.log_tamper.enabled);
    assert_eq!(config.modules.log_tamper.scan_interval_secs, 15);
    assert_eq!(config.modules.log_tamper.watch_paths.len(), 2);
}

#[test]
fn test_config_log_tamper_disabled_by_default() {
    let config = AppConfig::load(Path::new("/tmp/nonexistent-zettai-config.toml")).unwrap();
    assert!(!config.modules.log_tamper.enabled);
    assert_eq!(config.modules.log_tamper.scan_interval_secs, 30);
    assert_eq!(config.modules.log_tamper.watch_paths.len(), 4);
}

#[test]
fn test_config_with_systemd_service_section() {
    use std::io::Write;
    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
    write!(
        tmpfile,
        r#"
[modules.systemd_service]
enabled = true
scan_interval_secs = 60
watch_paths = ["/etc/systemd/system"]
"#
    )
    .unwrap();
    let config = AppConfig::load(tmpfile.path()).unwrap();
    assert!(config.modules.systemd_service.enabled);
    assert_eq!(config.modules.systemd_service.scan_interval_secs, 60);
    assert_eq!(config.modules.systemd_service.watch_paths.len(), 1);
}

#[test]
fn test_config_systemd_service_disabled_by_default() {
    let config = AppConfig::load(Path::new("/tmp/nonexistent-zettai-config.toml")).unwrap();
    assert!(!config.modules.systemd_service.enabled);
    assert_eq!(config.modules.systemd_service.scan_interval_secs, 120);
    assert_eq!(config.modules.systemd_service.watch_paths.len(), 3);
}

#[test]
fn test_config_with_firewall_monitor_section() {
    use std::io::Write;
    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
    write!(
        tmpfile,
        r#"
[modules.firewall_monitor]
enabled = true
scan_interval_secs = 30
watch_paths = ["/proc/net/ip_tables_names", "/proc/net/ip6_tables_names"]
"#
    )
    .unwrap();
    let config = AppConfig::load(tmpfile.path()).unwrap();
    assert!(config.modules.firewall_monitor.enabled);
    assert_eq!(config.modules.firewall_monitor.scan_interval_secs, 30);
    assert_eq!(config.modules.firewall_monitor.watch_paths.len(), 2);
}

#[test]
fn test_config_firewall_monitor_disabled_by_default() {
    let config = AppConfig::load(Path::new("/tmp/nonexistent-zettai-config.toml")).unwrap();
    assert!(!config.modules.firewall_monitor.enabled);
    assert_eq!(config.modules.firewall_monitor.scan_interval_secs, 60);
    assert_eq!(config.modules.firewall_monitor.watch_paths.len(), 6);
}

#[test]
fn test_config_with_mount_monitor_section() {
    use std::io::Write;
    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
    write!(
        tmpfile,
        r#"
[modules.mount_monitor]
enabled = true
scan_interval_secs = 15
mounts_path = "/proc/mounts"
"#
    )
    .unwrap();
    let config = AppConfig::load(tmpfile.path()).unwrap();
    assert!(config.modules.mount_monitor.enabled);
    assert_eq!(config.modules.mount_monitor.scan_interval_secs, 15);
    assert_eq!(
        config.modules.mount_monitor.mounts_path,
        std::path::PathBuf::from("/proc/mounts")
    );
}

#[test]
fn test_config_mount_monitor_disabled_by_default() {
    let config = AppConfig::load(Path::new("/tmp/nonexistent-zettai-config.toml")).unwrap();
    assert!(!config.modules.mount_monitor.enabled);
    assert_eq!(config.modules.mount_monitor.scan_interval_secs, 30);
    assert_eq!(
        config.modules.mount_monitor.mounts_path,
        std::path::PathBuf::from("/proc/mounts")
    );
}

#[test]
fn test_config_file_integrity_disabled_by_default() {
    let config = AppConfig::load(Path::new("/tmp/nonexistent-zettai-config.toml")).unwrap();
    assert!(!config.modules.file_integrity.enabled);
    assert_eq!(config.modules.file_integrity.scan_interval_secs, 300);
    assert!(config.modules.file_integrity.watch_paths.is_empty());
}

#[tokio::test]
async fn test_daemon_sigterm_shutdown() {
    use std::time::Duration;
    use tokio::time::timeout;

    let child = tokio::process::Command::new(env!("CARGO_BIN_EXE_zettai-mamorukun"))
        .arg("--config")
        .arg("/tmp/nonexistent-zettai-config.toml")
        .kill_on_drop(true)
        .spawn()
        .expect("デーモンの起動に失敗しました");

    // デーモンが起動するのを待つ
    tokio::time::sleep(Duration::from_secs(1)).await;

    let pid = child.id().expect("PID の取得に失敗");

    // SAFETY: テストコードにおいて、起動済みの子プロセスに SIGTERM を送信する。
    // pid は直前に取得した有効なプロセス ID であり、対象プロセスは自テストで起動したもの。
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }

    // 3秒以内に終了することを確認
    let result = timeout(Duration::from_secs(3), child.wait_with_output()).await;
    assert!(result.is_ok(), "デーモンが3秒以内に終了しませんでした");
    let output = result.unwrap().expect("出力の取得に失敗");
    assert!(output.status.success());
}

#[test]
fn test_config_with_shell_config_monitor_section() {
    use std::io::Write;
    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
    write!(
        tmpfile,
        r#"
[modules.shell_config_monitor]
enabled = true
scan_interval_secs = 60
watch_paths = ["/etc/profile", "/etc/bash.bashrc"]
"#
    )
    .unwrap();
    let config = AppConfig::load(tmpfile.path()).unwrap();
    assert!(config.modules.shell_config_monitor.enabled);
    assert_eq!(config.modules.shell_config_monitor.scan_interval_secs, 60);
    assert_eq!(config.modules.shell_config_monitor.watch_paths.len(), 2);
}

#[test]
fn test_config_shell_config_monitor_disabled_by_default() {
    let config = AppConfig::load(Path::new("/tmp/nonexistent-zettai-config.toml")).unwrap();
    assert!(!config.modules.shell_config_monitor.enabled);
    assert_eq!(config.modules.shell_config_monitor.scan_interval_secs, 120);
    assert_eq!(config.modules.shell_config_monitor.watch_paths.len(), 5);
}

#[test]
fn test_config_sudoers_monitor_disabled_by_default() {
    let config = AppConfig::load(Path::new("/tmp/nonexistent-zettai-config.toml")).unwrap();
    assert!(!config.modules.sudoers_monitor.enabled);
    assert_eq!(config.modules.sudoers_monitor.scan_interval_secs, 120);
    assert_eq!(config.modules.sudoers_monitor.watch_paths.len(), 2);
}

#[test]
fn test_config_with_sudoers_monitor_section() {
    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
    use std::io::Write;
    write!(
        tmpfile,
        r#"
[modules.sudoers_monitor]
enabled = true
scan_interval_secs = 60
watch_paths = ["/etc/sudoers"]
"#
    )
    .unwrap();
    let config = AppConfig::load(tmpfile.path()).unwrap();
    assert!(config.modules.sudoers_monitor.enabled);
    assert_eq!(config.modules.sudoers_monitor.scan_interval_secs, 60);
    assert_eq!(config.modules.sudoers_monitor.watch_paths.len(), 1);
}

#[test]
fn test_config_ssh_brute_force_disabled_by_default() {
    let config = AppConfig::load(Path::new("/tmp/nonexistent-zettai-config.toml")).unwrap();
    assert!(!config.modules.ssh_brute_force.enabled);
    assert_eq!(config.modules.ssh_brute_force.interval_secs, 30);
    assert_eq!(
        config.modules.ssh_brute_force.auth_log_path,
        std::path::PathBuf::from("/var/log/auth.log")
    );
    assert_eq!(config.modules.ssh_brute_force.max_failures, 5);
    assert_eq!(config.modules.ssh_brute_force.time_window_secs, 300);
}

#[test]
fn test_config_with_ssh_brute_force_section() {
    use std::io::Write;
    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
    write!(
        tmpfile,
        r#"
[modules.ssh_brute_force]
enabled = true
interval_secs = 15
auth_log_path = "/var/log/auth.log"
max_failures = 10
time_window_secs = 600
"#
    )
    .unwrap();
    let config = AppConfig::load(tmpfile.path()).unwrap();
    assert!(config.modules.ssh_brute_force.enabled);
    assert_eq!(config.modules.ssh_brute_force.interval_secs, 15);
    assert_eq!(
        config.modules.ssh_brute_force.auth_log_path,
        std::path::PathBuf::from("/var/log/auth.log")
    );
    assert_eq!(config.modules.ssh_brute_force.max_failures, 10);
    assert_eq!(config.modules.ssh_brute_force.time_window_secs, 600);
}

#[test]
fn test_config_event_bus_defaults() {
    let config = AppConfig::load(Path::new("/tmp/nonexistent-zettai-config.toml")).unwrap();
    assert!(!config.event_bus.enabled);
    assert_eq!(config.event_bus.channel_capacity, 1024);
}

#[test]
fn test_config_with_event_bus_section() {
    use std::io::Write;
    let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
    write!(
        tmpfile,
        r#"
[event_bus]
enabled = true
channel_capacity = 256
"#
    )
    .unwrap();
    let config = AppConfig::load(tmpfile.path()).unwrap();
    assert!(config.event_bus.enabled);
    assert_eq!(config.event_bus.channel_capacity, 256);
}
