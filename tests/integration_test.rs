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
