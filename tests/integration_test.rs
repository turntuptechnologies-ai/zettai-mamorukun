use std::path::Path;
use zettai_mamorukun::config::AppConfig;

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
