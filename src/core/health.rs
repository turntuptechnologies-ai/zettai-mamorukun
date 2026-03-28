use std::fs;
use std::time::Instant;

/// デーモンの健全性情報
#[derive(Debug)]
pub struct HealthStatus {
    /// 稼働時間（秒）
    pub uptime_secs: u64,
    /// メモリ使用量（KB）。取得できない場合は None。
    pub memory_rss_kb: Option<u64>,
}

/// デーモンのヘルスチェックを行う
pub struct HealthChecker {
    started_at: Instant,
}

impl HealthChecker {
    /// 新しいヘルスチェッカーを作成する
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
        }
    }

    /// 現在のヘルスステータスを取得する
    pub fn status(&self) -> HealthStatus {
        HealthStatus {
            uptime_secs: self.started_at.elapsed().as_secs(),
            memory_rss_kb: read_vm_rss_kb(),
        }
    }
}

impl Default for HealthChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// `/proc/self/status` から VmRSS（物理メモリ使用量）を読み取る
fn read_vm_rss_kb() -> Option<u64> {
    let content = fs::read_to_string("/proc/self/status").ok()?;
    for line in content.lines() {
        if let Some(value) = line.strip_prefix("VmRSS:") {
            let value = value.trim().trim_end_matches("kB").trim();
            return value.parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_health_checker_uptime() {
        let checker = HealthChecker::new();
        thread::sleep(Duration::from_millis(100));
        let status = checker.status();
        // 少なくとも 0 秒以上（ミリ秒単位のスリープなので 0 または 1）
        assert!(status.uptime_secs < 5);
    }

    #[test]
    fn test_health_checker_memory() {
        let checker = HealthChecker::new();
        let status = checker.status();
        // Linux 環境では /proc/self/status が存在するので Some が返る
        if cfg!(target_os = "linux") {
            assert!(status.memory_rss_kb.is_some());
            assert!(status.memory_rss_kb.unwrap() > 0);
        }
    }

    #[test]
    fn test_read_vm_rss_kb() {
        let rss = read_vm_rss_kb();
        if cfg!(target_os = "linux") {
            assert!(rss.is_some());
            assert!(rss.unwrap() > 0);
        }
    }

    #[test]
    fn test_health_checker_default() {
        let checker = HealthChecker::default();
        let status = checker.status();
        assert!(status.uptime_secs < 5);
    }
}
