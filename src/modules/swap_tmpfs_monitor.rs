//! スワップ / tmpfs 監視モジュール
//!
//! スワップ領域や tmpfs の不審な使用を定期スキャンし、
//! セキュリティリスクを検知する。
//!
//! 検知対象:
//! - スワップデバイスの追加・削除
//! - swappiness パラメータの変更
//! - tmpfs マウントの追加・削除
//! - tmpfs 上の実行ファイル（ELF バイナリ含む）
//! - tmpfs の使用量が閾値を超えた場合

use crate::config::SwapTmpfsMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

/// ELF マジックバイト（先頭 4 バイト）
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// スワップデバイスの情報
#[derive(Debug, Clone, PartialEq, Eq)]
struct SwapEntry {
    /// デバイスパス
    path: String,
    /// タイプ（partition / file）
    swap_type: String,
    /// サイズ（KB）
    size_kb: u64,
    /// 使用中（KB）
    used_kb: u64,
}

/// tmpfs マウントの情報
#[derive(Debug, Clone, PartialEq, Eq)]
struct TmpfsMount {
    /// マウントポイント
    mount_point: String,
    /// マウントオプション
    options: String,
}

/// tmpfs の使用状況
#[derive(Debug, Clone)]
struct TmpfsUsage {
    /// 全体のサイズ（バイト）
    total_bytes: u64,
    /// 使用中のサイズ（バイト）
    used_bytes: u64,
    /// 使用率（%）
    usage_percent: u64,
}

/// スナップショット — スワップ・tmpfs の現在の状態
struct Snapshot {
    /// スワップデバイス（パス → エントリ）
    swaps: HashMap<String, SwapEntry>,
    /// tmpfs マウント（マウントポイント → マウント情報）
    tmpfs_mounts: HashMap<String, TmpfsMount>,
    /// swappiness 値
    swappiness: u64,
}

/// スワップ / tmpfs 監視モジュール
///
/// `/proc/swaps`、`/proc/sys/vm/swappiness`、`/proc/mounts` を定期的に読み取り、
/// スワップ・tmpfs の構成変更やセキュリティリスクを検知する。
pub struct SwapTmpfsMonitorModule {
    config: SwapTmpfsMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl SwapTmpfsMonitorModule {
    /// 新しいスワップ / tmpfs 監視モジュールを作成する
    pub fn new(config: SwapTmpfsMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// `/proc/swaps` を読み取り、スワップデバイスの一覧を返す
    fn read_swaps(proc_path: &str) -> HashMap<String, SwapEntry> {
        let swaps_path = format!("{}/swaps", proc_path);
        let content = match std::fs::read_to_string(&swaps_path) {
            Ok(c) => c,
            Err(err) => {
                tracing::debug!(error = %err, path = %swaps_path, "/proc/swaps の読み取りに失敗しました");
                return HashMap::new();
            }
        };

        let mut swaps = HashMap::new();
        for line in content.lines().skip(1) {
            if let Some(entry) = Self::parse_swap_line(line) {
                swaps.insert(entry.path.clone(), entry);
            }
        }
        swaps
    }

    /// /proc/swaps の1行をパースする
    fn parse_swap_line(line: &str) -> Option<SwapEntry> {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 {
            return None;
        }
        let size_kb = fields[2].parse::<u64>().unwrap_or(0);
        let used_kb = fields[3].parse::<u64>().unwrap_or(0);
        Some(SwapEntry {
            path: fields[0].to_string(),
            swap_type: fields[1].to_string(),
            size_kb,
            used_kb,
        })
    }

    /// `/proc/sys/vm/swappiness` を読み取る
    fn read_swappiness(proc_path: &str) -> u64 {
        let path = format!("{}/sys/vm/swappiness", proc_path);
        match std::fs::read_to_string(&path) {
            Ok(content) => content.trim().parse::<u64>().unwrap_or(60),
            Err(err) => {
                tracing::debug!(error = %err, path = %path, "swappiness の読み取りに失敗しました");
                60
            }
        }
    }

    /// `/proc/mounts` から tmpfs マウントを読み取る
    fn read_tmpfs_mounts(proc_path: &str, exclude_paths: &[String]) -> HashMap<String, TmpfsMount> {
        let mounts_path = format!("{}/mounts", proc_path);
        let content = match std::fs::read_to_string(&mounts_path) {
            Ok(c) => c,
            Err(err) => {
                tracing::debug!(error = %err, path = %mounts_path, "/proc/mounts の読み取りに失敗しました");
                return HashMap::new();
            }
        };

        let exclude_set: HashSet<&str> = exclude_paths.iter().map(|s| s.as_str()).collect();
        let mut mounts = HashMap::new();

        for line in content.lines() {
            if let Some(mount) = Self::parse_mount_line(line)
                && !exclude_set.contains(mount.mount_point.as_str())
            {
                mounts.insert(mount.mount_point.clone(), mount);
            }
        }
        mounts
    }

    /// /proc/mounts の1行から tmpfs マウントをパースする
    fn parse_mount_line(line: &str) -> Option<TmpfsMount> {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            return None;
        }
        // fstype が tmpfs のもののみ
        if fields[2] != "tmpfs" {
            return None;
        }
        Some(TmpfsMount {
            mount_point: fields[1].to_string(),
            options: fields[3].to_string(),
        })
    }

    /// tmpfs の使用状況を取得する
    fn get_tmpfs_usage(mount_point: &str) -> Option<TmpfsUsage> {
        use std::ffi::CString;
        let c_path = CString::new(mount_point).ok()?;
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: c_path は有効な NUL 終端文字列で、stat は zeroed() で初期化済み
        let ret = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
        if ret != 0 {
            tracing::debug!(
                mount = %mount_point,
                "tmpfs の statvfs に失敗しました"
            );
            return None;
        }
        let block_size = stat.f_frsize;
        let total_bytes = stat.f_blocks * block_size;
        let free_bytes = stat.f_bavail * block_size;
        if total_bytes == 0 {
            return None;
        }
        let used_bytes = total_bytes.saturating_sub(free_bytes);
        let usage_percent = (used_bytes * 100) / total_bytes;
        Some(TmpfsUsage {
            total_bytes,
            used_bytes,
            usage_percent,
        })
    }

    /// tmpfs マウントポイント上の実行ファイルを検出する
    fn scan_tmpfs_executables(mount_point: &str) -> Vec<PathBuf> {
        let mut executables = Vec::new();
        let path = PathBuf::from(mount_point);
        if !path.exists() {
            return executables;
        }

        let entries = match std::fs::read_dir(&path) {
            Ok(entries) => entries,
            Err(err) => {
                tracing::debug!(error = %err, path = %mount_point, "tmpfs ディレクトリの読み取りに失敗しました");
                return executables;
            }
        };

        for entry in entries.filter_map(|e| e.ok()) {
            let file_path = entry.path();
            let metadata = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if !metadata.is_file() {
                continue;
            }
            // 実行権限があるか ELF バイナリか
            if metadata.permissions().mode() & 0o111 != 0 || Self::is_elf_binary(&file_path) {
                executables.push(file_path);
            }
        }
        executables
    }

    /// ファイルが ELF バイナリかどうかを判定する
    fn is_elf_binary(path: &PathBuf) -> bool {
        match std::fs::File::open(path) {
            Ok(mut file) => {
                use std::io::Read;
                let mut buf = [0u8; 4];
                match file.read_exact(&mut buf) {
                    Ok(()) => buf == ELF_MAGIC,
                    Err(_) => false,
                }
            }
            Err(_) => false,
        }
    }

    /// 現在のスナップショットを取得する
    fn take_snapshot(proc_path: &str, exclude_paths: &[String]) -> Snapshot {
        Snapshot {
            swaps: Self::read_swaps(proc_path),
            tmpfs_mounts: Self::read_tmpfs_mounts(proc_path, exclude_paths),
            swappiness: Self::read_swappiness(proc_path),
        }
    }

    /// ベースラインと現在のスナップショットを比較し、変更を検知する。
    /// 変更があった場合は `true` を返す。
    fn detect_and_report(
        baseline: &Snapshot,
        current: &Snapshot,
        event_bus: &Option<EventBus>,
        config: &SwapTmpfsMonitorConfig,
    ) -> bool {
        let mut has_changes = false;

        // スワップデバイスの追加検知
        for (path, entry) in &current.swaps {
            if !baseline.swaps.contains_key(path) {
                tracing::warn!(
                    path = %path,
                    swap_type = %entry.swap_type,
                    size_kb = entry.size_kb,
                    "スワップデバイスが追加されました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "swap_device_added",
                            Severity::Warning,
                            "swap_tmpfs_monitor",
                            "スワップデバイスが追加されました",
                        )
                        .with_details(format!(
                            "path={}, type={}, size={}KB",
                            path, entry.swap_type, entry.size_kb
                        )),
                    );
                }
                has_changes = true;
            }
        }

        // スワップデバイスの削除検知
        for path in baseline.swaps.keys() {
            if !current.swaps.contains_key(path) {
                tracing::warn!(
                    path = %path,
                    "スワップデバイスが削除されました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "swap_device_removed",
                            Severity::Warning,
                            "swap_tmpfs_monitor",
                            "スワップデバイスが削除されました",
                        )
                        .with_details(path.clone()),
                    );
                }
                has_changes = true;
            }
        }

        // swappiness の変更検知
        if current.swappiness != baseline.swappiness {
            tracing::info!(
                old = baseline.swappiness,
                new = current.swappiness,
                "swappiness パラメータが変更されました"
            );
            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        "swappiness_changed",
                        Severity::Info,
                        "swap_tmpfs_monitor",
                        "swappiness パラメータが変更されました",
                    )
                    .with_details(format!(
                        "old={}, new={}",
                        baseline.swappiness, current.swappiness
                    )),
                );
            }
            has_changes = true;
        }

        // tmpfs マウントの追加検知
        for mount_point in current.tmpfs_mounts.keys() {
            if !baseline.tmpfs_mounts.contains_key(mount_point) {
                tracing::warn!(
                    mount_point = %mount_point,
                    "新しい tmpfs マウントが追加されました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "tmpfs_added",
                            Severity::Warning,
                            "swap_tmpfs_monitor",
                            "新しい tmpfs マウントが追加されました",
                        )
                        .with_details(mount_point.clone()),
                    );
                }
                has_changes = true;
            }
        }

        // tmpfs マウントの削除検知
        for mount_point in baseline.tmpfs_mounts.keys() {
            if !current.tmpfs_mounts.contains_key(mount_point) {
                tracing::info!(
                    mount_point = %mount_point,
                    "tmpfs マウントが削除されました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "tmpfs_removed",
                            Severity::Info,
                            "swap_tmpfs_monitor",
                            "tmpfs マウントが削除されました",
                        )
                        .with_details(mount_point.clone()),
                    );
                }
                has_changes = true;
            }
        }

        // tmpfs 上の実行ファイル検知
        if config.scan_executables {
            for mount_point in current.tmpfs_mounts.keys() {
                let executables = Self::scan_tmpfs_executables(mount_point);
                for exec_path in &executables {
                    let is_elf = Self::is_elf_binary(exec_path);
                    let severity = if is_elf {
                        Severity::Critical
                    } else {
                        Severity::Warning
                    };
                    let msg = if is_elf {
                        "tmpfs 上に ELF バイナリが検出されました"
                    } else {
                        "tmpfs 上に実行可能ファイルが検出されました"
                    };
                    tracing::warn!(
                        path = %exec_path.display(),
                        mount_point = %mount_point,
                        is_elf = is_elf,
                        "{}", msg
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "tmpfs_executable_found",
                                severity,
                                "swap_tmpfs_monitor",
                                msg,
                            )
                            .with_details(format!(
                                "path={}, mount={}, elf={}",
                                exec_path.display(),
                                mount_point,
                                is_elf
                            )),
                        );
                    }
                    has_changes = true;
                }
            }
        }

        // tmpfs 使用量の閾値チェック
        for mount_point in current.tmpfs_mounts.keys() {
            if let Some(usage) = Self::get_tmpfs_usage(mount_point)
                && usage.usage_percent >= config.tmpfs_usage_threshold_percent
            {
                tracing::warn!(
                    mount_point = %mount_point,
                    usage_percent = usage.usage_percent,
                    used_bytes = usage.used_bytes,
                    total_bytes = usage.total_bytes,
                    threshold = config.tmpfs_usage_threshold_percent,
                    "tmpfs の使用量が閾値を超えました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "tmpfs_usage_high",
                            Severity::Warning,
                            "swap_tmpfs_monitor",
                            "tmpfs の使用量が閾値を超えました",
                        )
                        .with_details(format!(
                            "mount={}, usage={}%, used={}bytes, total={}bytes, threshold={}%",
                            mount_point,
                            usage.usage_percent,
                            usage.used_bytes,
                            usage.total_bytes,
                            config.tmpfs_usage_threshold_percent
                        )),
                    );
                }
                has_changes = true;
            }
        }

        has_changes
    }
}

impl Module for SwapTmpfsMonitorModule {
    fn name(&self) -> &str {
        "swap_tmpfs_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        if self.config.tmpfs_usage_threshold_percent > 100 {
            return Err(AppError::ModuleConfig {
                message: "tmpfs_usage_threshold_percent は 0〜100 の範囲で指定してください"
                    .to_string(),
            });
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            tmpfs_usage_threshold_percent = self.config.tmpfs_usage_threshold_percent,
            scan_executables = self.config.scan_executables,
            exclude_paths = ?self.config.exclude_paths,
            "スワップ / tmpfs 監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<(), AppError> {
        let proc_path = self.config.proc_path.clone();
        let exclude_paths = self.config.exclude_paths.clone();
        let baseline = Self::take_snapshot(&proc_path, &exclude_paths);
        tracing::info!(
            swap_count = baseline.swaps.len(),
            tmpfs_count = baseline.tmpfs_mounts.len(),
            swappiness = baseline.swappiness,
            "ベースラインスキャンが完了しました"
        );

        let scan_interval_secs = self.config.scan_interval_secs;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            interval.tick().await;

            let mut baseline = baseline;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("スワップ / tmpfs 監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = SwapTmpfsMonitorModule::take_snapshot(
                            &config.proc_path,
                            &config.exclude_paths,
                        );
                        let changed = SwapTmpfsMonitorModule::detect_and_report(
                            &baseline,
                            &current,
                            &event_bus,
                            &config,
                        );

                        if changed {
                            baseline = current;
                        } else {
                            tracing::debug!("スワップ / tmpfs に変更はありません");
                        }
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

        let snapshot = Self::take_snapshot(&self.config.proc_path, &self.config.exclude_paths);
        let mut issues_found = 0;
        let mut scan_snapshot = BTreeMap::new();

        // スワップデバイスを記録
        for (path, entry) in &snapshot.swaps {
            scan_snapshot.insert(
                format!("swap:{}", path),
                format!(
                    "type={},size={}KB,used={}KB",
                    entry.swap_type, entry.size_kb, entry.used_kb
                ),
            );
        }

        // swappiness を記録
        scan_snapshot.insert("swappiness".to_string(), snapshot.swappiness.to_string());

        // tmpfs マウントを記録
        for (mount_point, mount) in &snapshot.tmpfs_mounts {
            let mut details = format!("options={}", mount.options);

            // 使用量チェック
            if let Some(usage) = Self::get_tmpfs_usage(mount_point) {
                details.push_str(&format!(
                    ",usage={}%,used={}bytes,total={}bytes",
                    usage.usage_percent, usage.used_bytes, usage.total_bytes
                ));
                if usage.usage_percent >= self.config.tmpfs_usage_threshold_percent {
                    issues_found += 1;
                }
            }

            // 実行ファイルチェック
            if self.config.scan_executables {
                let executables = Self::scan_tmpfs_executables(mount_point);
                if !executables.is_empty() {
                    issues_found += executables.len();
                    let exec_list: Vec<String> = executables
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect();
                    details.push_str(&format!(",executables={}", exec_list.join(";")));
                }
            }

            scan_snapshot.insert(format!("tmpfs:{}", mount_point), details);
        }

        let items_scanned = snapshot.swaps.len() + snapshot.tmpfs_mounts.len();
        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "スワップ {}件、tmpfs {}件をスキャンし、{}件の問題を検出しました（swappiness={}）",
                snapshot.swaps.len(),
                snapshot.tmpfs_mounts.len(),
                issues_found,
                snapshot.swappiness
            ),
            snapshot: scan_snapshot,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn make_config(proc_dir: &str) -> SwapTmpfsMonitorConfig {
        SwapTmpfsMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            tmpfs_usage_threshold_percent: 80,
            scan_executables: true,
            exclude_paths: vec!["/dev/shm".to_string()],
            proc_path: proc_dir.to_string(),
        }
    }

    #[test]
    fn test_parse_swap_line_valid() {
        let line = "/dev/sda2                               partition\t2097148\t0\t-2";
        let entry = SwapTmpfsMonitorModule::parse_swap_line(line).unwrap();
        assert_eq!(entry.path, "/dev/sda2");
        assert_eq!(entry.swap_type, "partition");
        assert_eq!(entry.size_kb, 2097148);
        assert_eq!(entry.used_kb, 0);
    }

    #[test]
    fn test_parse_swap_line_file() {
        let line = "/swapfile                               file\t\t4194300\t1024\t-3";
        let entry = SwapTmpfsMonitorModule::parse_swap_line(line).unwrap();
        assert_eq!(entry.path, "/swapfile");
        assert_eq!(entry.swap_type, "file");
        assert_eq!(entry.size_kb, 4194300);
        assert_eq!(entry.used_kb, 1024);
    }

    #[test]
    fn test_parse_swap_line_too_short() {
        let line = "/dev/sda2 partition";
        assert!(SwapTmpfsMonitorModule::parse_swap_line(line).is_none());
    }

    #[test]
    fn test_parse_mount_line_tmpfs() {
        let line = "tmpfs /tmp tmpfs rw,nosuid,nodev 0 0";
        let mount = SwapTmpfsMonitorModule::parse_mount_line(line).unwrap();
        assert_eq!(mount.mount_point, "/tmp");
        assert_eq!(mount.options, "rw,nosuid,nodev");
    }

    #[test]
    fn test_parse_mount_line_non_tmpfs() {
        let line = "/dev/sda1 / ext4 rw,relatime 0 0";
        assert!(SwapTmpfsMonitorModule::parse_mount_line(line).is_none());
    }

    #[test]
    fn test_parse_mount_line_too_short() {
        let line = "tmpfs /tmp";
        assert!(SwapTmpfsMonitorModule::parse_mount_line(line).is_none());
    }

    #[test]
    fn test_read_swaps_with_mock_proc() {
        let dir = TempDir::new().unwrap();
        let swaps_content = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n/dev/sda2                               partition\t2097148\t\t0\t\t-2\n";
        fs::write(dir.path().join("swaps"), swaps_content).unwrap();

        let swaps = SwapTmpfsMonitorModule::read_swaps(dir.path().to_str().unwrap());
        assert_eq!(swaps.len(), 1);
        assert!(swaps.contains_key("/dev/sda2"));
    }

    #[test]
    fn test_read_swaps_nonexistent() {
        let swaps = SwapTmpfsMonitorModule::read_swaps("/tmp/nonexistent_zettai_proc_test");
        assert!(swaps.is_empty());
    }

    #[test]
    fn test_read_swappiness_with_mock() {
        let dir = TempDir::new().unwrap();
        let sys_vm = dir.path().join("sys/vm");
        fs::create_dir_all(&sys_vm).unwrap();
        fs::write(sys_vm.join("swappiness"), "60\n").unwrap();

        let val = SwapTmpfsMonitorModule::read_swappiness(dir.path().to_str().unwrap());
        assert_eq!(val, 60);
    }

    #[test]
    fn test_read_swappiness_nonexistent() {
        let val = SwapTmpfsMonitorModule::read_swappiness("/tmp/nonexistent_zettai_proc_test");
        assert_eq!(val, 60); // デフォルト値
    }

    #[test]
    fn test_read_tmpfs_mounts_with_mock() {
        let dir = TempDir::new().unwrap();
        let mounts_content = "/dev/sda1 / ext4 rw,relatime 0 0\ntmpfs /tmp tmpfs rw,nosuid,nodev 0 0\ntmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0\ntmpfs /run tmpfs rw,nosuid 0 0\n";
        fs::write(dir.path().join("mounts"), mounts_content).unwrap();

        let exclude = vec!["/dev/shm".to_string()];
        let mounts =
            SwapTmpfsMonitorModule::read_tmpfs_mounts(dir.path().to_str().unwrap(), &exclude);
        assert_eq!(mounts.len(), 2); // /tmp, /run（/dev/shm は除外）
        assert!(mounts.contains_key("/tmp"));
        assert!(mounts.contains_key("/run"));
        assert!(!mounts.contains_key("/dev/shm"));
    }

    #[test]
    fn test_read_tmpfs_mounts_no_exclude() {
        let dir = TempDir::new().unwrap();
        let mounts_content = "tmpfs /tmp tmpfs rw 0 0\ntmpfs /dev/shm tmpfs rw 0 0\n";
        fs::write(dir.path().join("mounts"), mounts_content).unwrap();

        let mounts = SwapTmpfsMonitorModule::read_tmpfs_mounts(dir.path().to_str().unwrap(), &[]);
        assert_eq!(mounts.len(), 2);
    }

    #[test]
    fn test_scan_tmpfs_executables_empty_dir() {
        let dir = TempDir::new().unwrap();
        let executables =
            SwapTmpfsMonitorModule::scan_tmpfs_executables(dir.path().to_str().unwrap());
        assert!(executables.is_empty());
    }

    #[test]
    fn test_scan_tmpfs_executables_with_exec() {
        let dir = TempDir::new().unwrap();
        let exec_path = dir.path().join("script.sh");
        fs::write(&exec_path, "#!/bin/sh\necho test").unwrap();
        fs::set_permissions(&exec_path, fs::Permissions::from_mode(0o755)).unwrap();

        // 通常ファイル（実行権限なし）
        let normal_path = dir.path().join("data.txt");
        fs::write(&normal_path, "just data").unwrap();

        let executables =
            SwapTmpfsMonitorModule::scan_tmpfs_executables(dir.path().to_str().unwrap());
        assert_eq!(executables.len(), 1);
        assert_eq!(executables[0], exec_path);
    }

    #[test]
    fn test_scan_tmpfs_executables_with_elf() {
        let dir = TempDir::new().unwrap();
        let elf_path = dir.path().join("binary");
        let mut file = fs::File::create(&elf_path).unwrap();
        file.write_all(&[0x7f, b'E', b'L', b'F', 0, 0, 0, 0])
            .unwrap();
        drop(file);
        // ELF は実行権限なくても検知される
        fs::set_permissions(&elf_path, fs::Permissions::from_mode(0o644)).unwrap();

        let executables =
            SwapTmpfsMonitorModule::scan_tmpfs_executables(dir.path().to_str().unwrap());
        assert_eq!(executables.len(), 1);
    }

    #[test]
    fn test_scan_tmpfs_executables_nonexistent() {
        let executables =
            SwapTmpfsMonitorModule::scan_tmpfs_executables("/tmp/nonexistent_zettai_tmpfs_test");
        assert!(executables.is_empty());
    }

    #[test]
    fn test_is_elf_binary_true() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("elf");
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(&[0x7f, b'E', b'L', b'F', 1, 1, 1, 0])
            .unwrap();
        drop(file);
        assert!(SwapTmpfsMonitorModule::is_elf_binary(&path));
    }

    #[test]
    fn test_is_elf_binary_false() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("not_elf");
        fs::write(&path, "not an elf binary").unwrap();
        assert!(!SwapTmpfsMonitorModule::is_elf_binary(&path));
    }

    #[test]
    fn test_detect_swap_added() {
        let baseline = Snapshot {
            swaps: HashMap::new(),
            tmpfs_mounts: HashMap::new(),
            swappiness: 60,
        };
        let mut current_swaps = HashMap::new();
        current_swaps.insert(
            "/dev/sda2".to_string(),
            SwapEntry {
                path: "/dev/sda2".to_string(),
                swap_type: "partition".to_string(),
                size_kb: 2097148,
                used_kb: 0,
            },
        );
        let current = Snapshot {
            swaps: current_swaps,
            tmpfs_mounts: HashMap::new(),
            swappiness: 60,
        };
        let config = make_config("/proc");
        assert!(SwapTmpfsMonitorModule::detect_and_report(
            &baseline, &current, &None, &config
        ));
    }

    #[test]
    fn test_detect_swap_removed() {
        let mut baseline_swaps = HashMap::new();
        baseline_swaps.insert(
            "/dev/sda2".to_string(),
            SwapEntry {
                path: "/dev/sda2".to_string(),
                swap_type: "partition".to_string(),
                size_kb: 2097148,
                used_kb: 0,
            },
        );
        let baseline = Snapshot {
            swaps: baseline_swaps,
            tmpfs_mounts: HashMap::new(),
            swappiness: 60,
        };
        let current = Snapshot {
            swaps: HashMap::new(),
            tmpfs_mounts: HashMap::new(),
            swappiness: 60,
        };
        let config = make_config("/proc");
        assert!(SwapTmpfsMonitorModule::detect_and_report(
            &baseline, &current, &None, &config
        ));
    }

    #[test]
    fn test_detect_swappiness_changed() {
        let baseline = Snapshot {
            swaps: HashMap::new(),
            tmpfs_mounts: HashMap::new(),
            swappiness: 60,
        };
        let current = Snapshot {
            swaps: HashMap::new(),
            tmpfs_mounts: HashMap::new(),
            swappiness: 10,
        };
        let config = make_config("/proc");
        assert!(SwapTmpfsMonitorModule::detect_and_report(
            &baseline, &current, &None, &config
        ));
    }

    #[test]
    fn test_detect_tmpfs_added() {
        let baseline = Snapshot {
            swaps: HashMap::new(),
            tmpfs_mounts: HashMap::new(),
            swappiness: 60,
        };
        let mut current_mounts = HashMap::new();
        current_mounts.insert(
            "/tmp/new_tmpfs".to_string(),
            TmpfsMount {
                mount_point: "/tmp/new_tmpfs".to_string(),
                options: "rw,nosuid".to_string(),
            },
        );
        let current = Snapshot {
            swaps: HashMap::new(),
            tmpfs_mounts: current_mounts,
            swappiness: 60,
        };
        let mut config = make_config("/proc");
        config.scan_executables = false; // スキャン対象パスが存在しないためスキップ
        assert!(SwapTmpfsMonitorModule::detect_and_report(
            &baseline, &current, &None, &config
        ));
    }

    #[test]
    fn test_detect_tmpfs_removed() {
        let mut baseline_mounts = HashMap::new();
        baseline_mounts.insert(
            "/tmp/old_tmpfs".to_string(),
            TmpfsMount {
                mount_point: "/tmp/old_tmpfs".to_string(),
                options: "rw".to_string(),
            },
        );
        let baseline = Snapshot {
            swaps: HashMap::new(),
            tmpfs_mounts: baseline_mounts,
            swappiness: 60,
        };
        let current = Snapshot {
            swaps: HashMap::new(),
            tmpfs_mounts: HashMap::new(),
            swappiness: 60,
        };
        let mut config = make_config("/proc");
        config.scan_executables = false;
        assert!(SwapTmpfsMonitorModule::detect_and_report(
            &baseline, &current, &None, &config
        ));
    }

    #[test]
    fn test_detect_no_changes() {
        let mut swaps = HashMap::new();
        swaps.insert(
            "/dev/sda2".to_string(),
            SwapEntry {
                path: "/dev/sda2".to_string(),
                swap_type: "partition".to_string(),
                size_kb: 2097148,
                used_kb: 0,
            },
        );
        let baseline = Snapshot {
            swaps: swaps.clone(),
            tmpfs_mounts: HashMap::new(),
            swappiness: 60,
        };
        let current = Snapshot {
            swaps,
            tmpfs_mounts: HashMap::new(),
            swappiness: 60,
        };
        let mut config = make_config("/proc");
        config.scan_executables = false;
        assert!(!SwapTmpfsMonitorModule::detect_and_report(
            &baseline, &current, &None, &config
        ));
    }

    #[test]
    fn test_init_zero_interval() {
        let config = SwapTmpfsMonitorConfig {
            enabled: true,
            scan_interval_secs: 0,
            ..SwapTmpfsMonitorConfig::default()
        };
        let mut module = SwapTmpfsMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_invalid_threshold() {
        let config = SwapTmpfsMonitorConfig {
            enabled: true,
            tmpfs_usage_threshold_percent: 101,
            ..SwapTmpfsMonitorConfig::default()
        };
        let mut module = SwapTmpfsMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let config = SwapTmpfsMonitorConfig::default();
        let mut module = SwapTmpfsMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let config = SwapTmpfsMonitorConfig {
            enabled: true,
            scan_interval_secs: 3600,
            ..SwapTmpfsMonitorConfig::default()
        };
        let mut module = SwapTmpfsMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();
        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let dir = TempDir::new().unwrap();
        // モック /proc/swaps
        let swaps_content = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n";
        fs::write(dir.path().join("swaps"), swaps_content).unwrap();
        // モック /proc/sys/vm/swappiness
        let sys_vm = dir.path().join("sys/vm");
        fs::create_dir_all(&sys_vm).unwrap();
        fs::write(sys_vm.join("swappiness"), "60\n").unwrap();
        // モック /proc/mounts
        fs::write(dir.path().join("mounts"), "").unwrap();

        let config = make_config(dir.path().to_str().unwrap());
        let module = SwapTmpfsMonitorModule::new(config, None);
        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.issues_found, 0);
        assert!(result.snapshot.contains_key("swappiness"));
    }

    #[tokio::test]
    async fn test_initial_scan_with_swaps() {
        let dir = TempDir::new().unwrap();
        let swaps_content = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n/dev/sda2                               partition\t2097148\t\t0\t\t-2\n";
        fs::write(dir.path().join("swaps"), swaps_content).unwrap();
        let sys_vm = dir.path().join("sys/vm");
        fs::create_dir_all(&sys_vm).unwrap();
        fs::write(sys_vm.join("swappiness"), "60\n").unwrap();
        fs::write(dir.path().join("mounts"), "").unwrap();

        let config = make_config(dir.path().to_str().unwrap());
        let module = SwapTmpfsMonitorModule::new(config, None);
        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 1);
        assert!(result.snapshot.contains_key("swap:/dev/sda2"));
    }
}
