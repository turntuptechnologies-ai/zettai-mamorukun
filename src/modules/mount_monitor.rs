//! マウントポイント監視モジュール
//!
//! `/proc/mounts` を定期的にスキャンし、マウントポイントの変更を検知する。
//!
//! 検知対象:
//! - 新規マウントポイントの追加
//! - 既存マウントポイントの削除
//! - マウントオプションやファイルシステムタイプの変更

use crate::config::MountMonitorConfig;
use crate::error::AppError;
use crate::modules::Module;
use std::collections::HashMap;
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

/// マウントエントリ（`/proc/mounts` の 1 行分）
#[derive(Debug, Clone, PartialEq, Eq)]
struct MountEntry {
    device: String,
    mount_point: String,
    fs_type: String,
    options: String,
}

/// マウントポイント変更レポート
struct ChangeReport {
    added: Vec<MountEntry>,
    removed: Vec<MountEntry>,
    modified: Vec<(MountEntry, MountEntry)>,
}

impl ChangeReport {
    /// 変更があったかどうかを返す
    fn has_changes(&self) -> bool {
        !self.added.is_empty() || !self.removed.is_empty() || !self.modified.is_empty()
    }
}

/// マウントポイント監視モジュール
///
/// `/proc/mounts` を定期スキャンし、ベースラインとの差分を検知する。
pub struct MountMonitorModule {
    config: MountMonitorConfig,
    cancel_token: CancellationToken,
}

impl MountMonitorModule {
    /// 新しいマウントポイント監視モジュールを作成する
    pub fn new(config: MountMonitorConfig) -> Self {
        Self {
            config,
            cancel_token: CancellationToken::new(),
        }
    }

    /// キャンセルトークンのクローンを返す
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    /// `/proc/mounts` の内容をパースしてマウントエントリのリストを返す
    fn parse_mounts(content: &str) -> Vec<MountEntry> {
        content
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() {
                    return None;
                }
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 4 {
                    tracing::debug!(
                        line = line,
                        "マウントエントリのパースに失敗しました。フィールド数不足"
                    );
                    return None;
                }
                Some(MountEntry {
                    device: fields[0].to_string(),
                    mount_point: fields[1].to_string(),
                    fs_type: fields[2].to_string(),
                    options: fields[3].to_string(),
                })
            })
            .collect()
    }

    /// マウントエントリのリストを mount_point をキーとする HashMap に変換する
    fn entries_to_map(entries: &[MountEntry]) -> HashMap<String, MountEntry> {
        let mut map = HashMap::new();
        for entry in entries {
            map.insert(entry.mount_point.clone(), entry.clone());
        }
        map
    }

    /// `/proc/mounts` ファイルを読み込みパースする
    fn read_mounts(mounts_path: &PathBuf) -> Result<Vec<MountEntry>, AppError> {
        let content = std::fs::read_to_string(mounts_path).map_err(|e| AppError::FileIo {
            path: mounts_path.clone(),
            source: e,
        })?;
        Ok(Self::parse_mounts(&content))
    }

    /// ベースラインと現在のマウント状態を比較し、変更レポートを返す
    fn detect_changes(
        baseline: &HashMap<String, MountEntry>,
        current: &HashMap<String, MountEntry>,
    ) -> ChangeReport {
        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut modified = Vec::new();

        for (mount_point, current_entry) in current {
            match baseline.get(mount_point) {
                Some(baseline_entry) if baseline_entry != current_entry => {
                    modified.push((baseline_entry.clone(), current_entry.clone()));
                }
                None => {
                    added.push(current_entry.clone());
                }
                _ => {}
            }
        }

        for (mount_point, baseline_entry) in baseline {
            if !current.contains_key(mount_point) {
                removed.push(baseline_entry.clone());
            }
        }

        ChangeReport {
            added,
            removed,
            modified,
        }
    }
}

impl Module for MountMonitorModule {
    fn name(&self) -> &str {
        "mount_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        tracing::info!(
            mounts_path = %self.config.mounts_path.display(),
            scan_interval_secs = self.config.scan_interval_secs,
            "マウントポイント監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<(), AppError> {
        // 初回スキャンでベースライン作成
        let entries = Self::read_mounts(&self.config.mounts_path)?;
        let baseline = Self::entries_to_map(&entries);
        tracing::info!(
            mount_count = baseline.len(),
            "ベースラインスキャンが完了しました"
        );

        let mounts_path = self.config.mounts_path.clone();
        let scan_interval_secs = self.config.scan_interval_secs;
        let cancel_token = self.cancel_token.clone();

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            // 最初の tick は即座に発火するのでスキップ
            interval.tick().await;

            let mut baseline = baseline;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("マウントポイント監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current_entries = match MountMonitorModule::read_mounts(&mounts_path) {
                            Ok(entries) => entries,
                            Err(e) => {
                                tracing::error!(error = %e, "マウント情報の読み取りに失敗しました");
                                continue;
                            }
                        };
                        let current = MountMonitorModule::entries_to_map(&current_entries);
                        let report = MountMonitorModule::detect_changes(&baseline, &current);

                        if report.has_changes() {
                            for entry in &report.added {
                                tracing::warn!(
                                    mount_point = %entry.mount_point,
                                    device = %entry.device,
                                    fs_type = %entry.fs_type,
                                    options = %entry.options,
                                    change = "added",
                                    "新規マウントポイントを検知しました"
                                );
                            }
                            for entry in &report.removed {
                                tracing::warn!(
                                    mount_point = %entry.mount_point,
                                    device = %entry.device,
                                    fs_type = %entry.fs_type,
                                    change = "removed",
                                    "マウントポイントの削除を検知しました"
                                );
                            }
                            for (old, new) in &report.modified {
                                tracing::warn!(
                                    mount_point = %new.mount_point,
                                    old_device = %old.device,
                                    new_device = %new.device,
                                    old_fs_type = %old.fs_type,
                                    new_fs_type = %new.fs_type,
                                    old_options = %old.options,
                                    new_options = %new.options,
                                    change = "modified",
                                    "マウントポイントの変更を検知しました"
                                );
                            }
                            // ベースラインを更新
                            baseline = current;
                        } else {
                            tracing::debug!("マウントポイントの変更はありません");
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mounts_basic() {
        let content = "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\nproc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n";
        let entries = MountMonitorModule::parse_mounts(content);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].device, "sysfs");
        assert_eq!(entries[0].mount_point, "/sys");
        assert_eq!(entries[0].fs_type, "sysfs");
        assert_eq!(entries[0].options, "rw,nosuid,nodev,noexec,relatime");
        assert_eq!(entries[1].device, "proc");
        assert_eq!(entries[1].mount_point, "/proc");
    }

    #[test]
    fn test_parse_mounts_empty() {
        let entries = MountMonitorModule::parse_mounts("");
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_mounts_blank_lines() {
        let content = "\n  \nsysfs /sys sysfs rw 0 0\n\n";
        let entries = MountMonitorModule::parse_mounts(content);
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_parse_mounts_insufficient_fields() {
        let content = "device /mnt\nsysfs /sys sysfs rw 0 0\n";
        let entries = MountMonitorModule::parse_mounts(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].device, "sysfs");
    }

    #[test]
    fn test_entries_to_map() {
        let entries = vec![
            MountEntry {
                device: "sysfs".to_string(),
                mount_point: "/sys".to_string(),
                fs_type: "sysfs".to_string(),
                options: "rw".to_string(),
            },
            MountEntry {
                device: "/dev/sda1".to_string(),
                mount_point: "/".to_string(),
                fs_type: "ext4".to_string(),
                options: "rw,relatime".to_string(),
            },
        ];
        let map = MountMonitorModule::entries_to_map(&entries);
        assert_eq!(map.len(), 2);
        assert!(map.contains_key("/sys"));
        assert!(map.contains_key("/"));
    }

    #[test]
    fn test_detect_changes_no_changes() {
        let entry = MountEntry {
            device: "/dev/sda1".to_string(),
            mount_point: "/".to_string(),
            fs_type: "ext4".to_string(),
            options: "rw".to_string(),
        };
        let mut baseline = HashMap::new();
        baseline.insert("/".to_string(), entry.clone());
        let current = baseline.clone();

        let report = MountMonitorModule::detect_changes(&baseline, &current);
        assert!(!report.has_changes());
    }

    #[test]
    fn test_detect_changes_added() {
        let baseline = HashMap::new();
        let mut current = HashMap::new();
        current.insert(
            "/mnt/evil".to_string(),
            MountEntry {
                device: "tmpfs".to_string(),
                mount_point: "/mnt/evil".to_string(),
                fs_type: "tmpfs".to_string(),
                options: "rw".to_string(),
            },
        );

        let report = MountMonitorModule::detect_changes(&baseline, &current);
        assert_eq!(report.added.len(), 1);
        assert!(report.removed.is_empty());
        assert!(report.modified.is_empty());
        assert_eq!(report.added[0].mount_point, "/mnt/evil");
    }

    #[test]
    fn test_detect_changes_removed() {
        let mut baseline = HashMap::new();
        baseline.insert(
            "/mnt/data".to_string(),
            MountEntry {
                device: "/dev/sdb1".to_string(),
                mount_point: "/mnt/data".to_string(),
                fs_type: "ext4".to_string(),
                options: "rw".to_string(),
            },
        );
        let current = HashMap::new();

        let report = MountMonitorModule::detect_changes(&baseline, &current);
        assert!(report.added.is_empty());
        assert_eq!(report.removed.len(), 1);
        assert!(report.modified.is_empty());
    }

    #[test]
    fn test_detect_changes_modified_options() {
        let mut baseline = HashMap::new();
        baseline.insert(
            "/".to_string(),
            MountEntry {
                device: "/dev/sda1".to_string(),
                mount_point: "/".to_string(),
                fs_type: "ext4".to_string(),
                options: "rw,relatime".to_string(),
            },
        );
        let mut current = HashMap::new();
        current.insert(
            "/".to_string(),
            MountEntry {
                device: "/dev/sda1".to_string(),
                mount_point: "/".to_string(),
                fs_type: "ext4".to_string(),
                options: "rw,noatime".to_string(),
            },
        );

        let report = MountMonitorModule::detect_changes(&baseline, &current);
        assert!(report.added.is_empty());
        assert!(report.removed.is_empty());
        assert_eq!(report.modified.len(), 1);
    }

    #[test]
    fn test_detect_changes_modified_device() {
        let mut baseline = HashMap::new();
        baseline.insert(
            "/mnt/data".to_string(),
            MountEntry {
                device: "/dev/sdb1".to_string(),
                mount_point: "/mnt/data".to_string(),
                fs_type: "ext4".to_string(),
                options: "rw".to_string(),
            },
        );
        let mut current = HashMap::new();
        current.insert(
            "/mnt/data".to_string(),
            MountEntry {
                device: "/dev/sdc1".to_string(),
                mount_point: "/mnt/data".to_string(),
                fs_type: "ext4".to_string(),
                options: "rw".to_string(),
            },
        );

        let report = MountMonitorModule::detect_changes(&baseline, &current);
        assert_eq!(report.modified.len(), 1);
        assert_eq!(report.modified[0].0.device, "/dev/sdb1");
        assert_eq!(report.modified[0].1.device, "/dev/sdc1");
    }

    #[test]
    fn test_detect_changes_combined() {
        let mut baseline = HashMap::new();
        baseline.insert(
            "/".to_string(),
            MountEntry {
                device: "/dev/sda1".to_string(),
                mount_point: "/".to_string(),
                fs_type: "ext4".to_string(),
                options: "rw".to_string(),
            },
        );
        baseline.insert(
            "/mnt/old".to_string(),
            MountEntry {
                device: "/dev/sdb1".to_string(),
                mount_point: "/mnt/old".to_string(),
                fs_type: "ext4".to_string(),
                options: "rw".to_string(),
            },
        );
        baseline.insert(
            "/mnt/changed".to_string(),
            MountEntry {
                device: "/dev/sdc1".to_string(),
                mount_point: "/mnt/changed".to_string(),
                fs_type: "ext4".to_string(),
                options: "rw".to_string(),
            },
        );

        let mut current = HashMap::new();
        current.insert(
            "/".to_string(),
            MountEntry {
                device: "/dev/sda1".to_string(),
                mount_point: "/".to_string(),
                fs_type: "ext4".to_string(),
                options: "rw".to_string(),
            },
        );
        current.insert(
            "/mnt/new".to_string(),
            MountEntry {
                device: "tmpfs".to_string(),
                mount_point: "/mnt/new".to_string(),
                fs_type: "tmpfs".to_string(),
                options: "rw".to_string(),
            },
        );
        current.insert(
            "/mnt/changed".to_string(),
            MountEntry {
                device: "/dev/sdc1".to_string(),
                mount_point: "/mnt/changed".to_string(),
                fs_type: "ext4".to_string(),
                options: "ro".to_string(),
            },
        );

        let report = MountMonitorModule::detect_changes(&baseline, &current);
        assert_eq!(report.added.len(), 1);
        assert_eq!(report.removed.len(), 1);
        assert_eq!(report.modified.len(), 1);
    }

    #[test]
    fn test_change_report_has_changes_empty() {
        let report = ChangeReport {
            added: vec![],
            removed: vec![],
            modified: vec![],
        };
        assert!(!report.has_changes());
    }

    #[test]
    fn test_init_zero_interval() {
        let config = MountMonitorConfig {
            enabled: true,
            scan_interval_secs: 0,
            mounts_path: PathBuf::from("/proc/mounts"),
        };
        let mut module = MountMonitorModule::new(config);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_init_valid() {
        let config = MountMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            mounts_path: PathBuf::from("/proc/mounts"),
        };
        let mut module = MountMonitorModule::new(config);
        let result = module.init();
        assert!(result.is_ok());
    }

    #[test]
    fn test_read_mounts_from_proc() {
        // /proc/mounts が存在する環境でのみテスト
        let path = PathBuf::from("/proc/mounts");
        if path.exists() {
            let entries = MountMonitorModule::read_mounts(&path).unwrap();
            assert!(!entries.is_empty());
        }
    }

    #[test]
    fn test_read_mounts_nonexistent() {
        let path = PathBuf::from("/tmp/nonexistent-zettai-mounts-test");
        let result = MountMonitorModule::read_mounts(&path);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        // テスト用の仮マウントファイルを作成
        let tmpfile = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmpfile.path(),
            "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n",
        )
        .unwrap();

        let config = MountMonitorConfig {
            enabled: true,
            scan_interval_secs: 3600,
            mounts_path: tmpfile.path().to_path_buf(),
        };
        let mut module = MountMonitorModule::new(config);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[test]
    fn test_parse_mounts_real_format() {
        let content = r#"/dev/sda1 / ext4 rw,relatime,errors=remount-ro 0 0
tmpfs /run tmpfs rw,nosuid,nodev,mode=755 0 0
/dev/sda2 /home ext4 rw,relatime 0 0
overlay /var/lib/docker/overlay2/abc/merged overlay rw,lowerdir=/var/lib/docker/overlay2/abc/diff,upperdir=/var/lib/docker/overlay2/abc/upper,workdir=/var/lib/docker/overlay2/abc/work 0 0
"#;
        let entries = MountMonitorModule::parse_mounts(content);
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[3].fs_type, "overlay");
        assert_eq!(
            entries[3].mount_point,
            "/var/lib/docker/overlay2/abc/merged"
        );
    }
}
