//! USB デバイス監視モジュール
//!
//! `/sys/bus/usb/devices/` を定期的にスキャンし、USB デバイスの接続・切断を検知する。
//! BadUSB 攻撃やキーロガー等の物理的な攻撃ベクターに対する防御機能。

use crate::config::UsbMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

/// USB デバイス情報
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct UsbDevice {
    /// デバイスパス（例: "1-1"）
    path: String,
    /// ベンダー ID（例: "0x1234"）
    vendor_id: String,
    /// プロダクト ID（例: "0x5678"）
    product_id: String,
    /// デバイスクラス（例: "09"）
    device_class: String,
    /// 製造者名
    manufacturer: String,
    /// 製品名
    product: String,
}

impl std::fmt::Display for UsbDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} ({}) [{}]",
            self.vendor_id,
            self.product_id,
            if self.product.is_empty() {
                &self.path
            } else {
                &self.product
            },
            self.device_class
        )
    }
}

/// USB デバイス監視モジュール
///
/// `/sys/bus/usb/devices/` を定期スキャンし、ベースラインとの差分を検知する。
pub struct UsbMonitorModule {
    config: UsbMonitorConfig,
    event_bus: Option<EventBus>,
    cancel_token: CancellationToken,
}

impl UsbMonitorModule {
    /// 新しい USB デバイス監視モジュールを作成する
    pub fn new(config: UsbMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// `/sys/bus/usb/devices/` 配下をスキャンし、USB デバイス一覧を返す
    fn scan_devices(devices_path: &PathBuf) -> Result<HashSet<UsbDevice>, AppError> {
        let mut devices = HashSet::new();

        let entries = std::fs::read_dir(devices_path).map_err(|e| AppError::FileIo {
            path: devices_path.clone(),
            source: e,
        })?;

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = entry.path();
            let device_name = match entry.file_name().to_str() {
                Some(name) => name.to_string(),
                None => continue,
            };

            // USB デバイスディレクトリには idVendor ファイルが存在する
            let vendor_path = path.join("idVendor");
            if !vendor_path.exists() {
                continue;
            }

            let vendor_id = Self::read_sysfs_file(&vendor_path);
            let product_id = Self::read_sysfs_file(&path.join("idProduct"));
            let device_class = Self::read_sysfs_file(&path.join("bDeviceClass"));
            let manufacturer = Self::read_sysfs_file(&path.join("manufacturer"));
            let product = Self::read_sysfs_file(&path.join("product"));

            devices.insert(UsbDevice {
                path: device_name,
                vendor_id,
                product_id,
                device_class,
                manufacturer,
                product,
            });
        }

        Ok(devices)
    }

    /// sysfs ファイルを読み込み、内容を trim して返す。読み込み失敗時は空文字列。
    fn read_sysfs_file(path: &PathBuf) -> String {
        std::fs::read_to_string(path)
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    }
}

impl Module for UsbMonitorModule {
    fn name(&self) -> &str {
        "usb_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }
        tracing::info!(
            devices_path = %self.config.devices_path.display(),
            scan_interval_secs = self.config.scan_interval_secs,
            "USB デバイス監視モジュールを初期化しました"
        );
        Ok(())
    }

    async fn start(&mut self) -> Result<(), AppError> {
        let baseline = Self::scan_devices(&self.config.devices_path)?;
        tracing::info!(
            device_count = baseline.len(),
            "USB デバイスベースラインスキャンが完了しました"
        );

        let devices_path = self.config.devices_path.clone();
        let scan_interval_secs = self.config.scan_interval_secs;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            // 最初の tick は即座に発火するのでスキップ
            interval.tick().await;

            let mut baseline = baseline;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("USB デバイス監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = match UsbMonitorModule::scan_devices(&devices_path) {
                            Ok(devices) => devices,
                            Err(e) => {
                                tracing::error!(error = %e, "USB デバイス情報の読み取りに失敗しました");
                                continue;
                            }
                        };

                        // 新規接続デバイスの検知
                        for device in current.difference(&baseline) {
                            tracing::warn!(
                                device_path = %device.path,
                                vendor_id = %device.vendor_id,
                                product_id = %device.product_id,
                                device_class = %device.device_class,
                                manufacturer = %device.manufacturer,
                                product = %device.product,
                                "USB デバイスの接続を検知しました"
                            );
                            if let Some(ref bus) = event_bus {
                                bus.publish(
                                    SecurityEvent::new(
                                        "usb_device_connected",
                                        Severity::Warning,
                                        "usb_monitor",
                                        format!("USB デバイスの接続を検知しました: {}", device),
                                    )
                                    .with_details(format!(
                                        "path={} vendor={} product={}",
                                        device.path, device.vendor_id, device.product_id
                                    )),
                                );
                            }
                        }

                        // 切断デバイスの検知
                        for device in baseline.difference(&current) {
                            tracing::info!(
                                device_path = %device.path,
                                vendor_id = %device.vendor_id,
                                product_id = %device.product_id,
                                "USB デバイスの切断を検知しました"
                            );
                            if let Some(ref bus) = event_bus {
                                bus.publish(
                                    SecurityEvent::new(
                                        "usb_device_disconnected",
                                        Severity::Info,
                                        "usb_monitor",
                                        format!("USB デバイスの切断を検知しました: {}", device),
                                    )
                                    .with_details(format!(
                                        "path={} vendor={} product={}",
                                        device.path, device.vendor_id, device.product_id
                                    )),
                                );
                            }
                        }

                        if current != baseline {
                            baseline = current;
                        } else {
                            tracing::debug!("USB デバイスの変更はありません");
                        }
                    }
                }
            }
        });

        Ok(())
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();
        let devices = Self::scan_devices(&self.config.devices_path)?;
        let items_scanned = devices.len();
        let snapshot: BTreeMap<String, String> = devices
            .iter()
            .map(|d| (d.path.clone(), format!("{}:{}", d.vendor_id, d.product_id)))
            .collect();
        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found: 0,
            duration,
            summary: format!("USB デバイス {}件を検出しました", items_scanned),
            snapshot,
        })
    }

    async fn stop(&mut self) -> Result<(), AppError> {
        self.cancel_token.cancel();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// テスト用の偽 USB デバイスディレクトリを作成する
    fn create_mock_usb_device(
        dir: &std::path::Path,
        name: &str,
        vendor: &str,
        product: &str,
        class: &str,
        manufacturer: &str,
        product_name: &str,
    ) {
        let device_dir = dir.join(name);
        std::fs::create_dir_all(&device_dir).unwrap();
        std::fs::write(device_dir.join("idVendor"), format!("{}\n", vendor)).unwrap();
        std::fs::write(device_dir.join("idProduct"), format!("{}\n", product)).unwrap();
        std::fs::write(device_dir.join("bDeviceClass"), format!("{}\n", class)).unwrap();
        std::fs::write(
            device_dir.join("manufacturer"),
            format!("{}\n", manufacturer),
        )
        .unwrap();
        std::fs::write(device_dir.join("product"), format!("{}\n", product_name)).unwrap();
    }

    #[test]
    fn test_scan_devices_empty_dir() {
        let tmp = TempDir::new().unwrap();
        let devices = UsbMonitorModule::scan_devices(&tmp.path().to_path_buf()).unwrap();
        assert!(devices.is_empty());
    }

    #[test]
    fn test_scan_devices_with_mock_device() {
        let tmp = TempDir::new().unwrap();
        create_mock_usb_device(
            tmp.path(),
            "1-1",
            "1234",
            "5678",
            "09",
            "TestVendor",
            "TestProduct",
        );

        let devices = UsbMonitorModule::scan_devices(&tmp.path().to_path_buf()).unwrap();
        assert_eq!(devices.len(), 1);

        let device = devices.iter().next().unwrap();
        assert_eq!(device.path, "1-1");
        assert_eq!(device.vendor_id, "1234");
        assert_eq!(device.product_id, "5678");
        assert_eq!(device.device_class, "09");
        assert_eq!(device.manufacturer, "TestVendor");
        assert_eq!(device.product, "TestProduct");
    }

    #[test]
    fn test_scan_devices_skips_non_usb_entries() {
        let tmp = TempDir::new().unwrap();
        // idVendor ファイルがないディレクトリはスキップされる
        let non_usb = tmp.path().join("usb1");
        std::fs::create_dir_all(&non_usb).unwrap();
        std::fs::write(non_usb.join("some_file"), "data").unwrap();

        // USB デバイスとして認識されるディレクトリ
        create_mock_usb_device(
            tmp.path(),
            "2-1",
            "abcd",
            "ef01",
            "03",
            "Keyboard",
            "USB Keyboard",
        );

        let devices = UsbMonitorModule::scan_devices(&tmp.path().to_path_buf()).unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices.iter().next().unwrap().path, "2-1");
    }

    #[test]
    fn test_scan_devices_nonexistent() {
        let result =
            UsbMonitorModule::scan_devices(&PathBuf::from("/nonexistent/path/usb/devices"));
        assert!(result.is_err());
    }

    #[test]
    fn test_read_sysfs_file_exists() {
        let tmp = TempDir::new().unwrap();
        let file_path = tmp.path().join("test_file");
        std::fs::write(&file_path, "  hello world  \n").unwrap();

        let content = UsbMonitorModule::read_sysfs_file(&file_path);
        assert_eq!(content, "hello world");
    }

    #[test]
    fn test_read_sysfs_file_not_exists() {
        let content = UsbMonitorModule::read_sysfs_file(&PathBuf::from("/nonexistent/file"));
        assert_eq!(content, "");
    }

    #[test]
    fn test_init_zero_interval() {
        let config = UsbMonitorConfig {
            enabled: true,
            scan_interval_secs: 0,
            devices_path: PathBuf::from("/tmp"),
        };
        let mut module = UsbMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_init_valid() {
        let tmp = TempDir::new().unwrap();
        let config = UsbMonitorConfig {
            enabled: true,
            scan_interval_secs: 10,
            devices_path: tmp.path().to_path_buf(),
        };
        let mut module = UsbMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let tmp = TempDir::new().unwrap();
        let config = UsbMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            devices_path: tmp.path().to_path_buf(),
        };
        let mut module = UsbMonitorModule::new(config, None);
        module.init().unwrap();

        let result = module.start().await;
        assert!(result.is_ok());

        let result = module.stop().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let tmp = TempDir::new().unwrap();
        create_mock_usb_device(
            tmp.path(),
            "1-1",
            "1234",
            "5678",
            "09",
            "TestVendor",
            "TestProduct",
        );

        let config = UsbMonitorConfig {
            enabled: true,
            scan_interval_secs: 10,
            devices_path: tmp.path().to_path_buf(),
        };
        let module = UsbMonitorModule::new(config, None);
        let result = module.initial_scan().await.unwrap();

        assert_eq!(result.items_scanned, 1);
        assert_eq!(result.issues_found, 0);
        assert!(result.summary.contains("1件"));
        assert!(result.snapshot.contains_key("1-1"));
        assert_eq!(result.snapshot["1-1"], "1234:5678");
    }

    #[test]
    fn test_usb_device_display() {
        let device = UsbDevice {
            path: "1-1".to_string(),
            vendor_id: "1234".to_string(),
            product_id: "5678".to_string(),
            device_class: "09".to_string(),
            manufacturer: "TestVendor".to_string(),
            product: "TestProduct".to_string(),
        };
        let display = format!("{}", device);
        assert_eq!(display, "1234:5678 (TestProduct) [09]");
    }

    #[test]
    fn test_usb_device_display_empty_product() {
        let device = UsbDevice {
            path: "2-1".to_string(),
            vendor_id: "abcd".to_string(),
            product_id: "ef01".to_string(),
            device_class: "03".to_string(),
            manufacturer: "".to_string(),
            product: "".to_string(),
        };
        let display = format!("{}", device);
        assert_eq!(display, "abcd:ef01 (2-1) [03]");
    }
}
