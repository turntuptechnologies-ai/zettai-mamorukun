//! カーネル taint フラグ監視モジュール
//!
//! `/proc/sys/kernel/tainted` を定期スキャンし、カーネルの汚染（taint）ビット
//! マスクの変化を検知する。新しく立ったビットは `SecurityEvent` として発行され、
//! 既存の `kernel_module` / `kallsyms_monitor` / `livepatch_monitor` と相補的に
//! カーネル状態の軽量な監視レイヤーを提供する。
//!
//! 検知対象:
//! - 運用中に新しく立った taint ビット（`kernel_taint_bit_set`）
//! - 起動時スキャンで既に立っていた taint ビット（`kernel_taint_startup_tainted`）

use crate::config::KernelTaintMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::BTreeMap;
use std::path::Path;
use tokio_util::sync::CancellationToken;

/// taint ビット定義の総数（Linux カーネルの TAINT_* 定数）
const TAINT_BIT_COUNT: u8 = 19;

/// taint ビットのメタデータ
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintBitInfo {
    /// ビット番号
    pub bit: u8,
    /// 表示文字（`P`, `F` 等）
    pub char: char,
    /// 定数名（`TAINT_PROPRIETARY_MODULE` 等）
    pub name: &'static str,
    /// デフォルト Severity
    pub default_severity: Severity,
}

/// 指定した taint ビットのメタデータを返す
///
/// Linux カーネル公式の `Documentation/admin-guide/tainted-kernels.rst` 準拠。
pub fn taint_bit_info(bit: u8) -> Option<TaintBitInfo> {
    let info = match bit {
        0 => TaintBitInfo {
            bit: 0,
            char: 'P',
            name: "TAINT_PROPRIETARY_MODULE",
            default_severity: Severity::Warning,
        },
        1 => TaintBitInfo {
            bit: 1,
            char: 'F',
            name: "TAINT_FORCED_MODULE",
            default_severity: Severity::Warning,
        },
        2 => TaintBitInfo {
            bit: 2,
            char: 'S',
            name: "TAINT_CPU_OUT_OF_SPEC",
            default_severity: Severity::Warning,
        },
        3 => TaintBitInfo {
            bit: 3,
            char: 'R',
            name: "TAINT_FORCED_RMMOD",
            default_severity: Severity::Warning,
        },
        4 => TaintBitInfo {
            bit: 4,
            char: 'M',
            name: "TAINT_MACHINE_CHECK",
            default_severity: Severity::Warning,
        },
        5 => TaintBitInfo {
            bit: 5,
            char: 'B',
            name: "TAINT_BAD_PAGE",
            default_severity: Severity::Warning,
        },
        6 => TaintBitInfo {
            bit: 6,
            char: 'U',
            name: "TAINT_USER",
            default_severity: Severity::Warning,
        },
        7 => TaintBitInfo {
            bit: 7,
            char: 'D',
            name: "TAINT_DIE",
            default_severity: Severity::Critical,
        },
        8 => TaintBitInfo {
            bit: 8,
            char: 'A',
            name: "TAINT_OVERRIDDEN_ACPI_TABLE",
            default_severity: Severity::Warning,
        },
        9 => TaintBitInfo {
            bit: 9,
            char: 'W',
            name: "TAINT_WARN",
            default_severity: Severity::Warning,
        },
        10 => TaintBitInfo {
            bit: 10,
            char: 'C',
            name: "TAINT_CRAP",
            default_severity: Severity::Info,
        },
        11 => TaintBitInfo {
            bit: 11,
            char: 'I',
            name: "TAINT_FIRMWARE_WORKAROUND",
            default_severity: Severity::Info,
        },
        12 => TaintBitInfo {
            bit: 12,
            char: 'O',
            name: "TAINT_OOT_MODULE",
            default_severity: Severity::Warning,
        },
        13 => TaintBitInfo {
            bit: 13,
            char: 'E',
            name: "TAINT_UNSIGNED_MODULE",
            default_severity: Severity::Critical,
        },
        14 => TaintBitInfo {
            bit: 14,
            char: 'L',
            name: "TAINT_SOFTLOCKUP",
            default_severity: Severity::Warning,
        },
        15 => TaintBitInfo {
            bit: 15,
            char: 'K',
            name: "TAINT_LIVEPATCH",
            default_severity: Severity::Warning,
        },
        16 => TaintBitInfo {
            bit: 16,
            char: 'X',
            name: "TAINT_AUX",
            default_severity: Severity::Info,
        },
        17 => TaintBitInfo {
            bit: 17,
            char: 'T',
            name: "TAINT_RANDSTRUCT",
            default_severity: Severity::Info,
        },
        18 => TaintBitInfo {
            bit: 18,
            char: 'N',
            name: "TAINT_TEST",
            default_severity: Severity::Warning,
        },
        _ => return None,
    };
    Some(info)
}

/// 文字列表現から Severity をパースする（未知値は `None`）
///
/// 設定の互換性のため `"High"` は `Warning` のエイリアスとして扱う
/// （現状の `Severity` は Info/Warning/Critical の 3 段階のみ）。
fn parse_severity(s: &str) -> Option<Severity> {
    match s {
        "Info" => Some(Severity::Info),
        "Warning" | "High" => Some(Severity::Warning),
        "Critical" => Some(Severity::Critical),
        _ => None,
    }
}

/// taint ファイルから u64 ビットマスクを読み取る
///
/// ファイルが存在しない、または非数値の場合は `None` を返す。
fn read_taint_mask(path: &Path) -> Option<u64> {
    let content = std::fs::read_to_string(path).ok()?;
    content.trim().parse::<u64>().ok()
}

/// `mask` 内で立っているビット番号を返す（昇順）
fn enumerate_set_bits(mask: u64) -> Vec<u8> {
    (0..TAINT_BIT_COUNT)
        .filter(|b| mask & (1u64 << b) != 0)
        .collect()
}

/// `previous` から `current` への差分で「新しく立った」ビットを返す
fn newly_set_bits(previous: u64, current: u64) -> Vec<u8> {
    let newly = current & !previous;
    enumerate_set_bits(newly)
}

/// 指定ビットの Severity を決定する（設定による上書きを反映）
fn resolve_severity(bit: u8, default: Severity, overrides: &BTreeMap<u8, String>) -> Severity {
    if let Some(name) = overrides.get(&bit)
        && let Some(sev) = parse_severity(name)
    {
        return sev;
    }
    default
}

/// カーネル taint フラグ監視モジュール
pub struct KernelTaintMonitorModule {
    config: KernelTaintMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl KernelTaintMonitorModule {
    /// 新しい taint 監視モジュールを作成する
    pub fn new(config: KernelTaintMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// 新しく立ったビットに対してイベントを発行する
    fn emit_bit_events(
        newly_set: &[u8],
        raw_value: u64,
        overrides: &BTreeMap<u8, String>,
        event_bus: &Option<EventBus>,
    ) {
        for &bit in newly_set {
            let info = match taint_bit_info(bit) {
                Some(i) => i,
                None => continue,
            };
            let severity = resolve_severity(bit, info.default_severity, overrides);
            let details = format!(
                "bit={}, char={}, name={}, raw_value={}, raw_hex=0x{:x}",
                info.bit, info.char, info.name, raw_value, raw_value
            );
            tracing::warn!(
                bit = info.bit,
                char = %info.char,
                name = info.name,
                raw_value = raw_value,
                "新しいカーネル taint ビットを検知しました"
            );
            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        "kernel_taint_bit_set",
                        severity,
                        "kernel_taint_monitor",
                        "新しいカーネル taint ビットを検知しました",
                    )
                    .with_details(details),
                );
            }
        }
    }
}

impl Module for KernelTaintMonitorModule {
    fn name(&self) -> &str {
        "kernel_taint_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        if self.config.tainted_path.contains("..") {
            return Err(AppError::ModuleConfig {
                message: format!(
                    "tainted_path に '..' を含めることはできません: {}",
                    self.config.tainted_path
                ),
            });
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            tainted_path = %self.config.tainted_path,
            ignore_initial_bits = ?self.config.ignore_initial_bits,
            severity_overrides_count = self.config.severity_overrides.len(),
            "カーネル taint フラグ監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        let tainted_path = self.config.tainted_path.clone();
        let scan_interval_secs = self.config.scan_interval_secs;
        let overrides = self.config.severity_overrides.clone();
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        let baseline_mask = read_taint_mask(Path::new(&tainted_path)).unwrap_or(0);
        tracing::info!(
            baseline_mask = baseline_mask,
            baseline_hex = %format!("0x{:x}", baseline_mask),
            "カーネル taint ベースラインを取得しました"
        );

        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            interval.tick().await;

            let mut previous_mask = baseline_mask;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("カーネル taint フラグ監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current_mask = match read_taint_mask(Path::new(&tainted_path)) {
                            Some(m) => m,
                            None => {
                                tracing::warn!(
                                    path = %tainted_path,
                                    "taint ファイルの読み取り/パースに失敗しました"
                                );
                                continue;
                            }
                        };

                        let newly = newly_set_bits(previous_mask, current_mask);
                        if !newly.is_empty() {
                            Self::emit_bit_events(&newly, current_mask, &overrides, &event_bus);
                        } else {
                            tracing::debug!("taint ビットに新しい変化はありません");
                        }

                        previous_mask = current_mask;
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();
        let tainted_path = Path::new(&self.config.tainted_path);

        let mask = read_taint_mask(tainted_path).unwrap_or(0);
        let set_bits = enumerate_set_bits(mask);
        let items_scanned = set_bits.len().max(1);
        let mut issues_found = 0usize;

        for &bit in &set_bits {
            if self.config.ignore_initial_bits.contains(&bit) {
                continue;
            }
            let info = match taint_bit_info(bit) {
                Some(i) => i,
                None => continue,
            };
            let severity =
                resolve_severity(bit, info.default_severity, &self.config.severity_overrides);

            tracing::warn!(
                bit = info.bit,
                char = %info.char,
                name = info.name,
                raw_value = mask,
                "起動時スキャン: カーネル taint ビットが既に立っています"
            );

            if let Some(bus) = &self.event_bus {
                bus.publish(
                    SecurityEvent::new(
                        "kernel_taint_startup_tainted",
                        severity,
                        "kernel_taint_monitor",
                        "起動時スキャン: カーネル taint ビットが既に立っています",
                    )
                    .with_details(format!(
                        "bit={}, char={}, name={}, raw_value={}, raw_hex=0x{:x}",
                        info.bit, info.char, info.name, mask, mask
                    )),
                );
            }
            issues_found += 1;
        }

        let mut snapshot: BTreeMap<String, String> = BTreeMap::new();
        snapshot.insert("taint_mask".to_string(), format!("0x{:x}", mask));
        snapshot.insert(
            "taint_bits".to_string(),
            set_bits
                .iter()
                .map(|b| b.to_string())
                .collect::<Vec<_>>()
                .join(","),
        );

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "taint mask=0x{:x}（{}個のビットが立つ、うち{}件が要注意）",
                mask,
                set_bits.len(),
                issues_found
            ),
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
    use std::collections::BTreeMap;
    use tempfile::TempDir;

    fn write_tainted(dir: &TempDir, content: &str) -> String {
        let path = dir.path().join("tainted");
        std::fs::write(&path, content).unwrap();
        path.to_str().unwrap().to_string()
    }

    fn default_config(tainted_path: String) -> KernelTaintMonitorConfig {
        KernelTaintMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            tainted_path,
            ignore_initial_bits: vec![15, 17],
            severity_overrides: BTreeMap::new(),
        }
    }

    #[test]
    fn test_init_valid() {
        let dir = TempDir::new().unwrap();
        let path = write_tainted(&dir, "0\n");
        let config = default_config(path);
        let mut module = KernelTaintMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[test]
    fn test_init_zero_interval() {
        let dir = TempDir::new().unwrap();
        let path = write_tainted(&dir, "0\n");
        let mut config = default_config(path);
        config.scan_interval_secs = 0;
        let mut module = KernelTaintMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_path_traversal_rejected() {
        let mut config = default_config("/proc/../etc/passwd".to_string());
        config.tainted_path = "/proc/sys/../secret".to_string();
        let mut module = KernelTaintMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains(".."));
    }

    #[test]
    fn test_read_taint_mask_ok() {
        let dir = TempDir::new().unwrap();

        let path0 = write_tainted(&dir, "0\n");
        assert_eq!(read_taint_mask(Path::new(&path0)), Some(0));

        let dir2 = TempDir::new().unwrap();
        let path1 = write_tainted(&dir2, "4096\n");
        assert_eq!(read_taint_mask(Path::new(&path1)), Some(4096));

        let dir3 = TempDir::new().unwrap();
        let path2 = write_tainted(&dir3, "12288");
        assert_eq!(read_taint_mask(Path::new(&path2)), Some(12288));
    }

    #[test]
    fn test_read_taint_mask_invalid() {
        let dir = TempDir::new().unwrap();
        let path = write_tainted(&dir, "not_a_number\n");
        assert_eq!(read_taint_mask(Path::new(&path)), None);

        let missing = dir.path().join("no_such_file");
        assert_eq!(read_taint_mask(&missing), None);
    }

    #[test]
    fn test_diff_new_bits_detected() {
        // 12288 = 0b11000000000000 = bits 12, 13
        let newly = newly_set_bits(0, 12288);
        assert_eq!(newly, vec![12, 13]);
    }

    #[test]
    fn test_diff_no_change() {
        assert!(newly_set_bits(12288, 12288).is_empty());
    }

    #[test]
    fn test_diff_bit_cleared_ignored() {
        // bit 13 が下がって bit 12 だけ残る
        let newly = newly_set_bits(12288, 4096);
        assert!(newly.is_empty(), "ビットが下がった場合は通知しない");
    }

    #[test]
    fn test_diff_mixed_set_and_clear() {
        // previous: bits 12, 13 (12288)
        // current:  bits 12, 14 (16384 + 4096 = 20480)
        // newly set: bit 14 only
        let newly = newly_set_bits(12288, 20480);
        assert_eq!(newly, vec![14]);
    }

    #[test]
    fn test_bit_name_and_char() {
        let info = taint_bit_info(13).expect("bit 13 exists");
        assert_eq!(info.name, "TAINT_UNSIGNED_MODULE");
        assert_eq!(info.char, 'E');
        assert_eq!(info.default_severity, Severity::Critical);

        let info12 = taint_bit_info(12).expect("bit 12 exists");
        assert_eq!(info12.name, "TAINT_OOT_MODULE");
        assert_eq!(info12.char, 'O');
        assert_eq!(info12.default_severity, Severity::Warning);

        let info7 = taint_bit_info(7).expect("bit 7 exists");
        assert_eq!(info7.name, "TAINT_DIE");
        assert_eq!(info7.default_severity, Severity::Critical);

        assert!(taint_bit_info(19).is_none());
        assert!(taint_bit_info(255).is_none());
    }

    #[test]
    fn test_severity_override_applied() {
        let mut overrides = BTreeMap::new();
        overrides.insert(10, "Warning".to_string());

        let sev = resolve_severity(10, Severity::Info, &overrides);
        assert_eq!(sev, Severity::Warning);

        // 未上書きビットはデフォルトを維持
        let sev2 = resolve_severity(11, Severity::Info, &overrides);
        assert_eq!(sev2, Severity::Info);

        // 不正な文字列はデフォルトを維持
        let mut bad = BTreeMap::new();
        bad.insert(10, "NonExistent".to_string());
        let sev3 = resolve_severity(10, Severity::Info, &bad);
        assert_eq!(sev3, Severity::Info);
    }

    #[tokio::test]
    async fn test_initial_scan_no_taint() {
        let dir = TempDir::new().unwrap();
        let path = write_tainted(&dir, "0\n");
        let config = default_config(path);
        let module = KernelTaintMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.issues_found, 0);
        assert!(result.summary.contains("taint"));
        assert_eq!(result.snapshot.get("taint_mask").unwrap(), "0x0");
    }

    #[tokio::test]
    async fn test_initial_scan_with_taint_ignores_configured_bits() {
        // bits 13, 15 → 0x2000 + 0x8000 = 0xA000 = 40960
        let dir = TempDir::new().unwrap();
        let path = write_tainted(&dir, "40960\n");
        let mut config = default_config(path);
        config.ignore_initial_bits = vec![15];
        let module = KernelTaintMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.issues_found, 1, "bit 13 のみが要注意扱い");
        assert!(result.items_scanned >= 1);
        assert_eq!(result.snapshot.get("taint_mask").unwrap(), "0xa000");
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let dir = TempDir::new().unwrap();
        let path = write_tainted(&dir, "0\n");
        let config = default_config(path);
        let mut module = KernelTaintMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();
        module.stop().await.unwrap();

        assert!(cancel_token.is_cancelled());
    }

    #[test]
    fn test_enumerate_set_bits() {
        assert!(enumerate_set_bits(0).is_empty());
        assert_eq!(enumerate_set_bits(1), vec![0]);
        assert_eq!(enumerate_set_bits(0b101), vec![0, 2]);
        // bit 18 は含む、bit 19 以降は無視
        let mask = (1u64 << 18) | (1u64 << 19);
        assert_eq!(enumerate_set_bits(mask), vec![18]);
    }

    #[test]
    fn test_parse_severity() {
        assert_eq!(parse_severity("Info"), Some(Severity::Info));
        assert_eq!(parse_severity("Warning"), Some(Severity::Warning));
        assert_eq!(parse_severity("High"), Some(Severity::Warning));
        // "High" は Warning のエイリアス
        assert_eq!(parse_severity("Critical"), Some(Severity::Critical));
        assert_eq!(parse_severity("info"), None);
        assert_eq!(parse_severity(""), None);
    }
}
