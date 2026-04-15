use crate::error::AppError;
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit, Nonce, aead::Aead};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;
const ENC_PREFIX: &str = "ENC[";
const ENC_SUFFIX: &str = "]";
const ENV_KEY_NAME: &str = "ZETTAI_ENCRYPTION_KEY";

/// 暗号化設定
#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq)]
pub struct EncryptionConfig {
    /// 暗号化鍵ファイルのパス
    pub key_file: Option<PathBuf>,
}

/// AES-256 暗号化鍵（メモリ破棄時にゼロクリア）
pub struct EncryptionKey {
    bytes: [u8; KEY_LEN],
}

impl Drop for EncryptionKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl EncryptionKey {
    fn new(bytes: [u8; KEY_LEN]) -> Self {
        Self { bytes }
    }

    fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }
}

/// 文字列が `ENC[...]` 形式かどうかを判定する
pub fn is_encrypted(value: &str) -> bool {
    value.starts_with(ENC_PREFIX) && value.ends_with(ENC_SUFFIX) && value.len() > 5
}

/// ランダムな暗号化鍵を生成する
pub fn generate_key() -> EncryptionKey {
    let mut bytes = [0u8; KEY_LEN];
    let key = Aes256Gcm::generate_key(aes_gcm::aead::OsRng);
    bytes.copy_from_slice(&key);
    EncryptionKey::new(bytes)
}

/// 暗号化鍵を Base64 エンコードして返す
pub fn key_to_base64(key: &EncryptionKey) -> String {
    BASE64.encode(key.as_bytes())
}

/// 環境変数または鍵ファイルから暗号化鍵を解決する
pub fn resolve_key(config: &Option<EncryptionConfig>) -> Result<Option<EncryptionKey>, AppError> {
    if let Ok(env_val) = std::env::var(ENV_KEY_NAME) {
        let decoded = BASE64
            .decode(env_val.trim())
            .map_err(|_| AppError::Encryption {
                message: format!("{} の Base64 デコードに失敗しました", ENV_KEY_NAME),
            })?;
        return Ok(Some(bytes_to_key(&decoded)?));
    }

    if let Some(enc_config) = config
        && let Some(ref key_path) = enc_config.key_file
    {
        return load_key_from_file(key_path).map(Some);
    }

    Ok(None)
}

fn load_key_from_file(path: &Path) -> Result<EncryptionKey, AppError> {
    let content = std::fs::read_to_string(path).map_err(|_| AppError::Encryption {
        message: format!(
            "暗号化鍵ファイルの読み込みに失敗しました: {}",
            path.display()
        ),
    })?;
    let decoded = BASE64
        .decode(content.trim())
        .map_err(|_| AppError::Encryption {
            message: format!(
                "暗号化鍵ファイルの Base64 デコードに失敗しました: {}",
                path.display()
            ),
        })?;
    bytes_to_key(&decoded)
}

fn bytes_to_key(bytes: &[u8]) -> Result<EncryptionKey, AppError> {
    if bytes.len() != KEY_LEN {
        return Err(AppError::Encryption {
            message: format!(
                "暗号化鍵の長さが不正です（期待: {} バイト、実際: {} バイト）",
                KEY_LEN,
                bytes.len()
            ),
        });
    }
    let mut key_bytes = [0u8; KEY_LEN];
    key_bytes.copy_from_slice(bytes);
    Ok(EncryptionKey::new(key_bytes))
}

/// 平文を AES-256-GCM で暗号化し `ENC[...]` 形式の文字列を返す
pub fn encrypt_value(key: &EncryptionKey, plaintext: &str) -> Result<String, AppError> {
    let cipher = Aes256Gcm::new(key.as_bytes().into());
    let nonce = Aes256Gcm::generate_nonce(aes_gcm::aead::OsRng);
    let ciphertext =
        cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|_| AppError::Encryption {
                message: "暗号化に失敗しました".to_string(),
            })?;

    let mut combined = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    combined.extend_from_slice(&nonce);
    combined.extend_from_slice(&ciphertext);

    Ok(format!(
        "{}{}{}",
        ENC_PREFIX,
        BASE64.encode(&combined),
        ENC_SUFFIX
    ))
}

/// `ENC[...]` 形式の文字列を復号し平文を返す
pub fn decrypt_value(key: &EncryptionKey, encrypted: &str) -> Result<String, AppError> {
    if !is_encrypted(encrypted) {
        return Err(AppError::Encryption {
            message: "暗号化値の形式が不正です（ENC[...] 形式を期待）".to_string(),
        });
    }

    let b64 = &encrypted[ENC_PREFIX.len()..encrypted.len() - ENC_SUFFIX.len()];
    let combined = BASE64.decode(b64).map_err(|_| AppError::Encryption {
        message: "暗号化値の Base64 デコードに失敗しました".to_string(),
    })?;

    let min_len = NONCE_LEN + TAG_LEN;
    if combined.len() < min_len {
        return Err(AppError::Encryption {
            message: format!(
                "暗号化値のデータが短すぎます（最小: {} バイト = nonce {} + tag {}）",
                min_len, NONCE_LEN, TAG_LEN
            ),
        });
    }

    let (nonce_bytes, ciphertext) = combined.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new(key.as_bytes().into());

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| AppError::Encryption {
            message: "暗号化値の復号に失敗しました（鍵が正しいか確認してください）".to_string(),
        })?;

    String::from_utf8(plaintext).map_err(|_| AppError::Encryption {
        message: "復号結果が有効な UTF-8 文字列ではありません".to_string(),
    })
}

/// 鍵ローテーション結果
pub struct RotateResult {
    /// ローテーション後の設定ファイル内容
    pub new_content: String,
    /// 再暗号化に成功した値の数
    pub rotated_count: usize,
    /// スキップした値の数
    pub skipped_count: usize,
    /// 各エラーの詳細メッセージ
    pub errors: Vec<String>,
}

/// 鍵ソース文字列から暗号化鍵を解決する
///
/// サポートする形式:
/// - `env:VARIABLE_NAME` — 環境変数から読み込み
/// - ファイルパス — ファイルから読み込み
/// - Base64 文字列 — 直接デコード
pub fn resolve_key_from_source(source: &str) -> Result<EncryptionKey, AppError> {
    if let Some(var_name) = source.strip_prefix("env:") {
        let env_val = std::env::var(var_name).map_err(|_| AppError::Encryption {
            message: format!("環境変数 {} が設定されていません", var_name),
        })?;
        let decoded = BASE64
            .decode(env_val.trim())
            .map_err(|_| AppError::Encryption {
                message: format!("環境変数 {} の Base64 デコードに失敗しました", var_name),
            })?;
        return bytes_to_key(&decoded);
    }

    let path = Path::new(source);
    if path.exists() {
        return load_key_from_file(path);
    }

    let decoded = BASE64
        .decode(source.trim())
        .map_err(|_| AppError::Encryption {
            message: "鍵ソースの Base64 デコードに失敗しました（env:変数名、ファイルパス、または Base64 文字列を指定してください）".to_string(),
        })?;
    bytes_to_key(&decoded)
}

/// TOML 文字列内の全 `ENC[...]` 値を旧鍵で復号し、新鍵で再暗号化する
pub fn rotate_config_keys(
    content: &str,
    old_key: &EncryptionKey,
    new_key: &EncryptionKey,
) -> RotateResult {
    let mut result = content.to_string();
    let mut rotated_count = 0;
    let mut skipped_count = 0;
    let mut errors = Vec::new();

    let mut search_start = 0;
    loop {
        let Some(start) = result[search_start..].find(ENC_PREFIX) else {
            break;
        };
        let start = search_start + start;

        let Some(end_offset) = result[start..].find(ENC_SUFFIX) else {
            break;
        };
        let end = start + end_offset + ENC_SUFFIX.len();
        let encrypted = result[start..end].to_string();

        let b64_part = &encrypted[ENC_PREFIX.len()..encrypted.len() - ENC_SUFFIX.len()];
        if !b64_part
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        {
            search_start = end;
            continue;
        }

        match decrypt_value(old_key, &encrypted) {
            Ok(plaintext) => match encrypt_value(new_key, &plaintext) {
                Ok(new_encrypted) => {
                    result = format!("{}{}{}", &result[..start], new_encrypted, &result[end..]);
                    search_start = start + new_encrypted.len();
                    rotated_count += 1;
                }
                Err(e) => {
                    errors.push(format!("再暗号化に失敗: {}", e));
                    skipped_count += 1;
                    search_start = end;
                }
            },
            Err(e) => {
                errors.push(format!("復号に失敗（旧鍵が正しくない可能性）: {}", e));
                skipped_count += 1;
                search_start = end;
            }
        }
    }

    RotateResult {
        new_content: result,
        rotated_count,
        skipped_count,
        errors,
    }
}

/// TOML 文字列内の全 `ENC[...]` 値を復号した TOML 文字列を返す
pub fn decrypt_config_content(content: &str) -> Result<String, AppError> {
    if !content.contains(ENC_PREFIX) {
        return Ok(content.to_string());
    }

    // [encryption] セクションを部分パースして鍵を解決
    #[derive(Deserialize)]
    struct PartialConfig {
        encryption: Option<EncryptionConfig>,
    }

    let partial: PartialConfig =
        toml::from_str(content).unwrap_or(PartialConfig { encryption: None });

    let key = resolve_key(&partial.encryption)?.ok_or_else(|| AppError::Encryption {
        message: "暗号化された設定値がありますが、暗号化鍵が設定されていません。環境変数 ZETTAI_ENCRYPTION_KEY を設定するか、[encryption] セクションで key_file を指定してください".to_string(),
    })?;

    let mut result = content.to_string();
    // ENC[...] パターンを検索して復号
    loop {
        let Some(start) = result.find(ENC_PREFIX) else {
            break;
        };
        let Some(end) = result[start..].find(ENC_SUFFIX) else {
            break;
        };
        let end = start + end + ENC_SUFFIX.len();
        let encrypted = &result[start..end];

        // Base64 文字のみで構成されているか簡易チェック
        let b64_part = &encrypted[ENC_PREFIX.len()..encrypted.len() - ENC_SUFFIX.len()];
        if !b64_part
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        {
            break;
        }

        let decrypted = decrypt_value(&key, encrypted)?;
        result = format!("{}{}{}", &result[..start], decrypted, &result[end..]);
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> EncryptionKey {
        let mut bytes = [0u8; KEY_LEN];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        EncryptionKey::new(bytes)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = test_key();
        let plaintext = "https://hooks.slack.com/services/T00/B00/xxxx";
        let encrypted = encrypt_value(&key, plaintext).unwrap();
        assert!(is_encrypted(&encrypted));
        let decrypted = decrypt_value(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty_string() {
        let key = test_key();
        let plaintext = "";
        let encrypted = encrypt_value(&key, plaintext).unwrap();
        let decrypted = decrypt_value(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_unicode() {
        let key = test_key();
        let plaintext = "日本語のテストデータ 🔒";
        let encrypted = encrypt_value(&key, plaintext).unwrap();
        let decrypted = decrypt_value(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_is_encrypted() {
        assert!(is_encrypted("ENC[AAAA]"));
        assert!(is_encrypted("ENC[dGVzdA==]"));
        assert!(!is_encrypted(""));
        assert!(!is_encrypted("ENC["));
        assert!(!is_encrypted("ENC[]"));
        assert!(!is_encrypted("plain text"));
        assert!(!is_encrypted("ENC[A")); // no closing bracket
    }

    #[test]
    fn test_decrypt_invalid_format() {
        let key = test_key();
        let result = decrypt_value(&key, "not-encrypted");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let key1 = test_key();
        let mut key2_bytes = [0u8; KEY_LEN];
        key2_bytes[0] = 0xFF;
        let key2 = EncryptionKey::new(key2_bytes);

        let encrypted = encrypt_value(&key1, "secret").unwrap();
        let result = decrypt_value(&key2, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_tampered_data() {
        let key = test_key();
        let encrypted = encrypt_value(&key, "secret").unwrap();

        // 暗号文の一部を改ざん
        let b64 = &encrypted[ENC_PREFIX.len()..encrypted.len() - ENC_SUFFIX.len()];
        let mut data = BASE64.decode(b64).unwrap();
        if let Some(last) = data.last_mut() {
            *last ^= 0xFF;
        }
        let tampered = format!("{}{}{}", ENC_PREFIX, BASE64.encode(&data), ENC_SUFFIX);

        let result = decrypt_value(&key, &tampered);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_data_too_short() {
        let key = test_key();
        let short_data = vec![0u8; 10]; // 12+16 より短い
        let encrypted = format!("{}{}{}", ENC_PREFIX, BASE64.encode(&short_data), ENC_SUFFIX);
        let result = decrypt_value(&key, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_key_length() {
        let key = generate_key();
        assert_eq!(key.as_bytes().len(), KEY_LEN);
    }

    #[test]
    fn test_key_to_base64_roundtrip() {
        let key = generate_key();
        let b64 = key_to_base64(&key);
        let decoded = BASE64.decode(&b64).unwrap();
        assert_eq!(decoded.len(), KEY_LEN);
        assert_eq!(decoded, key.as_bytes());
    }

    #[test]
    fn test_resolve_key_env_var() {
        let key = test_key();
        let b64 = key_to_base64(&key);
        unsafe { std::env::set_var(ENV_KEY_NAME, &b64) };
        let resolved = resolve_key(&None).unwrap();
        unsafe { std::env::remove_var(ENV_KEY_NAME) };
        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap().as_bytes(), key.as_bytes());
    }

    #[test]
    fn test_resolve_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("test.key");
        let key = test_key();
        std::fs::write(&key_path, key_to_base64(&key)).unwrap();

        let config = Some(EncryptionConfig {
            key_file: Some(key_path),
        });
        // 環境変数がセットされている場合に備えて削除
        unsafe { std::env::remove_var(ENV_KEY_NAME) };
        let resolved = resolve_key(&config).unwrap();
        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap().as_bytes(), key.as_bytes());
    }

    #[test]
    fn test_resolve_key_env_priority_over_file() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("test.key");

        let env_key = test_key();
        let mut file_key_bytes = [0u8; KEY_LEN];
        file_key_bytes[0] = 0xFF;
        let file_key = EncryptionKey::new(file_key_bytes);

        std::fs::write(&key_path, key_to_base64(&file_key)).unwrap();
        unsafe { std::env::set_var(ENV_KEY_NAME, key_to_base64(&env_key)) };

        let config = Some(EncryptionConfig {
            key_file: Some(key_path),
        });
        let resolved = resolve_key(&config).unwrap();
        unsafe { std::env::remove_var(ENV_KEY_NAME) };

        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap().as_bytes(), env_key.as_bytes());
    }

    #[test]
    fn test_resolve_key_none() {
        unsafe { std::env::remove_var(ENV_KEY_NAME) };
        let resolved = resolve_key(&None).unwrap();
        assert!(resolved.is_none());
    }

    #[test]
    fn test_key_base64_invalid() {
        unsafe { std::env::set_var(ENV_KEY_NAME, "not-valid-base64!!!") };
        let result = resolve_key(&None);
        unsafe { std::env::remove_var(ENV_KEY_NAME) };
        assert!(result.is_err());
    }

    #[test]
    fn test_key_wrong_length() {
        let short_key = BASE64.encode(&[0u8; 16]);
        unsafe { std::env::set_var(ENV_KEY_NAME, &short_key) };
        let result = resolve_key(&None);
        unsafe { std::env::remove_var(ENV_KEY_NAME) };
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_config_content_no_encrypted_values() {
        let content = r#"
[general]
log_level = "info"
"#;
        let result = decrypt_config_content(content).unwrap();
        assert_eq!(result, content);
    }

    #[test]
    fn test_decrypt_config_content_with_encrypted_values() {
        let key = test_key();
        let b64 = key_to_base64(&key);

        let secret_url = "https://hooks.slack.com/services/T00/B00/xxxx";
        let encrypted_url = encrypt_value(&key, secret_url).unwrap();

        let secret_header = "Bearer my-secret-token";
        let encrypted_header = encrypt_value(&key, secret_header).unwrap();

        unsafe { std::env::set_var(ENV_KEY_NAME, &b64) };

        let content = format!(
            r#"
[general]
log_level = "info"

[[actions.rules]]
name = "webhook-alert"
action = "webhook"
url = "{}"

[actions.rules.headers]
Authorization = "{}"
"#,
            encrypted_url, encrypted_header
        );

        let result = decrypt_config_content(&content).unwrap();
        unsafe { std::env::remove_var(ENV_KEY_NAME) };

        assert!(result.contains(secret_url));
        assert!(result.contains(secret_header));
        assert!(!result.contains("ENC["));
    }

    #[test]
    fn test_decrypt_config_no_key_with_encrypted_values() {
        unsafe { std::env::remove_var(ENV_KEY_NAME) };
        let content = r#"
[general]
log_level = "info"

[[actions.rules]]
name = "test"
action = "webhook"
url = "ENC[dGVzdGRhdGFmb3JlbmNyeXB0aW9u]"
"#;
        let result = decrypt_config_content(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_key_from_source_env() {
        let key = test_key();
        let b64 = key_to_base64(&key);
        let var_name = "ZETTAI_TEST_ROTATE_KEY_ENV";
        unsafe { std::env::set_var(var_name, &b64) };
        let resolved = resolve_key_from_source(&format!("env:{}", var_name)).unwrap();
        unsafe { std::env::remove_var(var_name) };
        assert_eq!(resolved.as_bytes(), key.as_bytes());
    }

    #[test]
    fn test_resolve_key_from_source_env_missing() {
        let result = resolve_key_from_source("env:ZETTAI_NONEXISTENT_VAR_12345");
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_key_from_source_file() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("rotate_test.key");
        let key = test_key();
        std::fs::write(&key_path, key_to_base64(&key)).unwrap();
        let resolved = resolve_key_from_source(key_path.to_str().unwrap()).unwrap();
        assert_eq!(resolved.as_bytes(), key.as_bytes());
    }

    #[test]
    fn test_resolve_key_from_source_base64() {
        let key = test_key();
        let b64 = key_to_base64(&key);
        let resolved = resolve_key_from_source(&b64).unwrap();
        assert_eq!(resolved.as_bytes(), key.as_bytes());
    }

    #[test]
    fn test_resolve_key_from_source_invalid() {
        let result = resolve_key_from_source("not-valid-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_rotate_config_keys_basic() {
        let old_key = test_key();
        let mut new_key_bytes = [0u8; KEY_LEN];
        new_key_bytes[0] = 0xFF;
        let new_key = EncryptionKey::new(new_key_bytes);

        let secret = "my-secret-value";
        let encrypted = encrypt_value(&old_key, secret).unwrap();

        let content = format!(
            r#"[section]
value = "{}"
plain = "hello"
"#,
            encrypted
        );

        let result = rotate_config_keys(&content, &old_key, &new_key);
        assert_eq!(result.rotated_count, 1);
        assert_eq!(result.skipped_count, 0);
        assert!(result.errors.is_empty());
        assert!(!result.new_content.contains(&encrypted));
        assert!(result.new_content.contains("ENC["));

        let new_enc_start = result.new_content.find("ENC[").unwrap();
        let new_enc_end =
            result.new_content[new_enc_start..].find(']').unwrap() + new_enc_start + 1;
        let new_encrypted = &result.new_content[new_enc_start..new_enc_end];
        let decrypted = decrypt_value(&new_key, new_encrypted).unwrap();
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn test_rotate_config_keys_multiple() {
        let old_key = test_key();
        let mut new_key_bytes = [0u8; KEY_LEN];
        new_key_bytes[0] = 0xFF;
        let new_key = EncryptionKey::new(new_key_bytes);

        let secret1 = "secret-one";
        let secret2 = "secret-two";
        let enc1 = encrypt_value(&old_key, secret1).unwrap();
        let enc2 = encrypt_value(&old_key, secret2).unwrap();

        let content = format!("a = \"{}\"\nb = \"{}\"\n", enc1, enc2);
        let result = rotate_config_keys(&content, &old_key, &new_key);
        assert_eq!(result.rotated_count, 2);
        assert_eq!(result.skipped_count, 0);
    }

    #[test]
    fn test_rotate_config_keys_wrong_old_key() {
        let old_key = test_key();
        let mut wrong_key_bytes = [0u8; KEY_LEN];
        wrong_key_bytes[0] = 0xAA;
        let wrong_key = EncryptionKey::new(wrong_key_bytes);
        let mut new_key_bytes = [0u8; KEY_LEN];
        new_key_bytes[0] = 0xFF;
        let new_key = EncryptionKey::new(new_key_bytes);

        let encrypted = encrypt_value(&old_key, "secret").unwrap();
        let content = format!("val = \"{}\"\n", encrypted);

        let result = rotate_config_keys(&content, &wrong_key, &new_key);
        assert_eq!(result.rotated_count, 0);
        assert_eq!(result.skipped_count, 1);
        assert_eq!(result.errors.len(), 1);
        assert!(result.new_content.contains(&encrypted));
    }

    #[test]
    fn test_rotate_config_keys_no_encrypted_values() {
        let old_key = test_key();
        let new_key = test_key();
        let content = "[section]\nplain = \"hello\"\n";
        let result = rotate_config_keys(content, &old_key, &new_key);
        assert_eq!(result.rotated_count, 0);
        assert_eq!(result.skipped_count, 0);
        assert_eq!(result.new_content, content);
    }

    #[test]
    fn test_rotate_config_keys_empty_content() {
        let old_key = test_key();
        let new_key = test_key();
        let result = rotate_config_keys("", &old_key, &new_key);
        assert_eq!(result.rotated_count, 0);
        assert_eq!(result.skipped_count, 0);
        assert!(result.errors.is_empty());
        assert_eq!(result.new_content, "");
    }

    #[test]
    fn test_rotate_config_keys_mixed_keys() {
        let old_key = test_key();
        let mut other_key_bytes = [0u8; KEY_LEN];
        other_key_bytes[0] = 0xAA;
        let other_key = EncryptionKey::new(other_key_bytes);
        let mut new_key_bytes = [0u8; KEY_LEN];
        new_key_bytes[0] = 0xFF;
        let new_key = EncryptionKey::new(new_key_bytes);

        let enc_old = encrypt_value(&old_key, "secret-old").unwrap();
        let enc_other = encrypt_value(&other_key, "secret-other").unwrap();

        let content = format!("a = \"{}\"\nb = \"{}\"\n", enc_old, enc_other);
        let result = rotate_config_keys(&content, &old_key, &new_key);
        assert_eq!(result.rotated_count, 1);
        assert_eq!(result.skipped_count, 1);
        assert_eq!(result.errors.len(), 1);

        assert!(result.new_content.contains(&enc_other));
        assert!(!result.new_content.contains(&enc_old));
    }

    #[test]
    fn test_resolve_key_from_source_env_empty_var_name() {
        let result = resolve_key_from_source("env:");
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_key_from_source_base64_wrong_length() {
        let short = BASE64.encode(&[0u8; 16]);
        let result = resolve_key_from_source(&short);
        assert!(result.is_err());
    }
}
