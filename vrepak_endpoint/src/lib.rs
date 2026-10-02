//! Endpoint Configuration (AES) - FModel compatible.
//!
//! Fetches a JSON document from an endpoint URL and evaluates a JSONPath
//! expression that must resolve to either:
//!   - a single element: the main AES key, or
//!   - 2 elements: [main_key, dynamic_keys]
//! where dynamic_keys is a list of `{guid, key, name?}`.
//!
//! Example (Wuthering Waves):
//!   endpoint: `https://yarik0chka.github.io/wuwa-keys/keys.json`
//!   expression: `$['mainKey', 'dynamicKeys']`

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointConfig {
    pub endpoint: String,
    pub expression: String,
}

impl EndpointConfig {
    pub fn new(endpoint: impl Into<String>, expression: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            expression: expression.into(),
        }
    }
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            expression: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicKey {
    pub guid: u128,
    pub guid_str: String,
    pub key: [u8; 32],
    pub key_str: String,
    pub name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ResolvedKeys {
    pub main_key: [u8; 32],
    pub main_key_str: String,
    pub dynamic_keys: Vec<DynamicKey>,
}

#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    #[error("http error: {0}")]
    Http(String),
    #[error("invalid url: {0}")]
    Url(String),
    #[error("json error: {0}")]
    Json(String),
    #[error("expression error: {0}")]
    Expression(String),
    #[error("validation error: {0}")]
    Validation(String),
    #[error("expect 256 bit AES key as hex (0x...) or base64, got: {0}")]
    Aes(String),
    #[error("expect 128 bit guid as 32 hex chars, got: {0}")]
    Guid(String),
}

pub fn normalize_expression(expr: &str) -> String {
    let t = expr.trim();
    if t.is_empty() {
        return "$".to_string();
    }
    // Screenshot shows `['mainKey', 'dynamicKeys']` without `$` - support both.
    if t.starts_with('$') {
        t.to_string()
    } else {
        format!("${t}")
    }
}

/// Fetch JSON document from endpoint URL (blocking).
pub fn fetch_json(endpoint: &str) -> Result<serde_json::Value, EndpointError> {
    let url = endpoint.trim();
    if url.is_empty() {
        return Err(EndpointError::Url("endpoint is empty".to_string()));
    }
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(EndpointError::Url(format!(
            "endpoint must start with http:// or https://, got: {url}"
        )));
    }
    let resp = reqwest::blocking::get(url).map_err(|e| EndpointError::Http(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(EndpointError::Http(format!(
            "endpoint returned HTTP {}",
            resp.status()
        )));
    }
    resp.json::<serde_json::Value>()
        .map_err(|e| EndpointError::Json(e.to_string()))
}

/// Evaluate JSONPath expression, return list of matched values.
///
/// Uses `jsonpath_lib`. FModel uses Newtonsoft.Json JSONPath, which is
/// compatible for the common `$['a', 'b']` multi-select used for AES.
pub fn evaluate(json: &serde_json::Value, expression: &str) -> Result<Vec<serde_json::Value>, EndpointError> {
    let expr = normalize_expression(expression);
    let selected = jsonpath_lib::select(json, &expr)
        .map_err(|e| EndpointError::Expression(format!("{e} (expr: {expr})")))?;
    Ok(selected.into_iter().cloned().collect())
}

/// Parse 256-bit AES key: hex with optional `0x`, or base64 (standard, with/without padding).
pub fn parse_aes_key(s: &str) -> Result<[u8; 32], EndpointError> {
    let t = s.trim().trim_matches('"').trim().to_string();
    let err = || EndpointError::Aes(t.clone());
    // try hex
    let hex_part = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(&t);
    if let Ok(bytes) = hex::decode(hex_part) {
        if bytes.len() == 32 {
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            return Ok(out);
        }
    }
    // try base64 (standard, no-pad tolerant)
    {
        use base64::{engine::general_purpose, Engine as _};
        if let Ok(bytes) = general_purpose::STANDARD
            .decode(t.trim_end_matches('=').to_string() + &"=".repeat((4 - t.len() % 4) % 4))
            .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(t.trim_end_matches('=')))
        {
            if bytes.len() == 32 {
                let mut out = [0u8; 32];
                out.copy_from_slice(&bytes);
                return Ok(out);
            }
        }
    }
    Err(err())
}

/// Parse 128-bit guid: 32 hex chars, dashes and `0x` optional.
pub fn parse_guid(s: &str) -> Result<(u128, String), EndpointError> {
    let t = s.trim().trim_matches('"').to_string();
    let clean: String = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(&t)
        .chars()
        .filter(|c| *c != '-' && *c != '{' && *c != '}')
        .collect();
    if clean.len() != 32 || !clean.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(EndpointError::Guid(t));
    }
    let v = u128::from_str_radix(&clean, 16).map_err(|_| EndpointError::Guid(t.clone()))?;
    Ok((v, clean.to_ascii_uppercase()))
}

fn value_to_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Null => None,
        _ => None,
    }
}

/// Resolve endpoint JSON + expression into validated keys.
///
/// Rules (FModel compatible):
/// - expression must evaluate to 1 or 2 elements.
/// - element 0: main AES key (mandatory, hex, 256-bit).
/// - element 1 (optional): list of `{guid, key, name?}`.
pub fn resolve_keys(
    json: &serde_json::Value,
    expression: &str,
) -> Result<ResolvedKeys, EndpointError> {
    let values = evaluate(json, expression)?;
    if values.is_empty() {
        return Err(EndpointError::Validation(
            "expression returned no elements; expected main AES key".to_string(),
        ));
    }
    if values.len() > 2 {
        return Err(EndpointError::Validation(format!(
            "AES expression supports up to 2 elements, got {}",
            values.len()
        )));
    }

    // --- main key ---
    let main_raw = value_to_string(&values[0]).ok_or_else(|| {
        EndpointError::Validation(format!(
            "first element must be a hex AES key string, got: {}",
            values[0]
        ))
    })?;
    let main_key = parse_aes_key(&main_raw)?;

    // --- dynamic keys (optional) ---
    let mut dynamic_keys = Vec::new();
    if values.len() == 2 {
        let arr = values[1].as_array().ok_or_else(|| {
            EndpointError::Validation(format!(
                "second element must be a list of {{guid, key}} objects, got: {}",
                values[1]
            ))
        })?;
        for (i, item) in arr.iter().enumerate() {
            let guid_v = item.get("guid").or_else(|| item.get("Guid")).or_else(|| item.get("GUID")).ok_or_else(|| {
                EndpointError::Validation(format!("dynamicKeys[{i}] missing \"guid\""))
            })?;
            let key_v = item.get("key").or_else(|| item.get("Key")).ok_or_else(|| {
                EndpointError::Validation(format!("dynamicKeys[{i}] missing \"key\""))
            })?;
            let guid_s = value_to_string(guid_v).ok_or_else(|| {
                EndpointError::Validation(format!("dynamicKeys[{i}].guid must be a string"))
            })?;
            let key_s = value_to_string(key_v).ok_or_else(|| {
                EndpointError::Validation(format!("dynamicKeys[{i}].key must be a string"))
            })?;
            let (guid, guid_str) = parse_guid(&guid_s).map_err(|_| {
                EndpointError::Validation(format!("dynamicKeys[{i}].guid invalid: {guid_s}"))
            })?;
            let key = parse_aes_key(&key_s).map_err(|_| {
                EndpointError::Validation(format!("dynamicKeys[{i}].key invalid (need 256-bit hex): {key_s}"))
            })?;
            let name = item
                .get("name")
                .or_else(|| item.get("Name"))
                .and_then(value_to_string);
            dynamic_keys.push(DynamicKey {
                guid,
                guid_str,
                key,
                key_str: key_s,
                name,
            });
        }
    }

    Ok(ResolvedKeys {
        main_key,
        main_key_str: main_raw,
        dynamic_keys,
    })
}

/// Fetch endpoint then resolve. Convenience for CLI/GUI `Send` + `Test`.
pub fn fetch_and_resolve(config: &EndpointConfig) -> Result<(serde_json::Value, ResolvedKeys), EndpointError> {
    let json = fetch_json(&config.endpoint)?;
    let resolved = resolve_keys(&json, &config.expression)?;
    Ok((json, resolved))
}

impl ResolvedKeys {
    /// Pick key for a pak: dynamic key matching `encryption_guid`, else main key.
    pub fn key_for_guid(&self, guid: Option<u128>) -> [u8; 32] {
        if let Some(g) = guid {
            if let Some(d) = self.dynamic_keys.iter().find(|d| d.guid == g) {
                return d.key;
            }
            // also try string-normalized match (endianness safety)
            let s = format!("{g:032X}");
            if let Some(d) = self.dynamic_keys.iter().find(|d| d.guid_str == s) {
                return d.key;
            }
        }
        self.main_key
    }

    pub fn key_for_guid_str(&self, guid_str: &str) -> [u8; 32] {
        if let Ok((g, _)) = parse_guid(guid_str) {
            return self.key_for_guid(Some(g));
        }
        self.main_key
    }
}

/// Load/save endpoint config JSON file (for GUI persistence).
pub fn load_config(path: &std::path::Path) -> Option<EndpointConfig> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
}

pub fn save_config(path: &std::path::Path, cfg: &EndpointConfig) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(cfg).unwrap())
}

pub fn default_config_path() -> std::path::PathBuf {
    if let Some(proj) = std::env::var_os("APPDATA") {
        std::path::PathBuf::from(proj).join("vrepak").join("endpoint.json")
    } else if let Some(home) = std::env::var_os("HOME") {
        std::path::PathBuf::from(home).join(".config").join("vrepak").join("endpoint.json")
    } else {
        std::path::PathBuf::from("endpoint.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_json() -> serde_json::Value {
        serde_json::json!({
            "mainKey": "0x6F80948821CA338739A24D4D9F778BCAC0996B2EF2A73897A789C68AFF05174E",
            "dynamicKeys": [
                {"guid": "B8BBEF2CF08D46FAAD154EA2B0F2856F", "key": "0x42ACDCFD26F9E4391C9FBABFC32BC06BACC2BFA7CAC0E2C9EDC0B86D968CE441"},
                {"guid": "434FF6B9EB0C49499655CF4F96316411", "key": "0xF00FB03520688C92C4B547F1F5FD147ABB4C8052ED9CFC69DD770E12B89A9A37"}
            ]
        })
    }

    #[test]
    fn normalize_adds_dollar() {
        assert_eq!(normalize_expression("['a','b']"), "$['a','b']");
        assert_eq!(normalize_expression("$['a','b']"), "$['a','b']");
    }

    #[test]
    fn resolves_wuwa_sample() {
        let j = sample_json();
        let r = resolve_keys(&j, "$['mainKey', 'dynamicKeys']").unwrap();
        assert_eq!(r.dynamic_keys.len(), 2);
        assert_eq!(r.guid_strs(), vec!["B8BBEF2CF08D46FAAD154EA2B0F2856F", "434FF6B9EB0C49499655CF4F96316411"]);
    }

    #[test]
    fn resolves_without_dollar() {
        let j = sample_json();
        let r = resolve_keys(&j, "['mainKey', 'dynamicKeys']").unwrap();
        assert_eq!(r.dynamic_keys.len(), 2);
    }

    #[test]
    fn single_key_only() {
        let j = serde_json::json!({"only": "0x0000000000000000000000000000000000000000000000000000000000000000"});
        let r = resolve_keys(&j, "$['only']").unwrap();
        assert!(r.dynamic_keys.is_empty());
    }

    #[test]
    fn rejects_three_elements() {
        let j = serde_json::json!({"a": "0x0000000000000000000000000000000000000000000000000000000000000000", "b": [], "c": 1});
        let e = resolve_keys(&j, "$['a','b','c']").unwrap_err();
        assert!(e.to_string().contains("up to 2"));
    }

    #[test]
    fn key_for_guid_lookup() {
        let j = sample_json();
        let r = resolve_keys(&j, "$['mainKey', 'dynamicKeys']").unwrap();
        let (g, _) = parse_guid("B8BBEF2CF08D46FAAD154EA2B0F2856F").unwrap();
        assert_ne!(r.key_for_guid(Some(g)), r.main_key);
        assert_eq!(r.key_for_guid(Some(0x1234)), r.main_key);
        assert_eq!(r.key_for_guid(None), r.main_key);
    }

    impl ResolvedKeys {
        fn guid_strs(&self) -> Vec<&str> {
            self.dynamic_keys.iter().map(|d| d.guid_str.as_str()).collect()
        }
    }
}
