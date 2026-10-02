//! vrepak GUI backend (Tauri) - Endpoint Configuration (AES) + pak operations.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct TestResult {
    valid: bool,
    message: String,
    main_key: Option<String>,
    dynamic_count: Option<usize>,
    preview: Option<Vec<DynamicPreview>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DynamicPreview {
    guid: String,
    key: String,
    name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PakInfo {
    mount_point: String,
    version: String,
    encrypted_index: bool,
    encryption_guid: Option<String>,
    file_count: usize,
}

fn aes_from_bytes(bytes: &[u8; 32]) -> aes::Aes256 {
    use aes::cipher::KeyInit;
    aes::Aes256::new_from_slice(bytes).expect("32 bytes")
}

#[tauri::command]
fn fetch_endpoint(endpoint: String) -> Result<serde_json::Value, String> {
    vrepak_endpoint::fetch_json(&endpoint).map_err(|e| e.to_string())
}

#[tauri::command]
fn test_expression(endpoint: String, expression: String) -> TestResult {
    let cfg = vrepak_endpoint::EndpointConfig::new(&endpoint, &expression);
    match vrepak_endpoint::fetch_and_resolve(&cfg) {
        Ok((_json, resolved)) => {
            let preview = resolved
                .dynamic_keys
                .iter()
                .take(20)
                .map(|d| DynamicPreview {
                    guid: d.guid_str.clone(),
                    key: d.key_str.clone(),
                    name: d.name.clone(),
                })
                .collect();
            TestResult {
                valid: true,
                message: "Your endpoint configuration is valid! Please, avoid any unnecessary modifications!".to_string(),
                main_key: Some(resolved.main_key_str.clone()),
                dynamic_count: Some(resolved.dynamic_keys.len()),
                preview: Some(preview),
            }
        }
        Err(e) => TestResult {
            valid: false,
            message: format!("Invalid: {e}"),
            main_key: None,
            dynamic_count: None,
            preview: None,
        },
    }
}

#[tauri::command]
fn save_endpoint_config(endpoint: String, expression: String) -> Result<String, String> {
    let cfg = vrepak_endpoint::EndpointConfig::new(endpoint, expression);
    let path = vrepak_endpoint::default_config_path();
    vrepak_endpoint::save_config(&path, &cfg).map_err(|e| e.to_string())?;
    Ok(path.to_string_lossy().to_string())
}

#[tauri::command]
fn load_endpoint_config() -> vrepak_endpoint::EndpointConfig {
    let path = vrepak_endpoint::default_config_path();
    vrepak_endpoint::load_config(&path).unwrap_or_default()
}

fn resolve_key_for_pak(
    pak_path: &str,
    explicit_key: Option<String>,
    endpoint: Option<String>,
    expression: Option<String>,
) -> Result<Option<aes::Aes256>, String> {
    // 1. explicit key wins
    if let Some(k) = explicit_key {
        if k.trim().is_empty() {
            return Ok(None);
        }
        return vrepak_endpoint::parse_aes_key(&k)
            .map(|b| Some(aes_from_bytes(&b)))
            .map_err(|e| e.to_string());
    }
    // 2. endpoint auto-resolve by GUID
    if let Some(ep) = endpoint {
        if ep.trim().is_empty() {
            return Ok(None);
        }
        let expr = expression.unwrap_or_default();
        let cfg = vrepak_endpoint::EndpointConfig::new(&ep, &expr);
        let (_json, resolved) =
            vrepak_endpoint::fetch_and_resolve(&cfg).map_err(|e| e.to_string())?;
        let guid = File::open(pak_path)
            .ok()
            .and_then(|mut f| vrepak::PakReader::peek_encryption_guid(&mut BufReader::new(&mut f)));
        let bytes = resolved.key_for_guid(guid);
        return Ok(Some(aes_from_bytes(&bytes)));
    }
    Ok(None)
}

#[tauri::command]
fn pak_info(
    pak_path: String,
    aes_key: Option<String>,
    endpoint: Option<String>,
    expression: Option<String>,
) -> Result<PakInfo, String> {
    let key = resolve_key_for_pak(&pak_path, aes_key, endpoint, expression)?;
    let mut builder = vrepak::PakBuilder::new();
    if let Some(k) = key {
        builder = builder.key(k);
    }
    let mut reader = BufReader::new(File::open(&pak_path).map_err(|e| e.to_string())?);
    let pak = builder.reader(&mut reader).map_err(|e| e.to_string())?;
    Ok(PakInfo {
        mount_point: pak.mount_point().to_string(),
        version: pak.version().to_string(),
        encrypted_index: pak.encrypted_index(),
        encryption_guid: pak.encryption_guid().map(|g| format!("{g:032X}")),
        file_count: pak.files().len(),
    })
}

#[tauri::command]
fn pak_list(
    pak_path: String,
    aes_key: Option<String>,
    endpoint: Option<String>,
    expression: Option<String>,
    strip_prefix: Option<String>,
) -> Result<Vec<String>, String> {
    let key = resolve_key_for_pak(&pak_path, aes_key, endpoint, expression)?;
    let mut builder = vrepak::PakBuilder::new();
    if let Some(k) = key {
        builder = builder.key(k);
    }
    let mut reader = BufReader::new(File::open(&pak_path).map_err(|e| e.to_string())?);
    let pak = builder.reader(&mut reader).map_err(|e| e.to_string())?;
    let prefix = strip_prefix.unwrap_or_else(|| "../../../".to_string());
    let mount = PathBuf::from(pak.mount_point());
    let mut out = Vec::new();
    for f in pak.files() {
        let full = mount.join(&f);
        let stripped = full
            .strip_prefix(&prefix)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| full.to_string_lossy().to_string());
        out.push(stripped.replace('\\', "/"));
    }
    out.sort();
    Ok(out)
}

#[tauri::command]
fn pak_unpack(
    pak_path: String,
    out_dir: String,
    aes_key: Option<String>,
    endpoint: Option<String>,
    expression: Option<String>,
) -> Result<String, String> {
    let key = resolve_key_for_pak(&pak_path, aes_key, endpoint, expression)?;
    let mut builder = vrepak::PakBuilder::new();
    if let Some(k) = key {
        builder = builder.key(k);
    }
    let mut reader = BufReader::new(File::open(&pak_path).map_err(|e| e.to_string())?);
    let pak = builder.reader(&mut reader).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
    let mount = PathBuf::from(pak.mount_point());
    let prefix = PathBuf::from("../../../");
    let mut count = 0;
    // re-open for parallel reads (simple sequential for GUI)
    let mut reader2 = BufReader::new(File::open(&pak_path).map_err(|e| e.to_string())?);
    for f in pak.files() {
        let full = mount.join(&f);
        let rel = full.strip_prefix(&prefix).map_err(|e| e.to_string())?;
        let out_path = PathBuf::from(&out_dir).join(rel);
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut out_file = File::create(&out_path).map_err(|e| e.to_string())?;
        // need fresh reader position each time; PakReader::read_file seeks internally
        pak.read_file(&f, &mut reader2, &mut out_file)
            .map_err(|e| e.to_string())?;
        count += 1;
    }
    Ok(format!("Unpacked {count} files to {out_dir}"))
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .invoke_handler(tauri::generate_handler![
            fetch_endpoint,
            test_expression,
            save_endpoint_config,
            load_endpoint_config,
            pak_info,
            pak_list,
            pak_unpack
        ])
        .run(tauri::generate_context!())
        .expect("error while running vrepak-gui");
}
