//! Unpack manifest sidecar (`vrepak-manifest.json`).
//!
//! Written next to unpacked files, records exactly how each file was stored:
//! AES key (hex), compression method, encryption flag and WuWa `CustomData`.
//! `pack` reads it back so a repack restores the original parameters unless
//! explicitly overridden by flags. Keep the file safe: it contains keys.

use serde::{Deserialize, Serialize};

pub const MANIFEST_FILENAME: &str = "vrepak-manifest.json";
const MANIFEST_FORMAT: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMeta {
    /// pak-relative path with `/` separators (as listed by `list`)
    pub path: String,
    /// compression method name (`Zlib`, `Gzip`, `Zstd`, `LZ4`, `Oodle`) or null
    pub compression: Option<String>,
    /// whether the stored bytes were encrypted
    pub encrypted: bool,
    /// effective AES key as `0x`-hex, if the file was encrypted
    pub key: Option<String>,
    /// where the key came from (informational, e.g. endpoint description)
    pub key_source: Option<String>,
    /// Wuthering Waves CustomData (meaningful for `wuthering-waves` engine)
    pub custom_data: u8,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PakManifest {
    pub format: u32,
    /// engine profile name (`stock`, `wuthering-waves`)
    pub engine: String,
    /// pak version name (`V11`, …)
    pub pak_version: String,
    pub mount_point: String,
    /// footer encryption guid as 32 hex chars, if any
    pub encryption_guid: Option<String>,
    /// whether the index itself was encrypted (missing in old manifests)
    #[serde(default)]
    pub index_encrypted: bool,
    /// key the index was encrypted with, as `0x`-hex (missing in old manifests)
    #[serde(default)]
    pub index_key: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<FileMeta>,
}

impl PakManifest {
    pub fn new(
        engine: crate::Engine,
        pak_version: crate::Version,
        mount_point: &str,
        encryption_guid: Option<u128>,
        index_encrypted: bool,
        index_key: Option<String>,
    ) -> Self {
        Self {
            format: MANIFEST_FORMAT,
            engine: engine.to_string(),
            pak_version: pak_version.to_string(),
            mount_point: mount_point.to_string(),
            encryption_guid: encryption_guid.map(|g| format!("{g:032X}")),
            index_encrypted,
            index_key: index_key.filter(|_| index_encrypted),
            files: vec![],
        }
    }

    pub fn to_json_pretty(&self) -> Result<String, crate::Error> {
        serde_json::to_string_pretty(self)
            .map_err(|e| crate::Error::Other(format!("manifest serialize: {e}")))
    }

    pub fn from_json(s: &str) -> Result<Self, crate::Error> {
        let manifest: Self =
            serde_json::from_str(s).map_err(|e| crate::Error::Other(format!("manifest parse: {e}")))?;
        if manifest.format != MANIFEST_FORMAT {
            return Err(crate::Error::Other(format!(
                "unsupported manifest format {}",
                manifest.format
            )));
        }
        Ok(manifest)
    }

    pub fn find(&self, path: &str) -> Option<&FileMeta> {
        self.files.iter().find(|f| f.path == path)
    }

    /// Build a manifest from an open pak. `index_key_hex` is the `0x`-hex key
    /// the index was encrypted with (if it was); `key_hex_for` maps a
    /// pak-relative file path to the effective key (`0x`-hex) used for it,
    /// if any.
    pub fn from_reader<F>(
        reader: &crate::PakReader,
        engine: crate::Engine,
        index_key_hex: Option<String>,
        mut key_hex_for: F,
    ) -> Self
    where
        F: FnMut(&str) -> Option<(String, Option<String>)>,
    {
        let index_encrypted = reader.encrypted_index();
        let mut manifest = Self::new(
            engine,
            reader.version(),
            reader.mount_point(),
            reader.encryption_guid(),
            index_encrypted,
            index_key_hex,
        );
        let mut files = reader.files();
        files.sort();
        for path in files {
            let info = reader.entry_info(&path);
            let (key, key_source) = key_hex_for(&path).unzip();
            let key_source = key_source.flatten();
            manifest.files.push(FileMeta {
                path,
                compression: info
                    .as_ref()
                    .and_then(|i| i.compression)
                    .map(|c| c.to_string()),
                encrypted: info.as_ref().map(|i| i.encrypted).unwrap_or(false),
                key,
                key_source,
                custom_data: info.as_ref().map(|i| i.custom_data).unwrap_or(0),
                compressed_size: info.as_ref().map(|i| i.compressed_size).unwrap_or(0),
                uncompressed_size: info.as_ref().map(|i| i.uncompressed_size).unwrap_or(0),
            });
        }
        manifest
    }

    /// Merge another manifest in (used when unpacking several paks into one
    /// directory): per-file entries from `other` win, pak-level fields too.
    pub fn merge(&mut self, other: Self) {
        for f in other.files {
            if let Some(slot) = self.files.iter_mut().find(|e| e.path == f.path) {
                *slot = f;
            } else {
                self.files.push(f);
            }
        }
        self.files.sort_by(|a, b| a.path.cmp(&b.path));
        self.engine = other.engine;
        self.pak_version = other.pak_version;
        self.mount_point = other.mount_point;
        self.encryption_guid = other.encryption_guid;
        self.index_encrypted = other.index_encrypted;
        self.index_key = other.index_key;
    }

    pub fn load_if_present(dir: &std::path::Path) -> Option<Self> {
        std::fs::read_to_string(dir.join(MANIFEST_FILENAME))
            .ok()
            .and_then(|s| Self::from_json(&s).ok())
    }

    pub fn save(&self, dir: &std::path::Path) -> Result<(), crate::Error> {
        let text = self.to_json_pretty()?;
        std::fs::write(dir.join(MANIFEST_FILENAME), text).map_err(|e| {
            crate::Error::Other(format!("manifest write: {e}"))
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn manifest_json_roundtrip() {
        let mut m = PakManifest::new(
            crate::Engine::WutheringWaves,
            crate::Version::V11,
            "../../../",
            Some(0xB8BBEF2CF08D46FAAD154EA2B0F2856F),
            true,
            Some("0x00".to_string()),
        );
        m.files.push(FileMeta {
            path: "a/b.uasset".to_string(),
            compression: Some("Zlib".to_string()),
            encrypted: true,
            key: Some("0x00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF".to_string()),
            key_source: Some("endpoint dynamic".to_string()),
            custom_data: 2,
            compressed_size: 100,
            uncompressed_size: 200,
        });
        let json = m.to_json_pretty().unwrap();
        let back = PakManifest::from_json(&json).unwrap();
        assert_eq!(back.files.len(), 1);
        assert_eq!(back.files[0].custom_data, 2);
        assert_eq!(back.engine, "wuthering-waves");
        assert!(back.find("a/b.uasset").is_some());
        assert!(back.find("nope").is_none());
        assert!(PakManifest::from_json("{\"format\": 999}").is_err());
    }

    #[test]
    fn manifest_index_fields() {
        let m = PakManifest::new(
            crate::Engine::Stock,
            crate::Version::V11,
            "../../../",
            None,
            true,
            Some("0x00".to_string()),
        );
        let back = PakManifest::from_json(&m.to_json_pretty().unwrap()).unwrap();
        assert!(back.index_encrypted);
        assert_eq!(back.index_key.as_deref(), Some("0x00"));
        // manifests written before these fields existed still parse
        let old = PakManifest::from_json(
            r#"{"format":1,"engine":"stock","pak_version":"V11","mount_point":"../../../","encryption_guid":null,"files":[]}"#,
        )
        .unwrap();
        assert!(!old.index_encrypted);
        assert_eq!(old.index_key, None);
    }
}
