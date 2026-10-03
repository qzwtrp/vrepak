use crate::data::build_partial_entry;
use crate::entry::Entry;
use crate::{Compression, Error, PartialEntry};

use super::ext::{ReadExt, WriteExt};
use super::{Version, VersionMajor};
use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use std::collections::BTreeMap;
use std::io::{self, Read, Seek, Write};

#[derive(Default, Clone, Copy)]
pub(crate) struct Hash(pub(crate) [u8; 20]);
impl std::fmt::Debug for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hash({})", hex::encode(self.0))
    }
}

#[derive(Debug)]
pub struct PakBuilder {
    key: super::Key,
    allowed_compression: Vec<Compression>,
    engine: super::Engine,
    encryption_guid: Option<u128>,
    wuwa_custom_data: u8,
    /// Force index encryption on/off. `None` (default) derives it from key
    /// presence. (`into_pakwriter` rewrite flows always preserve the source
    /// pak's own flag instead.)
    encrypt_index: Option<bool>,
}

impl Default for PakBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PakBuilder {
    pub fn new() -> Self {
        Self {
            key: Default::default(),
            allowed_compression: Default::default(),
            engine: Default::default(),
            encryption_guid: None,
            // most Wuthering Waves entries use CustomData 2 (first 0x800 bytes encrypted)
            wuwa_custom_data: 2,
            encrypt_index: None,
        }
    }
    #[cfg(feature = "encryption")]
    pub fn key(mut self, key: aes::Aes256) -> Self {
        self.key = super::Key::Some(key);
        self
    }
    #[cfg(feature = "compression")]
    pub fn compression(mut self, compression: impl IntoIterator<Item = Compression>) -> Self {
        self.allowed_compression = compression.into_iter().collect();
        self
    }
    /// Engine profile for game-specific pak quirks (default: stock Unreal Engine).
    pub fn engine(mut self, engine: super::Engine) -> Self {
        self.engine = engine;
        self
    }
    /// Encryption GUID recorded in the footer when packing encrypted paks
    /// (default: none, i.e. zeros — like Wuthering Waves paks).
    pub fn encryption_guid(mut self, guid: u128) -> Self {
        self.encryption_guid = Some(guid);
        self
    }
    /// `CustomData` byte assigned to fresh entries when packing with the
    /// Wuthering Waves engine (default: 2 = first 0x800 bytes encrypted).
    /// Ignored for stock engine paks.
    pub fn wuwa_custom_data(mut self, custom_data: u8) -> Self {
        self.wuwa_custom_data = custom_data;
        self
    }
    /// Force the packed index to be encrypted or plaintext, e.g. to
    /// reproduce a source pak's exact state from its unpack manifest.
    /// By default the index is encrypted iff a key is set.
    pub fn encrypt_index(mut self, encrypt: bool) -> Self {
        self.encrypt_index = Some(encrypt);
        self
    }
    pub fn reader<R: Read + Seek>(self, reader: &mut R) -> Result<PakReader, super::Error> {
        PakReader::new_any_inner(reader, self.key, self.engine)
    }
    pub fn reader_with_version<R: Read + Seek>(
        self,
        reader: &mut R,
        version: super::Version,
    ) -> Result<PakReader, super::Error> {
        PakReader::new_inner(reader, version, self.key, self.engine)
    }
    pub fn writer<W: Write + Seek>(
        self,
        writer: W,
        version: super::Version,
        mount_point: String,
        path_hash_seed: Option<u64>,
    ) -> PakWriter<W> {
        PakWriter::new_inner(
            writer,
            self.key,
            version,
            mount_point,
            path_hash_seed,
            self.allowed_compression,
            self.engine,
            self.encryption_guid,
            self.wuwa_custom_data,
            self.encrypt_index,
        )
    }
}

#[derive(Debug)]
pub struct PakReader {
    pak: Pak,
    key: super::Key,
    engine: super::Engine,
}

/// Per-file storage metadata (for manifests and diagnostics).
#[derive(Debug, Clone)]
pub struct EntryInfo {
    pub compression: Option<Compression>,
    pub encrypted: bool,
    pub custom_data: u8,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
}

#[derive(Debug)]
pub struct PakWriter<W: Write + Seek> {
    pak: Pak,
    writer: W,
    key: super::Key,
    allowed_compression: Vec<Compression>,
    engine: super::Engine,
    encryption_guid: Option<u128>,
    wuwa_custom_data: u8,
}

#[derive(Debug)]
pub(crate) struct Pak {
    version: Version,
    mount_point: String,
    index_offset: Option<u64>,
    index: Index,
    encrypted_index: bool,
    encryption_guid: Option<u128>,
    compression: Vec<Option<Compression>>,
}

impl Pak {
    fn new(version: Version, mount_point: String, path_hash_seed: Option<u64>) -> Self {
        Pak {
            version,
            mount_point,
            index_offset: None,
            index: Index::new(path_hash_seed),
            encrypted_index: false,
            encryption_guid: None,
            compression: (if version.version_major() < VersionMajor::FNameBasedCompression {
                vec![
                    Some(Compression::Zlib),
                    Some(Compression::Gzip),
                    Some(Compression::Oodle),
                ]
            } else {
                vec![]
            }),
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct Index {
    path_hash_seed: Option<u64>,
    entries: BTreeMap<String, super::entry::Entry>,
}

impl Index {
    fn new(path_hash_seed: Option<u64>) -> Self {
        Index {
            path_hash_seed,
            ..Index::default()
        }
    }

    fn entries(&self) -> &BTreeMap<String, super::entry::Entry> {
        &self.entries
    }

    fn into_entries(self) -> BTreeMap<String, super::entry::Entry> {
        self.entries
    }

    fn add_entry(&mut self, path: String, entry: super::entry::Entry) {
        self.entries.insert(path, entry);
    }
}

#[cfg(feature = "encryption")]
fn decrypt(key: &super::Key, bytes: &mut [u8]) -> Result<(), super::Error> {
    if let super::Key::Some(key) = key {
        use aes::cipher::BlockDecrypt;
        for chunk in bytes.chunks_mut(16) {
            key.decrypt_block(aes::Block::from_mut_slice(chunk))
        }
        Ok(())
    } else {
        Err(super::Error::Encrypted)
    }
}

#[cfg(feature = "encryption")]
fn encrypt_store(buf: &mut Vec<u8>, key: &super::Key) -> Result<(), super::Error> {
    use aes::cipher::BlockEncrypt;
    // stored length must stay an AES-block multiple: the reader consumes
    // exactly `align(size)` bytes.
    while buf.len() % 16 != 0 {
        buf.push(0);
    }
    let super::Key::Some(key) = key else {
        return Err(super::Error::Encrypted);
    };
    for block in buf.chunks_mut(16) {
        key.encrypt_block(aes::Block::from_mut_slice(block))
    }
    Ok(())
}
impl PakReader {
    fn new_any_inner<R: Read + Seek>(
        reader: &mut R,
        key: super::Key,
        engine: super::Engine,
    ) -> Result<Self, super::Error> {
        use std::fmt::Write;
        let mut log = "\n".to_owned();

        for ver in Version::iter() {
            match Pak::read(&mut *reader, ver, &key, engine) {
                Ok(pak) => return Ok(Self { pak, key, engine }),
                Err(err) => writeln!(log, "trying version {} failed: {}", ver, err)?,
            }
        }
        Err(super::Error::UnsupportedOrEncrypted(log))
    }

    fn new_inner<R: Read + Seek>(
        reader: &mut R,
        version: super::Version,
        key: super::Key,
        engine: super::Engine,
    ) -> Result<Self, super::Error> {
        Pak::read(reader, version, &key, engine).map(|pak| Self { pak, key, engine })
    }

    pub fn version(&self) -> super::Version {
        self.pak.version
    }

    pub fn mount_point(&self) -> &str {
        &self.pak.mount_point
    }

    pub fn encrypted_index(&self) -> bool {
        self.pak.encrypted_index
    }

    pub fn encryption_guid(&self) -> Option<u128> {
        self.pak.encryption_guid
    }

    pub fn path_hash_seed(&self) -> Option<u64> {
        self.pak.index.path_hash_seed
    }

    pub fn get<R: Read + Seek>(&self, path: &str, reader: &mut R) -> Result<Vec<u8>, super::Error> {
        let mut data = Vec::new();
        self.read_file(path, reader, &mut data)?;
        Ok(data)
    }

    pub fn read_file<R: Read + Seek, W: Write>(
        &self,
        path: &str,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<(), super::Error> {
        match self.pak.index.entries().get(path) {
            Some(entry) => entry.read_file(
                reader,
                self.pak.version,
                &self.pak.compression,
                &self.key,
                writer,
                self.engine,
            ),
            None => Err(super::Error::MissingEntry(path.to_owned())),
        }
    }

    pub fn files(&self) -> Vec<String> {
        self.pak.index.entries().keys().cloned().collect()
    }

    /// Per-file storage metadata for manifests/diagnostics.
    pub fn entry_info(&self, path: &str) -> Option<EntryInfo> {
        self.pak.index.entries().get(path).map(|e| EntryInfo {
            compression: e
                .compression_slot
                .and_then(|slot| self.pak.compression.get(slot as usize).cloned())
                .flatten(),
            encrypted: e.is_encrypted(),
            custom_data: e.custom_data,
            compressed_size: e.compressed,
            uncompressed_size: e.uncompressed,
        })
    }

    /// Peek encryption GUID without needing the AES key (footer is not encrypted).
    /// Tries all known versions, returns GUID if footer found.
    pub fn peek_encryption_guid<R: Read + Seek>(reader: &mut R) -> Option<u128> {
        for ver in super::Version::iter() {
            let size = ver.size();
            if reader.seek(io::SeekFrom::End(-size)).is_err() {
                continue;
            }
            if let Ok(footer) = super::footer::Footer::read(reader, ver) {
                // found a valid footer for this version; return its guid (may be None)
                // if guid is None, continue searching other versions? return None directly
                // to signal "found but no guid". We return the first valid footer's guid.
                return footer.encryption_uuid;
            }
        }
        None
    }

    pub fn used_compression(&self) -> Vec<Compression> {
        let mut used_compression = vec![0; self.pak.compression.len()];
        for entry in self.pak.index.entries.values() {
            if let Some(count) = entry
                .compression_slot
                .and_then(|slot| used_compression.get_mut(slot as usize))
            {
                *count += 1;
            }
        }
        used_compression
            .into_iter()
            .zip(self.pak.compression.iter())
            .filter_map(|(count, comp)| comp.filter(|_| count > 0))
            .collect()
    }

    pub fn into_pakwriter<W: Write + Seek>(
        self,
        mut writer: W,
    ) -> Result<PakWriter<W>, super::Error> {
        writer.seek(io::SeekFrom::Start(self.pak.index_offset.unwrap()))?;
        let encryption_guid = self.pak.encryption_guid;
        Ok(PakWriter {
            allowed_compression: self.pak.compression.iter().filter_map(|c| *c).collect(),
            pak: self.pak,
            key: self.key,
            writer,
            engine: self.engine,
            // rewriting preserves the source pak's guid; fresh entries keep
            // whatever CustomData they were read with (writer default unused)
            encryption_guid,
            wuwa_custom_data: 2,
        })
    }
}

impl<W: Write + Seek> PakWriter<W> {
    fn new_inner(
        writer: W,
        key: super::Key,
        version: Version,
        mount_point: String,
        path_hash_seed: Option<u64>,
        allowed_compression: Vec<Compression>,
        engine: super::Engine,
        encryption_guid: Option<u128>,
        wuwa_custom_data: u8,
        encrypt_index: Option<bool>,
    ) -> Self {
        let mut pak = Pak::new(version, mount_point, path_hash_seed);
        // a fresh pack encrypts its index iff a key was provided, unless
        // overridden explicitly (rewrite flows preserve the source instead)
        #[cfg(feature = "encryption")]
        {
            pak.encrypted_index = encrypt_index.unwrap_or(matches!(key, super::Key::Some(_)));
        }
        #[cfg(not(feature = "encryption"))]
        {
            let _ = encrypt_index;
        }
        #[cfg(not(feature = "encryption"))]
        {
            let _ = encrypt_index;
        }
        pak.encryption_guid = encryption_guid;
        PakWriter {
            pak,
            writer,
            key,
            allowed_compression,
            engine,
            encryption_guid,
            wuwa_custom_data,
        }
    }

    pub fn into_writer(self) -> W {
        self.writer
    }

    /// Encryption parameters for the next written entry, if a key is set.
    /// Takes individual fields (not `&self`) so the result can be used
    /// alongside `&mut` borrows of the writer.
    fn crypt(
        key: &super::Key,
        engine: super::Engine,
        wuwa_custom_data: u8,
    ) -> Result<Option<crate::entry::WriteCrypt<'_>>, super::Error> {
        #[cfg(not(feature = "encryption"))]
        {
            let _ = (key, engine, wuwa_custom_data);
            return Ok(None);
        }
        #[cfg(feature = "encryption")]
        {
            match key {
                super::Key::None => Ok(None),
                super::Key::Some(_) => {
                    let partial_limit = match engine {
                        super::Engine::WutheringWaves => {
                            Some(crate::entry::wuwa_decrypt_limit(wuwa_custom_data)?)
                        }
                        super::Engine::Stock => None,
                    };
                    Ok(Some(crate::entry::WriteCrypt {
                        key,
                        partial_limit,
                        custom_data: wuwa_custom_data,
                    }))
                }
            }
        }
    }

    pub fn write_file(
        &mut self,
        path: &str,
        allow_compress: bool,
        data: impl AsRef<[u8]>,
    ) -> Result<(), super::Error> {
        let crypt = Self::crypt(&self.key, self.engine, self.wuwa_custom_data)?;
        self.pak.index.add_entry(
            path.to_string(),
            Entry::write_file(
                &mut self.writer,
                self.pak.version,
                &mut self.pak.compression,
                if allow_compress {
                    &self.allowed_compression
                } else {
                    &[]
                },
                data.as_ref(),
                crypt,
            )?,
        );

        Ok(())
    }

    pub fn entry_builder(&self) -> EntryBuilder {
        EntryBuilder {
            allowed_compression: self.allowed_compression.clone(),
        }
    }

    /// Entry builder forcing one compression method (or none), for per-file
    /// manifest settings on pack. `None` means store uncompressed.
    pub fn entry_builder_for(&self, compression: Option<Compression>) -> EntryBuilder {
        EntryBuilder {
            allowed_compression: compression.into_iter().collect(),
        }
    }

    pub fn write_entry<D: AsRef<[u8]>>(
        &mut self,
        path: String,
        partial_entry: PartialEntry<D>,
    ) -> Result<(), Error> {
        let stream_position = self.writer.stream_position()?;

        let mut entry = partial_entry.build_entry(
            self.pak.version,
            &mut self.pak.compression,
            stream_position,
        )?;
        let crypt = Self::crypt(&self.key, self.engine, self.wuwa_custom_data)?;
        if let Some(c) = crypt {
            entry.flags |= 1;
            entry.custom_data = c.custom_data;
        }

        entry.write(
            &mut self.writer,
            self.pak.version,
            crate::entry::EntryLocation::Data,
        )?;

        self.pak.index.add_entry(path, entry);
        partial_entry.write_data(&mut self.writer, crypt)?;

        Ok(())
    }

    /// Like [`PakWriter::write_entry`], but with a per-file key and WuWa
    /// `CustomData` (for manifest-driven repacks). `key_bytes: None` writes
    /// a plaintext entry (the `custom_data` byte is still recorded for WuWa).
    pub fn write_entry_with_key<D: AsRef<[u8]>>(
        &mut self,
        path: String,
        partial_entry: PartialEntry<D>,
        key_bytes: Option<[u8; 32]>,
        custom_data: u8,
    ) -> Result<(), Error> {
        let stream_position = self.writer.stream_position()?;
        let mut entry = partial_entry.build_entry(
            self.pak.version,
            &mut self.pak.compression,
            stream_position,
        )?;
        #[cfg(feature = "encryption")]
        let owned_key: super::Key = match key_bytes {
            Some(bytes) => {
                use aes::cipher::KeyInit;
                super::Key::Some(
                    aes::Aes256::new_from_slice(&bytes).expect("per-file key is 32 bytes"),
                )
            }
            None => super::Key::None,
        };
        #[cfg(not(feature = "encryption"))]
        let owned_key: super::Key = {
            if key_bytes.is_some() {
                return Err(super::Error::Encryption);
            }
            super::Key::None
        };
        let crypt = Self::crypt(&owned_key, self.engine, custom_data)?;
        #[cfg(feature = "encryption")]
        if matches!(owned_key, super::Key::Some(_)) {
            entry.flags |= 1;
        }
        entry.custom_data = custom_data;
        entry.write(
            &mut self.writer,
            self.pak.version,
            crate::entry::EntryLocation::Data,
        )?;
        self.pak.index.add_entry(path, entry);
        partial_entry.write_data(&mut self.writer, crypt)?;
        Ok(())
    }
    pub fn write_index(mut self) -> Result<W, super::Error> {
        self.pak.write(&mut self.writer, &self.key, self.engine)?;
        Ok(self.writer)
    }
}

struct Data<'d>(Box<dyn AsRef<[u8]> + Send + Sync + 'd>);
impl AsRef<[u8]> for Data<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref().as_ref()
    }
}

#[derive(Clone)]
pub struct EntryBuilder {
    allowed_compression: Vec<Compression>,
}
impl EntryBuilder {
    /// Builder forcing one compression method (or none), for per-file
    /// manifest settings on pack.
    pub fn for_compression(compression: Option<Compression>) -> Self {
        EntryBuilder {
            allowed_compression: compression.into_iter().collect(),
        }
    }
    /// Builds an entry in memory (compressed if requested) which must be written out later
    pub fn build_entry<D: AsRef<[u8]> + Send + Sync>(
        &self,
        compress: bool,
        data: D,
    ) -> Result<PartialEntry<D>, Error> {
        let compression = if compress {
            self.allowed_compression.as_slice()
        } else {
            &[]
        };
        build_partial_entry(compression, data)
    }
}

impl Pak {
    fn read<R: Read + Seek>(
        reader: &mut R,
        version: super::Version,
        #[allow(unused)] key: &super::Key,
        engine: super::Engine,
    ) -> Result<Self, super::Error> {
        // read footer to get index, encryption & compression info
        reader.seek(io::SeekFrom::End(-version.size()))?;
        let footer = super::footer::Footer::read(reader, version)?;
        // read index to get all the entry info
        reader.seek(io::SeekFrom::Start(footer.index_offset))?;
        #[allow(unused_mut)]
        let mut index = reader.read_len(footer.index_size as usize)?;

        // decrypt index if needed
        if footer.encrypted {
            #[cfg(not(feature = "encryption"))]
            return Err(super::Error::Encryption);
            #[cfg(feature = "encryption")]
            decrypt(key, &mut index)?;
        }

        let mut index = io::Cursor::new(index);
        let mount_point = index.read_string()?;
        let len = index.read_u32::<LE>()? as usize;

        let index = if version.version_major() >= VersionMajor::PathHashIndex {
            let path_hash_seed = index.read_u64::<LE>()?;

            // Left in for potential desire to verify path index hashes.
            let _path_hash_index = if index.read_u32::<LE>()? != 0 {
                let path_hash_index_offset = index.read_u64::<LE>()?;
                let path_hash_index_size = index.read_u64::<LE>()?;
                let _path_hash_index_hash = index.read_len(20)?;

                reader.seek(io::SeekFrom::Start(path_hash_index_offset))?;
                let mut path_hash_index_buf = reader.read_len(path_hash_index_size as usize)?;
                // TODO verify hash

                if footer.encrypted {
                    #[cfg(not(feature = "encryption"))]
                    return Err(super::Error::Encryption);
                    #[cfg(feature = "encryption")]
                    decrypt(key, &mut path_hash_index_buf)?;
                }

                let mut path_hash_index = vec![];
                let mut phi_reader = io::Cursor::new(&mut path_hash_index_buf);
                for _ in 0..phi_reader.read_u32::<LE>()? {
                    let hash = phi_reader.read_u64::<LE>()?;
                    let encoded_entry_offset = phi_reader.read_i32::<LE>()?;
                    path_hash_index.push((hash, encoded_entry_offset));
                }

                Some(path_hash_index)
            } else {
                None
            };

            // Left in for potential desire to verify full directory index hashes.
            let full_directory_index = if index.read_u32::<LE>()? != 0 {
                let full_directory_index_offset = index.read_u64::<LE>()?;
                let full_directory_index_size = index.read_u64::<LE>()?;
                let _full_directory_index_hash = index.read_len(20)?;

                reader.seek(io::SeekFrom::Start(full_directory_index_offset))?;
                #[allow(unused_mut)]
                let mut full_directory_index =
                    reader.read_len(full_directory_index_size as usize)?;
                // TODO verify hash

                if footer.encrypted {
                    #[cfg(not(feature = "encryption"))]
                    return Err(super::Error::Encryption);
                    #[cfg(feature = "encryption")]
                    decrypt(key, &mut full_directory_index)?;
                }
                let mut fdi = io::Cursor::new(full_directory_index);

                let dir_count = fdi.read_u32::<LE>()? as usize;
                let mut directories = BTreeMap::new();
                for _ in 0..dir_count {
                    let dir_name = fdi.read_string()?;
                    let file_count = fdi.read_u32::<LE>()? as usize;
                    let mut files = BTreeMap::new();
                    for _ in 0..file_count {
                        let file_name = fdi.read_string()?;
                        files.insert(file_name, fdi.read_i32::<LE>()?);
                    }
                    directories.insert(dir_name, files);
                }
                Some(directories)
            } else {
                None
            };
            let size = index.read_u32::<LE>()? as usize;
            let encoded_entries = index.read_len(size)?;

            let non_encoded_entry_count = index.read_u32::<LE>()? as usize;
            let mut non_encoded_entries = Vec::with_capacity(non_encoded_entry_count);
            for _ in 0..non_encoded_entry_count {
                non_encoded_entries.push(Entry::read(&mut index, version)?);
            }

            let mut entries_by_path = BTreeMap::new();
            if let Some(fdi) = &full_directory_index {
                let mut encoded_entries = io::Cursor::new(&encoded_entries);
                for (dir_name, dir) in fdi {
                    for (file_name, encoded_offset) in dir {
                        // i32::MIN (0x80000000) is a deleted/pruned entry sentinel
                        // in the UE5 PAK format — skip it to avoid negate overflow.
                        if *encoded_offset == i32::MIN {
                            continue;
                        }
                        let entry = if *encoded_offset >= 0 {
                            encoded_entries.set_position(*encoded_offset as u64);
                            Entry::read_encoded(&mut encoded_entries, version, engine)?
                        } else {
                            let index = (-*encoded_offset) as usize - 1;
                            non_encoded_entries[index].clone()
                        };
                        let path = format!(
                            "{}{}",
                            dir_name.strip_prefix('/').unwrap_or(dir_name),
                            file_name
                        );
                        entries_by_path.insert(path, entry);
                    }
                }
            }

            Index {
                path_hash_seed: Some(path_hash_seed),
                entries: entries_by_path,
            }
        } else {
            let mut entries = BTreeMap::new();
            for _ in 0..len {
                entries.insert(
                    index.read_string()?,
                    super::entry::Entry::read(&mut index, version)?,
                );
            }
            Index {
                path_hash_seed: None,
                entries,
            }
        };

        Ok(Pak {
            version,
            mount_point,
            index_offset: Some(footer.index_offset),
            index,
            encrypted_index: footer.encrypted,
            encryption_guid: footer.encryption_uuid,
            compression: footer.compression,
        })
    }

    fn write<W: Write + Seek>(
        &self,
        writer: &mut W,
        #[allow(unused)] key: &super::Key,
        engine: super::Engine,
    ) -> Result<(), super::Error> {
        // Preserve the source pak's index-encryption state on rewrite; fresh
        // packs opt in via the builder key.
        let encrypting = self.encrypted_index;
        let index_offset = writer.stream_position()?;

        let mut index_buf = vec![];
        let mut index_writer = io::Cursor::new(&mut index_buf);
        index_writer.write_string(&self.mount_point)?;

        let secondary_index = if self.version < super::Version::V10 {
            let record_count = self.index.entries.len() as u32;
            index_writer.write_u32::<LE>(record_count)?;
            for (path, entry) in &self.index.entries {
                index_writer.write_string(path)?;
                entry.write(
                    &mut index_writer,
                    self.version,
                    super::entry::EntryLocation::Index,
                )?;
            }
            None
        } else {
            let record_count = self.index.entries.len() as u32;
            let path_hash_seed = self.index.path_hash_seed.unwrap_or_default();
            index_writer.write_u32::<LE>(record_count)?;
            index_writer.write_u64::<LE>(path_hash_seed)?;

            let (encoded_entries, offsets) = {
                let mut offsets = Vec::with_capacity(self.index.entries.len());
                let mut encoded_entries = io::Cursor::new(vec![]);
                for entry in self.index.entries.values() {
                    offsets.push(encoded_entries.get_ref().len() as u32);
                    entry.write_encoded(&mut encoded_entries, self.version, engine)?;
                }
                (encoded_entries.into_inner(), offsets)
            };

            // The index is organized sequentially as:
            // - Index Header, which contains:
            //     - Mount Point (u32 len + string w/ terminating byte)
            //     - Entry Count (u32)
            //     - Path Hash Seed (u64)
            //     - Has Path Hash Index (u32); if true, then:
            //         - Path Hash Index Offset (u64)
            //         - Path Hash Index Size (u64)
            //         - Path Hash Index Hash ([u8; 20])
            //     - Has Full Directory Index (u32); if true, then:
            //         - Full Directory Index Offset (u64)
            //         - Full Directory Index Size (u64)
            //         - Full Directory Index Hash ([u8; 20])
            //     - Encoded Index Records Size
            //     - (Unused) File Count
            // - Path Hash Index
            // - Full Directory Index
            // - Encoded Index Records; each encoded index record is (0xC bytes) from:
            //     - Flags (u32)
            //     - Offset (u32)
            //     - Size (u32)
            let bytes_before_phi = {
                let mut size = 0;
                size += 4; // mount point len
                size += self.mount_point.len() as u64 + 1; // mount point string w/ NUL byte
                size += 8; // path hash seed
                size += 4; // record count
                size += 4; // has path hash index (since we're generating, always true)
                size += 8 + 8 + 20; // path hash index offset, size and hash
                size += 4; // has full directory index (since we're generating, always true)
                size += 8 + 8 + 20; // full directory index offset, size and hash
                size += 4; // encoded entry size
                size += encoded_entries.len() as u64;
                size += 4; // unused file count
                size
            };

            let path_hash_index_offset = index_offset
                + if encrypting {
                    // AES-encrypted regions must start at a block multiple:
                    // the index grows to its padded length.
                    crate::entry::align(bytes_before_phi)
                } else {
                    bytes_before_phi
                };

            let mut phi_buf = vec![];
            let mut phi_writer = io::Cursor::new(&mut phi_buf);
            generate_path_hash_index(
                &mut phi_writer,
                path_hash_seed,
                &self.index.entries,
                &offsets,
            )?;

            #[cfg(feature = "encryption")]
            if encrypting {
                encrypt_store(&mut phi_buf, key)?;
            }

            let full_directory_index_offset = path_hash_index_offset + phi_buf.len() as u64;

            let mut fdi_buf = vec![];
            let mut fdi_writer = io::Cursor::new(&mut fdi_buf);
            generate_full_directory_index(&mut fdi_writer, &self.index.entries, &offsets)?;

            #[cfg(feature = "encryption")]
            if encrypting {
                // encrypted secondary indexes are stored ciphertext (like the
                // main index); encrypt here so all offsets/sizes/hashes below
                // cover the padded stored bytes.
                encrypt_store(&mut fdi_buf, key)?;
            }

            index_writer.write_u32::<LE>(1)?; // we have path hash index
            index_writer.write_u64::<LE>(path_hash_index_offset)?;
            index_writer.write_u64::<LE>(phi_buf.len() as u64)?; // path hash index size
            index_writer.write_all(&hash(&phi_buf).0)?;

            index_writer.write_u32::<LE>(1)?; // we have full directory index
            index_writer.write_u64::<LE>(full_directory_index_offset)?;
            index_writer.write_u64::<LE>(fdi_buf.len() as u64)?; // path hash index size
            index_writer.write_all(&hash(&fdi_buf).0)?;

            index_writer.write_u32::<LE>(encoded_entries.len() as u32)?;
            index_writer.write_all(&encoded_entries)?;

            index_writer.write_u32::<LE>(0)?;

            Some((phi_buf, fdi_buf))
        };

        #[cfg(feature = "encryption")]
        if encrypting {
            encrypt_store(&mut index_buf, key)?;
        }

        let index_hash = hash(&index_buf);

        writer.write_all(&index_buf)?;

        if let Some((phi_buf, fdi_buf)) = secondary_index {
            writer.write_all(&phi_buf[..])?;
            writer.write_all(&fdi_buf[..])?;
        }

        let footer = super::footer::Footer {
            encryption_uuid: self.encryption_guid,
            encrypted: self.encrypted_index,
            magic: super::MAGIC,
            version: self.version,
            version_major: self.version.version_major(),
            index_offset,
            index_size: index_buf.len() as u64,
            hash: index_hash,
            frozen: false,
            compression: self.compression.clone(), // TODO: avoid this clone
        };

        footer.write(writer)?;

        Ok(())
    }
}

fn hash(data: &[u8]) -> Hash {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(data);
    Hash(hasher.finalize().into())
}

fn generate_path_hash_index<W: Write>(
    writer: &mut W,
    path_hash_seed: u64,
    entries: &BTreeMap<String, super::entry::Entry>,
    offsets: &Vec<u32>,
) -> Result<(), super::Error> {
    writer.write_u32::<LE>(entries.len() as u32)?;
    for (path, offset) in entries.keys().zip(offsets) {
        let path_hash = fnv64_path(path, path_hash_seed);
        writer.write_u64::<LE>(path_hash)?;
        writer.write_u32::<LE>(*offset)?;
    }

    writer.write_u32::<LE>(0)?;

    Ok(())
}

fn fnv64<I>(data: I, offset: u64) -> u64
where
    I: IntoIterator<Item = u8>,
{
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x00000100000001b3;
    let mut hash = OFFSET.wrapping_add(offset);
    for b in data.into_iter() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

fn fnv64_path(path: &str, offset: u64) -> u64 {
    let lower = path.to_lowercase();
    let data = lower.encode_utf16().flat_map(u16::to_le_bytes);
    fnv64(data, offset)
}

fn split_path_child(path: &str) -> Option<(&str, &str)> {
    if path == "/" || path.is_empty() {
        None
    } else {
        let path = path.strip_suffix('/').unwrap_or(path);
        let i = path.rfind('/').map(|i| i + 1);
        match i {
            Some(i) => Some(path.split_at(i)),
            None => Some(("/", path)),
        }
    }
}

fn generate_full_directory_index<W: Write>(
    writer: &mut W,
    entries: &BTreeMap<String, super::entry::Entry>,
    offsets: &Vec<u32>,
) -> Result<(), super::Error> {
    let mut fdi: BTreeMap<&str, BTreeMap<&str, u32>> = Default::default();
    for (path, offset) in entries.keys().zip(offsets) {
        let mut p = path.as_str();
        while let Some((parent, _)) = split_path_child(p) {
            p = parent;
            fdi.entry(p).or_default();
        }

        let (directory, filename) = split_path_child(path).expect("none root path");

        fdi.entry(directory).or_default().insert(filename, *offset);
    }

    writer.write_u32::<LE>(fdi.len() as u32)?;
    for (directory, files) in &fdi {
        writer.write_string(directory)?;
        writer.write_u32::<LE>(files.len() as u32)?;
        for (filename, offset) in files {
            writer.write_string(filename)?;
            writer.write_u32::<LE>(*offset)?;
        }
    }

    Ok(())
}

#[cfg(feature = "encryption")]
fn encrypt(key: aes::Aes256, bytes: &mut [u8]) {
    use aes::cipher::BlockEncrypt;
    for chunk in bytes.chunks_mut(16) {
        key.encrypt_block(aes::Block::from_mut_slice(chunk))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_split_path_child() {
        assert_eq!(
            split_path_child("a/really/long/path"),
            Some(("a/really/long/", "path"))
        );
        assert_eq!(
            split_path_child("a/really/long/"),
            Some(("a/really/", "long"))
        );
        assert_eq!(split_path_child("a"), Some(("/", "a")));
        assert_eq!(split_path_child("a//b"), Some(("a//", "b")));
        assert_eq!(split_path_child("a//"), Some(("a/", "")));
        assert_eq!(split_path_child("/"), None);
        assert_eq!(split_path_child(""), None);
    }

    fn test_key() -> aes::Aes256 {
        use aes::cipher::KeyInit;
        aes::Aes256::new_from_slice(&[0x42u8; 32]).unwrap()
    }

    fn write_test_pak(
        engine: crate::Engine,
        version: crate::Version,
        custom_data: u8,
        files: &[(&str, Vec<u8>)],
    ) -> Vec<u8> {
        let mut pak = PakBuilder::new()
            .key(test_key())
            .engine(engine)
            .wuwa_custom_data(custom_data)
            .encryption_guid(0x0123456789ABCDEF0123456789ABCDEF)
            .writer(
                io::Cursor::new(vec![]),
                version,
                "../../../".to_string(),
                Some(0),
            );
        for (path, data) in files {
            pak.write_file(path, false, data).unwrap();
        }
        pak.write_index().unwrap().into_inner()
    }

    fn read_test_pak(engine: crate::Engine, bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut reader = io::Cursor::new(bytes);
        let pak = PakBuilder::new()
            .key(test_key())
            .engine(engine)
            .reader(&mut reader)
            .unwrap();
        pak.files()
            .into_iter()
            .map(|f| {
                let data = pak.get(&f, &mut reader).unwrap();
                (f, data)
            })
            .collect()
    }

    #[test]
    fn test_wuwa_v11_plaintext_roundtrip() {
        // no key at all: isolates the WuWa index layout from crypto
        let files = vec![("w.txt", b"plain wuwa".to_vec())];
        let mut pak = PakBuilder::new()
            .engine(crate::Engine::WutheringWaves)
            .writer(
                io::Cursor::new(vec![]),
                crate::Version::V11,
                "../../../".to_string(),
                Some(0),
            );
        for (path, data) in &files {
            pak.write_file(path, false, data).unwrap();
        }
        let bytes = pak.write_index().unwrap().into_inner();
        let mut reader = io::Cursor::new(&bytes[..]);
        let pak = PakBuilder::new()
            .engine(crate::Engine::WutheringWaves)
            .reader(&mut reader)
            .unwrap();
        let expected: Vec<(String, Vec<u8>)> = files
            .iter()
            .map(|(p, d)| (p.to_string(), d.clone()))
            .collect();
        let back: Vec<(String, Vec<u8>)> = pak
            .files()
            .into_iter()
            .map(|f| {
                let data = pak.get(&f, &mut reader).unwrap();
                (f, data)
            })
            .collect();
        assert_eq!(back, expected);
    }

    #[test]
    fn test_wuwa_plaintext_index_encrypted_data() {
        // the Wuthering Waves layout from the wild: plaintext index with
        // partially encrypted file data. Packing must NOT encrypt the index
        // just because a key is set when explicitly disabled.
        let payload: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
        let files = vec![("w.txt", payload)];
        let mut pak = PakBuilder::new()
            .key(test_key())
            .engine(crate::Engine::WutheringWaves)
            .wuwa_custom_data(2)
            .encrypt_index(false)
            .writer(
                io::Cursor::new(vec![]),
                crate::Version::V11,
                "../../../".to_string(),
                Some(0),
            );
        for (path, data) in &files {
            pak.write_file(path, false, data).unwrap();
        }
        let bytes = pak.write_index().unwrap().into_inner();
        // index parses even without a key...
        let mut reader = io::Cursor::new(&bytes[..]);
        let plain = PakBuilder::new()
            .engine(crate::Engine::WutheringWaves)
            .reader(&mut reader)
            .unwrap();
        assert!(!plain.encrypted_index());
        assert_eq!(plain.files(), vec!["w.txt".to_string()]);
        // ...and data decrypts with the key
        let mut reader = io::Cursor::new(&bytes[..]);
        let pak = PakBuilder::new()
            .key(test_key())
            .engine(crate::Engine::WutheringWaves)
            .reader(&mut reader)
            .unwrap();
        assert!(!pak.encrypted_index());
        let back: Vec<(String, Vec<u8>)> = pak
            .files()
            .into_iter()
            .map(|f| {
                let data = pak.get(&f, &mut reader).unwrap();
                (f, data)
            })
            .collect();
        let expected: Vec<(String, Vec<u8>)> = files
            .iter()
            .map(|(p, d)| (p.to_string(), d.clone()))
            .collect();
        assert_eq!(back, expected);
    }

    #[test]
    fn test_encrypted_roundtrip_stock() {
        let files = vec![
            ("a.txt", b"hello stock world".to_vec()),
            ("dir/b.bin", (0..5000u32).map(|i| (i % 251) as u8).collect()),
        ];
        let bytes = write_test_pak(crate::Engine::Stock, crate::Version::V8B, 0, &files);
        let back = read_test_pak(crate::Engine::Stock, &bytes);
        let expected: Vec<(String, Vec<u8>)> = files
            .iter()
            .map(|(p, d)| (p.to_string(), d.clone()))
            .collect();
        assert_eq!(back, expected);
    }

    #[test]
    fn test_encrypted_roundtrip_v11_empty() {
        // no entries at all: isolates footer/index-shell crypto
        let pak = PakBuilder::new()
            .key(test_key())
            .engine(crate::Engine::Stock)
            .writer(
                io::Cursor::new(vec![]),
                crate::Version::V11,
                "../../../".to_string(),
                Some(0),
            );
        let bytes = pak.write_index().unwrap().into_inner();
        let mut reader = io::Cursor::new(&bytes[..]);
        let pak = PakBuilder::new()
            .key(test_key())
            .engine(crate::Engine::Stock)
            .reader(&mut reader)
            .unwrap();
        assert!(pak.files().is_empty());
    }

    #[test]
    fn test_encrypted_roundtrip_stock_v11() {
        // V11 exercises encrypted secondary index buffers (path hash +
        // full directory index); V8B does not.
        let files = vec![("a.txt", b"hello v11".to_vec())];
        let mut pak = PakBuilder::new()
            .key(test_key())
            .engine(crate::Engine::Stock)
            .encryption_guid(0x0123456789ABCDEF0123456789ABCDEF)
            .writer(
                io::Cursor::new(vec![]),
                crate::Version::V11,
                "../../../".to_string(),
                Some(0),
            );
        for (path, data) in &files {
            pak.write_file(path, false, data).unwrap();
        }
        let bytes = pak.write_index().unwrap().into_inner();
        let mut reader = io::Cursor::new(&bytes[..]);
        let pak = PakBuilder::new()
            .key(test_key())
            .engine(crate::Engine::Stock)
            .reader(&mut reader)
            .unwrap();
        let expected: Vec<(String, Vec<u8>)> = files
            .iter()
            .map(|(p, d)| (p.to_string(), d.clone()))
            .collect();
        let back: Vec<(String, Vec<u8>)> = pak
            .files()
            .into_iter()
            .map(|f| {
                let data = pak.get(&f, &mut reader).unwrap();
                (f, data)
            })
            .collect();
        assert_eq!(back, expected);
    }

    #[test]
    fn test_encrypted_roundtrip_wuwa_partial() {
        // bigger than the 0x800 CustomData-2 prefix: proves only the prefix
        // is encrypted (stock full-decrypt of the same bytes must NOT match).
        let payload: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let files = vec![("w.txt", payload)];
        // V11: CustomData survives in encoded index records (plain-struct
        // entries of older versions cannot carry it).
        let bytes = write_test_pak(
            crate::Engine::WutheringWaves,
            crate::Version::V11,
            2,
            &files,
        );
        let back = read_test_pak(crate::Engine::WutheringWaves, &bytes);
        let expected: Vec<(String, Vec<u8>)> = files
            .iter()
            .map(|(p, d)| (p.to_string(), d.clone()))
            .collect();
        assert_eq!(back, expected);
        // stock full-decrypt of WuWa partial data must differ (or fail to read at all)
        let mut reader = io::Cursor::new(&bytes[..]);
        let stock_data = PakBuilder::new()
            .key(test_key())
            .engine(crate::Engine::Stock)
            .reader(&mut reader)
            .ok()
            .and_then(|pak| pak.get("w.txt", &mut reader).ok());
        if let Some(data) = stock_data {
            assert_ne!(data, files[0].1);
        }
    }
}
