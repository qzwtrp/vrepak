use crate::{data::build_partial_entry, Error, Hash};

use super::{ext::BoolExt, ext::ReadExt, Compression, Version, VersionMajor};
use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use std::io;

#[derive(Debug, PartialEq, Clone, Copy)]
pub(crate) enum EntryLocation {
    Data,
    Index,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct Block {
    pub start: u64,
    pub end: u64,
}

impl Block {
    pub fn read<R: io::Read>(reader: &mut R) -> Result<Self, super::Error> {
        Ok(Self {
            start: reader.read_u64::<LE>()?,
            end: reader.read_u64::<LE>()?,
        })
    }

    pub fn write<W: io::Write>(&self, writer: &mut W) -> Result<(), super::Error> {
        writer.write_u64::<LE>(self.start)?;
        writer.write_u64::<LE>(self.end)?;
        Ok(())
    }
}

fn align(offset: u64) -> u64 {
    // add alignment (aes block size: 16) then zero out alignment bits
    (offset + 15) & !15
}

fn compression_index_size(version: Version) -> CompressionIndexSize {
    match version {
        Version::V8A => CompressionIndexSize::U8,
        _ => CompressionIndexSize::U32,
    }
}

enum CompressionIndexSize {
    U8,
    U32,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct Entry {
    pub offset: u64,
    pub compressed: u64,
    pub uncompressed: u64,
    pub compression_slot: Option<u32>,
    pub timestamp: Option<u64>,
    pub hash: Option<Hash>,
    pub blocks: Option<Vec<Block>>,
    pub flags: u8,
    pub compression_block_size: u32,
    /// Wuthering Waves `CustomData` byte (encoded index entries, V11+).
    /// Selects how many leading bytes of the entry data are AES-encrypted.
    /// Always 0 (fully encrypted when the entry is flagged) for stock paks.
    pub custom_data: u8,
}

/// Undo the Wuthering Waves bitfield scrambling for V11+ encoded entries
/// (mirrors CUE4Parse `FPakEntry` handling for `GAME_WutheringWaves`).
fn wuwa_descramble(bitfield: u32) -> u32 {
    ((bitfield >> 16) & 0x3F)
        | ((bitfield & 0xFFFF) << 6)
        | ((bitfield & (1 << 28)) >> 6)
        | ((bitfield & 0x0FC0_0000) << 1)
        | ((bitfield & 0xC000_0000) >> 1)
        | ((bitfield & 0x2000_0000) << 2)
}

/// Number of leading entry-data bytes that are AES-encrypted for a
/// Wuthering Waves entry (`u64::MAX` = whole entry). Mirrors CUE4Parse
/// `CalculateEncryptedBytesCountForWutheringWaves`.
fn wuwa_decrypt_limit(custom_data: u8) -> Result<u64, super::Error> {
    match custom_data {
        0 => Ok(u64::MAX),
        1 => Ok(0x200000),
        2 => Ok(0x800),
        4 => Ok(0),
        other => Err(super::Error::Other(format!(
            "unknown Wuthering Waves CustomData {other} for partially encrypted file"
        ))),
    }
}

/// Whether the Wuthering Waves encoded-entry layout applies.
fn wuwa_entries(version: super::Version, engine: super::Engine) -> bool {
    engine == super::Engine::WutheringWaves && version >= super::Version::V11
}

impl Entry {
    pub fn is_encrypted(&self) -> bool {
        0 != (self.flags & 1)
    }
    pub fn is_deleted(&self) -> bool {
        0 != (self.flags >> 1) & 1
    }
    pub fn get_serialized_size(
        version: super::Version,
        compression: Option<u32>,
        block_count: u32,
    ) -> u64 {
        let mut size = 0;
        size += 8; // offset
        size += 8; // compressed
        size += 8; // uncompressed
        size += match compression_index_size(version) {
            CompressionIndexSize::U8 => 1,  // 8 bit compression
            CompressionIndexSize::U32 => 4, // 32 bit compression
        };
        size += match version.version_major() == VersionMajor::Initial {
            true => 8, // timestamp
            false => 0,
        };
        size += 20; // hash
        size += match compression {
            Some(_) => 4 + (8 + 8) * block_count as u64, // blocks
            None => 0,
        };
        size += 1; // encrypted
        size += match version.version_major() >= VersionMajor::CompressionEncryption {
            true => 4, // blocks uncompressed
            false => 0,
        };
        size
    }

    pub(crate) fn write_file<W: io::Write + io::Seek>(
        writer: &mut W,
        version: Version,
        compression_slots: &mut Vec<Option<Compression>>,
        allowed_compression: &[Compression],
        data: &[u8],
    ) -> Result<Self, Error> {
        let partial_entry = build_partial_entry(allowed_compression, data)?;
        let stream_position = writer.stream_position()?;
        let entry = partial_entry.build_entry(version, compression_slots, stream_position)?;
        entry.write(writer, version, crate::entry::EntryLocation::Data)?;
        partial_entry.write_data(writer)?;
        Ok(entry)
    }

    pub fn read<R: io::Read>(
        reader: &mut R,
        version: super::Version,
    ) -> Result<Self, super::Error> {
        let ver = version.version_major();
        let offset = reader.read_u64::<LE>()?;
        let compressed = reader.read_u64::<LE>()?;
        let uncompressed = reader.read_u64::<LE>()?;
        let compression = match match compression_index_size(version) {
            CompressionIndexSize::U8 => reader.read_u8()? as u32,
            CompressionIndexSize::U32 => reader.read_u32::<LE>()?,
        } {
            0 => None,
            n => Some(n - 1),
        };
        let timestamp = (ver == VersionMajor::Initial).then_try(|| reader.read_u64::<LE>())?;
        let hash = Some(Hash(reader.read_guid()?));
        let blocks = (ver >= VersionMajor::CompressionEncryption && compression.is_some())
            .then_try(|| reader.read_array(Block::read))?;
        let flags = (ver >= VersionMajor::CompressionEncryption)
            .then_try(|| reader.read_u8())?
            .unwrap_or(0);
        let compression_block_size = (ver >= VersionMajor::CompressionEncryption)
            .then_try(|| reader.read_u32::<LE>())?
            .unwrap_or(0);
        Ok(Self {
            offset,
            compressed,
            uncompressed,
            compression_slot: compression,
            timestamp,
            hash,
            blocks,
            flags,
            compression_block_size,
            custom_data: 0,
        })
    }

    pub fn write<W: io::Write>(
        &self,
        writer: &mut W,
        version: super::Version,
        location: EntryLocation,
    ) -> Result<(), super::Error> {
        writer.write_u64::<LE>(match location {
            EntryLocation::Data => 0,
            EntryLocation::Index => self.offset,
        })?;
        writer.write_u64::<LE>(self.compressed)?;
        writer.write_u64::<LE>(self.uncompressed)?;
        let compression = self.compression_slot.map_or(0, |n| n + 1);
        match compression_index_size(version) {
            CompressionIndexSize::U8 => writer.write_u8(compression.try_into().unwrap())?,
            CompressionIndexSize::U32 => writer.write_u32::<LE>(compression)?,
        }

        if version.version_major() == VersionMajor::Initial {
            writer.write_u64::<LE>(self.timestamp.unwrap_or_default())?;
        }
        if let Some(hash) = self.hash {
            writer.write_all(&hash.0)?;
        } else {
            panic!("hash missing");
        }
        if version.version_major() >= VersionMajor::CompressionEncryption {
            if let Some(blocks) = &self.blocks {
                writer.write_u32::<LE>(blocks.len() as u32)?;
                for block in blocks {
                    block.write(writer)?;
                }
            }
            writer.write_u8(self.flags)?;
            writer.write_u32::<LE>(self.compression_block_size)?;
        }

        Ok(())
    }

    pub fn read_encoded<R: io::Read>(
        reader: &mut R,
        version: super::Version,
        engine: super::Engine,
    ) -> Result<Self, super::Error> {
        let wuwa = wuwa_entries(version, engine);
        let mut bits = reader.read_u32::<LE>()?;
        let custom_data = if wuwa {
            bits = wuwa_descramble(bits);
            reader.read_u8()?
        } else {
            0
        };
        let compression = match (bits >> 23) & 0x3f {
            0 => None,
            n => Some(n - 1),
        };

        let encrypted = (bits & (1 << 22)) != 0;
        let compression_block_count: u32 = (bits >> 6) & 0xffff;
        let mut compression_block_size = bits & 0x3f;

        if compression_block_size == 0x3f {
            compression_block_size = reader.read_u32::<LE>()?;
        } else {
            compression_block_size <<= 11;
        }

        let mut var_int = |bit: u32| -> Result<_, super::Error> {
            Ok(if (bits & (1 << bit)) != 0 {
                reader.read_u32::<LE>()? as u64
            } else {
                reader.read_u64::<LE>()?
            })
        };

        let mut offset = var_int(31)?;
        let mut uncompressed = var_int(30)?;
        if wuwa {
            // Kuro's modified engine stores these swapped.
            std::mem::swap(&mut offset, &mut uncompressed);
        }
        let compressed = match compression {
            None => uncompressed,
            _ => var_int(29)?,
        };

        // The extra CustomData byte grows the on-disk record by one.
        let offset_base =
            Entry::get_serialized_size(version, compression, compression_block_count)
                + if wuwa { 1 } else { 0 };

        let blocks = if compression_block_count == 1 && !encrypted {
            Some(vec![Block {
                start: offset_base,
                end: offset_base + compressed,
            }])
        } else if compression_block_count > 0 {
            let mut index = offset_base;
            Some(
                (0..compression_block_count)
                    .map(|_| {
                        let mut block_size = reader.read_u32::<LE>()? as u64;
                        let block = Block {
                            start: index,
                            end: index + block_size,
                        };
                        if encrypted {
                            block_size = align(block_size);
                        }
                        index += block_size;
                        Ok(block)
                    })
                    .collect::<Result<Vec<_>, super::Error>>()?,
            )
        } else {
            None
        };

        Ok(Entry {
            offset,
            compressed,
            uncompressed,
            timestamp: None,
            compression_slot: compression,
            hash: None,
            blocks,
            flags: encrypted as u8,
            compression_block_size,
            custom_data,
        })
    }

    pub fn write_encoded<W: io::Write>(&self, writer: &mut W) -> Result<(), super::Error> {
        let mut compression_block_size = (self.compression_block_size >> 11) & 0x3f;
        if (compression_block_size << 11) != self.compression_block_size {
            compression_block_size = 0x3f;
        }
        let compression_blocks_count = if self.compression_slot.is_some() {
            self.blocks.as_ref().unwrap().len() as u32
        } else {
            0
        };
        let is_size_32_bit_safe = self.compressed <= u32::MAX as u64;
        let is_uncompressed_size_32_bit_safe = self.uncompressed <= u32::MAX as u64;
        let is_offset_32_bit_safe = self.offset <= u32::MAX as u64;

        assert!(
            compression_blocks_count < 0x10_000,
            "compression blocks count fits in 16 bits"
        );

        let flags = (compression_block_size)
            | (compression_blocks_count << 6)
            | ((self.is_encrypted() as u32) << 22)
            | (self.compression_slot.map_or(0, |n| n + 1) << 23)
            | ((is_size_32_bit_safe as u32) << 29)
            | ((is_uncompressed_size_32_bit_safe as u32) << 30)
            | ((is_offset_32_bit_safe as u32) << 31);

        writer.write_u32::<LE>(flags)?;

        if compression_block_size == 0x3f {
            writer.write_u32::<LE>(self.compression_block_size)?;
        }

        if is_offset_32_bit_safe {
            writer.write_u32::<LE>(self.offset as u32)?;
        } else {
            writer.write_u64::<LE>(self.offset)?;
        }

        if is_uncompressed_size_32_bit_safe {
            writer.write_u32::<LE>(self.uncompressed as u32)?
        } else {
            writer.write_u64::<LE>(self.uncompressed)?
        }

        if self.compression_slot.is_some() {
            if is_size_32_bit_safe {
                writer.write_u32::<LE>(self.compressed as u32)?;
            } else {
                writer.write_u64::<LE>(self.compressed)?;
            }

            assert!(self.blocks.is_some());
            let blocks = self.blocks.as_ref().unwrap();
            if blocks.len() > 1 || self.is_encrypted() {
                for b in blocks {
                    let block_size = b.end - b.start;
                    writer.write_u32::<LE>(block_size.try_into().unwrap())?;
                }
            }
        }

        Ok(())
    }

    pub fn read_file<R: io::Read + io::Seek, W: io::Write>(
        &self,
        reader: &mut R,
        version: Version,
        compression: &[Option<Compression>],
        #[allow(unused)] key: &super::Key,
        buf: &mut W,
        engine: super::Engine,
    ) -> Result<(), super::Error> {
        reader.seek(io::SeekFrom::Start(self.offset))?;
        Entry::read(reader, version)?;
        #[cfg(any(feature = "compression", feature = "oodle"))]
        let data_offset = reader.stream_position()?;
        #[allow(unused_mut)]
        let mut data = reader.read_len(match self.is_encrypted() {
            true => align(self.compressed),
            false => self.compressed,
        } as usize)?;
        if self.is_encrypted() {
            #[cfg(not(feature = "encryption"))]
            return Err(super::Error::Encryption);
            #[cfg(feature = "encryption")]
            {
                let super::Key::Some(key) = key else {
                    return Err(super::Error::Encrypted);
                };
                // Wuthering Waves only encrypts a CustomData-dependent prefix
                // of the stored data; the rest is plaintext.
                let decrypt_len = match engine {
                    super::Engine::WutheringWaves => {
                        let limit = wuwa_decrypt_limit(self.custom_data)?;
                        // limits are AES-block multiples; floor defensively.
                        ((data.len() as u64).min(limit) & !15) as usize
                    }
                    super::Engine::Stock => data.len(),
                };
                use aes::cipher::BlockDecrypt;
                for block in data[..decrypt_len].chunks_mut(16) {
                    key.decrypt_block(aes::Block::from_mut_slice(block))
                }
                data.truncate(self.compressed as usize);
            }
        }

        #[cfg(feature = "compression")]
        let ranges = {
            let offset = |index: u64| -> usize {
                (match version.version_major() >= VersionMajor::RelativeChunkOffsets {
                    true => index - (data_offset - self.offset),
                    false => index - data_offset,
                }) as usize
            };

            match &self.blocks {
                Some(blocks) => blocks
                    .iter()
                    .map(|block| offset(block.start)..offset(block.end))
                    .collect::<Vec<_>>(),
                #[allow(clippy::single_range_in_vec_init)]
                None => vec![0..data.len()],
            }
        };

        #[cfg(feature = "compression")]
        macro_rules! decompress {
            ($decompressor: ty) => {
                for range in ranges {
                    io::copy(&mut <$decompressor>::new(&data[range]), buf)?;
                }
            };
        }

        match self.compression_slot.and_then(|c| compression[c as usize]) {
            None => buf.write_all(&data)?,
            #[cfg(not(feature = "compression"))]
            _ => return Err(super::Error::Compression),
            #[cfg(feature = "compression")]
            Some(comp) => {
                let chunk_size = if ranges.len() == 1 {
                    self.uncompressed as usize
                } else {
                    self.compression_block_size as usize
                };

                match comp {
                    Compression::Zlib => decompress!(flate2::read::ZlibDecoder<&[u8]>),
                    Compression::Gzip => decompress!(flate2::read::GzDecoder<&[u8]>),
                    Compression::Zstd => {
                        for range in ranges {
                            io::copy(&mut zstd::stream::read::Decoder::new(&data[range])?, buf)?;
                        }
                    }
                    Compression::LZ4 => {
                        let mut decompressed = vec![0; self.uncompressed as usize];
                        for (decomp_chunk, comp_range) in
                            decompressed.chunks_mut(chunk_size).zip(ranges)
                        {
                            lz4_flex::block::decompress_into(&data[comp_range], decomp_chunk)
                                .map_err(|_| Error::DecompressionFailed(Compression::LZ4))?;
                        }
                        buf.write_all(&decompressed)?;
                    }
                    #[cfg(feature = "oodle")]
                    Compression::Oodle => {
                        let mut decompressed = vec![0; self.uncompressed as usize];
                        for (decomp_chunk, comp_range) in
                            decompressed.chunks_mut(chunk_size).zip(ranges)
                        {
                            let out =
                                oodle_loader::oodle()?.decompress(&data[comp_range], decomp_chunk);
                            if out == 0 {
                                return Err(Error::DecompressionFailed(Compression::Oodle));
                            }
                        }
                        buf.write_all(&decompressed)?;
                    }
                    #[cfg(not(feature = "oodle"))]
                    Compression::Oodle => return Err(super::Error::Oodle),
                }
            }
        }
        buf.flush()?;
        Ok(())
    }
}

mod test {
    #[test]
    fn test_entry() {
        let data = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x54, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0xDD, 0x94, 0xFD, 0xC3, 0x5F, 0xF5, 0x91, 0xA9, 0x9A, 0x5E, 0x14, 0xDC, 0x9B,
            0xD3, 0x58, 0x89, 0x78, 0xA6, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut out = vec![];
        let entry = super::Entry::read(&mut std::io::Cursor::new(data.clone()), super::Version::V5)
            .unwrap();
        entry
            .write(&mut out, super::Version::V5, super::EntryLocation::Data)
            .unwrap();
        assert_eq!(&data, &out);
    }

    #[test]
    fn test_wuwa_descramble_is_bit_permutation() {
        // the descramble must map every input bit to exactly one distinct
        // output bit (i.e. be a bit permutation); otherwise the port of the
        // CUE4Parse formula has a typo.
        use std::collections::HashSet;
        let mut outs = HashSet::new();
        for i in 0..32u32 {
            let o = super::wuwa_descramble(1 << i);
            assert!(
                o.is_power_of_two(),
                "bit {i} must map to a single bit, got {o:#010x}"
            );
            assert!(outs.insert(o), "output collision at bit {i}");
        }
        assert_eq!(outs.len(), 32);
    }

    #[test]
    fn test_wuwa_decrypt_limit() {
        assert_eq!(super::wuwa_decrypt_limit(0).unwrap(), u64::MAX);
        assert_eq!(super::wuwa_decrypt_limit(1).unwrap(), 0x200000);
        assert_eq!(super::wuwa_decrypt_limit(2).unwrap(), 0x800);
        assert_eq!(super::wuwa_decrypt_limit(4).unwrap(), 0);
        assert!(super::wuwa_decrypt_limit(3).is_err());
        assert!(super::wuwa_decrypt_limit(9).is_err());
    }
}
