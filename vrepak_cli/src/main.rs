use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter};
use std::path::{Path, PathBuf};

use clap::builder::TypedValueParser;
use clap::{Parser, Subcommand};
use itertools::Itertools;
use path_clean::PathClean;
use path_slash::PathExt;
use rayon::prelude::*;
use strum::VariantNames;

#[derive(Parser, Debug)]
struct ActionInfo {
    /// Input .pak path
    #[arg(index = 1)]
    input: String,
}

#[derive(Parser, Debug)]
struct ActionList {
    /// Input .pak path
    #[arg(index = 1)]
    input: String,

    /// Prefix to strip from entry path
    #[arg(short, long, default_value = "../../../")]
    strip_prefix: String,
}

#[derive(Parser, Debug)]
struct ActionHashList {
    /// Input .pak path
    #[arg(index = 1)]
    input: String,

    /// Prefix to strip from entry path
    #[arg(short, long, default_value = "../../../")]
    strip_prefix: String,
}

#[derive(Parser, Debug)]
struct ActionUnpack {
    /// Input .pak path
    #[arg(index = 1)]
    input: Vec<String>,

    /// Output directory. Defaults to next to input pak
    #[arg(short, long)]
    output: Option<String>,

    /// Prefix to strip from entry path
    #[arg(short, long, default_value = "../../../")]
    strip_prefix: String,

    /// Verbose
    #[arg(short, long, default_value = "false")]
    verbose: bool,

    /// Hides normal output such as progress bar and completion status
    #[arg(short, long, default_value = "false")]
    quiet: bool,

    /// Force overwrite existing files/directories.
    #[arg(short, long, default_value = "false")]
    force: bool,

    /// Files or directories to include. Can be specified multiple times. If not specified, everything is extracted.
    #[arg(action = clap::ArgAction::Append, short, long)]
    include: Vec<glob::Pattern>,
}

#[derive(Parser, Debug)]
struct ActionPack {
    /// Input directory
    #[arg(index = 1)]
    input: String,

    /// Output directory. Defaults to next to input dir
    #[arg(index = 2)]
    output: Option<String>,

    /// Mount point
    #[arg(short, long, default_value = "../../../")]
    mount_point: String,

    /// Version
    #[arg(
        long,
        default_value_t = vrepak::Version::V8B,
        value_parser = clap::builder::PossibleValuesParser::new(vrepak::Version::VARIANTS).map(|s| s.parse::<vrepak::Version>().unwrap())
    )]
    version: vrepak::Version,

    /// Compression
    #[arg(
        long,
        value_parser = clap::builder::PossibleValuesParser::new(vrepak::Compression::VARIANTS).map(|s| s.parse::<vrepak::Compression>().unwrap())
    )]
    compression: Option<vrepak::Compression>,

    /// Path hash seed for >= V10
    #[arg(short, long, default_value = "0")]
    path_hash_seed: u64,

    /// Encryption GUID recorded in the footer (32 hex chars).
    /// When absent on pack, the unpack manifest decides, otherwise zeros.
    /// Only used when packing with a key (--aes-key/--endpoint).
    #[arg(long)]
    encryption_guid: Option<String>,

    /// CustomData byte for fresh entries when packing with
    /// --engine wuthering-waves (0: full, 1: 0x200000, 2: 0x800, 4: plaintext).
    /// When absent, the unpack manifest decides, otherwise 2.
    #[arg(long)]
    wuwa_custom_data: Option<u8>,

    /// Verbose
    #[arg(short, long, default_value = "false")]
    verbose: bool,

    /// Hides normal output such as progress bar and completion status
    #[arg(short, long, default_value = "false")]
    quiet: bool,
}

#[derive(Parser, Debug)]
struct ActionGet {
    /// Input .pak path
    #[arg(index = 1)]
    input: String,

    /// Path to file to read to stdout
    #[arg(index = 2)]
    file: String,

    /// Prefix to strip from entry path
    #[arg(short, long, default_value = "../../../")]
    strip_prefix: String,
}

#[derive(Parser, Debug)]
struct ActionDiff {
    /// First .pak path
    #[arg(index = 1)]
    input1: String,

    /// Second .pak path
    #[arg(index = 2)]
    input2: String,

    /// Prefix to strip from entry path
    #[arg(short, long, default_value = "../../../")]
    strip_prefix: String,

    /// Only compare file lists, skip content hashing
    #[arg(long, default_value = "false")]
    names_only: bool,
}

#[derive(Subcommand, Debug)]
enum Action {
    /// Print .pak info
    Info(ActionInfo),
    /// List .pak files
    List(ActionList),
    /// List .pak files and the SHA256 of their contents. Useful for finding differences between paks
    HashList(ActionHashList),
    /// Unpack .pak file
    Unpack(ActionUnpack),
    /// Pack directory into .pak file
    Pack(ActionPack),
    /// Reads a single file to stdout
    Get(ActionGet),
    /// Compare two .pak files and list differences (exit code 1 when different)
    Diff(ActionDiff),
    /// Test endpoint configuration (AES) - FModel compatible
    EndpointTest(ActionEndpointTest),
}

#[derive(Parser, Debug)]
struct ActionEndpointTest {
    /// Endpoint URL returning JSON with keys
    #[arg(long)]
    endpoint: String,
    /// JSONPath expression, e.g. $['mainKey', 'dynamicKeys']
    #[arg(long, default_value = "")]
    expression: String,
}

#[derive(Parser, Debug)]
#[command(author, version, bin_name = "vrepak")]
struct Args {
    /// 256 bit AES encryption key as base64 or hex string if the pak is encrypted
    #[arg(short, long)]
    aes_key: Option<KeyBytes>,

    /// Endpoint URL returning JSON with AES keys (FModel compatible).
    /// If set, keys are auto-resolved per-pak GUID (main key fallback).
    #[arg(long)]
    endpoint: Option<String>,

    /// JSONPath expression for endpoint, e.g. $['mainKey', 'dynamicKeys'].
    /// Supports up to 2 elements: main key + dynamic [{guid, key}] list.
    #[arg(long, default_value = "")]
    expression: String,

    /// Engine profile for game-specific pak quirks (e.g. wuthering-waves
    /// for the modified Kuro Games engine with scrambled index entries
    /// and partially encrypted file data).
    #[arg(
        long,
        value_parser = clap::builder::PossibleValuesParser::new(vrepak::Engine::VARIANTS).map(|s| s.parse::<vrepak::Engine>().unwrap())
    )]
    engine: Option<vrepak::Engine>,

    #[command(subcommand)]
    action: Action,
}

/// 256-bit AES key bytes (hex with optional `0x`, or base64).
/// Keeps the raw bytes (unlike a cipher object) so unpack can record the
/// effective key per file into `vrepak-manifest.json`.
#[derive(Debug, Clone, Copy)]
struct KeyBytes([u8; 32]);
impl std::str::FromStr for KeyBytes {
    type Err = vrepak_endpoint::EndpointError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        vrepak_endpoint::parse_aes_key(s).map(KeyBytes)
    }
}
impl KeyBytes {
    fn cipher(&self) -> aes::Aes256 {
        use aes::cipher::KeyInit;
        aes::Aes256::new_from_slice(&self.0).expect("32-byte key")
    }
    fn hex(&self) -> String {
        vrepak_endpoint::key_to_hex(&self.0)
    }
}

/// Key resolved for one pak file, with provenance for manifests/status.
#[derive(Debug, Clone)]
struct ResolvedPakKey {
    cipher: aes::Aes256,
    hex: String,
    source: vrepak_endpoint::KeySource,
}

fn main() -> Result<(), vrepak::Error> {
    let args = Args::parse();
    let explicit_key = args.aes_key;
    let engine = args.engine.unwrap_or(vrepak::Engine::Stock);

    // Endpoint cache: fetch once per invocation if needed
    let endpoint_cache: Option<EndpointCache> = match (&explicit_key, &args.endpoint) {
        (None, Some(endpoint)) => {
            let cfg = vrepak_endpoint::EndpointConfig::new(endpoint.clone(), args.expression.clone());
            match vrepak_endpoint::fetch_and_resolve(&cfg) {
                Ok((_json, resolved)) => Some(EndpointCache { resolved }),
                Err(e) => {
                    eprintln!("endpoint error: {e}");
                    eprintln!("hint: use `vrepak endpoint-test --endpoint <URL> --expression <EXPR>` to debug");
                    std::process::exit(1);
                }
            }
        }
        _ => None,
    };

    // helper: resolve key for a pak file (explicit > endpoint-by-guid > none)
    let resolve_for_file = |pak_path: &str| -> Option<ResolvedPakKey> {
        if let Some(k) = explicit_key {
            return Some(ResolvedPakKey {
                cipher: k.cipher(),
                hex: k.hex(),
                source: vrepak_endpoint::KeySource::Explicit,
            });
        }
        if let Some(cache) = &endpoint_cache {
            // peek guid without key
            let guid = File::open(pak_path)
                .ok()
                .and_then(|mut f| vrepak::PakReader::peek_encryption_guid(&mut BufReader::new(&mut f)));
            let bytes = cache.resolved.key_for_guid(guid);
            let matched = guid.and_then(|g| {
                cache
                    .resolved
                    .dynamic_keys
                    .iter()
                    .find(|d| d.guid == g)
                    .map(|_| g)
            });
            let source = match matched {
                Some(g) => vrepak_endpoint::KeySource::EndpointDynamic { guid: g },
                None => vrepak_endpoint::KeySource::EndpointMain {
                    guid,
                    dynamics: cache.resolved.dynamic_keys.len(),
                },
            };
            use aes::cipher::KeyInit;
            return aes::Aes256::new_from_slice(&bytes).ok().map(|cipher| ResolvedPakKey {
                cipher,
                hex: vrepak_endpoint::key_to_hex(&bytes),
                source,
            });
        }
        None
    };

    match args.action {
        Action::Info(action) => {
            let k = resolve_for_file(&action.input).map(|k| k.cipher);
            info(k, engine, action)
        }
        Action::List(action) => {
            let k = resolve_for_file(&action.input).map(|k| k.cipher);
            list(k, engine, action)
        }
        Action::HashList(action) => {
            let k = resolve_for_file(&action.input).map(|k| k.cipher);
            hash_list(k, engine, action)
        }
        Action::Unpack(action) => {
            // per-file keys for multi-input unpack
            let mut per_file_keys: Vec<Option<ResolvedPakKey>> = Vec::new();
            for input in &action.input {
                per_file_keys.push(resolve_for_file(input));
            }
            unpack_with_keys(per_file_keys, engine, action)
        }
        Action::Pack(action) => pack(
            explicit_key,
            args.endpoint.clone(),
            args.expression.clone(),
            args.engine,
            action,
        ),
        Action::Get(action) => {
            let k = resolve_for_file(&action.input).map(|k| k.cipher);
            get(k, engine, action)
        }
        Action::Diff(action) => {
            let k1 = resolve_for_file(&action.input1).map(|k| k.cipher);
            let k2 = resolve_for_file(&action.input2).map(|k| k.cipher);
            diff(k1, k2, engine, action)
        }
        Action::EndpointTest(action) => endpoint_test(action),
    }
}

#[derive(Debug)]
struct EndpointCache {
    resolved: vrepak_endpoint::ResolvedKeys,
}

fn endpoint_test(action: ActionEndpointTest) -> Result<(), vrepak::Error> {
    let cfg = vrepak_endpoint::EndpointConfig::new(&action.endpoint, &action.expression);
    println!("endpoint: {}", cfg.endpoint);
    println!("expression: {}", cfg.expression);
    match vrepak_endpoint::fetch_and_resolve(&cfg) {
        Ok((_json, resolved)) => {
            println!("Your endpoint configuration is valid! Please, avoid any unnecessary modifications!");
            println!("main key: {}", resolved.main_key_str);
            println!("dynamic keys: {}", resolved.dynamic_keys.len());
            for d in resolved.dynamic_keys.iter().take(10) {
                if let Some(name) = &d.name {
                    println!("  {} => {} ({})", d.guid_str, d.key_str, name);
                } else {
                    println!("  {} => {}", d.guid_str, d.key_str);
                }
            }
            if resolved.dynamic_keys.len() > 10 {
                println!("  ... and {} more", resolved.dynamic_keys.len() - 10);
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("Your endpoint configuration is NOT valid: {e}");
            eprintln!("Instruction: expression must return 1-2 elements: main AES key (hex, 256-bit) and optional dynamic list [{{guid, key}}]. Example: $['mainKey', 'dynamicKeys']");
            std::process::exit(1);
        }
    }
}

fn info(aes_key: Option<aes::Aes256>, engine: vrepak::Engine, action: ActionInfo) -> Result<(), vrepak::Error> {
    let mut builder = vrepak::PakBuilder::new().engine(engine);
    if let Some(aes_key) = aes_key {
        builder = builder.key(aes_key);
    }
    let pak = builder.reader(&mut BufReader::new(File::open(action.input)?))?;
    println!("mount point: {}", pak.mount_point());
    println!("version: {}", pak.version());
    println!("version major: {}", pak.version().version_major());
    println!("encrypted index: {}", pak.encrypted_index());
    println!("encrytion guid: {:032X?}", pak.encryption_guid());
    let compression = pak.used_compression();
    if compression.is_empty() {
        println!("compression: None");
    } else {
        println!("compression: {}", compression.iter().join(" ,"));
    }
    println!("path hash seed: {:08X?}", pak.path_hash_seed());
    println!("{} file entries", pak.files().len());
    Ok(())
}

fn list(aes_key: Option<aes::Aes256>, engine: vrepak::Engine, action: ActionList) -> Result<(), vrepak::Error> {
    let mut builder = vrepak::PakBuilder::new().engine(engine);
    if let Some(aes_key) = aes_key {
        builder = builder.key(aes_key);
    }
    let pak = builder.reader(&mut BufReader::new(File::open(action.input)?))?;

    let mount_point = PathBuf::from(pak.mount_point());
    let prefix = Path::new(&action.strip_prefix);

    let full_paths = pak
        .files()
        .into_iter()
        .map(|f| mount_point.join(f))
        .collect::<Vec<_>>();
    let stripped = full_paths
        .iter()
        .map(|f| {
            f.strip_prefix(prefix)
                .map_err(|_| vrepak::Error::PrefixMismatch {
                    path: f.to_string_lossy().to_string(),
                    prefix: prefix.to_string_lossy().to_string(),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    for f in stripped {
        println!("{}", f.to_slash_lossy());
    }

    Ok(())
}

fn hash_list(aes_key: Option<aes::Aes256>, engine: vrepak::Engine, action: ActionHashList) -> Result<(), vrepak::Error> {
    let mut builder = vrepak::PakBuilder::new().engine(engine);
    if let Some(aes_key) = aes_key {
        builder = builder.key(aes_key);
    }
    let pak = builder.reader(&mut BufReader::new(File::open(&action.input)?))?;

    let mount_point = PathBuf::from(pak.mount_point());
    let prefix = Path::new(&action.strip_prefix);

    let full_paths = pak
        .files()
        .into_iter()
        .map(|f| (mount_point.join(&f), f))
        .collect::<Vec<_>>();
    let stripped = full_paths
        .iter()
        .map(|(full_path, _path)| {
            full_path
                .strip_prefix(prefix)
                .map_err(|_| vrepak::Error::PrefixMismatch {
                    path: full_path.to_string_lossy().to_string(),
                    prefix: prefix.to_string_lossy().to_string(),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let hashes: std::sync::Arc<std::sync::Mutex<BTreeMap<std::borrow::Cow<'_, str>, Vec<u8>>>> =
        Default::default();
    full_paths.par_iter().zip(stripped).try_for_each_init(
        || (hashes.clone(), File::open(&action.input)),
        |(hashes, file), ((_full_path, path), stripped)| -> Result<(), vrepak::Error> {
            use sha2::Digest;

            let mut hasher = sha2::Sha256::new();
            pak.read_file(
                path,
                &mut BufReader::new(file.as_ref().unwrap()),
                &mut hasher,
            )?;
            let hash = hasher.finalize();
            hashes
                .lock()
                .unwrap()
                .insert(stripped.to_slash_lossy(), hash.to_vec());
            Ok(())
        },
    )?;

    for (file, hash) in hashes.lock().unwrap().iter() {
        println!("{} {}", hex::encode(hash), file);
    }

    Ok(())
}

fn diff(
    aes_key1: Option<aes::Aes256>,
    aes_key2: Option<aes::Aes256>,
    engine: vrepak::Engine,
    action: ActionDiff,
) -> Result<(), vrepak::Error> {
    fn open(
        input: &str,
        aes_key: Option<aes::Aes256>,
        engine: vrepak::Engine,
    ) -> Result<vrepak::PakReader, vrepak::Error> {
        let mut builder = vrepak::PakBuilder::new().engine(engine);
        if let Some(aes_key) = aes_key {
            builder = builder.key(aes_key);
        }
        builder.reader(&mut BufReader::new(File::open(input)?))
    }
    fn stripped(
        pak: &vrepak::PakReader,
        strip_prefix: &str,
    ) -> Result<BTreeMap<String, (String, u64)>, vrepak::Error> {
        let mount_point = PathBuf::from(pak.mount_point());
        let prefix = Path::new(strip_prefix);
        let mut map = BTreeMap::new();
        for f in pak.files() {
            let full = mount_point.join(&f);
            let stripped = full
                .strip_prefix(prefix)
                .map_err(|_| vrepak::Error::PrefixMismatch {
                    path: full.to_string_lossy().to_string(),
                    prefix: prefix.to_string_lossy().to_string(),
                })?
                .to_slash_lossy()
                .into_owned();
            let size = pak
                .entry_info(&f)
                .map(|i| i.uncompressed_size)
                .unwrap_or(0);
            map.insert(stripped, (f, size));
        }
        Ok(map)
    }
    fn hash_one(
        pak: &vrepak::PakReader,
        input: &str,
        paths: &[String],
    ) -> Result<BTreeMap<String, Vec<u8>>, vrepak::Error> {
        let hashes: std::sync::Arc<std::sync::Mutex<BTreeMap<String, Vec<u8>>>> =
            Default::default();
        paths.par_iter().try_for_each_init(
            || (hashes.clone(), File::open(input)),
            |(hashes, file), path| -> Result<(), vrepak::Error> {
                use sha2::Digest;

                let mut hasher = sha2::Sha256::new();
                pak.read_file(
                    path,
                    &mut BufReader::new(file.as_ref().unwrap()),
                    &mut hasher,
                )?;
                let hash = hasher.finalize();
                hashes
                    .lock()
                    .unwrap()
                    .insert(path.clone(), hash.to_vec());
                Ok(())
            },
        )?;
        Ok(hashes.lock().unwrap().clone())
    }

    let pak1 = open(&action.input1, aes_key1, engine)?;
    let pak2 = open(&action.input2, aes_key2, engine)?;
    let map1 = stripped(&pak1, &action.strip_prefix)?;
    let map2 = stripped(&pak2, &action.strip_prefix)?;

    println!("--- {} ({}, {} files)", action.input1, pak1.version(), map1.len());
    println!("+++ {} ({}, {} files)", action.input2, pak2.version(), map2.len());

    let only1: Vec<&String> = map1.keys().filter(|k| !map2.contains_key(*k)).collect();
    let only2: Vec<&String> = map2.keys().filter(|k| !map1.contains_key(*k)).collect();
    println!("Only in {} ({}):", action.input1, only1.len());
    for f in &only1 {
        println!("  {f}");
    }
    println!("Only in {} ({}):", action.input2, only2.len());
    for f in &only2 {
        println!("  {f}");
    }

    let common: Vec<&String> = map1.keys().filter(|k| map2.contains_key(*k)).collect();
    let mut differing: Vec<(String, String)> = vec![];
    let mut identical = 0;
    if action.names_only {
        identical = common.len();
    } else {
        // same-size files go to content hashing; size mismatches are decisive
        let mut pending: Vec<(&String, &String, &String, u64)> = vec![];
        for f in &common {
            let (p1, size1) = &map1[*f];
            let (p2, size2) = &map2[*f];
            if size1 != size2 {
                differing.push(((*f).clone(), format!("{size1} -> {size2} bytes")));
            } else {
                pending.push((*f, p1, p2, *size1));
            }
        }
        if !pending.is_empty() {
            let to_hash1: Vec<String> = pending.iter().map(|(_, p1, _, _)| (*p1).clone()).collect();
            let to_hash2: Vec<String> = pending.iter().map(|(_, _, p2, _)| (*p2).clone()).collect();
            let h1 = hash_one(&pak1, &action.input1, &to_hash1)?;
            let h2 = hash_one(&pak2, &action.input2, &to_hash2)?;
            for (f, p1, p2, size) in pending {
                if h1[p1] != h2[p2] {
                    differing.push((f.clone(), format!("{size} bytes, content differs")));
                } else {
                    identical += 1;
                }
            }
        }
    }
    differing.sort();
    println!("Differing ({}):", differing.len());
    for (f, detail) in &differing {
        println!("  {f} ({detail})");
    }
    println!("Identical files: {identical}");

    if !only1.is_empty() || !only2.is_empty() || !differing.is_empty() {
        std::process::exit(1);
    }
    Ok(())
}

const STYLE: &str = "[{elapsed_precise}] [{wide_bar}] {pos}/{len} ({eta})";

#[derive(Clone)]
enum Output {
    Progress(indicatif::ProgressBar),
    Stdout,
}
impl Output {
    pub fn println<I: AsRef<str>>(&self, msg: I) {
        match self {
            Output::Progress(progress) => progress.println(msg),
            Output::Stdout => println!("{}", msg.as_ref()),
        }
    }
}

fn unpack_with_keys(per_file_keys: Vec<Option<ResolvedPakKey>>, engine: vrepak::Engine, action: ActionUnpack) -> Result<(), vrepak::Error> {
    for (idx, input) in action.input.iter().enumerate() {
        let resolved = per_file_keys.get(idx).cloned().flatten();
        let mut builder = vrepak::PakBuilder::new().engine(engine);
        if let Some(k) = resolved.as_ref() {
            builder = builder.key(k.cipher.clone());
        }
        let pak = builder.reader(&mut BufReader::new(File::open(input)?))?;
        let output = action
            .output
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| Path::new(input).with_extension(""));
        match fs::create_dir(&output) {
            Ok(_) => Ok(()),
            Err(ref e)
                if action.output.is_some() && e.kind() == std::io::ErrorKind::AlreadyExists =>
            {
                Ok(())
            }
            Err(e) => Err(e),
        }?;
        if action.output.is_none() && !action.force && output.read_dir()?.next().is_some() {
            return Err(vrepak::Error::OutputNotEmpty(
                output.to_string_lossy().to_string(),
            ));
        }
        let mount_point = PathBuf::from(pak.mount_point());
        let prefix = Path::new(&action.strip_prefix);

        struct UnpackEntry {
            entry_path: String,
            out_path: PathBuf,
            out_dir: PathBuf,
        }

        let entries = pak
            .files()
            .into_iter()
            .map(|entry_path| {
                let full_path = mount_point.join(&entry_path);
                if !action.include.is_empty() {
                    if let Ok(stripped) = full_path.strip_prefix(prefix) {
                        let options = glob::MatchOptions {
                            case_sensitive: true,
                            require_literal_separator: true,
                            require_literal_leading_dot: false,
                        };
                        if !action.include.iter().any(|i| {
                            // check full file path
                            i.matches_path_with(stripped, options)
                                // check ancestor directories
                                || stripped.ancestors().skip(1).any(|a| {
                                    i.matches_path_with(a, options)
                                        // hack to check ancestor directories with trailing slash
                                        || i.matches_path_with(&a.join(""), options)
                                })
                        }) {
                            return Ok(None);
                        }
                    } else {
                        return Ok(None);
                    }
                }
                let out_path = output
                    .join(full_path.strip_prefix(prefix).map_err(|_| {
                        vrepak::Error::PrefixMismatch {
                            path: full_path.to_string_lossy().to_string(),
                            prefix: prefix.to_string_lossy().to_string(),
                        }
                    })?)
                    .clean();

                if !out_path.starts_with(&output) {
                    return Err(vrepak::Error::WriteOutsideOutput(
                        out_path.to_string_lossy().to_string(),
                    ));
                }

                let out_dir = out_path.parent().expect("will be a file").to_path_buf();

                Ok(Some(UnpackEntry {
                    entry_path,
                    out_path,
                    out_dir,
                }))
            })
            .filter_map(|e| e.transpose())
            .collect::<Result<Vec<_>, vrepak::Error>>()?;

        let progress = (!action.quiet).then(|| {
            indicatif::ProgressBar::new(entries.len() as u64)
                .with_style(indicatif::ProgressStyle::with_template(STYLE).unwrap())
        });
        let log = match &progress {
            Some(progress) => Output::Progress(progress.clone()),
            None => Output::Stdout,
        };

        entries.par_iter().try_for_each_init(
            || (progress.clone(), File::open(input)),
            |(progress, file), entry| -> Result<(), vrepak::Error> {
                if action.verbose {
                    log.println(format!("unpacking {}", entry.entry_path));
                }
                fs::create_dir_all(&entry.out_dir)?;
                pak.read_file(
                    &entry.entry_path,
                    &mut BufReader::new(
                        file.as_ref()
                            .map_err(|e| vrepak::Error::Other(format!("error reading pak: {e}")))?,
                    ),
                    &mut fs::File::create(&entry.out_path)?,
                )?;
                if let Some(progress) = progress {
                    progress.inc(1);
                }
                Ok(())
            },
        )?;
        if let Some(progress) = progress {
            progress.finish();
        }

        if !action.quiet {
            println!(
                "Unpacked {} files to {} from {}",
                entries.len(),
                output.display(),
                input
            );
        }

        // unpack manifest: how each file was stored (key, compression,
        // encryption, CustomData), so `pack` can restore it exactly.
        // Merges with a manifest already present in the output dir.
        let fresh = vrepak::PakManifest::from_reader(&pak, engine, |path| {
            let encrypted = pak
                .entry_info(path)
                .map(|i| i.encrypted)
                .unwrap_or(false);
            if !encrypted {
                return None;
            }
            resolved.as_ref().map(|r| {
                (
                    r.hex.clone(),
                    Some(r.source.describe()),
                )
            })
        });
        let manifest_path = output.join(vrepak::MANIFEST_FILENAME);
        let manifest = if manifest_path.exists() {
            let text = fs::read_to_string(&manifest_path)?;
            let mut existing = vrepak::PakManifest::from_json(&text)?;
            existing.merge(fresh);
            existing
        } else {
            fresh
        };
        manifest
            .save(&output)
            .map_err(|e| vrepak::Error::Other(format!("manifest write: {e}")))?;
        if !action.quiet {
            log.println(format!(
                "Wrote {} ({} files)",
                manifest_path.display(),
                manifest.files.len()
            ));
        }
    }

    Ok(())
}

fn pack(
    aes_key: Option<KeyBytes>,
    endpoint: Option<String>,
    expression: String,
    engine: Option<vrepak::Engine>,
    args: ActionPack,
) -> Result<(), vrepak::Error> {
    let output = args.output.map(PathBuf::from).unwrap_or_else(|| {
        // NOTE: don't use `with_extension` here because it will replace e.g. the `.1` in
        // `test_v1.1`.
        PathBuf::from(format!("{}.pak", args.input))
    });

    fn collect_files(paths: &mut Vec<PathBuf>, dir: &Path) -> io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                collect_files(paths, &path)?;
            } else if entry.file_name().to_string_lossy().as_ref() != vrepak::MANIFEST_FILENAME {
                // the unpack manifest itself is metadata, never payload
                paths.push(entry.path());
            }
        }
        Ok(())
    }
    let input_path = Path::new(&args.input);
    if !input_path.is_dir() {
        return Err(vrepak::Error::InputNotADirectory(
            input_path.to_string_lossy().to_string(),
        ));
    }
    let mut paths = vec![];
    collect_files(&mut paths, input_path)?;
    paths.sort();

    // unpack manifest from a previous unpack: per-file defaults (key,
    // compression, encryption, CustomData) plus pak-level engine/guid.
    // Explicit flags always win over it.
    let manifest = vrepak::PakManifest::load_if_present(input_path);
    if let Some(m) = &manifest {
        if !args.quiet {
            println!(
                "Using {} ({} files) for per-file settings",
                vrepak::MANIFEST_FILENAME,
                m.files.len()
            );
        }
    }

    let explicit_bytes = aes_key.map(|k| k.0);
    // endpoint main key, fetched once (fallback when manifest has no key)
    let endpoint_bytes: Option<[u8; 32]> = match (&explicit_bytes, &endpoint) {
        (None, Some(ep)) if !ep.trim().is_empty() => {
            let cfg = vrepak_endpoint::EndpointConfig::new(ep, &expression);
            let (_json, resolved) = vrepak_endpoint::fetch_and_resolve(&cfg)
                .map_err(|e| vrepak::Error::Other(format!("endpoint error: {e}")))?;
            Some(resolved.key_for_guid(None))
        }
        _ => None,
    };
    // engine: explicit flag wins, otherwise the manifest, otherwise stock
    let engine = match engine {
        Some(e) => e,
        None => manifest
            .as_ref()
            .and_then(|m| m.engine.parse().ok())
            .unwrap_or(vrepak::Engine::Stock),
    };
    let guid = match &args.encryption_guid {
        Some(s) => {
            vrepak_endpoint::parse_guid(s)
                .map(|(g, _)| g)
                .map_err(|e| vrepak::Error::Other(format!("bad --encryption-guid: {e}")))?
        }
        None => manifest
            .as_ref()
            .and_then(|m| m.encryption_guid.as_deref())
            .and_then(|s| vrepak_endpoint::parse_guid(s).ok())
            .map(|(g, _)| g)
            .unwrap_or(0),
    };
    // index key: explicit flag wins, then endpoint main, then the first
    // encrypted file's key from the manifest (single-key roundtrips agree
    // on all three anyway)
    let index_key_bytes: Option<[u8; 32]> = explicit_bytes.or(endpoint_bytes).or_else(|| {
        manifest.as_ref().and_then(|m| {
            m.files
                .iter()
                .find(|f| f.encrypted)
                .and_then(|f| f.key.as_deref())
        })
        .and_then(|hex| vrepak_endpoint::parse_aes_key(hex).ok())
    });

    let mut builder = vrepak::PakBuilder::new().engine(engine);
    if let Some(b) = index_key_bytes {
        use aes::cipher::KeyInit;
        builder = builder.key(
            aes::Aes256::new_from_slice(&b).expect("manifest key is 32 bytes"),
        );
    }
    // record a guid only on encrypted paks (an unencrypted pak with a guid
    // would mislead readers into requesting a key)
    if index_key_bytes.is_some() && guid != 0 {
        builder = builder.encryption_guid(guid);
    }
    let mut pak = builder.writer(
        BufWriter::new(File::create(&output)?),
        args.version,
        args.mount_point,
        Some(args.path_hash_seed),
    );

    use indicatif::ProgressIterator;

    let iter = paths.iter();
    let (log, iter) = if !args.quiet {
        let iter =
            iter.progress_with_style(indicatif::ProgressStyle::with_template(STYLE).unwrap());
        (
            Output::Progress(iter.progress.clone()),
            itertools::Either::Left(iter),
        )
    } else {
        (Output::Stdout, itertools::Either::Right(iter))
    };
    let log = log.clone();
    let done_log = log.clone();

    let mut result = None;
    let result_ref = &mut result;
    rayon::in_place_scope(|scope| -> Result<(), vrepak::Error> {
        let (tx, rx) = std::sync::mpsc::sync_channel(0);

        scope.spawn(move |_| {
            *result_ref = Some(
                iter.par_bridge()
                    .try_for_each(|p| -> Result<(), vrepak::Error> {
                        let rel = &p
                            .strip_prefix(input_path)
                            .expect("file not in input directory")
                            .to_slash()
                            .expect("failed to convert to slash path");
                        if args.verbose {
                            log.println(format!("packing {}", &rel));
                        }
                        let meta = manifest.as_ref().and_then(|m| m.find(&rel));
                        // compression: explicit flag wins, then manifest, then none
                        let comp: Option<vrepak::Compression> = match args.compression {
                            Some(c) => Some(c),
                            None => meta
                                .and_then(|m| m.compression.as_deref())
                                .map(|s| {
                                    s.parse().map_err(|_| {
                                        vrepak::Error::Other(format!(
                                            "unknown compression {s:?} for {rel}"
                                        ))
                                    })
                                })
                                .transpose()?,
                        };
                        // key: explicit flag wins, then manifest, then endpoint
                        let key_bytes: Option<[u8; 32]> = match explicit_bytes {
                            Some(b) => Some(b),
                            None => match meta.and_then(|m| m.key.as_deref()) {
                                Some(hex) => Some(vrepak_endpoint::parse_aes_key(hex).map_err(
                                    |e| vrepak::Error::Other(format!("bad key for {rel}: {e}")),
                                )?),
                                None => endpoint_bytes,
                            },
                        };
                        // encrypt iff the manifest says so, else iff we have a key
                        let encrypt = match meta {
                            Some(m) => m.encrypted,
                            None => key_bytes.is_some(),
                        };
                        if encrypt && key_bytes.is_none() {
                            return Err(vrepak::Error::Other(format!(
                                "no key for encrypted file {rel} (pass --aes-key/--endpoint)"
                            )));
                        }
                        let custom: u8 = match args.wuwa_custom_data {
                            Some(n) => n,
                            None => meta.map(|m| m.custom_data).unwrap_or(2),
                        };
                        let entry = vrepak::EntryBuilder::for_compression(comp)
                            .build_entry(true, std::fs::read(p)?)?;

                        tx.send((
                            rel.to_string(),
                            entry,
                            if encrypt { key_bytes } else { None },
                            custom,
                        ))
                        .unwrap();
                        Ok(())
                    }),
            );
        });

        use std::sync::atomic::{AtomicBool, Ordering};
        let any_encrypted = AtomicBool::new(false);
        for (path, entry, key, custom) in rx {
            if key.is_some() {
                any_encrypted.store(true, Ordering::Relaxed);
            }
            pak.write_entry_with_key(path, entry, key, custom)?;
        }
        if !args.quiet && any_encrypted.load(Ordering::Relaxed) {
            done_log.println("(encrypted entries packed)");
        }
        Ok(())
    })?;
    result.unwrap()?;

    pak.write_index()?;

    if !args.quiet {
        println!("Packed {} files to {}", paths.len(), output.display());
    }

    Ok(())
}

fn get(aes_key: Option<aes::Aes256>, engine: vrepak::Engine, args: ActionGet) -> Result<(), vrepak::Error> {
    let mut reader = BufReader::new(File::open(&args.input)?);
    let mut builder = vrepak::PakBuilder::new().engine(engine);
    if let Some(aes_key) = aes_key {
        builder = builder.key(aes_key);
    }
    let pak = builder.reader(&mut reader)?;
    let mount_point = PathBuf::from(pak.mount_point());
    let prefix = Path::new(&args.strip_prefix);

    let full_path = prefix.join(args.file);
    let file = full_path
        .strip_prefix(&mount_point)
        .map_err(|_| vrepak::Error::PrefixMismatch {
            path: full_path.to_string_lossy().to_string(),
            prefix: mount_point.to_string_lossy().to_string(),
        })?;

    use std::io::Write;
    std::io::stdout().write_all(&pak.get(&file.to_slash_lossy(), &mut reader)?)?;
    Ok(())
}
