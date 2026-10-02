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

    /// Encryption GUID recorded in the footer (32 hex chars, default zeros).
    /// Only used when packing with a key (--aes-key/--endpoint).
    #[arg(long, default_value = "00000000000000000000000000000000")]
    encryption_guid: String,

    /// CustomData byte for fresh entries when packing with
    /// --engine wuthering-waves (0: full, 1: 0x200000, 2: 0x800, 4: plaintext).
    #[arg(long, default_value = "2")]
    wuwa_custom_data: u8,

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
    aes_key: Option<AesKey>,

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
        default_value_t = vrepak::Engine::Stock,
        value_parser = clap::builder::PossibleValuesParser::new(vrepak::Engine::VARIANTS).map(|s| s.parse::<vrepak::Engine>().unwrap())
    )]
    engine: vrepak::Engine,

    #[command(subcommand)]
    action: Action,
}

#[derive(Debug, Clone)]
struct AesKey(aes::Aes256);
impl std::str::FromStr for AesKey {
    type Err = vrepak::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use aes::cipher::KeyInit;
        use base64::{engine::general_purpose, Engine as _};
        let try_parse = |bytes: Vec<_>| aes::Aes256::new_from_slice(&bytes).ok().map(AesKey);
        hex::decode(s.strip_prefix("0x").unwrap_or(s))
            .ok()
            .and_then(try_parse)
            .or_else(|| {
                general_purpose::STANDARD_NO_PAD
                    .decode(s.trim_end_matches('='))
                    .ok()
                    .and_then(try_parse)
            })
            .ok_or(vrepak::Error::Aes)
    }
}

fn main() -> Result<(), vrepak::Error> {
    let args = Args::parse();
    let explicit_key = args.aes_key.map(|k| k.0);

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
    let resolve_for_file = |pak_path: &str| -> Option<aes::Aes256> {
        if let Some(k) = explicit_key.clone() {
            return Some(k);
        }
        if let Some(cache) = &endpoint_cache {
            // peek guid without key
            let guid = File::open(pak_path)
                .ok()
                .and_then(|mut f| vrepak::PakReader::peek_encryption_guid(&mut BufReader::new(&mut f)));
            let bytes = cache.resolved.key_for_guid(guid);
            use aes::cipher::KeyInit;
            return aes::Aes256::new_from_slice(&bytes).ok();
        }
        None
    };

    match args.action {
        Action::Info(action) => {
            let k = resolve_for_file(&action.input);
            info(k, args.engine, action)
        }
        Action::List(action) => {
            let k = resolve_for_file(&action.input);
            list(k, args.engine, action)
        }
        Action::HashList(action) => {
            let k = resolve_for_file(&action.input);
            hash_list(k, args.engine, action)
        }
        Action::Unpack(action) => {
            // per-file keys for multi-input unpack
            let mut per_file_keys: Vec<Option<aes::Aes256>> = Vec::new();
            for input in &action.input {
                per_file_keys.push(resolve_for_file(input));
            }
            unpack_with_keys(per_file_keys, args.engine, action)
        }
        Action::Pack(action) => pack(
            explicit_key.clone(),
            args.endpoint.clone(),
            args.expression.clone(),
            args.engine,
            action,
        ),
        Action::Get(action) => {
            let k = resolve_for_file(&action.input);
            get(k, args.engine, action)
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

fn unpack_with_keys(per_file_keys: Vec<Option<aes::Aes256>>, engine: vrepak::Engine, action: ActionUnpack) -> Result<(), vrepak::Error> {
    for (idx, input) in action.input.iter().enumerate() {
        let aes_key = per_file_keys.get(idx).cloned().flatten();
        let mut builder = vrepak::PakBuilder::new().engine(engine);
        if let Some(aes_key) = aes_key.clone() {
            builder = builder.key(aes_key);
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
    }

    Ok(())
}

fn pack(
    aes_key: Option<aes::Aes256>,
    endpoint: Option<String>,
    expression: String,
    engine: vrepak::Engine,
    args: ActionPack,
) -> Result<(), vrepak::Error> {
    let output = args.output.map(PathBuf::from).unwrap_or_else(|| {
        // NOTE: don't use `with_extension` here because it will replace e.g. the `.1` in
        // `test_v1.1`.
        PathBuf::from(format!("{}.pak", args.input))
    });

    // key for encryption: explicit flag wins, otherwise the endpoint's main key
    let aes_key = match aes_key {
        Some(k) => Some(k),
        None => match endpoint {
            Some(ep) if !ep.trim().is_empty() => {
                let cfg = vrepak_endpoint::EndpointConfig::new(&ep, &expression);
                let (_json, resolved) =
                    vrepak_endpoint::fetch_and_resolve(&cfg).map_err(|e| {
                        vrepak::Error::Other(format!("endpoint error: {e}"))
                    })?;
                use aes::cipher::KeyInit;
                Some(
                    aes::Aes256::new_from_slice(&resolved.key_for_guid(None))
                        .expect("endpoint key is 32 bytes"),
                )
            }
            _ => None,
        },
    };
    let (guid, _) = vrepak_endpoint::parse_guid(&args.encryption_guid)
        .map_err(|e| vrepak::Error::Other(format!("bad --encryption-guid: {e}")))?;

    fn collect_files(paths: &mut Vec<PathBuf>, dir: &Path) -> io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                collect_files(paths, &path)?;
            } else {
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

    let encrypting = aes_key.is_some();
    let mut builder = vrepak::PakBuilder::new()
        .compression(args.compression.iter().cloned())
        .engine(engine)
        .wuwa_custom_data(args.wuwa_custom_data);
    if let Some(k) = aes_key {
        builder = builder.key(k);
    }
    // record a guid only on encrypted paks (an unencrypted pak with a guid
    // would mislead readers into requesting a key)
    if encrypting && guid != 0 {
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

    let mut result = None;
    let result_ref = &mut result;
    rayon::in_place_scope(|scope| -> Result<(), vrepak::Error> {
        let (tx, rx) = std::sync::mpsc::sync_channel(0);
        let entry_builder = pak.entry_builder();

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
                        let entry = entry_builder.build_entry(true, std::fs::read(p)?)?;

                        tx.send((rel.to_string(), entry)).unwrap();
                        Ok(())
                    }),
            );
        });

        for (path, entry) in rx {
            pak.write_entry(path, entry)?;
        }
        Ok(())
    })?;
    result.unwrap()?;

    pak.write_index()?;

    if !args.quiet {
        if encrypting {
            println!(
                "Packed {} files to {} (encrypted, engine {engine})",
                paths.len(),
                output.display()
            );
        } else {
            println!("Packed {} files to {}", paths.len(), output.display());
        }
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
