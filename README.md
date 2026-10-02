# vrepak

> **Fork of [`repak`](https://github.com/trumank/repak)** — library and CLI tool for working with Unreal Engine .pak files.

Library and CLI tool for working with Unreal Engine .pak files.

 - Supports reading and writing a wide range of versions
 - Easy to use API while providing low level control:
   - Only parses index initially and reads file data upon request
   - Can rewrite index in place to perform append or delete operations without rewriting entire pak

`vrepak` CLI
 - Sane handling of mount points: defaults to `../../../` but can be configured via flag
 - 2x faster unpacking over `UnrealPak`
 - Unpacking is guarded against malicious pak that attempt to write to parent directories
 - FModel-compatible AES endpoint configuration: fetch main + dynamic (per-GUID) keys from a JSON endpoint

## cli
```console
$ vrepak --help
Usage: vrepak [OPTIONS] <COMMAND>

Commands:
  info           Print .pak info
  list           List .pak files
  hash-list      List .pak files and the SHA256 of their contents. Useful for finding differences between paks
  unpack         Unpack .pak file
  pack           Pack directory into .pak file
  get            Reads a single file to stdout
  endpoint-test  Test endpoint configuration (AES) - FModel compatible
  help           Print this message or the help of the given subcommand(s)

Options:
  -a, --aes-key <AES_KEY>        256 bit AES encryption key as base64 or hex string if the pak is encrypted
      --endpoint <ENDPOINT>      Endpoint URL returning JSON with AES keys (FModel compatible). If set, keys are auto-resolved per-pak GUID (main key fallback)
      --expression <EXPRESSION>  JSONPath expression for endpoint, e.g. $['mainKey', 'dynamicKeys']. Supports up to 2 elements: main key + dynamic [{guid, key}] list [default: ]
  -h, --help                     Print help
  -V, --version                  Print version
```

### packing
```console
$ find mod
mod
mod/assets
mod/assets/AssetA.uasset
mod/assets/AssetA.uexp

$ vrepak pack -v mod
packing assets/AssetA.uasset
packing assets/AssetA.uexp
Packed 4 files to mod.pak

$ vrepak list mod.pak
assets/AssetA.uasset
assets/AssetA.uexp
```

### unpacking
```console
$ vrepak --aes-key 0x12345678 unpack MyEncryptedGame.pak
Unpacked 12345 files to MyEncryptedGame from MyEncryptedGame.pak
```

### endpoint configuration (AES)

Instead of passing `--aes-key` manually, `vrepak` can fetch keys from a JSON endpoint,
using the same concept as FModel's *Endpoint Configuration (AES)*.
The endpoint must return JSON, and a JSONPath expression selects the key(s) from it.

The expression supports up to 2 elements:
- element 1 (mandatory): the main AES key — hex string with optional `0x` prefix (base64 also accepted);
- element 2 (optional): list of dynamic keys, each an object with at least `guid` and `key`
  (plus optional `name`):
```json
[
    {
        "guid": "00000000000000000000000000000000",
        "key": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "name": "pakchunk0-WindowsClient.pak"
    }
]
```

```console
$ vrepak endpoint-test --endpoint https://example.com/keys.json --expression "$['mainKey', 'dynamicKeys']"
Your endpoint configuration is valid! Please, avoid any unnecessary modifications!
main key: 0x...
dynamic keys: 512

$ vrepak --endpoint https://example.com/keys.json --expression "$['mainKey', 'dynamicKeys']" info MyGame.pak
$ vrepak --endpoint https://example.com/keys.json --expression "$['mainKey', 'dynamicKeys']" unpack MyGame.pak
```

For each `.pak`, `vrepak` peeks its encryption GUID from the (unencrypted) footer and
picks the matching dynamic key, falling back to the main key. An explicitly passed
`--aes-key` always wins over the endpoint.

The GUI (`vrepak-gui`) persists the endpoint configuration to
`%APPDATA%\vrepak\endpoint.json` on Windows or `~/.config/vrepak/endpoint.json` otherwise.

## gui

`vrepak-gui` is a native GUI wrapper around the `vrepak` library (no WebView needed)
with an *Endpoint Configuration (AES)* dialog: Endpoint + Send, instruction,
Expression + Test, validity status bar, plus basic pak tools (`info` / `list` / `unpack`).

```console
$ cargo run -p vrepak_gui
```

## workspace

| Crate | Description |
|-------|-------------|
| `vrepak` | Core library: reading/writing `.pak` (fork of [`repak`](https://github.com/trumank/repak)) |
| `vrepak_cli` | `vrepak` binary: `info` / `list` / `hash-list` / `unpack` / `pack` / `get` / `endpoint-test` |
| `vrepak_endpoint` | Endpoint configuration (AES): fetch JSON + JSONPath evaluation + key validation (FModel compatible) |
| `vrepak_gui` | `vrepak-gui` binary: native egui GUI |
| `oodle_loader` | Optional Oodle loader (unchanged from upstream) |

## compatibility

| UE Version   | Version | Version Feature       | Read               | Write                  |
|--------------|---------|-----------------------|--------------------|------------------------|
|              | 1       | Initial               | :grey_question:    | :grey_question:        |
| 4.0-4.2      | 2       | NoTimestamps          | :heavy_check_mark: | :heavy_check_mark:     |
| 4.3-4.15     | 3       | CompressionEncryption | :heavy_check_mark: | :heavy_check_mark:     |
| 4.16-4.19    | 4       | IndexEncryption       | :heavy_check_mark: | :heavy_check_mark:     |
| 4.20         | 5       | RelativeChunkOffsets  | :heavy_check_mark: | :heavy_check_mark:     |
|              | 6       | DeleteRecords         | :grey_question:    | :grey_question:        |
| 4.21         | 7       | EncryptionKeyGuid     | :heavy_check_mark: | :heavy_check_mark:     |
| 4.22         | 8A      | FNameBasedCompression | :heavy_check_mark: | :heavy_check_mark:     |
| 4.23-4.24    | 8B      | FNameBasedCompression | :heavy_check_mark: | :heavy_check_mark:     |
| 4.25         | 9       | FrozenIndex           | :heavy_check_mark: | :heavy_check_mark:[^1] |
|              | 10      | PathHashIndex         | :grey_question:    | :grey_question:        |
| 4.26-5.3[^2] | 11      | Fnv64BugFix           | :heavy_check_mark: | :heavy_check_mark:     |

| Feature         | Read               | Write           |
|-----------------|--------------------|-----------------|
| Compression     | :heavy_check_mark: | :wavy_dash:[^3] |
| Encrypted Index | :heavy_check_mark: | :x:             |
| Encrypted Data  | :heavy_check_mark: | :x:             |


[^1]: Except for paks compressed using frozen index which has significant
    complexity and only existed for UE 4.25 anyway.
[^2]: As of writing. Later versions are likely supported but untested.
[^3]: Zlib, Gzip, and Zstd are supported. Not all compression algorithms are
    available in all games.

Supports reading encrypted (both index and/or data) and compressed paks.
Writing does not support compression or encryption yet.

## notes

### determinism

As far as I can tell, the index is not necessarily written deterministically by `UnrealPak`. `vrepak` uses `BTreeMap` in place of `HashMap` to deterministically write the index and *happens* to rewrite the test paks in the same order, but this more likely than not stops happening on larger pak files.

### full directory index

`UnrealPak` includes a directory entry in the full directory index for all parent directories back to the pak root for a given file path regardless of whether those directories contain any files or just other directories. `vrepak` only includes directories that contain files. So far no functional differences have been observed as a result.

## acknowledgements
- [repak](https://github.com/trumank/repak): upstream project this is forked from
- [unpak](https://github.com/bananaturtlesandwich/unpak): original crate featuring read-only pak operations
- [rust-u4pak](https://github.com/panzi/rust-u4pak)'s README detailing the pak file layout
- [jieyouxu](https://github.com/jieyouxu) for serialization implementation of the significantly more complex V11 index
- [FModel](https://github.com/4sval/FModel): inspiration for the endpoint configuration (AES) concept
