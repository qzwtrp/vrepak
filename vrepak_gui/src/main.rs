//! vrepak-gui: native GUI for vrepak with Endpoint Configuration (AES) + pak tools.
//!
//! Pure Rust egui: no WebView, no JavaScript, no IPC. Endpoint fetching and
//! pak operations run in worker threads; the UI only polls results.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, TryRecvError};

use eframe::egui;
use strum::VariantNames;

const INSTRUCTION: &str = "In order to make this work you first need to understand JSON and its query language. If you don't, please close this window. If your game never changes its AES keys or is not even encrypted, please close this window. If you do understand what you are doing, you have to know that the AES expression supports up to 2 elements.\n\nThe first element is mandatory and will be assigned to the main AES key. It has to be looking like a key, else your configuration will not be valid (the key validity against your files will not be checked). Said key must be hexadecimal and can start without \"0x\".\n\nIf your game uses several AES keys, you can specify a second element that will be your list of dynamic keys. The format needed is a list of objects with, at least, the next 2 variables:\n{\n  \"guid\": \"the archive guid\",\n  \"key\": \"the archive aes key\"\n}";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Endpoint,
    Pak,
    Pack,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StatusKind {
    Info,
    Ok,
    Err,
}

impl StatusKind {
    fn color(self) -> egui::Color32 {
        match self {
            StatusKind::Info => egui::Color32::LIGHT_GRAY,
            StatusKind::Ok => egui::Color32::from_rgb(126, 231, 135),
            StatusKind::Err => egui::Color32::from_rgb(255, 123, 114),
        }
    }
}

enum JobResult {
    EndpointJson { pretty: String, ok: bool, status: String },
    EndpointTest { report: String, ok: bool, status: String },
    Pak { text: String, ok: bool, status: String },
    Pack { text: String, ok: bool, status: String },
}

fn aes_from_bytes(bytes: &[u8; 32]) -> aes::Aes256 {
    use aes::cipher::KeyInit;
    aes::Aes256::new_from_slice(bytes).expect("32 bytes")
}

enum KeySource {
    Explicit,
    EndpointDynamic { guid: u128 },
    EndpointMain { guid: Option<u128>, dynamics: usize },
    None,
}

impl KeySource {
    fn describe(&self) -> String {
        match self {
            KeySource::Explicit => "explicit --aes-key".to_string(),
            KeySource::EndpointDynamic { guid } => {
                format!("endpoint dynamic (guid {guid:032X})")
            }
            KeySource::EndpointMain { guid, dynamics } => match guid {
                Some(g) => format!(
                    "endpoint main fallback (pak guid {g:032X} not in {dynamics} dynamic keys)"
                ),
                None => format!(
                    "endpoint main fallback (no guid in pak, {dynamics} dynamic keys)"
                ),
            },
            KeySource::None => "none (no key supplied)".to_string(),
        }
    }
}

fn resolve_key_for_pak(
    pak_path: &str,
    explicit_key: Option<String>,
    endpoint: Option<String>,
    expression: Option<String>,
) -> Result<(Option<aes::Aes256>, KeySource), String> {
    if let Some(k) = explicit_key {
        if k.trim().is_empty() {
            return Ok((None, KeySource::None));
        }
        return vrepak_endpoint::parse_aes_key(&k)
            .map(|b| (Some(aes_from_bytes(&b)), KeySource::Explicit))
            .map_err(|e| e.to_string());
    }
    if let Some(ep) = endpoint {
        if ep.trim().is_empty() {
            return Ok((None, KeySource::None));
        }
        let expr = expression.unwrap_or_default();
        let cfg = vrepak_endpoint::EndpointConfig::new(&ep, &expr);
        let (_json, resolved) =
            vrepak_endpoint::fetch_and_resolve(&cfg).map_err(|e| e.to_string())?;
        let guid = File::open(pak_path)
            .ok()
            .and_then(|mut f| vrepak::PakReader::peek_encryption_guid(&mut BufReader::new(&mut f)));
        let dynamics = resolved.dynamic_keys.len();
        let matched = guid.and_then(|g| {
            resolved
                .dynamic_keys
                .iter()
                .find(|d| d.guid == g)
                .map(|_| g)
        });
        let bytes = resolved.key_for_guid(guid);
        let source = match matched {
            Some(g) => KeySource::EndpointDynamic { guid: g },
            None => KeySource::EndpointMain {
                guid,
                dynamics,
            },
        };
        return Ok((Some(aes_from_bytes(&bytes)), source));
    }
    Ok((None, KeySource::None))
}

fn pak_info_text(
    pak_path: &str,
    aes_key: Option<String>,
    endpoint: Option<String>,
    expression: Option<String>,
    engine: vrepak::Engine,
) -> Result<String, String> {
    let (key, source) = resolve_key_for_pak(pak_path, aes_key, endpoint, expression)?;
    let mut builder = vrepak::PakBuilder::new().engine(engine);
    if let Some(k) = key {
        builder = builder.key(k);
    }
    let mut reader = BufReader::new(File::open(pak_path).map_err(|e| e.to_string())?);
    let pak = builder.reader(&mut reader).map_err(|e| e.to_string())?;
    Ok(format!(
        "[engine: {engine}]\n[key: {}]\nmount point: {}\nversion: {}\nencrypted index: {}\nencryption guid: {:032X?}\n{} file entries",
        source.describe(),
        pak.mount_point(),
        pak.version(),
        pak.encrypted_index(),
        pak.encryption_guid(),
        pak.files().len()
    ))
}

fn pak_list_text(
    pak_path: &str,
    aes_key: Option<String>,
    endpoint: Option<String>,
    expression: Option<String>,
    engine: vrepak::Engine,
) -> Result<String, String> {
    let (key, source) = resolve_key_for_pak(pak_path, aes_key, endpoint, expression)?;
    let mut builder = vrepak::PakBuilder::new().engine(engine);
    if let Some(k) = key {
        builder = builder.key(k);
    }
    let mut reader = BufReader::new(File::open(pak_path).map_err(|e| e.to_string())?);
    let pak = builder.reader(&mut reader).map_err(|e| e.to_string())?;
    let mount = PathBuf::from(pak.mount_point());
    let prefix = PathBuf::from("../../../");
    let mut out: Vec<String> = pak
        .files()
        .into_iter()
        .map(|f| {
            mount
                .join(&f)
                .strip_prefix(&prefix)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or(f)
                .replace('\\', "/")
        })
        .collect();
    out.sort();
    out.insert(0, format!("[key: {}]", source.describe()));
    Ok(out.join("\n"))
}

fn pak_unpack_with_key(
    pak_path: &str,
    out_dir: &str,
    key: Option<aes::Aes256>,
    engine: vrepak::Engine,
) -> Result<String, String> {
    let mut builder = vrepak::PakBuilder::new().engine(engine);
    if let Some(k) = key {
        builder = builder.key(k);
    }
    let mut reader = BufReader::new(File::open(pak_path).map_err(|e| e.to_string())?);
    let pak = builder.reader(&mut reader).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(out_dir).map_err(|e| e.to_string())?;
    let mount = PathBuf::from(pak.mount_point());
    let prefix = PathBuf::from("../../../");
    let mut reader2 = BufReader::new(File::open(pak_path).map_err(|e| e.to_string())?);
    let mut count = 0;
    for f in pak.files() {
        let rel = mount
            .join(&f)
            .strip_prefix(&prefix)
            .map_err(|e| e.to_string())?
            .to_path_buf();
        let out_path = PathBuf::from(out_dir).join(&rel);
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut out_file = File::create(&out_path).map_err(|e| e.to_string())?;
        pak.read_file(&f, &mut reader2, &mut out_file)
            .map_err(|e| e.to_string())?;
        count += 1;
    }
    Ok(format!("Unpacked {count} files to {out_dir}"))
}

fn pak_pack_text(
    input: &str,
    output: &str,
    mount: &str,
    version: vrepak::Version,
    compression: Option<vrepak::Compression>,
    key: Option<aes::Aes256>,
    guid: u128,
    custom_data: u8,
    engine: vrepak::Engine,
) -> Result<String, String> {
    fn collect_files(paths: &mut Vec<PathBuf>, dir: &std::path::Path) -> std::io::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                collect_files(paths, &path)?;
            } else {
                paths.push(path);
            }
        }
        Ok(())
    }
    let input_path = std::path::Path::new(input);
    if !input_path.is_dir() {
        return Err(format!("input is not a directory: {input}"));
    }
    let mut paths = vec![];
    collect_files(&mut paths, input_path).map_err(|e| e.to_string())?;
    paths.sort();

    let mut builder = vrepak::PakBuilder::new()
        .engine(engine)
        .wuwa_custom_data(custom_data);
    if let Some(c) = compression {
        builder = builder.compression([c]);
    }
    let encrypting = key.is_some();
    if let Some(k) = key {
        builder = builder.key(k);
    }
    if encrypting && guid != 0 {
        builder = builder.encryption_guid(guid);
    }
    let mut pak = builder.writer(
        std::io::BufWriter::new(File::create(output).map_err(|e| e.to_string())?),
        version,
        mount.to_string(),
        Some(0),
    );
    let entry_builder = pak.entry_builder();
    for p in &paths {
        let rel = p
            .strip_prefix(input_path)
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .replace('\\', "/");
        let data = std::fs::read(p).map_err(|e| e.to_string())?;
        let entry = entry_builder
            .build_entry(true, data)
            .map_err(|e| e.to_string())?;
        pak.write_entry(rel, entry).map_err(|e| e.to_string())?;
    }
    pak.write_index().map_err(|e| e.to_string())?;
    Ok(if encrypting {
        format!("Packed {} files to {output} (encrypted, engine {engine})", paths.len())
    } else {
        format!("Packed {} files to {output}", paths.len())
    })
}

struct GuiApp {
    tab: Tab,
    endpoint: String,
    expression: String,
    json_text: String,
    expr_report: String,
    status: (String, StatusKind),
    pak_path: String,
    aes_key: String,
    engine: vrepak::Engine,
    pak_output: String,
    pack_input: String,
    pack_output: String,
    pack_mount: String,
    pack_version: vrepak::Version,
    pack_compression: Option<vrepak::Compression>,
    pack_guid: String,
    pack_custom_data: String,
    pack_log: String,
    pending: Option<Receiver<JobResult>>,
    busy: bool,
}

impl GuiApp {
    fn new() -> Self {
        let cfg_path = vrepak_endpoint::default_config_path();
        let saved = vrepak_endpoint::load_config(&cfg_path).unwrap_or_default();
        Self {
            tab: Tab::Endpoint,
            endpoint: saved.endpoint,
            expression: saved.expression,
            json_text: String::new(),
            expr_report: String::new(),
            status: (
                "Configure endpoint, then press Test.".to_string(),
                StatusKind::Info,
            ),
            pak_path: String::new(),
            aes_key: String::new(),
            engine: vrepak::Engine::Stock,
            pak_output: String::new(),
            pack_input: String::new(),
            pack_output: String::new(),
            pack_mount: "../../../".to_string(),
            pack_version: vrepak::Version::V8B,
            pack_compression: None,
            pack_guid: String::new(),
            pack_custom_data: "2".to_string(),
            pack_log: String::new(),
            pending: None,
            busy: false,
        }
    }

    fn set_status(&mut self, msg: impl Into<String>, kind: StatusKind) {
        self.status = (msg.into(), kind);
    }

    fn spawn_job(&mut self, job: impl FnOnce() -> JobResult + Send + 'static) {
        let (tx, rx) = mpsc::channel();
        self.pending = Some(rx);
        self.busy = true;
        std::thread::spawn(move || {
            let _ = tx.send(job());
        });
    }

    fn poll(&mut self, ctx: &egui::Context) {
        let res = match self.pending.as_ref() {
            Some(rx) => match rx.try_recv() {
                Ok(r) => Some(r),
                Err(TryRecvError::Empty) => {
                    ctx.request_repaint();
                    None
                }
                Err(TryRecvError::Disconnected) => {
                    self.pending = None;
                    self.busy = false;
                    self.set_status("Worker failed.", StatusKind::Err);
                    return;
                }
            },
            None => None,
        };
        if let Some(res) = res {
            self.pending = None;
            self.busy = false;
            match res {
                JobResult::EndpointJson { pretty, ok, status } => {
                    self.json_text = pretty;
                    self.set_status(status, if ok { StatusKind::Ok } else { StatusKind::Err });
                }
                JobResult::EndpointTest { report, ok, status } => {
                    self.expr_report = report;
                    self.set_status(status, if ok { StatusKind::Ok } else { StatusKind::Err });
                }
                JobResult::Pak { text, ok, status } => {
                    self.pak_output = text;
                    self.set_status(status, if ok { StatusKind::Ok } else { StatusKind::Err });
                }
                JobResult::Pack { text, ok, status } => {
                    self.pack_log = text;
                    self.set_status(status, if ok { StatusKind::Ok } else { StatusKind::Err });
                }
            }
        }
    }

    fn on_send(&mut self) {
        if self.busy || self.endpoint.trim().is_empty() {
            return;
        }
        let endpoint = self.endpoint.clone();
        self.set_status("Fetching endpoint…", StatusKind::Info);
        self.spawn_job(move || match vrepak_endpoint::fetch_json(&endpoint) {
            Ok(v) => {
                let mut pretty =
                    serde_json::to_string_pretty(&v).unwrap_or_else(|e| e.to_string());
                if pretty.len() > 20000 {
                    pretty.truncate(20000);
                    pretty.push_str("\n…(truncated)");
                }
                JobResult::EndpointJson {
                    pretty,
                    ok: true,
                    status: "Endpoint fetched. Now press Test.".to_string(),
                }
            }
            Err(e) => JobResult::EndpointJson {
                pretty: e.to_string(),
                ok: false,
                status: format!("Fetch failed: {e}"),
            },
        });
    }

    fn on_test(&mut self) {
        if self.busy
            || self.endpoint.trim().is_empty()
            || self.expression.trim().is_empty()
        {
            return;
        }
        let cfg = vrepak_endpoint::EndpointConfig::new(
            self.endpoint.clone(),
            self.expression.clone(),
        );
        self.set_status("Testing expression…", StatusKind::Info);
        self.spawn_job(move || match vrepak_endpoint::fetch_and_resolve(&cfg) {
            Ok((_json, resolved)) => {
                let mut report = format!(
                    "main key: {}\ndynamic keys: {}\n",
                    resolved.main_key_str,
                    resolved.dynamic_keys.len()
                );
                for d in resolved.dynamic_keys.iter().take(20) {
                    report.push_str(&format!("  {} => {}\n", d.guid_str, d.key_str));
                }
                if resolved.dynamic_keys.len() > 20 {
                    report.push_str(&format!("  …and {} more\n", resolved.dynamic_keys.len() - 20));
                }
                JobResult::EndpointTest {
                    report,
                    ok: true,
                    status: "Your endpoint configuration is valid! Please, avoid any unnecessary modifications!".to_string(),
                }
            }
            Err(e) => JobResult::EndpointTest {
                report: e.to_string(),
                ok: false,
                status: format!("Invalid: {e}"),
            },
        });
    }

    fn on_ok(&mut self) {
        let cfg = vrepak_endpoint::EndpointConfig::new(
            self.endpoint.clone(),
            self.expression.clone(),
        );
        let path = vrepak_endpoint::default_config_path();
        match vrepak_endpoint::save_config(&path, &cfg) {
            Ok(()) => self.set_status(
                format!("Saved to {}", path.to_string_lossy()),
                StatusKind::Ok,
            ),
            Err(e) => self.set_status(format!("Save failed: {e}"), StatusKind::Err),
        }
    }

    fn endpoint_args(&self) -> (Option<String>, Option<String>) {
        (
            if self.endpoint.trim().is_empty() {
                None
            } else {
                Some(self.endpoint.clone())
            },
            if self.expression.trim().is_empty() {
                None
            } else {
                Some(self.expression.clone())
            },
        )
    }

    fn on_info(&mut self) {
        if self.pak_path.trim().is_empty() {
            self.pak_output = "Set Pak file path first.".to_string();
            return;
        }
        let (ep, ex) = self.endpoint_args();
        let aes = if self.aes_key.trim().is_empty() {
            None
        } else {
            Some(self.aes_key.clone())
        };
        match pak_info_text(&self.pak_path, aes, ep, ex, self.engine) {
            Ok(t) => {
                self.pak_output = t;
                self.set_status("Info loaded.", StatusKind::Ok);
            }
            Err(e) => {
                self.pak_output = e.clone();
                self.set_status(format!("Info failed: {e}"), StatusKind::Err);
            }
        }
    }

    fn on_list(&mut self) {
        if self.pak_path.trim().is_empty() {
            self.pak_output = "Set Pak file path first.".to_string();
            return;
        }
        let (ep, ex) = self.endpoint_args();
        let aes = if self.aes_key.trim().is_empty() {
            None
        } else {
            Some(self.aes_key.clone())
        };
        match pak_list_text(&self.pak_path, aes, ep, ex, self.engine) {
            Ok(t) => {
                self.pak_output = t;
                self.set_status("File list loaded.", StatusKind::Ok);
            }
            Err(e) => {
                self.pak_output = e.clone();
                self.set_status(format!("List failed: {e}"), StatusKind::Err);
            }
        }
    }

    fn on_unpack(&mut self) {
        if self.busy || self.pak_path.trim().is_empty() {
            return;
        }
        let pak_path = self.pak_path.clone();
        let out_dir = pak_path.trim_end_matches(".pak").to_string();
        let (ep, ex) = self.endpoint_args();
        let aes = if self.aes_key.trim().is_empty() {
            None
        } else {
            Some(self.aes_key.clone())
        };
        // resolve synchronously so endpoint failures are reported distinctly
        let (key, source) = match resolve_key_for_pak(&pak_path, aes, ep, ex) {
            Ok(v) => v,
            Err(e) => {
                self.pak_output = e.clone();
                self.set_status(format!("Unpack failed [key resolution]: {e}"), StatusKind::Err);
                return;
            }
        };
        let source_str = source.describe();
        let engine = self.engine;
        self.set_status("Unpacking…", StatusKind::Info);
        self.spawn_job(
            move || match pak_unpack_with_key(&pak_path, &out_dir, key, engine) {
                Ok(t) => JobResult::Pak {
                    text: t.clone(),
                    ok: true,
                    status: format!("{t} [key: {source_str}]"),
                },
                Err(e) => JobResult::Pak {
                    text: e.clone(),
                    ok: false,
                    status: format!("Unpack failed [key: {source_str}]: {e}"),
                },
            },
        );
    }

    /// Single-line labeled field with an optional trailing button.
    /// Returns true when the button was clicked.
    /// Widths are computed from the space actually available, so the
    /// button can never be pushed out of its column.
    fn field_row(
        ui: &mut egui::Ui,
        label: &str,
        text: &mut String,
        hint: &str,
        button_text: Option<&str>,
    ) -> bool {
        let mut clicked = false;
        ui.horizontal(|ui| {
            ui.label(label);
            let reserve = if button_text.is_some() { 76.0 } else { 8.0 };
            let w = (ui.available_width() - reserve).max(60.0);
            ui.add(
                egui::TextEdit::singleline(text)
                    .hint_text(hint)
                    .desired_width(w),
            );
            if let Some(b) = button_text {
                if ui.button(b).clicked() {
                    clicked = true;
                }
            }
        });
        clicked
    }

    /// Rows of multiline code that fill the remaining panel height.
    fn fill_rows(ui: &egui::Ui) -> usize {
        let line_h = ui
            .text_style_height(&egui::TextStyle::Monospace)
            .max(10.0);
        ((ui.available_height() - 8.0) / line_h).max(6.0) as usize
    }

    fn show_endpoint_tab(&mut self, ui: &mut egui::Ui) {
        ui.columns(2, |cols| {
            // left: endpoint + raw JSON
            cols[0].vertical(|ui| {
                if Self::field_row(ui, "Endpoint", &mut self.endpoint, "https://...", Some("Send")) {
                    self.on_send();
                }
                let rows = Self::fill_rows(ui);
                ui.add(
                    egui::TextEdit::multiline(&mut self.json_text)
                        .code_editor()
                        .desired_rows(rows)
                        .desired_width(f32::INFINITY),
                );
            });
            // right: instruction + expression + result
            cols[1].vertical(|ui| {
                ui.heading("Instruction");
                ui.label(INSTRUCTION);
                if Self::field_row(
                    ui,
                    "Expression",
                    &mut self.expression,
                    "$['mainKey', 'dynamicKeys']",
                    Some("Test"),
                ) {
                    self.on_test();
                }
                let rows = Self::fill_rows(ui);
                ui.add(
                    egui::TextEdit::multiline(&mut self.expr_report)
                        .code_editor()
                        .desired_rows(rows)
                        .desired_width(f32::INFINITY),
                );
            });
        });
    }

    fn show_pak_tab(&mut self, ui: &mut egui::Ui) {
        if Self::field_row(
            ui,
            "Pak file",
            &mut self.pak_path,
            r"C:\games\pakchunk0.pak",
            Some("…"),
        ) {
            if let Some(p) = rfd::FileDialog::new()
                .add_filter("Unreal pak", &["pak"])
                .pick_file()
            {
                self.pak_path = p.to_string_lossy().into_owned();
            }
        }
        Self::field_row(
            ui,
            "AES key (optional if endpoint set)",
            &mut self.aes_key,
            "0x...",
            None,
        );
        ui.horizontal(|ui| {
            if ui.button("Info").clicked() {
                self.on_info();
            }
            if ui.button("List").clicked() {
                self.on_list();
            }
            if ui.button("Unpack").clicked() {
                self.on_unpack();
            }
        });
        let rows = Self::fill_rows(ui);
        ui.add(
            egui::TextEdit::multiline(&mut self.pak_output)
                .code_editor()
                .desired_rows(rows)
                .desired_width(f32::INFINITY),
        );
    }

    fn show_pack_tab(&mut self, ui: &mut egui::Ui) {
        if Self::field_row(
            ui,
            "Input dir",
            &mut self.pack_input,
            r"C:\mods\mymod",
            Some("…"),
        ) {
            if let Some(p) = rfd::FileDialog::new().pick_folder() {
                self.pack_input = p.to_string_lossy().into_owned();
                if self.pack_output.trim().is_empty() {
                    self.pack_output = format!("{}.pak", self.pack_input);
                }
            }
        }
        Self::field_row(
            ui,
            "Output pak",
            &mut self.pack_output,
            r"C:\mods\mymod.pak",
            None,
        );
        Self::field_row(
            ui,
            "Mount point",
            &mut self.pack_mount,
            "../../../",
            None,
        );
        ui.horizontal(|ui| {
            ui.label("Version");
            egui::ComboBox::from_id_salt("pack_version")
                .selected_text(self.pack_version.to_string())
                .show_ui(ui, |ui| {
                    for name in vrepak::Version::VARIANTS {
                        let v: vrepak::Version = name.parse().unwrap();
                        ui.selectable_value(&mut self.pack_version, v, *name);
                    }
                });
            ui.label("Compression");
            let label = self
                .pack_compression
                .map(|c| c.to_string())
                .unwrap_or_else(|| "None".to_string());
            egui::ComboBox::from_id_salt("pack_compression")
                .selected_text(label)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.pack_compression, None, "None");
                    for name in vrepak::Compression::VARIANTS {
                        let c: vrepak::Compression = name.parse().unwrap();
                        ui.selectable_value(&mut self.pack_compression, Some(c), *name);
                    }
                });
        });
        Self::field_row(
            ui,
            "Encryption GUID",
            &mut self.pack_guid,
            "(empty = zeros; needs AES key above or endpoint)",
            None,
        );
        Self::field_row(
            ui,
            "WuWa CustomData",
            &mut self.pack_custom_data,
            "2 (0: full, 1: 0x200000, 2: 0x800, 4: plain)",
            None,
        );
        ui.horizontal(|ui| {
            if ui.button("Pack").clicked() {
                self.on_pack();
            }
            ui.label("Key: explicit AES field, else endpoint main key. Engine: top bar.");
        });
        let rows = Self::fill_rows(ui);
        ui.add(
            egui::TextEdit::multiline(&mut self.pack_log)
                .code_editor()
                .desired_rows(rows)
                .desired_width(f32::INFINITY),
        );
    }

    fn on_pack(&mut self) {
        if self.busy || self.pack_input.trim().is_empty() {
            return;
        }
        let input = self.pack_input.clone();
        let output = if self.pack_output.trim().is_empty() {
            format!("{input}.pak")
        } else {
            self.pack_output.clone()
        };
        let (ep, ex) = self.endpoint_args();
        let aes = if self.aes_key.trim().is_empty() {
            None
        } else {
            Some(self.aes_key.clone())
        };
        // resolve synchronously so endpoint failures are reported distinctly
        let key = match aes {
            Some(k) => match vrepak_endpoint::parse_aes_key(&k) {
                Ok(b) => Some(aes_from_bytes(&b)),
                Err(e) => {
                    self.pack_log = e.to_string();
                    self.set_status(
                        format!("Pack failed [key]: {e}"),
                        StatusKind::Err,
                    );
                    return;
                }
            },
            None => match ep {
                Some(ep) if !ep.trim().is_empty() => {
                    let cfg = vrepak_endpoint::EndpointConfig::new(&ep, &ex.unwrap_or_default());
                    match vrepak_endpoint::fetch_and_resolve(&cfg) {
                        Ok((_json, resolved)) => {
                            Some(aes_from_bytes(&resolved.key_for_guid(None)))
                        }
                        Err(e) => {
                            self.pack_log = e.to_string();
                            self.set_status(
                                format!("Pack failed [endpoint]: {e}"),
                                StatusKind::Err,
                            );
                            return;
                        }
                    }
                }
                _ => None,
            },
        };
        let guid = if self.pack_guid.trim().is_empty() {
            0
        } else {
            match vrepak_endpoint::parse_guid(&self.pack_guid) {
                Ok((g, _)) => g,
                Err(e) => {
                    self.pack_log = e.to_string();
                    self.set_status(
                        format!("Pack failed [guid]: {e}"),
                        StatusKind::Err,
                    );
                    return;
                }
            }
        };
        let custom_data: u8 = match self.pack_custom_data.trim().parse() {
            Ok(n) => n,
            Err(_) => {
                self.pack_log = "CustomData must be a number (0, 1, 2 or 4)".to_string();
                self.set_status("Pack failed [custom data]", StatusKind::Err);
                return;
            }
        };
        let mount = self.pack_mount.clone();
        let version = self.pack_version;
        let compression = self.pack_compression;
        let engine = self.engine;
        self.set_status("Packing…", StatusKind::Info);
        self.spawn_job(
            move || match pak_pack_text(
                &input,
                &output,
                &mount,
                version,
                compression,
                key,
                guid,
                custom_data,
                engine,
            ) {
                Ok(t) => JobResult::Pack {
                    text: t.clone(),
                    ok: true,
                    status: t,
                },
                Err(e) => JobResult::Pack {
                    text: e.clone(),
                    ok: false,
                    status: format!("Pack failed: {e}"),
                },
            },
        );
    }
}

impl eframe::App for GuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll(ctx);

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.strong("Endpoint Configuration (AES)");
                ui.separator();
                ui.selectable_value(&mut self.tab, Tab::Endpoint, "Endpoint (AES)");
                ui.selectable_value(&mut self.tab, Tab::Pak, "Pak Tools");
                ui.selectable_value(&mut self.tab, Tab::Pack, "Pack");
                ui.separator();
                ui.label("Engine");
                ui.selectable_value(&mut self.engine, vrepak::Engine::Stock, "Stock UE");
                ui.selectable_value(
                    &mut self.engine,
                    vrepak::Engine::WutheringWaves,
                    "Wuthering Waves",
                );
                if self.busy {
                    ui.spinner();
                }
            });
        });

        egui::TopBottomPanel::bottom("bottom").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(concat!("vrepak-gui ", env!("CARGO_PKG_VERSION"), " (native)"));
                ui.colored_label(self.status.1.color(), &self.status.0);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Online Evaluator").clicked() {
                        if let Err(e) = open::that("https://jsonpath.com/") {
                            self.set_status(format!("Cannot open browser: {e}"), StatusKind::Err);
                        }
                    }
                    if ui.button("Expression Syntax").clicked() {
                        if let Err(e) = open::that(
                            "https://github.com/4sval/FModel/wiki/Settings-Explanation#endpoint-configuration",
                        ) {
                            self.set_status(format!("Cannot open browser: {e}"), StatusKind::Err);
                        }
                    }
                    if ui.button("OK").clicked() {
                        self.on_ok();
                    }
                });
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Endpoint => self.show_endpoint_tab(ui),
            Tab::Pak => self.show_pak_tab(ui),
            Tab::Pack => self.show_pack_tab(ui),
        });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Endpoint Configuration (AES) - vrepak GUI")
            .with_inner_size([1100.0, 700.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Endpoint Configuration (AES) - vrepak GUI",
        options,
        Box::new(|cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Ok(Box::new(GuiApp::new()))
        }),
    )
}
