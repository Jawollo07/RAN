use base64::{engine::general_purpose, Engine as _};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use clap::Parser;
use rayon::prelude::*;
use rsa::{pkcs8::DecodePrivateKey, Oaep, RsaPrivateKey};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

// Die Struktur muss exakt mit dem Encryptor übereinstimmen
#[derive(serde::Serialize, serde::Deserialize)]
struct RecoveryMetadata {
    encrypted_master_key: Vec<u8>,
    nonce_salt: [u8; 16],
    chunk_size: usize,
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

#[derive(Parser)]
#[command(author, version, about = "Recovery tool for RAN encrypted files")]
struct Args {
    /// Directory containing encrypted files
    #[arg(
        short,
        long,
        default_value = "/home/jannik/Cloud/Dev/RAN/enc/test_data"
    )]
    target_dir: String,

    /// Path to private PEM key
    #[arg(
        short = 'k',
        long,
        default_value = "/home/jannik/Cloud/Dev/RAN/keys/private.pem"
    )]
    private_key_path: String,

    /// Path to recovery INFO.bin
    #[arg(
        short = 'i',
        long,
        default_value = "/home/jannik/Cloud/Dev/RAN/enc/INFO.bin"
    )]
    recovery_info_path: String,

    /// Dry run (do not modify files)
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let target_dir = args.target_dir;
    let private_key_path = args.private_key_path;
    let recovery_info_path = args.recovery_info_path;
    let dry_run = args.dry_run;

    println!("--- Recovery Tool ---");

    // 2. Private Key & Metadaten laden
    let priv_pem = fs::read_to_string(private_key_path)?;
    let priv_key = RsaPrivateKey::from_pkcs8_pem(&priv_pem)?;

    let meta_data = fs::read(recovery_info_path)?;
    let meta: RecoveryMetadata = bincode::deserialize(&meta_data)?;

    // 3. Master-Key mit RSA entschlüsseln
    let master_key_vec = priv_key
        .decrypt(Oaep::new::<Sha256>(), &meta.encrypted_master_key)
        .map_err(|_| anyhow::anyhow!("Falscher Private Key oder beschädigte Metadaten!"))?;

    let mut master_key = [0u8; 32];
    master_key.copy_from_slice(&master_key_vec);
    println!("✅ Master-Key erfolgreich wiederhergestellt.");

    // 4. Dateien sammeln
    let entries: Vec<PathBuf> = WalkDir::new(target_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect();
    if entries.is_empty() {
        println!("⚠️  Keine Dateien im Zielverzeichnis gefunden. Überprüfe den Pfad.");
        return Ok(());
    }
    println!(
        "✅ {} verschlüsselte Dateien gefunden. Starte Wiederherstellung...",
        entries.len()
    );
    // 5. Dateien entschlüsseln (In-Place & Rename)
    entries.par_iter().for_each(|path| {
        if let Err(e) = recover_file(path, &master_key, &meta) {
            eprintln!("Fehler bei Datei {:?}: {}", path, e);
        }
    });

    println!("--- Wiederherstellung abgeschlossen ---");
    Ok(())
}

fn recover_file(path: &Path, master_key: &[u8; 32], meta: &RecoveryMetadata) -> anyhow::Result<()> {
    let encrypted_name = path.file_name().unwrap().to_string_lossy();

    // A: DATEINAME ENTSCHLÜSSELN
    // Wir müssen den Namen erst zurückrechnen, um den "Originalpfad" für die Nonce-Ableitung zu erhalten
    let name_bytes = general_purpose::URL_SAFE_NO_PAD.decode(encrypted_name.as_bytes())?;

    // Nonce für den Namen berechnen (muss exakt wie beim Encryptor sein!)
    let parent = path
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let name_nonce_input = format!("{}_name", parent);
    let name_nonce = meta.derive_nonce(master_key, &name_nonce_input);
    let mut name_cipher = ChaCha20::new(master_key.into(), &name_nonce.into());

    let mut decrypted_name_bytes = name_bytes.clone();
    name_cipher.apply_keystream(&mut decrypted_name_bytes);
    let original_name = String::from_utf8(decrypted_name_bytes)?;

    // B: ORIGINALEN PFAD FÜR CONTENT-NONCE REKONSTRUIEREN
    let mut original_path = path.to_path_buf();
    original_path.set_file_name(&original_name);
    let original_path_str = original_path.to_string_lossy();

    // C: INHALT ENTSCHLÜSSELN
    let content_nonce = meta.derive_nonce(master_key, &original_path_str);
    let mut content_cipher = ChaCha20::new(master_key.into(), &content_nonce.into());

    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let size = file.metadata()?.len();
    let to_read = std::cmp::min(size, meta.chunk_size as u64);

    let mut buffer = vec![0u8; to_read as usize];
    file.read_exact(&mut buffer)?;
    content_cipher.apply_keystream(&mut buffer);

    file.seek(SeekFrom::Start(0))?;
    file.write_all(&buffer)?;

    // D: DATEI ZURÜCK UMBENENNEN
    drop(file); // Datei-Handle schließen vor dem Rename
    fs::rename(path, original_path)?;

    Ok(())
}
