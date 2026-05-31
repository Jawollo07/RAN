use base64::{Engine as _, engine::general_purpose};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use clap::Parser;
use rayon::prelude::*;
use rsa::{Oaep, RsaPrivateKey, pkcs8::DecodePrivateKey};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const BUFFER_4MB: usize = 4 * 1024 * 1024;
const BUFFER_1MB: usize = 1 * 1024 * 1024;
const SMALL_FILE_THRESHOLD: u64 = 1 * 1024 * 1024;
const MEDIUM_FILE_THRESHOLD: u64 = 500 * 1024 * 1024;
const SPARSE_BLOCKS: usize = 5;
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

#[derive(Parser)]
#[command(author, version, about = "Recovery tool for RAN encrypted files")]
struct Args {
    #[arg(
        short,
        long,
        default_value = "/home/jannik/Cloud/Dev/RAN/enc/test_data"
    )]
    target_dir: String,

    #[arg(
        short = 'k',
        long,
        default_value = "/home/jannik/Cloud/Dev/RAN/keys/private.pem"
    )]
    private_key_path: String,

    #[arg(
        short = 'i',
        long,
        default_value = "/home/jannik/Cloud/Dev/RAN/enc/INFO.bin"
    )]
    recovery_info_path: String,

    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

fn main() -> anyhow::Result<()> {
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

    let entries: Vec<PathBuf> = WalkDir::new(&args.target_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect();

    println!("{} Dateien gefunden.", entries.len());

    entries.par_iter().for_each(|path| {
        if let Err(e) = recover_file(path, &master_key, &meta) {
            eprintln!("Fehler bei {:?}: {}", path, e);
        }
    });

    println!("✅ Wiederherstellung abgeschlossen!");
    Ok(())
}

fn recover_file(path: &Path, master_key: &[u8; 32], meta: &RecoveryMetadata) -> anyhow::Result<()> {
    let encrypted_name = path.file_name().unwrap().to_string_lossy();
    let name_bytes = general_purpose::URL_SAFE_NO_PAD.decode(encrypted_name.as_bytes())?;

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

    let mut original_path = path.to_path_buf();
    original_path.set_file_name(&original_name);
    let original_path_str = original_path.to_string_lossy().to_string();

    // Content entschlüsseln
    let content_nonce = meta.derive_nonce(master_key, &original_path_str);
    let mut content_cipher = ChaCha20::new(master_key.into(), &content_nonce.into());

    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let size = file.metadata()?.len();

    match size {
        s if s < SMALL_FILE_THRESHOLD => decrypt_full(&mut file, size, &mut content_cipher)?,
        s if s < MEDIUM_FILE_THRESHOLD => decrypt_header(&mut file, &mut content_cipher)?,
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

fn decrypt_header(file: &mut std::fs::File, cipher: &mut ChaCha20) -> anyhow::Result<()> {
    let mut buffer = vec![0u8; BUFFER_4MB];
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
    decrypt_header(file, cipher)?;

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
