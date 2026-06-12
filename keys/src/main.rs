use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand::thread_rng;
use std::fs;
use x25519_dalek::{PublicKey as EccPublicKey, StaticSecret};

fn main() -> anyhow::Result<()> {
    let mut rng = thread_rng();

    println!("🚀 Starten der X25519 Schlüsselgenerierung...");

    // 1. Erzeuge den geheimen, langlebigen Private Key (32 Bytes Rohdaten)
    let private_key = StaticSecret::random_from_rng(&mut rng);

    // 2. Leite den passenden Public Key daraus ab (32 Bytes Rohdaten)
    let public_key = EccPublicKey::from(&private_key);

    let priv_bytes = private_key.to_bytes();
    let pub_bytes = public_key.to_bytes();

    // =========================================================================
    // 3. ASN.1 STRUCTURE WRAPPING (Für OpenSSL & PHP Kompatibilität)
    // =========================================================================
    // Statische DER-Präfixe, damit Krypto-Bibliotheken wissen, dass es X25519 ist
    let pkcs8_private_prefix = hex::decode("302e020100300506032b656e04220420").unwrap();
    let pkcs8_public_prefix = hex::decode("302a300506032b656e032100").unwrap();

    // Private Key DER zusammenbauen
    let mut full_priv_der = pkcs8_private_prefix;
    full_priv_der.extend_from_slice(&priv_bytes);

    // Public Key DER zusammenbauen
    let mut full_pub_der = pkcs8_public_prefix;
    full_pub_der.extend_from_slice(&pub_bytes);

    // =========================================================================
    // 4. PEM-DATEIEN GENERIEREN (Base64-Kodierung + Zeilenumbrüche)
    // =========================================================================
    let priv_b64 = BASE64.encode(&full_priv_der);
    let pub_b64 = BASE64.encode(&full_pub_der);

    // Strikte Formatierung auf 64 Zeichen Breite pro Zeile für PEM-Parser
    let priv_pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        chunk_string(&priv_b64, 64)
    );
    let pub_pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        chunk_string(&pub_b64, 64)
    );

    // Dateien auf die Festplatte schreiben
    fs::write("private.pem", priv_pem.as_bytes())?;
    println!("✅ 'private.pem' wurde erstellt. (Sicher und geheim aufbewahren!)");

    fs::write("public.pem", pub_pem.as_bytes())?;
    println!("✅ 'public.pem' wurde erstellt. (Für dein Hauptprogramm)");

    // =========================================================================
    // 5. HEX-AUSGABE FÜR SCHNELLE CONFIGS
    // =========================================================================
    let server_pub_hex = hex::encode(pub_bytes);

    println!("\n-----------------------------------------------------------");
    println!("🔑 PUBLIC KEY ALS HEX-STRING (Für Skripte / PHP-Direkteingabe):");
    println!("{}", server_pub_hex);
    println!("-----------------------------------------------------------");

    Ok(())
}

// Hilfsfunktion zum sauberen Umbrechen des Base64-Strings nach X Zeichen
fn chunk_string(s: &str, width: usize) -> String {
    s.chars()
        .collect::<Vec<char>>()
        .chunks(width)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<String>>()
        .join("\n")
}
