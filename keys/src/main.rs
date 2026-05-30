use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
};
use std::fs;

fn main() -> anyhow::Result<()> {
    let mut rng = rand::thread_rng();
    let bits = 4096;

    println!("Generiere RSA-4096 Schlüsselpaar... (Das kann einen Moment dauern)");

    // 1. RSA Private Key generieren
    let private_key = RsaPrivateKey::new(&mut rng, bits)?;

    // 2. RSA Public Key daraus ableiten
    let public_key = RsaPublicKey::from(&private_key);

    // 3. Private Key als PEM (PKCS#8) exportieren
    // ACHTUNG: In einer echten Umgebung sollte dieser Key mit einem Passwort verschlüsselt werden!
    let priv_pem = private_key.to_pkcs8_pem(LineEnding::LF)?;
    fs::write("private.pem", priv_pem.as_bytes())?;
    println!("✅ 'private.pem' wurde erstellt. SICHER AUFBEWAHREN!");

    // 4. Public Key als PEM (PKCS#8) exportieren
    let pub_pem = public_key.to_public_key_pem(LineEnding::LF)?;
    fs::write("public.pem", pub_pem.as_bytes())?;
    println!("✅ 'public.pem' wurde erstellt. Diesen in den Encryptor einbauen.");

    println!("\nFertig. Kopiere den Inhalt von 'public.pem' in dein Hauptprogramm.");
    Ok(())
}
