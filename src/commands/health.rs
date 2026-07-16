use std::path::PathBuf;

use crate::config::Config;
use crate::crypto;
use crate::error::S2Error;
use crate::permissions;

/// Prove each file decrypts with its keychain/file-store passphrase.
///
/// No provider registry is built, so this makes NO SSM/Vault calls — a failure
/// means the passphrase is missing or wrong, never that a remote provider was
/// unreachable. Non-destructive: the decrypted plaintext is discarded (unlike
/// `decrypt`, which rewrites the file). Exit 0 = every file decrypts.
pub fn run(config: &Config, files: Vec<PathBuf>, profile: Option<String>) -> Result<(), S2Error> {
    let files = config.resolve_files(&files, &profile)?;

    for path in &files {
        let canonical = path.canonicalize().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                S2Error::FileNotFound(path.clone())
            } else {
                S2Error::Io(e)
            }
        })?;

        permissions::check_permissions(&canonical)?;

        let bytes = std::fs::read(&canonical)?;
        if !crypto::is_age_encrypted(&bytes) {
            eprintln!("File is not age-encrypted: {}", canonical.display());
            std::process::exit(1);
        }

        // Decrypt in memory to prove the passphrase resolves; plaintext is dropped.
        // Errors: keychain miss → "passphrase not found…"; bad ciphertext → decryption failed.
        crypto::decrypt_file_content(&canonical, &bytes, config.biometric)?;
    }

    Ok(())
}
