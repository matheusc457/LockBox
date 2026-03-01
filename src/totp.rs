use totp_rs::{Algorithm, Secret, TOTP};
use std::time::SystemTime;

pub fn generate_code(secret_str: &str) -> Option<String> {
    let mut secret_bytes = Secret::Encoded(secret_str.to_string()).to_bytes()
        .unwrap_or_else(|_| secret_str.as_bytes().to_vec());

    if secret_bytes.len() < 16 {
        secret_bytes.resize(16, 0);
    }

    let totp = match TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
    ) {
        Ok(t) => t,
        Err(_) => return None,
    };

    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()?
        .as_secs();

    Some(totp.generate(time))
}

pub fn get_remaining_seconds() -> u64 {
    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    30 - (time % 30)
}

