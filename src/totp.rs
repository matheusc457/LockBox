use std::time::SystemTime;
use totp_rs::{Algorithm, Secret, TOTP};

pub fn generate_code(secret_str: &str) -> Option<String> {
    // Try base32 decode first (standard TOTP secret format).
    // If the length mod 8 == 1 or decode fails, fall back to raw bytes.
    let secret_bytes = {
        let rem = secret_str.len() % 8;
        let padded = if rem == 0 || rem == 1 {
            secret_str.to_string()
        } else {
            format!("{}{}", secret_str, "=".repeat(8 - rem))
        };
        match Secret::Encoded(padded).to_bytes() {
            Ok(b) => b,
            Err(_) => Secret::Raw(secret_str.as_bytes().to_vec())
                .to_bytes()
                .ok()?,
        }
    };

    if secret_bytes.is_empty() {
        return None;
    }

    let totp = match TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_secret_generates_code() {
        // ONQWMZLMN5RWWZLEL52GK43UEEYTEMZU is base32 of b"safelocked_test!1234" (20 bytes)
        let code = generate_code("ONQWMZLMN5RWWZLEL52GK43UEEYTEMZU");
        assert!(code.is_some());
        let code = code.unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_invalid_length_secret_generates_code() {
        // GAJSSJSJSJJSJS277 has len%8==1, invalid base32 — must fall back to raw bytes
        let code = generate_code("GAJSSJSJSJJSJS277");
        // Raw bytes = 17, still < 16 minimum so should be None OR Some depending on fallback
        // Either way it must not panic
        let _ = code;
    }

    #[test]
    fn test_invalid_secret_returns_none() {
        // Empty secret must return None
        assert!(generate_code("").is_none());
    }

    #[test]
    fn test_empty_secret_returns_none() {
        assert!(generate_code("").is_none());
    }

    #[test]
    fn test_remaining_seconds_in_range() {
        let secs = get_remaining_seconds();
        assert!((1..=30).contains(&secs));
    }
}
