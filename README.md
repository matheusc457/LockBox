# SafeLocked

![CI](https://github.com/matheusc457/SafeLocked/actions/workflows/ci.yml/badge.svg)

> Secure and minimal TOTP (2FA) CLI manager for Linux, written in Rust.

SafeLocked follows a local-first security model. Authentication secrets are encrypted at rest and only accessible during active agent sessions. Works fully offline with no cloud dependency.

---

## Features

- AES-256-GCM encryption for vault protection
- Argon2id key derivation with 32-byte salt
- Background agent keeps the master key in memory only
- Agent session persists until explicit `lock` command
- No decrypted secrets ever written to disk
- TOTP secrets never exposed in shell history
- Encrypted backup and restore via `export` and `import`
- Supports any TOTP secret format used in practice
- Fully offline operation

---

## Installation

### Requirements

- Linux
- Rust and Cargo

### Build from source

```bash
git clone https://github.com/matheusc457/SafeLocked
cd SafeLocked
cargo build --release
sudo cp target/release/safelocked /usr/local/bin/
```

Verify:

```bash
safelocked --help
```

---

## Usage

```bash
safelocked init              # Initialize a new vault
safelocked unlock            # Unlock and start background agent
safelocked status            # Check if vault is unlocked
safelocked add Google        # Add a new service (secret entered interactively)
safelocked list              # List all TOTP codes
safelocked list Google       # Filter by name
safelocked watch Google      # Watch a code update in real time
safelocked rename Google Gmail  # Rename a service
safelocked remove Google     # Remove a service
safelocked export ~/backup   # Export vault (encrypted or plain JSON)
safelocked import            # Import from backup
safelocked lock              # Lock vault and stop agent
safelocked purge             # Delete vault permanently
```

> Run `safelocked <command> --help` for detailed information about any command.

---

## Security

SafeLocked uses multiple layers of protection:

**AES-256-GCM** encrypts the vault file on disk. Without the correct key the file is unreadable. The GCM tag also detects any tampering.

**Argon2id** derives the encryption key from your master password. Intentionally slow and memory-intensive, making brute force impractical even with powerful hardware.

**32-byte random salt** ensures two users with the same password produce completely different keys, eliminating precomputed dictionary attacks.

**Background agent** holds the master key exclusively in RAM, never written to disk. Destroyed immediately when you run `lock`.

**Unix socket with 600 permissions** restricts agent access to your user only.

**Vault file with 600 permissions** ensures the encrypted file is only readable by your user.

**Interactive secret prompt** prevents TOTP secrets from appearing in shell history or system logs.

### Threat model

SafeLocked is designed for personal use on a trusted device. All protections hold as long as your user session is not compromised. If an attacker gains active access to your user session, all secrets accessible in that session are at risk — this is true of any local password or 2FA manager.

---

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create a branch for your feature or fix (`git checkout -b feat/my-feature`)
3. Make your changes and run `cargo fmt` and `cargo clippy` before committing
4. Open a Pull Request describing what you changed and why

Please make sure all tests pass before submitting:

```bash
cargo test
```

---

## License

This project is licensed under the MIT License.

---

<p align="center">Made with ❤️ by <a href="https://github.com/matheusc457">Matheus</a></p>

