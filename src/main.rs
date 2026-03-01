mod crypto;
mod storage;
mod totp;

use clap::{Parser, Subcommand};
use storage::{Vault, TwoFactorItem};
use std::io::{self, Write};

#[derive(Parser)]
#[command(name = "safelocked")]
#[command(about = "Secure 2FA/TOTP CLI manager", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Add { name: String, secret: String },
    List,
    Get { name: String },
}

fn get_password() -> String {
    print!("Enter Master Password: ");
    io::stdout().flush().unwrap();
    let mut password = String::new();
    io::stdin().read_line(&mut password).unwrap();
    password.trim().to_string()
}

fn main() {
    let cli = Cli::parse();
    let password = get_password();

    match &cli.command {
        Commands::Add { name, secret } => {
            let mut vault = if let Ok(data) = Vault::load_from_disk() {
                let salt: [u8; 16] = data[0..16].try_into().expect("Invalid salt length");
                let key = crypto::derive_key(&password, &salt);
                Vault::deserialize(&crypto::decrypt(&data[16..], &key).expect("Invalid Password"))
            } else {
                let mut salt = [0u8; 16];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
                Vault::new(salt)
            };

            vault.items.push(TwoFactorItem {
                name: name.clone(),
                secret: secret.clone(),
            });

            let key = crypto::derive_key(&password, &vault.salt);
            let encrypted = crypto::encrypt(&vault.serialize(), &key);
            
            let mut final_data = vault.salt.to_vec();
            final_data.extend(encrypted);
            
            vault.save_to_disk(&final_data).expect("Failed to save vault");
            println!("Service '{}' added successfully!", name);
        }
        Commands::List => {
            if let Ok(data) = Vault::load_from_disk() {
                let salt: [u8; 16] = data[0..16].try_into().expect("Invalid salt length");
                let key = crypto::derive_key(&password, &salt);
                let vault = Vault::deserialize(&crypto::decrypt(&data[16..], &key).expect("Invalid Password"));
                
                println!("Stored Services:");
                for item in vault.items {
                    println!(" - {}", item.name);
                }
            } else {
                println!("Vault not found. Add a service first.");
            }
        }
        Commands::Get { name } => {
            if let Ok(data) = Vault::load_from_disk() {
                let salt: [u8; 16] = data[0..16].try_into().expect("Invalid salt length");
                let key = crypto::derive_key(&password, &salt);
                let vault = Vault::deserialize(&crypto::decrypt(&data[16..], &key).expect("Invalid Password"));
                
                if let Some(item) = vault.items.iter().find(|i| &i.name == name) {
                    if let Some(code) = totp::generate_code(&item.secret) {
                        println!("Code for {}: {} (Expires in {}s)", name, code, totp::get_remaining_seconds());
                    }
                } else {
                    println!("Service not found.");
                }
            } else {
                println!("Vault not found.");
            }
        }
    }
}

