mod sss;
mod crypto;
mod cmd_da;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use base64::{engine::general_purpose, Engine as _};
use hex::encode as hex_encode;

use std::fs;
use std::io::Read;

use crate::sss::{split_secret, recover_secret};
use crate::crypto::{gen_key, encrypt_aes_gcm, decrypt_aes_gcm};
use dsdn_common::cid::sha256_hex;
use dsdn_storage::rpc;

#[derive(Parser)]
#[command(author="INEVA", version, about="DSDN Agent CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate random key (32 bytes). Optionally split into n shares with threshold k.
    GenKey {
        #[arg(short, long, default_value_t = 0)]
        n: u8,
        #[arg(short, long, default_value_t = 0)]
        k: u8,
        #[arg(short, long)]
        out_dir: Option<PathBuf>,
    },

    /// Recover key from shares (provide file paths as args)
    RecoverKey {
        #[arg(required = true)]
        shares: Vec<PathBuf>,
    },

    /// Upload a file to node (node_addr like 127.0.0.1:50051). If --encrypt, agent encrypts with new key and prints key (base64).
    Upload {
        node_addr: String,
        file: PathBuf,
        #[arg(long)]
        encrypt: bool,
    },

    /// Download a file by hash from node. Optionally decrypt with provided key (base64)
    Get {
        node_addr: String,
        hash: String,
        #[arg(long)]
        decrypt_key_b64: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Decrypt a local encrypted file (nonce || ciphertext) using AES-GCM key (base64)
    DecryptFile {
        /// Encrypted input file (produced by encrypt_aes_gcm)
        enc_file: PathBuf,
        /// Output plaintext file path
        out_file: PathBuf,
        /// AES-GCM key in base64 (32 bytes after decode)
        key_b64: String,
    },

    /// DA (Data Availability) layer commands
    Da {
        #[command(subcommand)]
        da_cmd: DaCommands,
    },
}

/// DA layer subcommands
#[derive(Subcommand)]
enum DaCommands {
    /// Show DA layer status
    Status {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Commands::GenKey { n, k, out_dir } => {
            let key = gen_key();
            if n > 0 && k > 0 {
                let shares = split_secret(&key, n, k)?;
                if let Some(dir) = out_dir {
                    fs::create_dir_all(&dir)?;
                    for (x, data) in shares.iter() {
                        let fname = dir.join(format!("share-{}.b64", x));
                        let b64 = general_purpose::STANDARD.encode(&data);
                        fs::write(&fname, &b64)?;
                        println!("wrote {}", fname.display());
                    }
                } else {
                    for (x, data) in shares.iter() {
                        println!("share-{}: {}", x, general_purpose::STANDARD.encode(&data));
                    }
                }
            } else {
                let b64 = general_purpose::STANDARD.encode(&key);
                println!("KEY_B64: {}", b64);
                println!("KEY_HEX: {}", hex_encode(&key));
            }
        }

        Commands::RecoverKey { shares } => {
            let mut parts = Vec::new();
            for p in shares {
                let s = fs::read_to_string(&p)?;
                let s = s.trim();
                let data = general_purpose::STANDARD.decode(s)?;
                let fname = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                let x: u8 = if fname.starts_with("share-") {
                    fname[6..].split('.').next().unwrap_or("1").parse().unwrap_or(1)
                } else {
                    1
                };
                parts.push((x, data));
            }
            let recovered = recover_secret(&parts)?;
            println!("recovered key (hex): {}", hex_encode(&recovered));
            println!("recovered key (b64): {}", general_purpose::STANDARD.encode(&recovered));
        }

        Commands::Upload { node_addr, file, encrypt } => {
            let mut f = fs::File::open(&file)?;
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)?;
            let to_upload = buf;
            let mut printed_key: Option<String> = None;
            let connect = format!("http://{}", node_addr);

            if encrypt {
                let key = gen_key();
                let cipher_blob = encrypt_aes_gcm(&key, &to_upload)?;
                let hash = sha256_hex(&cipher_blob);
                println!("Uploading encrypted blob (cid {}) to {}", hash, node_addr);

                let returned = rpc::client_put(connect.clone(), hash.clone(), cipher_blob.clone())
                    .await
                    .map_err(|e| anyhow::anyhow!(format!("{}", e)))?;
                println!("uploaded -> returned {}", returned);

                let b64 = general_purpose::STANDARD.encode(&key);
                printed_key = Some(b64.clone());
                println!("ENCRYPTION_KEY_B64: {}", b64);
            } else {
                let hash = sha256_hex(&to_upload);
                println!("Uploading blob (cid {}) to {}", hash, node_addr);
                let returned = rpc::client_put(connect.clone(), hash.clone(), to_upload.clone())
                    .await
                    .map_err(|e| anyhow::anyhow!(format!("{}", e)))?;
                println!("uploaded -> returned {}", returned);
            }
            if let Some(_k) = printed_key {
                println!("Note: save this encryption key (base64) to decrypt later.");
            }
        }

        Commands::Get { node_addr, hash, decrypt_key_b64, out } => {
            let connect = format!("http://{}", node_addr);
            let opt = rpc::client_get(connect.clone(), hash.clone())
                .await
                .map_err(|e| anyhow::anyhow!(format!("{}", e)))?;
            match opt {
                None => {
                    println!("not found on node {}", node_addr);
                }
                Some(data) => {
                    if let Some(b64) = decrypt_key_b64 {
                        let key = general_purpose::STANDARD.decode(&b64)?;
                        if key.len() != 32 { anyhow::bail!("invalid key length"); }
                        let mut k32 = [0u8; 32];
                        k32.copy_from_slice(&key);
                        let plain = decrypt_aes_gcm(&k32, &data)?;
                        if let Some(path) = out {
                            fs::write(path, &plain)?;
                            println!("wrote decrypted to file");
                        } else {
                            println!("decrypted bytes (hex): {}", hex_encode(&plain));
                        }
                    } else {
                        if let Some(path) = out {
                            fs::write(path, &data)?;
                            println!("wrote bytes to file");
                        } else {
                            println!("bytes (hex): {}", hex_encode(&data));
                        }
                    }
                }
            }
        }

        Commands::DecryptFile { enc_file, out_file, key_b64 } => {
            // baca file terenkripsi (nonce || ciphertext)
            let enc = fs::read(&enc_file)?;
            // decode key base64
            let key_bytes = general_purpose::STANDARD.decode(&key_b64)?;
            if key_bytes.len() != 32 {
                anyhow::bail!("invalid key length: expected 32 bytes, got {}", key_bytes.len());
            }
            let mut k32 = [0u8; 32];
            k32.copy_from_slice(&key_bytes);
            // decrypt
            let plain = decrypt_aes_gcm(&k32, &enc)?;
            fs::write(&out_file, &plain)?;
            println!("decrypted {} -> {}", enc_file.display(), out_file.display());
        }

        Commands::Da { da_cmd } => {
            match da_cmd {
                DaCommands::Status { json } => {
                    cmd_da::handle_da_status(json).await?;
                }
            }
        }
    }

    Ok(())
}