use aes::Aes128;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use clap::Parser;
use rand::Rng;
use ring::digest::{Context, SHA256};
use std::error::Error;
use std::path::PathBuf;
use std::{fs, str};

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

#[derive(Parser)]
#[command(version, about, long_about = None)]
/// A Command-line tool for encrypting files.
pub struct Cli {
    /// The path of the file to encrypt
    pub file: PathBuf,

    /// The path of the output file
    pub output_file: PathBuf,

    #[arg(short)]
    /// Decrypt the file
    pub d: bool,
}

pub struct Config {
    pub file: PathBuf,
    pub output_file: PathBuf,
    pub encrypt: bool,
    pub key: String,
}

impl Config {
    pub fn build(cli: Cli, key: String) -> Config {
        Config {
            encrypt: !cli.d,
            file: cli.file,
            output_file: cli.output_file,
            key,
        }
    }
}

pub fn run(config: Config) -> Result<(), Box<dyn Error>> {
    let contents = fs::read(config.file)?;

    if config.encrypt {
        create_encrypted_file(
            encrypt(&contents, config.key, generate_random_iv()),
            config.output_file,
        )?;
    } else {
        create_encrypted_file(decrypt(&contents, config.key), config.output_file)?;
    }
    Ok(())
}

/// Generate a 128-bit key using SHA-256 hashing algorithm.
fn generate_key(input: &str) -> Result<Vec<u8>, hex::FromHexError> {
    let mut context = Context::new(&SHA256);
    context.update(input.as_bytes());
    let key = hex::encode(context.finish().as_ref())[..32].to_string();
    hex::decode(key)
}

/// Generate a random 128-bit Initialization Vector.
fn generate_random_iv() -> [u8; 16] {
    rand::thread_rng().gen::<[u8; 16]>()
}

/// Encrypt a vector of bytes using the provided key and Initialization Vector.
///
/// It uses a implementation of 128-bit AES with CFB (Cipher Feedback) mode.
pub fn encrypt(bytes: &Vec<u8>, key: String, iv: [u8; 16]) -> Vec<u8> {
    let key = generate_key(&key).unwrap();
    let cipher = Aes128Cbc::new_from_slices(&key, &iv).unwrap();
    let pos = bytes.len();
    let mut buffer = [0u8; 128];
    buffer[..pos].copy_from_slice(bytes);
    let encrypted_content = cipher.encrypt(&mut buffer, pos).unwrap().to_vec();

    // Prepend the IV to encrypted content
    let mut encrypted_data = Vec::with_capacity(iv.len() + encrypted_content.len());
    encrypted_data.extend_from_slice(&iv);
    encrypted_data.extend_from_slice(&encrypted_content);
    encrypted_data
}

/// Decrypt a vector of bytes using the provided key.
fn decrypt(bytes: &Vec<u8>, key: String) -> Vec<u8> {
    // The IV is the first 16 bytes of the vector,
    // which means the rest of it is the actual content.
    let iv = &bytes[..16];
    let bytes = &bytes[16..];

    let key = generate_key(&key).unwrap();
    let cipher = Aes128Cbc::new_from_slices(&key, &iv).unwrap();
    cipher.decrypt(&mut bytes.to_vec()).unwrap().to_vec()
}

/// Create a file from a vector of bytes.
pub fn create_encrypted_file(
    encrypted_content: Vec<u8>,
    encrypted_file_path: std::path::PathBuf,
) -> Result<(), Box<dyn Error>> {
    fs::write(encrypted_file_path, encrypted_content.as_slice())?;
    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_encrypt() {
        use hex_literal::hex;
        let iv = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"); // 128-bit Initialization Vector
        let bytes = "Hello".as_bytes().to_vec();
        let key = String::from("abc");
        assert_eq!(
            encrypt(&bytes, key, iv),
            vec![
                240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255,
                118, 161, 123, 220, 32, 89, 118, 55, 177, 159, 69, 238, 118, 70, 133, 134
            ] // `f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff76a17bdc20597637b19f45ee76468586`
        );
    }

    #[test]
    fn test_encrypt_with_multiple_lines() {
        use hex_literal::hex;
        let iv = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"); // 128-bit Initialization Vector
        let bytes = "Hi\nHello".as_bytes().to_vec();
        let key = String::from("aBc");
        assert_eq!(
            encrypt(&bytes, key, iv),
            vec![
                240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255,
                223, 164, 57, 68, 76, 196, 187, 166, 172, 154, 8, 214, 138, 36, 201, 46
            ] // `f0f1f2f3f4f5f6f7f8f9fafbfcfdfeffdfa439444cc4bba6ac9a08d68a24c92e`
        );
    }

    #[test]
    fn test_decrypt() {
        let bytes = vec![
            240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 118,
            161, 123, 220, 32, 89, 118, 55, 177, 159, 69, 238, 118, 70, 133, 134,
        ]; //`f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff76a17bdc20597637b19f45ee76468586`
        let key = String::from("abc");
        assert_eq!(decrypt(&bytes, key), "Hello".as_bytes().to_vec());
    }

    #[test]
    fn test_decrypt_with_multiple_lines() {
        let bytes = vec![
            240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 223,
            164, 57, 68, 76, 196, 187, 166, 172, 154, 8, 214, 138, 36, 201, 46,
        ]; // `f0f1f2f3f4f5f6f7f8f9fafbfcfdfeffdfa439444cc4bba6ac9a08d68a24c92e`
        let key = String::from("aBc");
        assert_eq!(decrypt(&bytes, key), "Hi\nHello".as_bytes().to_vec());
    }
}
