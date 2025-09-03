use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use rand::RngCore;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use base64::{Engine as _, engine::general_purpose};

pub fn key_derivation(pass:&str,salt:&[u8]) -> [u8;32] {
    let mut key = [0u8;32];
    pbkdf2_hmac::<Sha256>(pass.as_bytes(),salt,100_000,&mut key);
    key
}

pub fn pass_encrypt(pass:&str,key:&[u8;32]) -> Result<(String,String),String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    let mut nonce_byte = [0u8;12];
    OsRng.fill_bytes(&mut nonce_byte);
    let nonce = Nonce::from_slice(&nonce_byte);

    let encrypted_pass = cipher.encrypt(nonce,pass.as_bytes()).map_err(|_| "Encryption Failed")?;

    let nonce_64 = general_purpose::STANDARD.encode(nonce_byte);
    let encrypted_pass_64 = general_purpose::STANDARD.encode(encrypted_pass);

    Ok((nonce_64,encrypted_pass_64))
}

pub fn salt_generator() -> [u8;32] {
    let mut salt = [0u8;32];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn pass_decrypt(nonce_64:&str,encrypted_pass_64:&str,key:&[u8;32]) -> Result<String,String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    let nonce_byte = general_purpose::STANDARD.decode(nonce_64).map_err(|_| "Invalid nonce encoding")?;
    let encrypted_pass = general_purpose::STANDARD.decode(encrypted_pass_64).map_err(|_| "Invalid encrypted_pass encoding")?;

    if  nonce_byte.len() != 12{
        return Err("Invalid Nonce !".into());
    }

    let nonce = Nonce::from_slice(&nonce_byte);
    let pass = cipher.decrypt(nonce,encrypted_pass.as_ref()).map_err(|_| "Decryption Failed")?;

    String::from_utf8(pass).map_err(|_| "Invalid UTF-8 in decrypt data".into())
}