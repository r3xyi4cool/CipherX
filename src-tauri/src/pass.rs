use std::fs;
use serde::{Deserialize, Serialize};
use crate::crypto::{encrypt_password, decrypt_password, derive_key_from_password};

#[derive(Serialize,Deserialize,Clone)]
pub struct Secret{
    pub site : String,
    pub randomizer : String,
    pub ciphertext :String,
}

#[derive(Serialize,Deserialize)]
pub struct PasswordFile{
    pub username : String,
    pub password : String,
    pub salt : String,
    pub secret : Vec<string>,
}

