use crate::error::{PqcError, Result};
use crate::{kem, sign};
use serde::{Deserialize, Serialize};
use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use rand::Rng;

#[derive(Serialize, Deserialize)]
pub struct DeviceCredentials {
    pub kyber_public_key: Vec<u8>,
    pub kyber_secret_key: Vec<u8>,
    pub dilithium_public_key: Vec<u8>,
    pub dilithium_secret_key: Vec<u8>,
}

impl DeviceCredentials {
    pub fn generate() -> Result<Self> {
        let kyber_keys = kem::generate_keypair()?;
        let dilithium_keys = sign::generate_keypair()?;
        
        Ok(Self {
            kyber_public_key: kyber_keys.public_key,
            kyber_secret_key: kyber_keys.secret_key,
            dilithium_public_key: dilithium_keys.public_key,
            dilithium_secret_key: dilithium_keys.secret_key,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedEntropy {
    pub ciphertext: Vec<u8>,
    pub encrypted_data: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct AuthRequest {
    pub device_id: String,
    pub nonce: Vec<u8>,
    pub signature: Vec<u8>,
}

pub fn encrypt_entropy_for_device(entropy: &[u8], device_kyber_public_key: &[u8]) -> Result<EncryptedEntropy> {
    let (ciphertext, shared_secret) = kem::encapsulate(device_kyber_public_key)?;
    let encrypted_data = encrypt_with_aes(&shared_secret, entropy)?;
    Ok(EncryptedEntropy { ciphertext, encrypted_data })
}

pub fn decrypt_entropy(encrypted: &EncryptedEntropy, device_kyber_secret_key: &[u8]) -> Result<Vec<u8>> {
    let shared_secret = kem::decapsulate(device_kyber_secret_key, &encrypted.ciphertext)?;
    decrypt_with_aes(&shared_secret, &encrypted.encrypted_data)
}

pub fn create_auth_request(device_id: &str, nonce: &[u8], device_dilithium_secret_key: &[u8]) -> Result<AuthRequest> {
    let message = format!("{}|{}", device_id, hex::encode(nonce));
    let signature = sign::sign(message.as_bytes(), device_dilithium_secret_key)?;
    Ok(AuthRequest { device_id: device_id.to_string(), nonce: nonce.to_vec(), signature })
}

pub fn verify_auth_request(request: &AuthRequest, device_dilithium_public_key: &[u8]) -> Result<bool> {
    let message = format!("{}|{}", request.device_id, hex::encode(&request.nonce));
    sign::verify(message.as_bytes(), &request.signature, device_dilithium_public_key)
}

fn encrypt_with_aes(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(&key[..32])
        .map_err(|e| PqcError::Encryption(format!("{}", e)))?;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|e| PqcError::Encryption(format!("{}", e)))?;
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn decrypt_with_aes(key: &[u8], ciphertext_with_nonce: &[u8]) -> Result<Vec<u8>> {
    if ciphertext_with_nonce.len() < 12 {
        return Err(PqcError::Decryption("Invalid ciphertext".to_string()));
    }
    let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(&key[..32])
        .map_err(|e| PqcError::Decryption(format!("{}", e)))?;
    cipher.decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|e| PqcError::Decryption(format!("{}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_entropy_flow() {
        let device = DeviceCredentials::generate().unwrap();
        let entropy = b"secret_entropy_data";
        let encrypted = encrypt_entropy_for_device(entropy, &device.kyber_public_key).unwrap();
        let decrypted = decrypt_entropy(&encrypted, &device.kyber_secret_key).unwrap();
        assert_eq!(entropy.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_full_auth_flow() {
        let device = DeviceCredentials::generate().unwrap();
        let auth_request = create_auth_request("device_123", b"nonce", &device.dilithium_secret_key).unwrap();
        let is_valid = verify_auth_request(&auth_request, &device.dilithium_public_key).unwrap();
        assert!(is_valid);
    }
}