use crate::error::{PqcError, Result};
use oqs::kem::{Kem, Algorithm};

pub struct KyberKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

pub fn generate_keypair() -> Result<KyberKeyPair> {
    let kem = Kem::new(Algorithm::Kyber1024)
        .map_err(|e| PqcError::KeyGeneration(format!("{:?}", e)))?;
    
    let (pk, sk) = kem.keypair()
        .map_err(|e| PqcError::KeyGeneration(format!("{:?}", e)))?;
    
    Ok(KyberKeyPair {
        public_key: pk.into_vec(),
        secret_key: sk.into_vec(),
    })
}

pub fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let kem = Kem::new(Algorithm::Kyber1024)
        .map_err(|e| PqcError::Encryption(format!("{:?}", e)))?;
    
    // Convert byte slice to PublicKeyRef using the kem method
    let pk_ref = kem.public_key_from_bytes(public_key)
        .ok_or_else(|| PqcError::Encryption("Invalid public key length".to_string()))?;
    
    let (ciphertext, shared_secret) = kem.encapsulate(pk_ref)
        .map_err(|e| PqcError::Encryption(format!("{:?}", e)))?;
    
    Ok((ciphertext.into_vec(), shared_secret.into_vec()))
}

pub fn decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let kem = Kem::new(Algorithm::Kyber1024)
        .map_err(|e| PqcError::Decryption(format!("{:?}", e)))?;
    
    // Convert byte slices to SecretKeyRef and CiphertextRef using kem methods
    let sk_ref = kem.secret_key_from_bytes(secret_key)
        .ok_or_else(|| PqcError::Decryption("Invalid secret key length".to_string()))?;
    let ct_ref = kem.ciphertext_from_bytes(ciphertext)
        .ok_or_else(|| PqcError::Decryption("Invalid ciphertext length".to_string()))?;
    
    let shared_secret = kem.decapsulate(sk_ref, ct_ref)
        .map_err(|e| PqcError::Decryption(format!("{:?}", e)))?;
    
    Ok(shared_secret.into_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyber_roundtrip() {
        let keypair = generate_keypair().unwrap();
        let (ciphertext, shared_secret_sender) = encapsulate(&keypair.public_key).unwrap();
        let shared_secret_receiver = decapsulate(&keypair.secret_key, &ciphertext).unwrap();
        
        assert_eq!(shared_secret_sender, shared_secret_receiver);
    }
}