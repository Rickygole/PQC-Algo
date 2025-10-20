use crate::error::{PqcError, Result};
use oqs::sig::{Sig, Algorithm};

pub struct DilithiumKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

pub fn generate_keypair() -> Result<DilithiumKeyPair> {
    let sig = Sig::new(Algorithm::Dilithium3)
        .map_err(|e| PqcError::KeyGeneration(format!("{:?}", e)))?;
    
    let (pk, sk) = sig.keypair()
        .map_err(|e| PqcError::KeyGeneration(format!("{:?}", e)))?;
    
    Ok(DilithiumKeyPair {
        public_key: pk.into_vec(),
        secret_key: sk.into_vec(),
    })
}

pub fn sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    let sig = Sig::new(Algorithm::Dilithium3)
        .map_err(|e| PqcError::Signing(format!("{:?}", e)))?;
    
    let sk_ref = sig.secret_key_from_bytes(secret_key)
        .ok_or_else(|| PqcError::Signing("Invalid secret key length".to_string()))?;
    
    let signature = sig.sign(message, sk_ref)
        .map_err(|e| PqcError::Signing(format!("{:?}", e)))?;
    
    Ok(signature.into_vec())
}

pub fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    let sig = Sig::new(Algorithm::Dilithium3)
        .map_err(|e| PqcError::Verification(format!("{:?}", e)))?;
    
    let pk_ref = sig.public_key_from_bytes(public_key)
        .ok_or_else(|| PqcError::Verification("Invalid public key length".to_string()))?;
    
    let sig_ref = sig.signature_from_bytes(signature)
        .ok_or_else(|| PqcError::Verification("Invalid signature length".to_string()))?;
    
    match sig.verify(message, sig_ref, pk_ref) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dilithium_sign_verify() {
        let keypair = generate_keypair().unwrap();
        let message = b"device_id:123|nonce:abc|timestamp:1234567890";
        
        let signature = sign(message, &keypair.secret_key).unwrap();
        let is_valid = verify(message, &signature, &keypair.public_key).unwrap();
        
        assert!(is_valid);
    }

    #[test]
    fn test_dilithium_invalid_signature() {
        let keypair = generate_keypair().unwrap();
        let message = b"original message";
        
        let signature = sign(message, &keypair.secret_key).unwrap();
        
        // Try to verify with tampered message
        let tampered_message = b"tampered message";
        let is_valid = verify(tampered_message, &signature, &keypair.public_key).unwrap();
        
        assert!(!is_valid);
    }
}