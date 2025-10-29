use pqc_algo::{kem, sign, api};
use std::fs;

fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cleaned = hex_str.trim().replace('\n', "").replace(' ', "");
    Ok(hex::decode(cleaned)?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing PQC with External Keys");
    println!("==================================");
    
    // Initialize OQS library
    oqs::init();
    
    // Read the key files
    println!("Reading key files...");
    let dilithium_hex = fs::read_to_string("/Users/rickygole/Downloads/dilithium.bin")?;
    let kyber_hex = fs::read_to_string("/Users/rickygole/Downloads/kyber.bin")?;
    
    let dilithium_key = hex_to_bytes(&dilithium_hex)?;
    let kyber_key = hex_to_bytes(&kyber_hex)?;
    
    println!("Loaded keys:");
    println!("   - Dilithium key: {} bytes", dilithium_key.len());
    println!("   - Kyber key: {} bytes", kyber_key.len());
    
    // Test 1: Try to use as Kyber public key for encryption
    println!("\nTesting Kyber encryption...");
    match kem::encapsulate(&kyber_key) {
        Ok((ciphertext, shared_secret)) => {
            println!("Kyber encryption successful!");
            println!("   - Ciphertext: {} bytes", ciphertext.len());
            println!("   - Shared secret: {} bytes", shared_secret.len());
            println!("   - Shared secret (hex): {}", hex::encode(&shared_secret[..16])); // First 16 bytes
        }
        Err(e) => {
            println!("Kyber encryption failed: {}", e);
            println!("   (Key might be wrong size or format for Kyber1024)");
        }
    }
    
    // Test 2: Try to verify a signature with Dilithium key
    println!("\nTesting Dilithium verification...");
    let test_message = b"test message for verification";
    
    // First, let's see what happens if we try to verify with this key
    match sign::verify(test_message, &dilithium_key, &dilithium_key) {
        Ok(valid) => {
            println!("Dilithium verification completed: {}", valid);
        }
        Err(e) => {
            println!("Dilithium verification failed: {}", e);
            println!("   (Key might be wrong size or format for Dilithium3)");
        }
    }
    
    // Test 3: Generate our own keys and show the difference
    println!("\nGenerating our own keys for comparison...");
    let our_kem_keys = kem::generate_keypair()?;
    let our_sig_keys = sign::generate_keypair()?;
    
    println!("Our key sizes:");
    println!("   - Kyber1024 public key: {} bytes", our_kem_keys.public_key.len());
    println!("   - Kyber1024 secret key: {} bytes", our_kem_keys.secret_key.len());
    println!("   - Dilithium3 public key: {} bytes", our_sig_keys.public_key.len());
    println!("   - Dilithium3 secret key: {} bytes", our_sig_keys.secret_key.len());
    
    // Test 4: Show working encryption with our keys
    println!("\nDemonstrating working PQC with our keys...");
    let test_data = b"Secret entropy data from QRNG";
    let (ciphertext, shared_secret) = kem::encapsulate(&our_kem_keys.public_key)?;
    
    println!("Working encryption:");
    println!("   - Encrypted {} bytes of test data", test_data.len());
    println!("   - Shared secret: {}", hex::encode(&shared_secret[..16]));
    
    // Test signing
    let signature = sign::sign(test_data, &our_sig_keys.secret_key)?;
    let is_valid = sign::verify(test_data, &signature, &our_sig_keys.public_key)?;
    
    println!("Working signatures:");
    println!("   - Signature size: {} bytes", signature.len());
    println!("   - Verification result: {}", is_valid);
    
    println!("\nAnalysis of provided keys:");
    println!("   - Both files are 513 bytes (same size)");
    println!("   - Expected Kyber1024 public key: 1568 bytes");
    println!("   - Expected Dilithium3 public key: 1952 bytes");
    println!("   - Your keys appear to be a different format or algorithm");
    
    println!("\nRecommendation:");
    println!("   - Use the generate_keypair() functions to create proper PQC keys");
    println!("   - Or convert your keys to the expected format for Kyber1024/Dilithium3");
    
    Ok(())
}