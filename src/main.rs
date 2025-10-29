use pqc_algo::api::{DeviceCredentials, encrypt_entropy_for_device, decrypt_entropy, create_auth_request, verify_auth_request};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("PQC-Algo Demo - Post-Quantum Cryptography");
    println!("============================================");
    
    // Generate device credentials
    println!("\nGenerating device credentials...");
    let device = DeviceCredentials::generate()?;
    println!("Device credentials generated!");
    println!("   Kyber public key size: {} bytes", device.kyber_public_key.len());
    println!("   Dilithium public key size: {} bytes", device.dilithium_public_key.len());
    
    // Demo entropy encryption
    println!("\nEncrypting entropy for device...");
    let entropy = b"super_secret_random_data_for_quantum_security";
    let encrypted = encrypt_entropy_for_device(entropy, &device.kyber_public_key)?;
    println!("Entropy encrypted successfully!");
    println!("   Ciphertext size: {} bytes", encrypted.ciphertext.len());
    println!("   Encrypted data size: {} bytes", encrypted.encrypted_data.len());
    
    // Demo entropy decryption
    println!("\nDecrypting entropy with device secret key...");
    let decrypted = decrypt_entropy(&encrypted, &device.kyber_secret_key)?;
    println!("Entropy decrypted successfully!");
    
    // Verify integrity
    if entropy.as_slice() == decrypted.as_slice() {
        println!("Integrity verification passed!");
    } else {
        println!("Integrity verification failed!");
    }
    
    // Demo authentication
    println!("\nCreating authentication request...");
    let nonce = b"random_nonce_12345";
    let auth_request = create_auth_request("device_123", nonce, &device.dilithium_secret_key)?;
    println!("Authentication request created!");
    
    println!("\nVerifying authentication...");
    let is_valid = verify_auth_request(&auth_request, &device.dilithium_public_key)?;
    if is_valid {
        println!("Authentication verified! Device is authentic.");
    } else {
        println!("Authentication failed! Device may be compromised.");
    }
    
    println!("\nDemo completed successfully!");
    println!("The PQC-Algo library is ready for quantum-resistant cryptography.");
    
    Ok(())
}