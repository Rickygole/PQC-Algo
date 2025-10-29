use pqc_algo::qrng::{QRNG, QRNGEntropyService};
use pqc_algo::api::{encrypt_entropy_for_device, decrypt_entropy};
use std::io::{self, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("QRNG (Quantum Random Number Generator) Demo");
    println!("================================================");
    
    // Check if quantum seed files exist
    if !std::path::Path::new("kyber.bin").exists() {
        println!("kyber.bin not found. Please ensure quantum seed files are available.");
        return Ok(());
    }
    
    if !std::path::Path::new("dilithium.bin").exists() {
        println!("dilithium.bin not found. Please ensure quantum seed files are available.");
        return Ok(());
    }
    
    // Initialize QRNG with quantum seeds
    println!("\nInitializing QRNG with quantum seeds...");
    let mut qrng = QRNG::new("kyber.bin", "dilithium.bin")?;
    println!("QRNG initialized successfully!");
    println!("{}", qrng.seed_info());
    
    // Initialize quantum entropy service
    println!("\nStarting Quantum Entropy Service...");
    let mut service = QRNGEntropyService::new("kyber.bin", "dilithium.bin")?;
    println!("Quantum entropy service ready!");
    
    loop {
        println!("\nQRNG Menu:");
        println!("1. Generate quantum entropy");
        println!("2. Provision quantum-secured device");
        println!("3. Full entropy-as-a-service demo");
        println!("4. Quantum randomness test");
        println!("5. Exit");
        
        print!("\nSelect option (1-5): ");
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        
        match input.trim() {
            "1" => demo_quantum_entropy(&mut qrng)?,
            "2" => demo_device_provisioning(&mut service)?,
            "3" => demo_full_entropy_service(&mut service)?,
            "4" => demo_randomness_test(&mut qrng)?,
            "5" => {
                println!("Goodbye!");
                break;
            },
            _ => println!("Invalid option. Please select 1-5."),
        }
    }
    
    Ok(())
}

fn demo_quantum_entropy(qrng: &mut QRNG) -> Result<(), Box<dyn std::error::Error>> {
    println!("\nGenerating Quantum Entropy");
    println!("-----------------------------");
    
    print!("Enter entropy size in bytes (default 32): ");
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let size = input.trim().parse().unwrap_or(32);
    
    let entropy = qrng.generate_entropy_refreshed(size);
    println!("Generated {} bytes of quantum entropy:", entropy.len());
    println!("Entropy (hex): {}", hex::encode(&entropy));
    println!("Entropy (first 16 bytes): {:?}", &entropy[..entropy.len().min(16)]);
    
    Ok(())
}

fn demo_device_provisioning(service: &mut QRNGEntropyService) -> Result<(), Box<dyn std::error::Error>> {
    println!("\nQuantum Device Provisioning");
    println!("-------------------------------");
    
    print!("Enter device ID: ");
    io::stdout().flush()?;
    
    let mut device_id = String::new();
    io::stdin().read_line(&mut device_id)?;
    let device_id = device_id.trim();
    
    let credentials = service.provision_device(device_id)?;
    
    println!("Device '{}' provisioned with quantum-secured credentials!", device_id);
    println!("Kyber public key size: {} bytes", credentials.kyber_public_key.len());
    println!("Dilithium public key size: {} bytes", credentials.dilithium_public_key.len());
    println!("Keys are quantum-entropy secured!");
    
    Ok(())
}

fn demo_full_entropy_service(service: &mut QRNGEntropyService) -> Result<(), Box<dyn std::error::Error>> {
    println!("\nFull Quantum Entropy-as-a-Service Demo");
    println!("==========================================");
    
    // 1. Provision a quantum device
    let device_id = "quantum_device_001";
    println!("1. Provisioning quantum device: {}", device_id);
    let device = service.provision_device(device_id)?;
    
    // 2. Generate quantum entropy for the device
    println!("\n2. Generating quantum entropy for device...");
    let quantum_entropy = service.generate_entropy_for_device(device_id, 64)?;
    println!("Generated {} bytes of device-specific quantum entropy", quantum_entropy.len());
    
    // 3. Encrypt the quantum entropy using PQC
    println!("\n3. Encrypting quantum entropy with Kyber1024...");
    let encrypted = encrypt_entropy_for_device(&quantum_entropy, &device.kyber_public_key)?;
    println!("Quantum entropy encrypted successfully!");
    println!("Ciphertext size: {} bytes", encrypted.ciphertext.len());
    println!("Encrypted data size: {} bytes", encrypted.encrypted_data.len());
    
    // 4. Decrypt the quantum entropy
    println!("\n4. Decrypting quantum entropy with device secret key...");
    let decrypted = decrypt_entropy(&encrypted, &device.kyber_secret_key)?;
    println!("Quantum entropy decrypted successfully!");
    
    // 5. Verify integrity
    println!("\n5. Verifying quantum entropy integrity...");
    if quantum_entropy == decrypted {
        println!("Quantum entropy integrity verified!");
        println!("Original:  {}", hex::encode(&quantum_entropy[..16]));
        println!("Decrypted: {}", hex::encode(&decrypted[..16]));
    } else {
        println!("Integrity check failed!");
    }
    
    println!("\nQuantum entropy-as-a-service demo completed successfully!");
    
    Ok(())
}

fn demo_randomness_test(qrng: &mut QRNG) -> Result<(), Box<dyn std::error::Error>> {
    println!("\nQuantum Randomness Quality Test");
    println!("----------------------------------");
    
    println!("Generating 1000 quantum random bytes for analysis...");
    let test_data = qrng.generate_entropy_refreshed(1000);
    
    // Basic randomness tests
    let mut byte_counts = [0u32; 256];
    for &byte in &test_data {
        byte_counts[byte as usize] += 1;
    }
    
    // Calculate entropy
    let mut entropy = 0.0;
    for &count in &byte_counts {
        if count > 0 {
            let p = count as f64 / test_data.len() as f64;
            entropy -= p * p.log2();
        }
    }
    
    println!("Quantum randomness analysis:");
    println!("   - Data size: {} bytes", test_data.len());
    println!("   - Entropy: {:.4} bits (ideal: 8.0)", entropy);
    println!("   - Unique bytes: {}", byte_counts.iter().filter(|&&c| c > 0).count());
    
    if entropy > 7.8 {
        println!("High-quality quantum randomness detected!");
    } else if entropy > 7.0 {
        println!("Good quantum randomness quality");
    } else {
        println!("Randomness quality could be improved");
    }
    
    println!("Sample quantum bytes: {}", hex::encode(&test_data[..32]));
    
    Ok(())
}