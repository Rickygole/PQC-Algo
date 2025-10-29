use pqc_algo::binary_loader::{load_kyber_binary, hex_to_bytes};
use std::env;
use std::fs;

fn analyze_binary_type(data: &[u8], filename: &str) -> String {
    let mut analysis = String::new();
    
    analysis.push_str(&format!("Analysis of {}\n", filename));
    analysis.push_str(&format!("- File size: {} bytes\n", data.len()));
    analysis.push_str(&format!("- Hex size: {} characters\n", data.len() * 2));
    
    // Check if it looks like an executable binary
    if data.len() > 4 {
        let magic = &data[0..4];
        match magic {
            [0x7f, 0x45, 0x4c, 0x46] => analysis.push_str("- Type: ELF executable (Linux)\n"),
            [0xfe, 0xed, 0xfa, 0xce] | [0xfe, 0xed, 0xfa, 0xcf] => analysis.push_str("- Type: Mach-O executable (macOS)\n"),
            [0x4d, 0x5a, _, _] => analysis.push_str("- Type: PE executable (Windows)\n"),
            _ => {
                // Check if it's all printable hex characters
                let is_hex = data.iter().all(|&b| b.is_ascii_hexdigit());
                if is_hex {
                    analysis.push_str("- Type: Hex-encoded data (likely cryptographic key)\n");
                } else {
                    analysis.push_str("- Type: Binary data (unknown format)\n");
                }
            }
        }
    }
    
    // Check entropy/randomness
    let mut byte_counts = [0u32; 256];
    for &byte in data {
        byte_counts[byte as usize] += 1;
    }
    
    let entropy = calculate_entropy(&byte_counts, data.len());
    analysis.push_str(&format!("- Entropy: {:.2} (0=structured, 8=random)\n", entropy));
    
    // Check for common patterns
    if data.len() == 256 {
        analysis.push_str("- Size suggests: Possible 256-byte key or hash\n");
    } else if data.len() == 1568 {
        analysis.push_str("- Size suggests: Kyber1024 public key\n");
    } else if data.len() == 3168 {
        analysis.push_str("- Size suggests: Kyber1024 secret key\n");
    } else if data.len() == 1312 {
        analysis.push_str("- Size suggests: Dilithium2 public key\n");
    } else if data.len() == 2544 {
        analysis.push_str("- Size suggests: Dilithium2 secret key\n");
    } else if data.len() == 1952 {
        analysis.push_str("- Size suggests: Dilithium3 public key\n");
    } else if data.len() == 4000 {
        analysis.push_str("- Size suggests: Dilithium3 secret key\n");
    }
    
    // Sample data
    analysis.push_str(&format!("- First 16 bytes: {}\n", 
        data.iter().take(16).map(|b| format!("{:02x}", b)).collect::<String>()));
    analysis.push_str(&format!("- Last 16 bytes: {}\n", 
        data.iter().rev().take(16).rev().map(|b| format!("{:02x}", b)).collect::<String>()));
    
    analysis
}

fn calculate_entropy(counts: &[u32; 256], total: usize) -> f64 {
    let mut entropy = 0.0;
    for &count in counts {
        if count > 0 {
            let p = count as f64 / total as f64;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        println!("Usage: {} <binary_file> [binary_file2] ...", args[0]);
        println!("Example: {} kyber.bin dilithium.bin", args[0]);
        return;
    }
    
    for file_path in &args[1..] {
        println!("Processing: {}", file_path);
        
        // Try to read as raw binary first
        match fs::read(file_path) {
            Ok(raw_data) => {
                // Check if it's a hex file by trying to parse it
                if let Ok(hex_string) = std::str::from_utf8(&raw_data) {
                    if let Ok(decoded_data) = hex_to_bytes(hex_string.trim()) {
                        println!("Successfully decoded as hex data");
                        println!("{}", analyze_binary_type(&decoded_data, file_path));
                        
                        // Test cryptographic compatibility
                        test_crypto_compatibility(&decoded_data, file_path);
                    } else {
                        println!("Raw binary data (not hex-encoded)");
                        println!("{}", analyze_binary_type(&raw_data, file_path));
                    }
                } else {
                    println!("Raw binary data (not text)");
                    println!("{}", analyze_binary_type(&raw_data, file_path));
                }
            },
            Err(e) => {
                println!("Failed to read {}: {}", file_path, e);
            }
        }
        println!();
    }
}

fn test_crypto_compatibility(data: &[u8], _filename: &str) {
    println!("Cryptographic Compatibility Test:");
    
    // Test as Kyber public key
    match pqc_algo::kem::encapsulate(data) {
        Ok(_) => println!("  Valid as Kyber public key"),
        Err(_) => println!("  Invalid as Kyber public key"),
    }
    
    // Test as signature verification (we'd need a message and signature for full test)
    match pqc_algo::sign::verify(b"test message", data, data) {
        Ok(_) => println!("  Could be used for signature verification"),
        Err(_) => println!("  Invalid for signature verification"),
    }
    
    println!("  Recommendation: {} bytes suggests {}", 
        data.len(),
        match data.len() {
            256 => "custom key format or truncated key",
            1568 => "Kyber1024 public key",
            3168 => "Kyber1024 secret key", 
            1312 => "Dilithium2 public key",
            2544 => "Dilithium2 secret key",
            1952 => "Dilithium3 public key",
            4000 => "Dilithium3 secret key",
            _ => "unknown key format"
        }
    );
}