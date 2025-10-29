use std::fs;
use std::path::Path;
use crate::error::{PqcError, Result};

/// Load Kyber key data from a binary file
pub fn load_kyber_binary(file_path: &str) -> Result<Vec<u8>> {
    if !Path::new(file_path).exists() {
        return Err(PqcError::Io(format!("File not found: {}", file_path)));
    }
    
    let hex_content = fs::read_to_string(file_path)
        .map_err(|e| PqcError::Io(format!("Failed to read file: {}", e)))?;
    
    // Remove any whitespace/newlines
    let hex_content = hex_content.trim();
    
    // Convert hex string to bytes
    hex_to_bytes(hex_content)
}

/// Convert hex string to bytes
pub fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>> {
    let cleaned = hex_str.trim();
    
    if cleaned.len() % 2 != 0 {
        return Err(PqcError::InvalidKey("Hex string must have even length".to_string()));
    }
    
    let mut bytes = Vec::new();
    for i in (0..cleaned.len()).step_by(2) {
        let hex_pair = &cleaned[i..i+2];
        let byte = u8::from_str_radix(hex_pair, 16)
            .map_err(|_| PqcError::InvalidKey(format!("Invalid hex pair: {}", hex_pair)))?;
        bytes.push(byte);
    }
    
    Ok(bytes)
}

/// Analyze the loaded Kyber binary data
pub fn analyze_kyber_data(data: &[u8]) -> String {
    let mut analysis = String::new();
    
    analysis.push_str(&format!("Kyber Binary Analysis:\n"));
    analysis.push_str(&format!("- Data size: {} bytes\n", data.len()));
    analysis.push_str(&format!("- First 32 bytes (hex): {}\n", 
        data.iter().take(32).map(|b| format!("{:02x}", b)).collect::<String>()));
    analysis.push_str(&format!("- Last 32 bytes (hex): {}\n", 
        data.iter().rev().take(32).rev().map(|b| format!("{:02x}", b)).collect::<String>()));
    
    // Check if it's a valid Kyber key size
    match data.len() {
        1568 => analysis.push_str("- Matches Kyber1024 public key size\n"),
        3168 => analysis.push_str("- Matches Kyber1024 secret key size\n"),
        800 => analysis.push_str("- Matches Kyber512 public key size\n"),
        1632 => analysis.push_str("- Matches Kyber512 secret key size\n"),
        1184 => analysis.push_str("- Matches Kyber768 public key size\n"),
        2400 => analysis.push_str("- Matches Kyber768 secret key size\n"),
        256 => analysis.push_str("- Matches 256-byte data (custom format?)\n"),
        _ => analysis.push_str(&format!("- Non-standard size for Kyber keys\n")),
    }
    
    analysis
}

/// Test if the binary data can be used as a Kyber key
pub fn test_kyber_binary_compatibility(data: &[u8]) -> Result<String> {
    let mut result = String::new();
    
    result.push_str(&analyze_kyber_data(data));
    result.push_str("\nCompatibility Test:\n");
    
    // Try to use as public key for encapsulation
    match crate::kem::encapsulate(data) {
        Ok((ciphertext, shared_secret)) => {
            result.push_str(&format!("Successfully used as Kyber public key!\n"));
            result.push_str(&format!("- Ciphertext size: {} bytes\n", ciphertext.len()));
            result.push_str(&format!("- Shared secret size: {} bytes\n", shared_secret.len()));
        },
        Err(e) => {
            result.push_str(&format!("Failed to use as Kyber public key: {}\n", e));
        }
    }
    
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_conversion() {
        let hex = "48656c6c6f";  // "Hello" in hex
        let bytes = hex_to_bytes(hex).unwrap();
        assert_eq!(bytes, b"Hello");
    }

    #[test]
    fn test_load_kyber_binary() {
        // This test will only work if kyber.bin exists
        if std::path::Path::new("kyber.bin").exists() {
            let data = load_kyber_binary("kyber.bin").unwrap();
            assert!(!data.is_empty());
            println!("{}", analyze_kyber_data(&data));
        }
    }
}