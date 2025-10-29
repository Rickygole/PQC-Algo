use pqc_algo::binary_loader::{load_kyber_binary, test_kyber_binary_compatibility};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() != 2 {
        println!("Usage: {} <kyber_binary_file>", args[0]);
        println!("Example: {} kyber.bin", args[0]);
        return;
    }
    
    let file_path = &args[1];
    
    println!("Loading Kyber binary from: {}", file_path);
    
    match load_kyber_binary(file_path) {
        Ok(data) => {
            println!("\nSuccessfully loaded binary data!");
            
            match test_kyber_binary_compatibility(&data) {
                Ok(analysis) => {
                    println!("\n{}", analysis);
                },
                Err(e) => {
                    println!("\nAnalysis failed: {}", e);
                }
            }
        },
        Err(e) => {
            println!("\nFailed to load binary: {}", e);
        }
    }
}