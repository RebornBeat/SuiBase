//! SuiStack0X TEE Framework CLI Entry Point

use std::env;
use std::process;
use tee::check_tee_support;
use tee::cli;
use tee::init;

#[tokio::main]
async fn main() {
    // Initialize the TEE framework
    if let Err(e) = init() {
        eprintln!("Initialization error: {}", e);
        process::exit(1);
    }

    // Check TEE platform support
    match check_tee_support() {
        Ok(platforms) => {
            println!("Supported TEE Platforms:");
            for platform in platforms {
                println!("- {}", platform);
            }
        }
        Err(e) => {
            eprintln!("Error checking TEE support: {}", e);
            process::exit(1);
        }
    }

    // Parse and execute CLI commands
    let args: Vec<String> = env::args().collect();
    if let Err(e) = cli::run(&args).await {
        eprintln!("CLI Error: {}", e);
        process::exit(1);
    }
}
