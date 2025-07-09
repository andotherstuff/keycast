// ABOUTME: Simple test to verify Google Cloud KMS integration
// ABOUTME: Run with: cargo run --bin test-kms

use keycast_core::encryption::gcp_key_manager::GcpKeyManager;
use keycast_core::encryption::KeyManager;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables
    dotenv::dotenv().ok();

    println!("🔑 Testing Google Cloud KMS integration...");

    // Check if KMS is enabled
    let use_kms = env::var("USE_GCP_KMS").unwrap_or_else(|_| "false".to_string()) == "true";

    if !use_kms {
        println!("❌ USE_GCP_KMS is not set to true. Set it in .env file.");
        return Ok(());
    }

    println!("📋 Configuration:");
    println!(
        "   Project: {}",
        env::var("GCP_PROJECT_ID").unwrap_or_else(|_| "not set".to_string())
    );
    println!(
        "   Location: {}",
        env::var("GCP_KMS_LOCATION").unwrap_or_else(|_| "global".to_string())
    );
    println!(
        "   Key Ring: {}",
        env::var("GCP_KMS_KEY_RING").unwrap_or_else(|_| "keycast-keys".to_string())
    );
    println!(
        "   Key Name: {}",
        env::var("GCP_KMS_KEY_NAME").unwrap_or_else(|_| "master-key".to_string())
    );

    // Initialize KMS manager
    println!("🔐 Initializing Google Cloud KMS manager...");
    let kms_manager = GcpKeyManager::new().await?;
    println!("✅ KMS manager initialized successfully!");

    // Test encrypt/decrypt
    let test_data = b"Hello, OpenVine! This is a test of Google Cloud KMS integration.";
    println!(
        "🔒 Testing encryption with {} bytes of data...",
        test_data.len()
    );

    let encrypted = kms_manager.encrypt(test_data).await?;
    println!(
        "✅ Encryption successful! Encrypted size: {} bytes",
        encrypted.len()
    );

    println!("🔓 Testing decryption...");
    let decrypted = kms_manager.decrypt(&encrypted).await?;
    println!(
        "✅ Decryption successful! Decrypted size: {} bytes",
        decrypted.len()
    );

    // Verify data integrity
    if test_data == decrypted.as_slice() {
        println!("✅ Data integrity verified! Original and decrypted data match.");
    } else {
        println!("❌ Data integrity check failed! Data corruption detected.");
        return Err("Data integrity check failed".into());
    }

    println!("🎉 Google Cloud KMS integration test completed successfully!");
    println!("🚀 Keycast is ready to use Google Cloud KMS for the openvine-co project!");

    Ok(())
}
