// ABOUTME: Main entry point for unified NIP-46 signer daemon
// ABOUTME: Handles all bunker URLs in a single process, routing requests to appropriate authorizations

use dotenv::dotenv;
use keycast_core::database::Database;
use keycast_core::encryption::file_key_manager::FileKeyManager;
use keycast_core::encryption::gcp_key_manager::GcpKeyManager;
use keycast_core::encryption::KeyManager;
use std::env;
use std::path::PathBuf;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

// Import the unified signer from signer_daemon module
mod signer_daemon;
use signer_daemon::UnifiedSigner;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n\n================================================");
    println!("🔑 Keycast Unified Signer Starting...");

    dotenv().ok();

    // Initialize tracing
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Set up database
    let root_dir = env!("CARGO_MANIFEST_DIR");
    let database_url = PathBuf::from(root_dir)
        .parent()
        .unwrap()
        .join("database/keycast.db");
    let database_migrations = PathBuf::from(root_dir)
        .parent()
        .unwrap()
        .join("database/migrations");

    let database = Database::new(database_url.clone(), database_migrations.clone()).await?;
    println!("✔︎ Database initialized");

    // Setup key manager
    let key_manager: Box<dyn KeyManager> =
        if env::var("USE_GCP_KMS").unwrap_or_else(|_| "false".to_string()) == "true" {
            tracing::info!("Using Google Cloud KMS for encryption");
            Box::new(GcpKeyManager::new().await?)
        } else {
            tracing::info!("Using file-based encryption");
            Box::new(FileKeyManager::new()?)
        };

    // Create and run unified signer
    let mut signer = UnifiedSigner::new(database.pool.clone(), key_manager).await?;
    signer.load_authorizations().await?;
    signer.connect_to_relays().await?;

    println!("🤙 Unified signer daemon ready, listening for NIP-46 requests");

    signer.run().await?;

    Ok(())
}
