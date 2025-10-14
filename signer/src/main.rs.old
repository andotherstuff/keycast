mod signer_manager;

use config::{Config, File};
use keycast_core::database::Database;
use nostr_connect::prelude::*;
use signer_manager::SignerManager;
use std::path::PathBuf;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n\n================================================");
    println!("🔑 Keycast Signer Starting...");

    // Load config
    let root_dir = env!("CARGO_MANIFEST_DIR");
    let config_path = PathBuf::from(root_dir).join("config.toml");

    let config = Config::builder()
        .add_source(File::from(config_path))
        .build()
        .unwrap();

    let process_check_interval_seconds =
        config.get::<u64>("process_check_interval_seconds").unwrap();

    println!("✔︎ Config loaded");
    println!("Process check interval: {}", process_check_interval_seconds);

    // Initialize tracing with debug level
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Set up database
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

    let mut manager = SignerManager::new(
        database_url.to_string_lossy().to_string(),
        database.pool.clone(),
        process_check_interval_seconds,
    );
    println!("✔︎ Signer manager initialized");

    // Setup shutdown signal handler
    let database_clone = database.clone();
    let mut manager_clone = manager.clone();
    tokio::spawn(async move {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {
                println!("\n\n================================================");
                println!("🫡 Shutdown signal received, cleaning up...");
                manager_clone
                    .shutdown()
                    .await
                    .expect("Failed to shutdown signer manager");
                println!("✔︎ Keycast Signer manager shutdown complete");
                let pool = database_clone.pool;
                pool.close().await;
                println!("✔︎ Database pool closed");
                println!("🤙 Pura Vida!");
                println!("================================================");
                std::process::exit(0);
            }
            Err(err) => {
                eprintln!("Error: {}", err);
                std::process::exit(1);
            }
        }
    });

    println!("🤙 Keycast Signer manager started");
    // This will block and keep the main process running because of the process monitoring loop
    manager.run().await?;

    Ok(())
}
