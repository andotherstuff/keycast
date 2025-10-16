// ABOUTME: Main entry point for unified NIP-46 signer daemon with HTTP health endpoint
// ABOUTME: Handles all bunker URLs in a single process, routing requests to appropriate authorizations

use axum::{routing::get, Router};
use dotenv::dotenv;
use keycast_core::database::Database;
use keycast_core::encryption::file_key_manager::FileKeyManager;
use keycast_core::encryption::gcp_key_manager::GcpKeyManager;
use keycast_core::encryption::KeyManager;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

// Import the unified signer from signer_daemon module
mod signer_daemon;
use signer_daemon::UnifiedSigner;

// Health check endpoint handler
async fn health() -> &'static str {
    "OK"
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n\n================================================");
    println!("🔑 Keycast Unified Signer Starting...");

    dotenv().ok();

    // Check for existing pidfile to prevent multiple instances
    // Use SIGNER_PIDFILE env var if set, otherwise use local database directory
    let pidfile_path = if let Ok(custom_path) = env::var("SIGNER_PIDFILE") {
        PathBuf::from(custom_path)
    } else {
        let root_dir = env!("CARGO_MANIFEST_DIR");
        PathBuf::from(root_dir)
            .parent()
            .unwrap()
            .join("database/.signer.pid")
    };

    if pidfile_path.exists() {
        let existing_pid_str = fs::read_to_string(&pidfile_path)?;
        if let Ok(existing_pid) = existing_pid_str.trim().parse::<i32>() {
            // Check if process is still running
            if unsafe { libc::kill(existing_pid, 0) } == 0 {
                eprintln!("❌ ERROR: Another signer daemon is already running (PID: {})", existing_pid);
                eprintln!("   Pidfile: {}", pidfile_path.display());
                eprintln!("   Stop the existing daemon before starting a new one.");
                process::exit(1);
            } else {
                // Stale pidfile, remove it
                tracing::warn!("Found stale pidfile (PID {} not running), removing it", existing_pid);
                fs::remove_file(&pidfile_path).ok();
            }
        }
    }

    // Write our PID
    let our_pid = process::id();
    fs::write(&pidfile_path, our_pid.to_string())?;
    println!("✔︎ Pidfile created: {} (PID: {})", pidfile_path.display(), our_pid);

    // Register cleanup handler
    let pidfile_clone = pidfile_path.clone();
    ctrlc::set_handler(move || {
        println!("\n🛑 Received shutdown signal, cleaning up...");
        fs::remove_file(&pidfile_clone).ok();
        process::exit(0);
    })?;

    // Initialize tracing
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Set up database
    let root_dir = env!("CARGO_MANIFEST_DIR");

    // Support DATABASE_PATH env var for Litestream compatibility
    // Default to /data/keycast.db for Cloud Run, fallback to local path for dev
    let database_url = env::var("DATABASE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(root_dir)
                .parent()
                .unwrap()
                .join("database/keycast.db")
        });

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

    // Get port from environment or use default
    let port = env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .unwrap_or(8080);

    // Build HTTP router for health checks
    let app = Router::new().route("/health", get(health));

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    println!("🌐 HTTP health server listening on {}", addr);

    // Spawn HTTP server in background
    let http_server = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        axum::serve(listener, app).await.unwrap();
    });

    // Run NIP-46 signer (blocks forever)
    let signer_task = tokio::spawn(async move {
        signer.run().await.unwrap();
    });

    // Wait for either task to complete (they shouldn't unless there's an error)
    tokio::select! {
        res = http_server => {
            tracing::error!("HTTP server exited: {:?}", res);
        }
        res = signer_task => {
            tracing::error!("Signer task exited: {:?}", res);
        }
    }

    Ok(())
}
