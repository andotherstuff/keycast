// ABOUTME: Unified binary that runs both API server and Signer daemon in one process
// ABOUTME: Shares AuthorizationHandler state between HTTP endpoints and NIP-46 signer for optimal performance

use dotenv::dotenv;
use keycast_core::database::Database;
use keycast_core::encryption::file_key_manager::FileKeyManager;
use keycast_core::encryption::gcp_key_manager::GcpKeyManager;
use keycast_core::encryption::KeyManager;
use keycast_signer::UnifiedSigner;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n================================================");
    println!("🔑 Keycast Unified Service Starting...");
    println!("   Running API + Signer in single process");
    println!("================================================\n");

    dotenv().ok();

    // Initialize tracing
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Setup database
    let root_dir = env!("CARGO_MANIFEST_DIR");
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
    tracing::info!("✔︎ Database initialized at {:?}", database_url);

    // Setup key managers (one for signer, one for API - they're cheap to create)
    let use_gcp_kms = env::var("USE_GCP_KMS").unwrap_or_else(|_| "false".to_string()) == "true";

    let signer_key_manager: Box<dyn KeyManager> = if use_gcp_kms {
        tracing::info!("Using Google Cloud KMS for encryption");
        Box::new(GcpKeyManager::new().await?)
    } else {
        tracing::info!("Using file-based encryption");
        Box::new(FileKeyManager::new()?)
    };

    let api_key_manager: Box<dyn KeyManager> = if use_gcp_kms {
        Box::new(GcpKeyManager::new().await?)
    } else {
        Box::new(FileKeyManager::new()?)
    };

    // Create signer and load all authorizations into memory
    let mut signer = UnifiedSigner::new(database.pool.clone(), signer_key_manager).await?;
    signer.load_authorizations().await?;
    signer.connect_to_relays().await?;
    tracing::info!("✔︎ Signer daemon initialized and connected to relays");

    // Get shared handlers for API (converted to trait objects)
    let signer_handlers = signer.handlers_as_trait_objects().await;

    // Create API state with shared signer handlers
    let api_state = Arc::new(keycast_api::state::KeycastState {
        db: database.pool.clone(),
        key_manager: Arc::new(api_key_manager),
        signer_handlers: Some(signer_handlers),
    });

    // Set global state for routes that use it
    keycast_api::state::KEYCAST_STATE.set(api_state.clone()).ok();

    // Get API port (default 3000)
    let api_port = env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse::<u16>()
        .unwrap_or(3000);

    // Build API router with health check
    use axum::{Router, routing::get, http::StatusCode, response::IntoResponse};

    async fn health_check() -> impl IntoResponse {
        StatusCode::OK
    }

    let api_routes = keycast_api::api::http::routes::routes(database.pool.clone(), api_state.clone());
    let app = Router::new()
        .route("/health", get(health_check))
        .merge(api_routes);

    let api_addr = std::net::SocketAddr::from(([0, 0, 0, 0], api_port));
    tracing::info!("✔︎ API server ready on {}", api_addr);

    // Spawn API server task
    let api_handle = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(api_addr).await.unwrap();
        tracing::info!("🌐 API server listening on {}", api_addr);
        axum::serve(listener, app).await.unwrap();
    });

    // Spawn Signer daemon task
    let signer_handle = tokio::spawn(async move {
        tracing::info!("🤙 Signer daemon ready, listening for NIP-46 requests");
        signer.run().await.unwrap();
    });

    println!("✨ Unified service running!");
    println!("   API: http://0.0.0.0:{}", api_port);
    println!("   Signer: NIP-46 relay listener active");
    println!("   Shared state: AuthorizationHandlers cached\n");

    // Wait for either task to complete (they shouldn't unless there's an error)
    tokio::select! {
        result = api_handle => {
            tracing::error!("API server exited: {:?}", result);
        }
        result = signer_handle => {
            tracing::error!("Signer daemon exited: {:?}", result);
        }
    }

    Ok(())
}
