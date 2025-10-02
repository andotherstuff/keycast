mod api;
mod state;

use crate::state::{get_db_pool, KeycastState, KEYCAST_STATE};
use axum::{
    http::{HeaderValue, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use dotenv::dotenv;
use keycast_core::database::Database;
use keycast_core::encryption::file_key_manager::FileKeyManager;
use keycast_core::encryption::gcp_key_manager::GcpKeyManager;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n\n================================================");
    println!("🔑 Keycast API Starting...");

    // Load environment variables
    dotenv().ok();

    // Initialize tracing with JSON format for production
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let is_production = env::var("NODE_ENV").unwrap_or_default() == "production"
        || env::var("RUST_ENV").unwrap_or_default() == "production";

    if is_production {
        // JSON logging for production (Cloud Logging compatibility)
        tracing_subscriber::registry()
            .with(env_filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_target(true)
                    .with_current_span(true)
                    .with_span_list(true)
            )
            .init();
        eprintln!("✔︎ Structured JSON logging enabled (production mode)");
    } else {
        // Human-readable logging for development
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
        println!("✔︎ Human-readable logging enabled (development mode)");
    }

    // Setup shutdown signal handler
    tokio::spawn(async {
        match signal::ctrl_c().await {
            Ok(()) => {
                println!("\n\n================================================");
                println!("🫡 Shutdown signal received, cleaning up...");
                println!("✔︎ API shutdown complete");
                if let Ok(pool) = get_db_pool() {
                    pool.close().await;
                }
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

    // Setup key manager based on environment
    let key_manager: Box<dyn keycast_core::encryption::KeyManager> =
        if env::var("USE_GCP_KMS").unwrap_or_else(|_| "false".to_string()) == "true" {
            println!("🔑 Using Google Cloud KMS for encryption");
            Box::new(
                GcpKeyManager::new()
                    .await
                    .expect("Failed to create GCP key manager"),
            )
        } else {
            println!("🔑 Using file-based encryption");
            Box::new(FileKeyManager::new().expect("Failed to create file key manager"))
        };
    println!("✔︎ Encryption key manager initialized");

    // Create a shared state with the database and key manager
    let state = Arc::new(KeycastState {
        db: database.pool,
        key_manager,
    });

    // Set the shared state in the once cell
    KEYCAST_STATE
        .set(state)
        .map_err(|_| "Failed to set KeycastState")?;

    // Start up the API with permissive CORS for embeddable auth flows
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_credentials(false);

    println!("✔︎ CORS configured to allow all origins (embeddable auth)");

    let app = Router::new()
        .route("/health", get(health_check))
        .nest("/api", api::http::routes(get_db_pool().unwrap().clone()))
        .layer(TraceLayer::new_for_http())
        .layer(cors);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("✔︎ API listening on {}", listener.local_addr().unwrap());
    println!("🤙 Keycast API ready! LFG!");
    println!("================================================");

    axum::serve(listener, app).await.unwrap();

    Ok(())
}

async fn health_check() -> impl IntoResponse {
    StatusCode::OK
}
