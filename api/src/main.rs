mod api;
mod state;
mod technical_docs;

use crate::state::{get_db_pool, KeycastState, KEYCAST_STATE};
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use tower_http::services::ServeDir;
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

    // Serve static test/example HTML files from examples directory
    let examples_path = PathBuf::from(root_dir)
        .parent()
        .unwrap()
        .join("examples");

    let app = Router::new()
        .route("/", get(landing_page))
        .route("/docs", get(technical_docs::technical_docs))
        .route("/health", get(health_check))
        .route("/.well-known/nostr.json", get(api::http::nostr_discovery_public))
        .nest("/api", api::http::routes(get_db_pool().unwrap().clone(), KEYCAST_STATE.get().unwrap().clone()))
        .nest_service("/examples", ServeDir::new(examples_path))
        .layer(TraceLayer::new_for_http())
        .layer(cors);

    println!("✔︎ Static files served from /examples");

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

async fn landing_page() -> Html<&'static str> {
    Html(r#"
<!DOCTYPE html>
<html>
<head>
    <title>Keycast - NIP-46 Remote Signing with OAuth 2.0</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            max-width: 900px; margin: 0 auto; padding: 20px;
            background: #1a1a1a; color: #e0e0e0;
            line-height: 1.6;
        }
        h1 { color: #bb86fc; margin-top: 20px; }
        h2 { color: #03dac6; margin-top: 40px; border-bottom: 1px solid #333; padding-bottom: 10px; }
        h3 { color: #03dac6; margin-top: 25px; font-size: 1.1em; }
        a { color: #03dac6; text-decoration: none; }
        a:hover { text-decoration: underline; }
        code { background: #2a2a2a; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }
        .intro { font-size: 1.1em; margin: 20px 0; }
        .highlight { background: #2a2a2a; padding: 15px; margin: 15px 0; border-radius: 8px; border-left: 3px solid #bb86fc; }
        .endpoint { background: #2a2a2a; padding: 12px; margin: 10px 0; border-radius: 5px; }
        .method { color: #bb86fc; font-weight: bold; font-family: monospace; }
        .test-links { background: #2a2a2a; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .test-links ul { margin: 10px 0; }
        .test-links li { margin: 8px 0; }
        .footer { margin-top: 60px; padding-top: 20px; border-top: 1px solid #333; font-size: 0.9em; color: #888; }
    </style>
</head>
<body>
    <h1>🔑 Keycast</h1>
    <p class="intro">
        <strong>Sign in to Nostr apps with just email and password</strong>
    </p>

    <div class="highlight" style="font-size: 1.05em;">
        <strong>What is Keycast?</strong><br>
        Keycast is a server that holds your Nostr identity and lets you sign in to any Nostr app - no setup required.
        <br><br>
        <strong>It works like this:</strong><br>
        1. Create an account with your email<br>
        2. When you want to use a Nostr app, click "Login with Keycast"<br>
        3. That's it! The app can now post and interact on your behalf
        <br><br>
        Your identity is stored encrypted on our servers, so you can access it from any device without copying keys or installing browser extensions.
        <strong>It's like having your Nostr account in the cloud.</strong>
    </div>

    <h2>🔐 How It Works (Like Bluesky)</h2>
    <p>
        Keycast works similarly to how Bluesky handles authentication - making decentralized social media accessible to everyone:
    </p>
    <p>
        <strong>1. Your keys are encrypted and stored securely</strong><br>
        When you register, we generate Nostr keys for you and encrypt them with Google Cloud KMS.
        Your keys never leave our secure servers unencrypted.
    </p>
    <p>
        <strong>2. Apps request permission to sign on your behalf</strong><br>
        When a Nostr app wants to post or interact as you, it requests authorization via OAuth 2.0
        (the same system used by "Login with Google"). You approve once, and the app can request signatures.
    </p>
    <p>
        <strong>3. Remote signing keeps your keys safe</strong><br>
        Apps send signing requests through Nostr relays using NIP-46. Our signer daemon receives these requests,
        signs events with your encrypted keys, and sends back the signed result. Apps never touch your private keys.
    </p>
    <p>
        <strong>4. Works everywhere - no extensions needed</strong><br>
        Because signing happens remotely, you can use the same identity across any device or browser.
        No copying keys, no browser extensions, no complicated setup. Just like Bluesky, but for the open Nostr protocol.
    </p>

    <h2>🆚 Keycast vs Traditional Nostr</h2>
    <div class="highlight">
        <strong>Traditional Nostr:</strong> Manage your own keys, install browser extensions (Alby, nos2x),
        manually copy keys between devices, risk losing keys = losing identity forever.<br><br>
        <strong>Keycast:</strong> Sign in with email/password anywhere, authorize apps with OAuth,
        keys encrypted and backed up on our servers, recovery possible, works on any device instantly.
    </div>

    <h2>⚠️ Trade-offs</h2>
    <p>
        <strong>Trust:</strong> You're trusting us to keep your encrypted keys secure. We use Google Cloud KMS for encryption,
        but this is still custodial - similar to how you trust Bluesky with your account.<br><br>
        <strong>Privacy:</strong> We can see which apps you authorize and when you sign events (but not the content of encrypted messages).<br><br>
        <strong>For maximum sovereignty:</strong> Use a local signer like Alby or nos2x where you control your keys directly.
        Keycast is for people who prioritize convenience and accessibility over absolute sovereignty.
    </p>

    <h2>🧪 Try It Now</h2>
    <div class="test-links">
        <p><strong>Live test clients on <a href="https://oauth.divine.video">oauth.divine.video</a>:</strong></p>
        <ul>
            <li><a href="https://oauth.divine.video/examples/keycast-test.html" target="_blank">Basic Keycast Test</a> - Test authentication and signing flow</li>
            <li><a href="https://oauth.divine.video/examples/oauth-test-client.html" target="_blank">OAuth Test Client</a> - Full OAuth 2.0 authorization flow</li>
            <li><a href="https://oauth.divine.video/examples/nostr-oauth-sign-test.html" target="_blank">OAuth Sign Test</a> - Test event signing with OAuth</li>
            <li><a href="https://oauth.divine.video/examples/nostr-login-test.html" target="_blank">Login Test</a> - Quick login flow test</li>
        </ul>
        <p style="margin-top: 15px; font-size: 0.95em; color: #aaa;">
            Or try them locally at <a href="/examples/keycast-test.html">/examples/</a>
        </p>
    </div>

    <h2>📡 API Endpoints</h2>

    <h3>Authentication</h3>
    <div class="endpoint">
        <span class="method">POST</span> <code>/api/auth/register</code><br>
        Create a new account with email and password. Returns a JWT token.
    </div>
    <div class="endpoint">
        <span class="method">POST</span> <code>/api/auth/login</code><br>
        Authenticate with existing credentials. Returns a JWT token.
    </div>
    <div class="endpoint">
        <span class="method">GET</span> <code>/api/user/bunker</code><br>
        Get your personal NIP-46 bunker:// URL (requires authentication).
    </div>

    <h3>OAuth 2.0 Flow</h3>
    <div class="endpoint">
        <span class="method">GET</span> <code>/api/oauth/authorize</code><br>
        Start OAuth authorization flow. Shows approval page for user consent.
    </div>
    <div class="endpoint">
        <span class="method">POST</span> <code>/api/oauth/authorize</code><br>
        User approves or denies the authorization request.
    </div>
    <div class="endpoint">
        <span class="method">POST</span> <code>/api/oauth/token</code><br>
        Exchange authorization code for a NIP-46 bunker:// URL and connection secret.
    </div>

    <h3>Nostr Discovery</h3>
    <div class="endpoint">
        <span class="method">GET</span> <code>/.well-known/nostr.json?name=username</code><br>
        NIP-05 identifier discovery endpoint.
    </div>

    <h2>🔗 Resources</h2>
    <ul>
        <li><a href="/docs"><strong>Technical Documentation</strong></a> - Deep dive into architecture, protocols, and security</li>
        <li><a href="https://github.com/nostr-protocol/nips/blob/master/46.md" target="_blank">NIP-46 Specification</a> - Remote signing protocol</li>
        <li><a href="https://github.com/nostr-protocol/nips/blob/master/05.md" target="_blank">NIP-05 Specification</a> - Nostr identifiers</li>
    </ul>

    <div class="footer">
        <p>Keycast is an open-source NIP-46 remote signer implementation with OAuth 2.0 flows.</p>
        <p>Running on relays: relay.damus.io, nos.lol, relay.nsec.app</p>
        <p><a href="/docs">Read the technical documentation</a> for implementers and developers.</p>
    </div>
</body>
</html>
    "#)
}
