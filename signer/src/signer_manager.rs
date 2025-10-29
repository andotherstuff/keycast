use keycast_core::types::authorization::{Authorization, AuthorizationError};
use keycast_core::types::oauth_authorization::OAuthAuthorization;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

#[derive(Error, Debug)]
pub enum SignerManagerError {
    #[error("Failed to get authorizations")]
    Authorizations(#[from] AuthorizationError),
    #[error("Failed to spawn signing daemon")]
    Spawn,
    #[error("Failed to shutdown signing daemon")]
    Shutdown,
    #[error("Failed to get process")]
    GetProcess(#[from] std::io::Error),
    #[error("Failed to get environment variable")]
    EnvVar(#[from] std::env::VarError),
    #[error("Failed to find signing_daemon binary")]
    SigningDaemonBinary,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AuthorizationType {
    Regular,
    OAuth,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthorizationKey {
    pub id: u32,
    pub auth_type: AuthorizationType,
}

#[derive(Debug, Clone)]
pub struct SignerManager {
    database_url: String,
    pub pool: PgPool,
    process_check_interval_seconds: u64,
    signer_processes: Arc<Mutex<HashMap<AuthorizationKey, Child>>>, // (auth_id, type) -> process
}

impl SignerManager {
    pub fn new(
        database_url: String,
        pool: PgPool,
        process_check_interval_seconds: u64,
    ) -> Self {
        Self {
            database_url,
            pool,
            process_check_interval_seconds,
            signer_processes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn run(&mut self) -> Result<(), SignerManagerError> {
        // Get all regular authorizations
        let regular_auth_ids = Authorization::all_ids(&self.pool).await?;
        // Get all OAuth authorizations
        let oauth_auth_ids = OAuthAuthorization::all_ids(&self.pool).await?;

        tracing::debug!(
            target: "keycast_signer::signer_manager",
            "Starting signer processes for {} regular + {} OAuth authorizations",
            regular_auth_ids.len(),
            oauth_auth_ids.len()
        );

        let mut failed = Vec::new();

        // Spawn regular authorization processes
        for auth_id in &regular_auth_ids {
            let key = AuthorizationKey {
                id: *auth_id,
                auth_type: AuthorizationType::Regular,
            };
            match self.spawn_signer_process(key.clone()).await {
                Ok(_) => (),
                Err(e) => {
                    failed.push(key);
                    tracing::error!(
                        target: "keycast_signer::signer_manager",
                        "Failed to start regular signer process for authorization {}: {}",
                        auth_id,
                        e
                    );
                }
            }
        }

        // Spawn OAuth authorization processes
        for auth_id in &oauth_auth_ids {
            let key = AuthorizationKey {
                id: *auth_id,
                auth_type: AuthorizationType::OAuth,
            };
            match self.spawn_signer_process(key.clone()).await {
                Ok(_) => (),
                Err(e) => {
                    failed.push(key);
                    tracing::error!(
                        target: "keycast_signer::signer_manager",
                        "Failed to start OAuth signer process for authorization {}: {}",
                        auth_id,
                        e
                    );
                }
            }
        }

        tracing::debug!(
            "Started signer processes for {} authorizations",
            regular_auth_ids.len() + oauth_auth_ids.len()
        );
        if !failed.is_empty() {
            tracing::warn!(
                target: "keycast_signer::signer_manager",
                "Failed to start signer processes for {} authorizations",
                failed.len()
            );
        }

        // Add process monitoring loop
        let interval = tokio::time::Duration::from_secs(self.process_check_interval_seconds);
        let mut interval_timer = tokio::time::interval(interval);

        loop {
            interval_timer.tick().await;
            if let Err(e) = self.healthcheck().await {
                tracing::error!(target: "keycast_signer::signer_manager", "Error checking health: {}", e);
            }
        }
    }

    /// Shutdown all signer processes
    pub async fn shutdown(&mut self) -> Result<(), SignerManagerError> {
        let auth_keys: Vec<AuthorizationKey> = self.signer_processes.lock().await.keys().cloned().collect();
        for auth_key in auth_keys {
            self.shutdown_signer_process(&auth_key).await?;
        }
        Ok(())
    }

    async fn spawn_signer_process(&mut self, auth_key: AuthorizationKey) -> Result<(), SignerManagerError> {
        // Try multiple possible locations for the binary
        let possible_paths = vec![
            // Same directory as current executable
            std::env::current_exe()?
                .parent()
                .ok_or(SignerManagerError::Spawn)?
                .join("signer_daemon"),
            // Current working directory
            std::env::current_dir()?.join("signer_daemon"),
            // Try with .exe extension on Windows
            #[cfg(windows)]
            std::env::current_exe()?
                .parent()
                .ok_or(SignerManagerError::Spawn)?
                .join("signer_daemon.exe"),
        ];

        let binary_path = possible_paths
            .into_iter()
            .find(|path| path.exists())
            .ok_or(SignerManagerError::SigningDaemonBinary)?;

        let auth_type_str = match auth_key.auth_type {
            AuthorizationType::Regular => "regular",
            AuthorizationType::OAuth => "oauth",
        };

        tracing::info!(
            target: "keycast_signer::signer_manager",
            "Starting {} signer process for authorization {} using binary at {:?}",
            auth_type_str,
            auth_key.id,
            binary_path
        );

        // Get master key path from environment, defaulting to /app/master.key if not set
        let master_key_path =
            std::env::var("MASTER_KEY_PATH").unwrap_or_else(|_| "/app/master.key".to_string());

        let child = Command::new(binary_path)
            .env("AUTH_ID", auth_key.id.to_string())
            .env("AUTH_TYPE", auth_type_str)
            .env("DATABASE_URL", self.database_url.clone())
            .env("MASTER_KEY_PATH", master_key_path)
            .spawn()
            .map_err(|_| SignerManagerError::Spawn)?;

        {
            let mut processes = self.signer_processes.lock().await;
            processes.insert(auth_key, child);
        }
        Ok(())
    }

    async fn shutdown_signer_process(&mut self, auth_key: &AuthorizationKey) -> Result<(), SignerManagerError> {
        let mut processes = self.signer_processes.lock().await;
        if let Some(mut child) = processes.remove(auth_key) {
            child
                .kill()
                .await
                .map_err(|_| SignerManagerError::Shutdown)?;
            child
                .wait()
                .await
                .map_err(|_| SignerManagerError::Shutdown)?;
        }
        Ok(())
    }

    pub async fn healthcheck(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        tracing::info!(target: "keycast_signer::signer_manager", "Running healthcheck...");
        // First sync with the database to get the current set of authorizations
        self.sync_with_database().await?;

        // Then check for any dead processes and restart them
        self.check_and_restart_processes().await?;

        Ok(())
    }

    pub async fn check_and_restart_processes(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // First, check for dead processes and restart them
        let mut processes = self.signer_processes.lock().await;
        let keys_to_restart: Vec<AuthorizationKey> = processes
            .iter_mut()
            .filter_map(|(key, process)| {
                match process.try_wait() {
                    Ok(Some(_)) => Some(key.clone()),
                    Ok(None) => None,
                    Err(e) => {
                        tracing::error!(target: "keycast_signer::signer_manager", "Error checking process for key {:?}: {}", key, e);
                        Some(key.clone())
                    }
                }
            })
            .collect();

        // Remove the dead processes
        for key in &keys_to_restart {
            processes.remove(key);
        }
        drop(processes);

        // Restart the dead processes
        for key in keys_to_restart {
            tracing::info!(target: "keycast_signer::signer_manager", "Restarting signer process for key: {:?}", key);
            self.spawn_signer_process(key).await?;
        }

        Ok(())
    }

    async fn sync_with_database(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Get current authorization IDs from database
        let regular_auth_ids = Authorization::all_ids(&self.pool).await?;
        let oauth_auth_ids = OAuthAuthorization::all_ids(&self.pool).await?;

        // Convert to AuthorizationKeys
        let mut db_auth_keys: Vec<AuthorizationKey> = Vec::new();
        for id in regular_auth_ids {
            db_auth_keys.push(AuthorizationKey {
                id,
                auth_type: AuthorizationType::Regular,
            });
        }
        for id in oauth_auth_ids {
            db_auth_keys.push(AuthorizationKey {
                id,
                auth_type: AuthorizationType::OAuth,
            });
        }

        let current_processes = self.signer_processes.lock().await;

        // Find authorizations that need new processes
        let new_auths: Vec<AuthorizationKey> = db_auth_keys
            .iter()
            .filter(|key| !current_processes.contains_key(key))
            .cloned()
            .collect();

        // Find processes that need to be shut down
        let to_remove: Vec<AuthorizationKey> = current_processes
            .keys()
            .filter(|key| !db_auth_keys.contains(key))
            .cloned()
            .collect();

        drop(current_processes);

        // Start new processes
        for auth_key in new_auths {
            tracing::info!(target: "keycast_signer::signer_manager", "Starting signer process for new authorization: {:?}", auth_key);
            self.spawn_signer_process(auth_key).await?;
        }

        // Shutdown removed processes
        for auth_key in to_remove {
            tracing::info!(target: "keycast_signer::signer_manager", "Shutting down signer process for removed authorization: {:?}", auth_key);
            self.shutdown_signer_process(&auth_key).await?;
        }

        Ok(())
    }
}
