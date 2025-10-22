use keycast_core::encryption::KeyManager;
use keycast_core::signing_handler::SigningHandler;
use once_cell::sync::OnceCell;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Error, Debug)]
pub enum StateError {
    #[error("Database not initialized")]
    DatabaseNotInitialized,
    #[error("Key manager not initialized")]
    KeyManagerNotInitialized,
}

pub struct KeycastState {
    pub db: SqlitePool,
    pub key_manager: Arc<Box<dyn KeyManager>>,
    /// Optional signer handlers for unified mode
    /// Maps bunker_public_key -> SigningHandler trait object
    pub signer_handlers: Option<Arc<RwLock<HashMap<String, Arc<dyn SigningHandler>>>>>,
}

pub static KEYCAST_STATE: OnceCell<Arc<KeycastState>> = OnceCell::new();

pub fn get_db_pool() -> Result<&'static SqlitePool, StateError> {
    KEYCAST_STATE
        .get()
        .map(|state| &state.db)
        .ok_or(StateError::DatabaseNotInitialized)
}

pub fn get_key_manager() -> Result<&'static dyn KeyManager, StateError> {
    KEYCAST_STATE
        .get()
        .map(|state| state.key_manager.as_ref().as_ref())
        .ok_or(StateError::KeyManagerNotInitialized)
}

pub fn get_keycast_state() -> Result<&'static Arc<KeycastState>, StateError> {
    KEYCAST_STATE
        .get()
        .ok_or(StateError::DatabaseNotInitialized)
}
