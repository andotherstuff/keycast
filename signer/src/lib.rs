// ABOUTME: Library interface for the Keycast signer daemon
// ABOUTME: Exports signer_daemon module for use by binaries and tests

pub mod signer_daemon;

// Re-export main types for convenience
pub use signer_daemon::{AuthorizationHandler, UnifiedSigner};
