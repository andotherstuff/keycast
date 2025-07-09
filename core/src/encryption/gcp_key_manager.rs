// ABOUTME: Google Cloud KMS key manager implementation for secure key encryption
// ABOUTME: Uses envelope encryption pattern with KMS for data encryption keys

use super::{KeyManager, KeyManagerError};
use async_trait::async_trait;
use google_cloud_kms::client::{Client, ClientConfig};
use google_cloud_kms::grpc::kms::v1::{DecryptRequest, EncryptRequest};
use std::env;
use tracing::{debug, error, info};

pub struct GcpKeyManager {
    client: Client,
    key_name: String,
}

impl GcpKeyManager {
    pub async fn new() -> Result<Self, KeyManagerError> {
        let project_id = env::var("GCP_PROJECT_ID").map_err(|_| {
            KeyManagerError::ConfigurationError("GCP_PROJECT_ID not set".to_string())
        })?;

        let location = env::var("GCP_KMS_LOCATION").unwrap_or_else(|_| "global".to_string());

        let key_ring = env::var("GCP_KMS_KEY_RING").unwrap_or_else(|_| "keycast-keys".to_string());

        let key_name = env::var("GCP_KMS_KEY_NAME").unwrap_or_else(|_| "master-key".to_string());

        info!("Initializing Google Cloud KMS client");
        debug!(
            "Project: {}, Location: {}, Key Ring: {}, Key: {}",
            project_id, location, key_ring, key_name
        );

        let config = ClientConfig::default()
            .with_auth()
            .await
            .map_err(|e| KeyManagerError::ConfigurationError(format!("GCP auth failed: {}", e)))?;

        let client = Client::new(config).await.map_err(|e| {
            KeyManagerError::ConfigurationError(format!("GCP client creation failed: {}", e))
        })?;

        let full_key_name = format!(
            "projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}",
            project_id, location, key_ring, key_name
        );

        info!("Google Cloud KMS client initialized successfully");

        Ok(Self {
            client,
            key_name: full_key_name,
        })
    }
}

#[async_trait]
impl KeyManager for GcpKeyManager {
    async fn encrypt(&self, plaintext_bytes: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        debug!(
            "Encrypting {} bytes with Google Cloud KMS",
            plaintext_bytes.len()
        );

        let request = EncryptRequest {
            name: self.key_name.clone(),
            plaintext: plaintext_bytes.to_vec(),
            additional_authenticated_data: vec![],
            plaintext_crc32c: None,
            additional_authenticated_data_crc32c: None,
        };

        let response = self.client.encrypt(request, None).await.map_err(|e| {
            error!("Google Cloud KMS encryption failed: {}", e);
            KeyManagerError::EncryptionError(format!("KMS encryption failed: {}", e))
        })?;

        let ciphertext = response.ciphertext;
        debug!("Successfully encrypted to {} bytes", ciphertext.len());

        Ok(ciphertext)
    }

    async fn decrypt(&self, ciphertext_bytes: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        debug!(
            "Decrypting {} bytes with Google Cloud KMS",
            ciphertext_bytes.len()
        );

        let request = DecryptRequest {
            name: self.key_name.clone(),
            ciphertext: ciphertext_bytes.to_vec(),
            additional_authenticated_data: vec![],
            ciphertext_crc32c: None,
            additional_authenticated_data_crc32c: None,
        };

        let response = self.client.decrypt(request, None).await.map_err(|e| {
            error!("Google Cloud KMS decryption failed: {}", e);
            KeyManagerError::DecryptionError(format!("KMS decryption failed: {}", e))
        })?;

        let plaintext = response.plaintext;
        debug!("Successfully decrypted to {} bytes", plaintext.len());

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip() {
        // Skip test if GCP credentials not available
        if env::var("GCP_PROJECT_ID").is_err() {
            return;
        }

        let manager = GcpKeyManager::new()
            .await
            .expect("Failed to create GCP key manager");
        let plaintext = b"test data for encryption";

        let ciphertext = manager.encrypt(plaintext).await.expect("Encryption failed");
        let decrypted = manager
            .decrypt(&ciphertext)
            .await
            .expect("Decryption failed");

        assert_eq!(plaintext, decrypted.as_slice());
    }
}
