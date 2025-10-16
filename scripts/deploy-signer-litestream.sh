#!/bin/bash
set -e

# Keycast Signer Litestream Deployment Script
# This script deploys the NIP-46 signer daemon with Litestream for persistent SQLite

PROJECT_ID=$(gcloud config get-value project)
REGION="us-central1"
SERVICE_NAME="keycast-signer"
BUCKET_NAME="keycast-database-backups"
IMAGE_URL="us-central1-docker.pkg.dev/${PROJECT_ID}/docker/keycast:latest"

echo "================================================"
echo "🔑 Keycast Signer Litestream Deployment"
echo "================================================"
echo "Project: $PROJECT_ID"
echo "Region: $REGION"
echo "Service: $SERVICE_NAME"
echo "Bucket: $BUCKET_NAME (shared with API)"
echo ""

# Step 1: Verify GCS bucket exists (should be created by API deployment)
echo "📦 Verifying GCS bucket for database backups..."
if gsutil ls gs://$BUCKET_NAME 2>/dev/null; then
    echo "✅ Bucket gs://$BUCKET_NAME exists"
else
    echo "❌ ERROR: Bucket gs://$BUCKET_NAME does not exist!"
    echo "   Run ./scripts/deploy-litestream.sh first to deploy the API and create the bucket."
    exit 1
fi

# Step 2: Get Cloud Run service account
echo ""
echo "🔐 Configuring service account permissions..."
SERVICE_ACCOUNT="${PROJECT_ID}@appspot.gserviceaccount.com"
echo "Service Account: $SERVICE_ACCOUNT"

# Grant bucket access to service account (may already exist from API deployment)
gsutil iam ch serviceAccount:$SERVICE_ACCOUNT:roles/storage.objectAdmin gs://$BUCKET_NAME 2>/dev/null || true
echo "✅ Granted storage.objectAdmin to service account"

# Grant Secret Manager access for all required secrets
echo ""
echo "🔐 Granting Secret Manager access to service account..."
for SECRET in keycast-gcp-project keycast-master-key litestream-config; do
    if gcloud secrets describe $SECRET --project=$PROJECT_ID 2>/dev/null; then
        gcloud secrets add-iam-policy-binding $SECRET \
            --member="serviceAccount:$SERVICE_ACCOUNT" \
            --role="roles/secretmanager.secretAccessor" \
            --project=$PROJECT_ID >/dev/null 2>&1 || true
        echo "  ✅ $SECRET"
    else
        echo "  ⚠️  $SECRET (secret doesn't exist yet)"
    fi
done
echo "✅ Secret Manager permissions granted"

# Step 3: Grant KMS permissions for encryption/decryption
echo ""
echo "🔑 Granting KMS permissions..."
gcloud kms keys add-iam-policy-binding master-key \
    --keyring=keycast-keys \
    --location=global \
    --member="serviceAccount:$SERVICE_ACCOUNT" \
    --role="roles/cloudkms.cryptoKeyEncrypterDecrypter" \
    --project=$PROJECT_ID >/dev/null 2>&1 || true
echo "✅ KMS permissions granted"

# Step 4: Update signer-service.yaml with actual values
echo ""
echo "📝 Preparing signer service configuration..."
sed -e "s|IMAGE_URL|$IMAGE_URL|g" \
    -e "s|PROJECT_ID@appspot.gserviceaccount.com|$SERVICE_ACCOUNT|g" \
    signer-service.yaml > signer-service-deploy.yaml
echo "✅ Signer service config prepared"

# Step 5: Deploy to Cloud Run
echo ""
echo "🚀 Deploying signer to Cloud Run..."
gcloud run services replace signer-service-deploy.yaml \
    --region=$REGION \
    --project=$PROJECT_ID

# Step 6: Update service constraints (single instance for SQLite)
echo ""
echo "⚙️  Configuring scaling limits..."
echo "Note: min-instances=1 keeps warm instance (continuous relay connection)"
echo "      This ensures the signer daemon is always listening for NIP-46 requests."
gcloud run services update $SERVICE_NAME \
    --region=$REGION \
    --project=$PROJECT_ID \
    --max-instances=1 \
    --min-instances=1 \
    --cpu=1 \
    --memory=1Gi

echo ""
echo "================================================"
echo "✅ Signer Deployment Complete!"
echo "================================================"
echo ""
echo "Service URL: https://$SERVICE_NAME-$(gcloud run services describe $SERVICE_NAME --region=$REGION --format='value(status.url)' | cut -d'/' -f3 | cut -d'-' -f2-)"
echo ""
echo "📊 Check deployment status:"
echo "  gcloud run services describe $SERVICE_NAME --region=$REGION"
echo ""
echo "📝 View logs:"
echo "  gcloud run services logs read $SERVICE_NAME --region=$REGION --limit=50"
echo ""
echo "🔍 Verify signer is processing events:"
echo "  gcloud run services logs read $SERVICE_NAME --region=$REGION --limit=50 | grep -i 'authorizations\\|nip-46'"
echo ""
echo "================================================"
