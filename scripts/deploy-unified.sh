#!/bin/bash
set -e

# Keycast Unified Service Deployment Script
# This script deploys API + Signer in a single Cloud Run service with Litestream

PROJECT_ID=$(gcloud config get-value project)
REGION="us-central1"
SERVICE_NAME="keycast-unified"
BUCKET_NAME="keycast-database-backups"
IMAGE_URL="us-central1-docker.pkg.dev/${PROJECT_ID}/docker/keycast:latest"

echo "================================================"
echo "🔑 Keycast Unified Service Deployment"
echo "================================================"
echo "Project: $PROJECT_ID"
echo "Region: $REGION"
echo "Service: $SERVICE_NAME (API + Signer in one container)"
echo "Bucket: $BUCKET_NAME"
echo ""

# Step 1: Verify/Create GCS bucket for Litestream backups
echo "📦 Verifying GCS bucket for database backups..."
if gsutil ls gs://$BUCKET_NAME 2>/dev/null; then
    echo "✅ Bucket gs://$BUCKET_NAME exists"
else
    echo "Creating bucket gs://$BUCKET_NAME..."
    gsutil mb -l $REGION gs://$BUCKET_NAME/
    echo "✅ Created bucket gs://$BUCKET_NAME"
fi

# Step 2: Get Cloud Run service account
echo ""
echo "🔐 Configuring service account permissions..."
SERVICE_ACCOUNT="${PROJECT_ID}@appspot.gserviceaccount.com"
echo "Service Account: $SERVICE_ACCOUNT"

# Grant bucket access to service account
gsutil iam ch serviceAccount:$SERVICE_ACCOUNT:roles/storage.objectAdmin gs://$BUCKET_NAME 2>/dev/null || true
echo "✅ Granted storage.objectAdmin to service account"

# Grant Secret Manager access for all required secrets
echo ""
echo "🔐 Granting Secret Manager access to service account..."
for SECRET in keycast-gcp-project keycast-jwt-secret keycast-sendgrid-api-key keycast-master-key litestream-config; do
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

# Step 4: Create or update litestream-config in Secret Manager
echo ""
echo "🔒 Updating Litestream configuration in Secret Manager..."
if gcloud secrets describe litestream-config --project=$PROJECT_ID 2>/dev/null; then
    gcloud secrets versions add litestream-config \
        --data-file=litestream.yml \
        --project=$PROJECT_ID >/dev/null
else
    gcloud secrets create litestream-config \
        --data-file=litestream.yml \
        --project=$PROJECT_ID
fi
echo "✅ Litestream config stored in Secret Manager"

# Step 5: Update unified-service.yaml with actual values
echo ""
echo "📝 Preparing unified service configuration..."
sed -e "s|IMAGE_URL|$IMAGE_URL|g" \
    -e "s|PROJECT_ID@appspot.gserviceaccount.com|$SERVICE_ACCOUNT|g" \
    unified-service.yaml > unified-service-deploy.yaml
echo "✅ Unified service config prepared"

# Step 6: Deploy to Cloud Run
echo ""
echo "🚀 Deploying unified service to Cloud Run..."
gcloud run services replace unified-service-deploy.yaml \
    --region=$REGION \
    --project=$PROJECT_ID

# Step 7: Update service constraints (single instance for SQLite)
echo ""
echo "⚙️  Configuring scaling limits..."
echo "Note: max-instances=1 required for SQLite (no concurrent writes)"
echo "      min-instances=1 keeps service warm (signer must stay connected to relays)"
gcloud run services update $SERVICE_NAME \
    --region=$REGION \
    --project=$PROJECT_ID \
    --max-instances=1 \
    --min-instances=1 \
    --cpu=2 \
    --memory=2Gi

echo ""
echo "================================================"
echo "✅ Unified Service Deployment Complete!"
echo "================================================"
echo ""
echo "Service URL: $(gcloud run services describe $SERVICE_NAME --region=$REGION --format='value(status.url)')"
echo ""
echo "📊 Check deployment status:"
echo "  gcloud run services describe $SERVICE_NAME --region=$REGION"
echo ""
echo "📝 View logs:"
echo "  gcloud run services logs read $SERVICE_NAME --region=$REGION --limit=50"
echo ""
echo "🔍 Verify both services are running:"
echo "  gcloud run services logs read $SERVICE_NAME --region=$REGION --limit=100 | grep -E 'Starting (API|Signer)'"
echo ""
echo "🔍 Verify signer loaded authorizations:"
echo "  gcloud run services logs read $SERVICE_NAME --region=$REGION --limit=100 | grep 'Loaded.*authorizations'"
echo ""
echo "================================================"
