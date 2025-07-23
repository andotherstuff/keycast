#!/bin/bash
# ABOUTME: Google Cloud deployment and testing script for Keycast
# ABOUTME: Deploys to GCP using Cloud Run and runs health checks

set -e

# Configuration
PROJECT_ID=${GCP_PROJECT_ID:-""}
REGION=${GCP_REGION:-"us-central1"}
SERVICE_NAME=${SERVICE_NAME:-"keycast"}
DOMAIN=${DOMAIN:-""}

echo "🚀 Keycast Google Cloud Deployment & Testing"

# Check required environment variables
if [ -z "$PROJECT_ID" ]; then
    echo "❌ Error: GCP_PROJECT_ID environment variable not set"
    echo "Usage: GCP_PROJECT_ID=your-project-id DOMAIN=your-domain.com ./scripts/test-gcloud.sh"
    exit 1
fi

if [ -z "$DOMAIN" ]; then
    echo "⚠️  Warning: DOMAIN not set. Using Cloud Run auto-generated URLs"
    DOMAIN="auto-generated"
fi

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
    echo "❌ Error: gcloud CLI not found. Please install Google Cloud SDK"
    exit 1
fi

# Set project
echo "📋 Setting GCP project to: $PROJECT_ID"
gcloud config set project $PROJECT_ID

# Enable required APIs
echo "🔧 Enabling required GCP APIs..."
gcloud services enable \
    cloudbuild.googleapis.com \
    run.googleapis.com \
    secretmanager.googleapis.com \
    artifactregistry.googleapis.com

# Create artifact registry if doesn't exist
echo "📦 Setting up Artifact Registry..."
if ! gcloud artifacts repositories describe docker --location=$REGION &>/dev/null; then
    gcloud artifacts repositories create docker \
        --repository-format=docker \
        --location=$REGION \
        --description="Docker repository"
fi

# Check if master key exists in Secret Manager
echo "🔐 Checking master key..."
if ! gcloud secrets describe keycast-master-key &>/dev/null; then
    if [ ! -f "./master.key" ]; then
        echo "❌ Error: master.key not found locally. Run 'bun run key:generate' first"
        exit 1
    fi
    echo "📤 Uploading master key to Secret Manager..."
    gcloud secrets create keycast-master-key --data-file=./master.key
else
    echo "✅ Master key already exists in Secret Manager"
fi

# Build and push Docker image
echo "🐳 Building Docker image..."
IMAGE_URL="$REGION-docker.pkg.dev/$PROJECT_ID/docker/$SERVICE_NAME:latest"

# Create cloudbuild.yaml for multi-service deployment
cat > cloudbuild.yaml << EOF
steps:
  # Build the image
  - name: 'gcr.io/cloud-builders/docker'
    args: ['build', '-t', '$IMAGE_URL', '.']
  
  # Push the image
  - name: 'gcr.io/cloud-builders/docker'
    args: ['push', '$IMAGE_URL']

  # Deploy API service
  - name: 'gcr.io/google.com/cloudsdktool/cloud-sdk'
    entrypoint: gcloud
    args:
      - 'run'
      - 'deploy'
      - '${SERVICE_NAME}-api'
      - '--image'
      - '$IMAGE_URL'
      - '--region'
      - '$REGION'
      - '--platform'
      - 'managed'
      - '--allow-unauthenticated'
      - '--command'
      - 'api'
      - '--port'
      - '3000'
      - '--set-env-vars'
      - 'RUST_LOG=info'
      - '--set-secrets'
      - 'MASTER_KEY_PATH=/secrets/master.key=keycast-master-key:latest'
      - '--memory'
      - '512Mi'

  # Deploy Web service
  - name: 'gcr.io/google.com/cloudsdktool/cloud-sdk'
    entrypoint: gcloud
    args:
      - 'run'
      - 'deploy'
      - '${SERVICE_NAME}-web'
      - '--image'
      - '$IMAGE_URL'
      - '--region'
      - '$REGION'
      - '--platform'
      - 'managed'
      - '--allow-unauthenticated'
      - '--command'
      - 'web'
      - '--port'
      - '5173'
      - '--set-env-vars'
      - 'NODE_ENV=production,VITE_DOMAIN=$DOMAIN,VITE_ALLOWED_PUBKEYS=${ALLOWED_PUBKEYS:-}'
      - '--memory'
      - '256Mi'

  # Deploy Signer service
  - name: 'gcr.io/google.com/cloudsdktool/cloud-sdk'
    entrypoint: gcloud
    args:
      - 'run'
      - 'deploy'
      - '${SERVICE_NAME}-signer'
      - '--image'
      - '$IMAGE_URL'
      - '--region'
      - '$REGION'
      - '--platform'
      - 'managed'
      - '--no-allow-unauthenticated'
      - '--command'
      - 'signer'
      - '--set-env-vars'
      - 'RUST_LOG=info,keycast_signer=debug'
      - '--set-secrets'
      - 'MASTER_KEY_PATH=/secrets/master.key=keycast-master-key:latest'
      - '--memory'
      - '256Mi'

images:
  - '$IMAGE_URL'
EOF

# Submit build
echo "🏗️ Building and deploying to Cloud Run..."
gcloud builds submit --config=cloudbuild.yaml .

# Get service URLs
echo "📍 Getting service URLs..."
API_URL=$(gcloud run services describe ${SERVICE_NAME}-api --region=$REGION --format='value(status.url)')
WEB_URL=$(gcloud run services describe ${SERVICE_NAME}-web --region=$REGION --format='value(status.url)')

echo ""
echo "🧪 Running health checks..."

# Test API health
echo -n "API Health ($API_URL): "
if curl -s "$API_URL/health" | grep -q "OK"; then
    echo "✅ OK"
else
    echo "❌ Failed"
fi

# Test Web health
echo -n "Web Health ($WEB_URL): "
if curl -s "$WEB_URL/health" > /dev/null; then
    echo "✅ OK"
else
    echo "❌ Failed"
fi

echo ""
echo "📊 Deployment Summary:"
echo "- API URL: $API_URL"
echo "- Web URL: $WEB_URL"
echo "- Project: $PROJECT_ID"
echo "- Region: $REGION"
echo ""
echo "🔒 Security Notes:"
echo "- API and Web services are publicly accessible"
echo "- Signer service is private (no public access)"
echo "- Master key is stored in Secret Manager"
echo ""
echo "📝 Next steps:"
echo "1. Set up a load balancer with your domain: $DOMAIN"
echo "2. Configure Cloud SQL for production database"
echo "3. Set up monitoring and alerting"

# Clean up
rm -f cloudbuild.yaml