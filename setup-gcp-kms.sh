#!/bin/bash

# ABOUTME: Google Cloud KMS setup script for Keycast
# ABOUTME: Creates KMS key ring and crypto key for production use

set -e

echo "🔑 Setting up Google Cloud KMS for Keycast..."

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
    echo "❌ gcloud CLI not found. Please install it first:"
    echo "   https://cloud.google.com/sdk/docs/install"
    exit 1
fi

# Get project ID
PROJECT_ID=${GCP_PROJECT_ID:-openvine-co}
if [ -z "$PROJECT_ID" ]; then
    echo "❌ No project ID found. Set GCP_PROJECT_ID or run 'gcloud config set project YOUR_PROJECT_ID'"
    exit 1
fi

LOCATION=${GCP_KMS_LOCATION:-global}
KEY_RING=${GCP_KMS_KEY_RING:-keycast-keys}
KEY_NAME=${GCP_KMS_KEY_NAME:-master-key}

echo "📋 Configuration:"
echo "   Project ID: $PROJECT_ID"
echo "   Location: $LOCATION"
echo "   Key Ring: $KEY_RING"
echo "   Key Name: $KEY_NAME"

# Enable KMS API
echo "🔧 Enabling Cloud KMS API..."
gcloud services enable cloudkms.googleapis.com --project=$PROJECT_ID

# Create key ring (ignore if exists)
echo "🔑 Creating KMS key ring..."
gcloud kms keyrings create $KEY_RING \
    --location=$LOCATION \
    --project=$PROJECT_ID \
    --quiet 2>/dev/null || echo "   Key ring already exists"

# Create crypto key (ignore if exists)
echo "🔐 Creating crypto key..."
gcloud kms keys create $KEY_NAME \
    --location=$LOCATION \
    --keyring=$KEY_RING \
    --purpose=encryption \
    --project=$PROJECT_ID \
    --quiet 2>/dev/null || echo "   Crypto key already exists"

# Set up authentication
echo "🔐 Setting up authentication..."
gcloud auth application-default login --project=$PROJECT_ID

# Create .env file
echo "📄 Creating .env file..."
cat > .env << EOF
# Database configuration
DATABASE_URL=sqlite:../database/keycast.db

# Key management configuration
USE_GCP_KMS=true

# Google Cloud KMS configuration
GCP_PROJECT_ID=$PROJECT_ID
GCP_KMS_LOCATION=$LOCATION
GCP_KMS_KEY_RING=$KEY_RING
GCP_KMS_KEY_NAME=$KEY_NAME

# Signer daemon configuration
AUTH_ID=1
EOF

echo "✅ Google Cloud KMS setup complete!"
echo ""
echo "📋 Next steps:"
echo "   1. Review the .env file and adjust if needed"
echo "   2. Run 'cargo build' to build with GCP KMS support"
echo "   3. Set USE_GCP_KMS=true to enable KMS encryption"
echo ""
echo "🔧 To test the setup:"
echo "   export USE_GCP_KMS=true"
echo "   cargo run --bin keycast_api"
echo ""
echo "💡 The key path is:"
echo "   projects/$PROJECT_ID/locations/$LOCATION/keyRings/$KEY_RING/cryptoKeys/$KEY_NAME"