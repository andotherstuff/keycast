#!/bin/bash
# ABOUTME: Quick test script for openvine-co project
# ABOUTME: Provides simple commands for local and cloud testing

set -e

echo "🚀 Keycast Testing Quickstart"
echo ""

# Load environment variables
if [ -f .env.test ]; then
    export $(cat .env.test | grep -v '^#' | xargs)
fi

case "${1:-help}" in
    local)
        echo "🏠 Running local tests..."
        ./scripts/test-runner.sh --env local
        ;;
    
    docker)
        echo "🐳 Running local Docker tests..."
        ./scripts/test-runner.sh --env local --docker
        ;;
    
    gcloud)
        echo "☁️  Deploying to Google Cloud (openvine-co)..."
        echo "Project: $GCP_PROJECT_ID"
        echo "Region: $GCP_REGION"
        echo ""
        
        # Check if user is authenticated
        if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q .; then
            echo "❌ Not authenticated. Please run: gcloud auth login"
            exit 1
        fi
        
        # Run the deployment
        ./scripts/test-gcloud.sh
        ;;
    
    setup)
        echo "🔧 Setting up test environment..."
        
        # Install dependencies
        echo "Installing dependencies..."
        bun install
        cd web && bun install && cd ..
        
        # Generate master key if needed
        if [ ! -f "./master.key" ]; then
            echo "Generating master key..."
            bun run key:generate
        fi
        
        # Initialize database
        echo "Initializing database..."
        bun run db:reset
        
        echo "✅ Setup complete!"
        ;;
    
    *)
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  setup    - Set up the test environment"
        echo "  local    - Run local tests"
        echo "  docker   - Run local Docker tests"
        echo "  gcloud   - Deploy and test on Google Cloud"
        echo ""
        echo "Current configuration (.env.test):"
        echo "  Project: ${GCP_PROJECT_ID:-not set}"
        echo "  Region: ${GCP_REGION:-not set}"
        echo ""
        echo "Examples:"
        echo "  $0 setup     # First time setup"
        echo "  $0 local     # Test locally"
        echo "  $0 gcloud    # Deploy to openvine-co"
        ;;
esac