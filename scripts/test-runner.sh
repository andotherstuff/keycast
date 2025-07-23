#!/bin/bash
# ABOUTME: Main test runner for Keycast - supports local and cloud testing
# ABOUTME: Provides options for different test environments and configurations

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
TEST_ENV="local"
USE_DOCKER=false
VERBOSE=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --env)
            TEST_ENV="$2"
            shift 2
            ;;
        --docker)
            USE_DOCKER=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --env <local|gcloud>  Test environment (default: local)"
            echo "  --docker              Use Docker for local testing"
            echo "  --verbose             Enable verbose output"
            echo "  --help                Show this help message"
            echo ""
            echo "Environment variables:"
            echo "  GCP_PROJECT_ID        Google Cloud project ID (for gcloud)"
            echo "  GCP_REGION           Google Cloud region (default: us-central1)"
            echo "  DOMAIN               Domain for deployment"
            echo "  ALLOWED_PUBKEYS      Comma-separated list of allowed pubkeys"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo -e "${GREEN}🧪 Keycast Test Runner${NC}"
echo "Environment: $TEST_ENV"
echo "Use Docker: $USE_DOCKER"
echo ""

# Function to check prerequisites
check_prerequisites() {
    echo -e "${YELLOW}Checking prerequisites...${NC}"
    
    # Check for required tools
    local missing_tools=()
    
    if ! command -v bun &> /dev/null; then
        missing_tools+=("bun")
    fi
    
    if ! command -v cargo &> /dev/null; then
        missing_tools+=("cargo (Rust)")
    fi
    
    if [ "$USE_DOCKER" = true ] || [ "$TEST_ENV" = "gcloud" ]; then
        if ! command -v docker &> /dev/null; then
            missing_tools+=("docker")
        fi
    fi
    
    if [ "$TEST_ENV" = "gcloud" ]; then
        if ! command -v gcloud &> /dev/null; then
            missing_tools+=("gcloud")
        fi
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo -e "${RED}❌ Missing required tools: ${missing_tools[*]}${NC}"
        exit 1
    fi
    
    # Check for master key
    if [ ! -f "./master.key" ]; then
        echo -e "${YELLOW}⚠️  Master key not found. Generating...${NC}"
        bun run key:generate
    fi
    
    echo -e "${GREEN}✅ All prerequisites met${NC}"
}

# Function to run local tests
run_local_tests() {
    if [ "$USE_DOCKER" = true ]; then
        echo -e "${YELLOW}Running local tests with Docker...${NC}"
        
        # Create test network if it doesn't exist
        docker network create keycast-test 2>/dev/null || true
        
        # Stop any existing test containers
        docker-compose -f docker-compose.test.yml down 2>/dev/null || true
        
        # Build and start test containers
        docker-compose -f docker-compose.test.yml up -d --build
        
        # Wait for services to be healthy
        echo "Waiting for services to be healthy..."
        sleep 10
        
        # Run health checks
        echo -e "\n${YELLOW}Running health checks...${NC}"
        
        # API health check
        echo -n "API Health: "
        if curl -s localhost:3001/health | grep -q "OK"; then
            echo -e "${GREEN}✅ OK${NC}"
        else
            echo -e "${RED}❌ Failed${NC}"
        fi
        
        # Web health check
        echo -n "Web Health: "
        if curl -s localhost:5174/health > /dev/null; then
            echo -e "${GREEN}✅ OK${NC}"
        else
            echo -e "${RED}❌ Failed${NC}"
        fi
        
        # Show logs if verbose
        if [ "$VERBOSE" = true ]; then
            echo -e "\n${YELLOW}Container logs:${NC}"
            docker-compose -f docker-compose.test.yml logs --tail=20
        fi
        
        # Show URLs
        echo -e "\n${GREEN}Test URLs:${NC}"
        echo "API: http://localhost:3001"
        echo "Web: http://localhost:5174"
        
        # Cleanup option
        echo -e "\n${YELLOW}To stop test containers: docker-compose -f docker-compose.test.yml down${NC}"
        
    else
        echo -e "${YELLOW}Running local tests without Docker...${NC}"
        ./scripts/test-local.sh
    fi
}

# Function to run Google Cloud tests
run_gcloud_tests() {
    echo -e "${YELLOW}Running Google Cloud tests...${NC}"
    
    # Check required environment variables
    if [ -z "$GCP_PROJECT_ID" ] || [ -z "$DOMAIN" ]; then
        echo -e "${RED}❌ Missing required environment variables${NC}"
        echo "Required: GCP_PROJECT_ID, DOMAIN"
        exit 1
    fi
    
    ./scripts/test-gcloud.sh
}

# Main execution
check_prerequisites

case $TEST_ENV in
    local)
        run_local_tests
        ;;
    gcloud)
        run_gcloud_tests
        ;;
    *)
        echo -e "${RED}❌ Unknown environment: $TEST_ENV${NC}"
        exit 1
        ;;
esac