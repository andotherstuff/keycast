# Keycast Testing Guide

This guide covers how to test Keycast both locally and on Google Cloud Platform.

## Quick Start

```bash
# Run local tests (without Docker)
./scripts/test-runner.sh --env local

# Run local tests with Docker
./scripts/test-runner.sh --env local --docker

# Run Google Cloud tests
GCP_PROJECT_ID=your-project DOMAIN=your-domain.com ./scripts/test-runner.sh --env gcloud
```

## Local Testing

### Prerequisites
- Bun
- Rust/Cargo
- SQLite
- Docker (optional)

### Without Docker

Run all services locally using the development environment:

```bash
./scripts/test-local.sh
```

This will:
1. Check for master key and database
2. Start API server on port 3000
3. Start web server on port 5173
4. Start signer daemon
5. Run health checks
6. Display service URLs

### With Docker

Use Docker Compose for isolated testing:

```bash
# Using test runner
./scripts/test-runner.sh --env local --docker

# Or directly with docker-compose
docker-compose -f docker-compose.test.yml up -d
```

Test containers use different ports to avoid conflicts:
- API: http://localhost:3001
- Web: http://localhost:5174

## Google Cloud Testing

### Prerequisites
- Google Cloud SDK (`gcloud`)
- Docker
- Active GCP project
- Enabled APIs (Cloud Run, Secret Manager, Artifact Registry)

### Environment Variables

```bash
export GCP_PROJECT_ID="your-project-id"
export GCP_REGION="us-central1"  # optional, defaults to us-central1
export DOMAIN="your-domain.com"
export ALLOWED_PUBKEYS="pubkey1,pubkey2"  # optional
```

### Deployment

```bash
./scripts/test-gcloud.sh
```

This script will:
1. Enable required GCP APIs
2. Create Artifact Registry repository
3. Upload master key to Secret Manager
4. Build and push Docker image
5. Deploy three Cloud Run services (api, web, signer)
6. Run health checks
7. Display service URLs

### Security Notes

- API and Web services are publicly accessible
- Signer service is private (no public access)
- Master key is stored in Secret Manager
- Each service has appropriate memory limits

## Test Scripts

### test-runner.sh
Main test orchestrator with options:
- `--env <local|gcloud>`: Choose test environment
- `--docker`: Use Docker for local testing
- `--verbose`: Enable verbose output
- `--help`: Show help message

### test-local.sh
Runs services locally without containerization. Good for development.

### test-gcloud.sh
Deploys and tests on Google Cloud Platform. Requires GCP credentials.

### docker-compose.test.yml
Docker Compose configuration for local containerized testing.

## Health Checks

All services expose `/health` endpoints:

```bash
# API health
curl http://localhost:3000/health

# Web health
curl http://localhost:5173/health
```

## Troubleshooting

### Local Testing

1. **Port conflicts**: Test containers use ports 3001 and 5174 to avoid conflicts
2. **Master key missing**: Run `bun run key:generate`
3. **Database issues**: Run `bun run db:reset`

### Google Cloud Testing

1. **Authentication**: Run `gcloud auth login`
2. **Project selection**: Run `gcloud config set project PROJECT_ID`
3. **API enablement**: The script auto-enables required APIs
4. **Build failures**: Ensure Docker daemon is running

## Next Steps

After successful testing:

1. Set up monitoring and alerting
2. Configure custom domain with load balancer
3. Set up Cloud SQL for production database
4. Implement CI/CD pipeline
5. Add integration and unit tests