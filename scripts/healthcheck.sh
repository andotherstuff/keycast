#!/bin/bash
set -e

if [ "$1" = "api" ]; then
    # For API, check the /health endpoint
    curl -f http://localhost:3000/health || exit 1
elif [ "$1" = "web" ]; then
    # For web, check the /health endpoint
    curl -f http://localhost:5173/health || exit 1
elif [ "$1" = "signer" ]; then
    # For signer, check the /health endpoint (signer runs on port 8080)
    curl -f http://localhost:8080/health || exit 1
else
    # Check all services if no argument provided
    curl -f http://localhost:3000/health || exit 1
    curl -f http://localhost:5173/health || exit 1
    curl -f http://localhost:8080/health || exit 1
fi
