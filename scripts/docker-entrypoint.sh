#!/bin/bash
set -e

# Function to wait for a port to be ready
wait_for_port() {
    local host=$1
    local port=$2
    local timeout=30
    local count=0
    echo "Attempting to connect to $host:$port..."
    while ! nc -z -v $host $port 2>&1; do
        echo "Waiting for $host:$port... (attempt $count of $timeout)"
        sleep 1
        count=$((count + 1))
        if [ $count -gt $timeout ]; then
            echo "Timeout waiting for $host:$port"
            exit 1
        fi
    done
    echo "Successfully connected to $host:$port"
}

if [ "$1" = "api" ]; then
    echo "Starting signer daemon in background..."
    # Run signer in background, redirecting output to ensure it's captured in logs
    ./keycast_signer 2>&1 &
    SIGNER_PID=$!
    echo "Signer daemon started with PID $SIGNER_PID"

    # Give signer a moment to start
    sleep 2

    echo "Starting API server..."
    exec ./keycast_api
elif [ "$1" = "web" ]; then
    # Check for API using api service name instead of localhost
    if [ ! -z "$WAIT_FOR_API" ]; then
        echo "WAIT_FOR_API is set, checking network..."
        # Debug: Check network connectivity
        echo "Network status:"
        ip addr
        echo "DNS resolution:"
        getent hosts keycast-api || echo "Could not resolve keycast-api hostname"
        echo "Attempting to reach API..."
        wait_for_port keycast-api 3000
    fi
    echo "Starting web server..."
    exec bun web/index.js
elif [ "$1" = "signer" ]; then
    echo "Starting signer daemon..."
    exec ./keycast_signer
else
    echo "Unknown command: $1"
    echo "Available commands: api, web, signer"
    exit 1
fi
