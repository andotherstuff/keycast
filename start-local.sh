#!/bin/bash
# ABOUTME: Start all Keycast services locally in separate terminals
# ABOUTME: Requires iTerm2 or tmux for multiple terminals

set -e

echo "🚀 Starting Keycast Services..."

# Check which terminal multiplexer is available
if command -v tmux &> /dev/null; then
    echo "Using tmux..."
    
    # Kill existing tmux session if it exists
    tmux kill-session -t keycast 2>/dev/null || true
    
    # Create new tmux session
    tmux new-session -d -s keycast -n api
    
    # Start API
    tmux send-keys -t keycast:api "cd api && RUST_LOG=debug cargo run" C-m
    
    # Create window for web
    tmux new-window -t keycast -n web
    tmux send-keys -t keycast:web "cd web && bun run dev" C-m
    
    # Create window for signer
    tmux new-window -t keycast -n signer
    tmux send-keys -t keycast:signer "RUST_LOG=warn,keycast_signer=debug MASTER_KEY_PATH=./master.key cargo run --bin keycast_signer" C-m
    
    # Attach to tmux session
    echo "✅ Services starting in tmux session 'keycast'"
    echo ""
    echo "Commands:"
    echo "  View all windows: tmux attach -t keycast"
    echo "  Switch windows: Ctrl+B then window number (0-2)"
    echo "  Detach: Ctrl+B then D"
    echo "  Kill all: tmux kill-session -t keycast"
    
    tmux attach -t keycast
    
elif [[ "$TERM_PROGRAM" == "iTerm.app" ]]; then
    echo "Using iTerm2..."
    
    # Start API in new tab
    osascript -e 'tell application "iTerm"
        tell current window
            create tab with default profile
            tell current session
                write text "cd '"$PWD"'/api && RUST_LOG=debug cargo run"
            end tell
        end tell
    end tell'
    
    # Start Web in new tab
    osascript -e 'tell application "iTerm"
        tell current window
            create tab with default profile
            tell current session
                write text "cd '"$PWD"'/web && bun run dev"
            end tell
        end tell
    end tell'
    
    # Start Signer in new tab
    osascript -e 'tell application "iTerm"
        tell current window
            create tab with default profile
            tell current session
                write text "cd '"$PWD"' && RUST_LOG=warn,keycast_signer=debug MASTER_KEY_PATH=./master.key cargo run --bin keycast_signer"
            end tell
        end tell
    end tell'
    
    echo "✅ Services starting in separate iTerm tabs"
    
else
    echo "No terminal multiplexer found. Starting services with concurrently..."
    bun run dev
fi