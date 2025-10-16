#!/usr/bin/env bash
# ABOUTME: Tenant management CLI for keycast multi-tenancy
# ABOUTME: Add, list, and manage tenants from the command line

set -euo pipefail

# Database path
DATABASE_PATH="${DATABASE_PATH:-database/keycast.db}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
info() {
    echo -e "${BLUE}ℹ ${NC}$1"
}

success() {
    echo -e "${GREEN}✓ ${NC}$1"
}

error() {
    echo -e "${RED}✗ ${NC}$1" >&2
}

warn() {
    echo -e "${YELLOW}⚠ ${NC}$1"
}

# Check if sqlite3 is installed
if ! command -v sqlite3 &> /dev/null; then
    error "sqlite3 command not found. Please install sqlite3."
    exit 1
fi

# Check if database exists
if [ ! -f "$DATABASE_PATH" ]; then
    error "Database not found at: $DATABASE_PATH"
    error "Set DATABASE_PATH environment variable or run from project root"
    exit 1
fi

# List all tenants
list_tenants() {
    info "Listing all tenants..."
    echo ""
    sqlite3 "$DATABASE_PATH" <<EOF
.mode column
.headers on
SELECT id, domain, name, created_at FROM tenants ORDER BY id;
EOF
    echo ""
}

# Add a new tenant
add_tenant() {
    local domain="$1"
    local name="$2"
    local relay="${3:-wss://relay.damus.io}"
    local email_from="${4:-noreply@$domain}"

    info "Adding tenant: $name ($domain)"

    # Check if tenant already exists
    existing=$(sqlite3 "$DATABASE_PATH" "SELECT COUNT(*) FROM tenants WHERE domain = '$domain'")
    if [ "$existing" -gt 0 ]; then
        error "Tenant with domain $domain already exists"
        exit 1
    fi

    # Create settings JSON
    settings="{\"relay\":\"$relay\",\"email_from\":\"$email_from\"}"

    # Insert tenant
    sqlite3 "$DATABASE_PATH" <<EOF
INSERT INTO tenants (domain, name, settings, created_at, updated_at)
VALUES ('$domain', '$name', '$settings', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
EOF

    # Get the new tenant ID
    tenant_id=$(sqlite3 "$DATABASE_PATH" "SELECT id FROM tenants WHERE domain = '$domain'")

    success "Tenant created successfully!"
    echo ""
    echo "  ID:         $tenant_id"
    echo "  Domain:     $domain"
    echo "  Name:       $name"
    echo "  Relay:      $relay"
    echo "  Email From: $email_from"
    echo ""
}

# Show tenant details
show_tenant() {
    local identifier="$1"

    info "Fetching tenant details..."
    echo ""

    # Check if identifier is numeric (ID) or string (domain)
    if [[ "$identifier" =~ ^[0-9]+$ ]]; then
        sqlite3 "$DATABASE_PATH" <<EOF
.mode line
SELECT id, domain, name, settings, created_at, updated_at
FROM tenants WHERE id = $identifier;
EOF
    else
        sqlite3 "$DATABASE_PATH" <<EOF
.mode line
SELECT id, domain, name, settings, created_at, updated_at
FROM tenants WHERE domain = '$identifier';
EOF
    fi
    echo ""
}

# Delete a tenant (WARNING: This will orphan all tenant data)
delete_tenant() {
    local identifier="$1"

    warn "WARNING: This will delete the tenant record but NOT the associated data!"
    warn "All users, OAuth apps, and other tenant data will be orphaned."
    read -p "Are you sure you want to continue? (yes/no): " confirm

    if [ "$confirm" != "yes" ]; then
        info "Aborted."
        exit 0
    fi

    # Check if identifier is numeric (ID) or string (domain)
    if [[ "$identifier" =~ ^[0-9]+$ ]]; then
        sqlite3 "$DATABASE_PATH" "DELETE FROM tenants WHERE id = $identifier;"
    else
        sqlite3 "$DATABASE_PATH" "DELETE FROM tenants WHERE domain = '$identifier';"
    fi

    success "Tenant deleted"
}

# Update tenant settings
update_tenant() {
    local identifier="$1"
    local field="$2"
    local value="$3"

    info "Updating tenant..."

    case "$field" in
        name)
            if [[ "$identifier" =~ ^[0-9]+$ ]]; then
                sqlite3 "$DATABASE_PATH" "UPDATE tenants SET name = '$value', updated_at = CURRENT_TIMESTAMP WHERE id = $identifier;"
            else
                sqlite3 "$DATABASE_PATH" "UPDATE tenants SET name = '$value', updated_at = CURRENT_TIMESTAMP WHERE domain = '$identifier';"
            fi
            ;;
        relay)
            # Update just the relay in settings JSON (this is simplistic, assumes existing settings)
            warn "Updating relay in settings (this may overwrite other settings)"
            local settings="{\"relay\":\"$value\",\"email_from\":\"noreply@domain\"}"
            if [[ "$identifier" =~ ^[0-9]+$ ]]; then
                sqlite3 "$DATABASE_PATH" "UPDATE tenants SET settings = '$settings', updated_at = CURRENT_TIMESTAMP WHERE id = $identifier;"
            else
                sqlite3 "$DATABASE_PATH" "UPDATE tenants SET settings = '$settings', updated_at = CURRENT_TIMESTAMP WHERE domain = '$identifier';"
            fi
            ;;
        *)
            error "Unknown field: $field"
            error "Valid fields: name, relay"
            exit 1
            ;;
    esac

    success "Tenant updated"
}

# Show usage
usage() {
    cat <<EOF
Keycast Tenant Management CLI

Usage: $0 <command> [arguments]

Commands:
  list                          List all tenants
  add <domain> <name> [relay] [email_from]
                               Add a new tenant
  show <id|domain>             Show tenant details
  update <id|domain> <field> <value>
                               Update tenant field (name, relay)
  delete <id|domain>           Delete a tenant (WARNING: orphans data)

Examples:
  $0 list
  $0 add holis.social "Holis Social" wss://relay.holis.social noreply@holis.social
  $0 show holis.social
  $0 show 1
  $0 update holis.social name "Holis Network"
  $0 delete holis.social

Environment:
  DATABASE_PATH                Path to SQLite database (default: database/keycast.db)

EOF
}

# Main command dispatcher
main() {
    if [ $# -eq 0 ]; then
        usage
        exit 1
    fi

    command="$1"
    shift

    case "$command" in
        list)
            list_tenants
            ;;
        add)
            if [ $# -lt 2 ]; then
                error "Usage: $0 add <domain> <name> [relay] [email_from]"
                exit 1
            fi
            add_tenant "$@"
            ;;
        show)
            if [ $# -lt 1 ]; then
                error "Usage: $0 show <id|domain>"
                exit 1
            fi
            show_tenant "$1"
            ;;
        update)
            if [ $# -lt 3 ]; then
                error "Usage: $0 update <id|domain> <field> <value>"
                exit 1
            fi
            update_tenant "$1" "$2" "$3"
            ;;
        delete)
            if [ $# -lt 1 ]; then
                error "Usage: $0 delete <id|domain>"
                exit 1
            fi
            delete_tenant "$1"
            ;;
        help|--help|-h)
            usage
            ;;
        *)
            error "Unknown command: $command"
            usage
            exit 1
            ;;
    esac
}

main "$@"
