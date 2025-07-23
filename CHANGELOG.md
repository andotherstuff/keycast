# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - 2025-07-23

### Added
- Complete transformation from team-based to personal authentication system
- NIP-05 discovery implementation with `.well-known/nostr.json` endpoint
- Domain management API for NIP-05 identifiers
- User-centric database schema with enhanced user table
- Multiple authentication methods support (NIP-07, NIP-46, email/password, OAuth, passkey)
- User keys management (primary, app-specific, temporary)
- Dynamic application registration and discovery
- Authorization flow system for app connection attempts
- User sessions with bearer token authentication
- Activity logging and audit trail infrastructure
- App connection attempts tracking
- Authorization requests with pending/approved/rejected states
- Personal policies system (adapted from team policies)
- Support for app-specific metadata and icons

### Changed
- Completely rewrote database schema from team-based to user-based
- Replaced incremental migrations with clean initial schema
- Updated all core types to be user-centric
- Modified authorization system to work with personal keys
- Enhanced user model with email, NIP-05, and profile fields

### Removed
- All team-related functionality and database tables
- Team management API endpoints
- Team user roles and permissions
- Team-based policy system (replaced with personal policies)

### Technical Details
- Database migration using clean initial schema approach
- SQLx compatibility updates for nullable fields
- UUID-based IDs for better distributed system support
- JSON metadata storage for flexible app data
- Comprehensive indexes for performance optimization

### Migration Notes
- This is a breaking change from the team-based system
- Existing data will need to be migrated using the provided scripts
- Minimal legacy tables retained for backward compatibility during transition