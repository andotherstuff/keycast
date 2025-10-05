# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- Personal authentication system with email/password registration and login
- JWT-based authentication with 24-hour token expiration
- Automatic login after registration (returns JWT token immediately)
- NIP-46 bunker URL generation for registered users
- Database migrations for personal authentication (email, password_hash, personal_keys table)
- GCP KMS integration for encrypting user secret keys
- CORS configuration allowing all origins for embeddable authentication flows
- Test client HTML page for demonstrating auth flow
- OAuth authorization flow with NIP-46 remote signing
- Unified signer daemon architecture handling all bunker URLs in single process
- OAuthAuthorization type in core for managing OAuth-based remote signing
- Database migration for OAuth authorizations table with proper schema
- Three new API endpoints:
  - `POST /api/auth/register` - Register new user with email/password (auto-login)
  - `POST /api/auth/login` - Login existing user
  - `GET /api/user/bunker` - Get NIP-46 bunker URL (requires authentication)

### Changed
- Updated CORS from single origin to allow all origins for embeddable auth
- Registration endpoint now returns JWT token for seamless user experience
- **BREAKING**: Refactored signer from multi-process (one per authorization) to unified single-process architecture
- OAuth authorizations now use user's personal key instead of generating random keys
- OAuth bunker URLs use user's public key as bunker_public_key with unique connection secret per app
- Signer now handles both regular and OAuth authorizations in single unified process with routing by bunker_pubkey

### Security
- Passwords hashed with bcrypt (DEFAULT_COST)
- User secret keys encrypted with GCP KMS or file-based key manager
- JWT tokens for secure session management
- Unique bunker secrets (64-character alphanumeric) for NIP-46 connections
- OAuth authorizations support per-app revocation via unique bunker URL per app
