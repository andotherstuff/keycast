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
- Three new API endpoints:
  - `POST /api/auth/register` - Register new user with email/password (auto-login)
  - `POST /api/auth/login` - Login existing user
  - `GET /api/user/bunker` - Get NIP-46 bunker URL (requires authentication)

### Changed
- Updated CORS from single origin to allow all origins for embeddable auth
- Registration endpoint now returns JWT token for seamless user experience

### Security
- Passwords hashed with bcrypt (DEFAULT_COST)
- User secret keys encrypted with GCP KMS or file-based key manager
- JWT tokens for secure session management
- Unique bunker secrets (64-character alphanumeric) for NIP-46 connections
