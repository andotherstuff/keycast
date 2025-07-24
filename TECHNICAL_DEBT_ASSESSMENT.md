# Keycast Technical Debt Assessment Report

## Executive Summary

This comprehensive analysis of the Keycast codebase reveals significant technical debt and architectural issues stemming from an incomplete migration from a team-based authentication system to a personal authentication model. The codebase contains numerous database schema mismatches, duplicate type definitions, dead code, and half-implemented features that need urgent attention.

## Critical Issues

### 1. Database Schema Mismatches

#### Missing Tables Referenced in Code
- **`team_users` table**: Referenced extensively in `/core/src/types/user.rs` and `/api/src/api/http/teams.rs` but does not exist in the schema
- **`sessions` table**: Referenced in multiple test files and auth handlers but only `user_sessions` exists in the schema

#### Column Name Mismatches
- Code references `app_id` but schema uses `application_id`
- Code references `user_public_key` but schema uses `public_key` in users table
- Code references `description` field in policies table which doesn't exist
- Code uses `team_id` in policies table but schema doesn't have this column

#### Incorrect References
- `stored_key_id` is still referenced in many places despite being marked as legacy
- Authorization queries join on non-existent relationships

### 2. Duplicate Type Definitions

#### Authorization Types
- `Authorization` in `/core/src/types/authorization.rs`
- `AuthorizationEnhanced` in `/core/src/types/authorization_enhanced.rs`
- Both define nearly identical error enums and structures
- Unclear which should be used where

#### User Types
- `User` in `/core/src/types/user.rs`
- `UserEnhanced` in `/core/src/types/user_enhanced.rs`
- Duplicate functionality with slight variations

#### Duplicate Function Names
- 9 different `routes()` functions across different modules
- 3 different `validate_policy()` implementations
- 2 `test_default()` functions in custom permissions
- Multiple `from_permission()` implementations

### 3. Dead Code and Unused Features

#### Team-Based Legacy Code
- Entire team management system in `/api/src/api/http/teams.rs` still active
- Team-related types and database queries throughout the codebase
- `TeamUser`, `TeamWithRelations`, `TeamUserRole` types still defined but tables don't exist

#### Unused Imports
- Multiple files import types and traits that are never used
- Legacy encryption methods imported but replaced by new implementations

### 4. Architectural Issues

#### Mixed Authentication Models
- Both team-based and user-based authentication code paths exist
- Unclear separation of concerns between old and new systems
- Authorization flow has conditional logic for both models

#### Inconsistent API Design
- Team endpoints (`/api/teams/*`) still exposed
- User endpoints (`/api/users/*`) partially implemented
- Some endpoints expect team context, others expect user context

#### Database Transaction Issues
- No consistent transaction boundaries
- Missing rollback handling in critical paths
- Potential for partial state updates

### 5. Type Safety Issues

#### SQL Query Type Mismatches
- Raw SQL queries with string concatenation
- Type conversions between i32/u32 for IDs inconsistently
- Optional fields treated as required in some queries

#### Error Handling
- Multiple error types for same logical errors
- Inconsistent error propagation
- Some functions swallow errors silently

### 6. Half-Implemented Features

#### Personal Auth Migration
- User keys system partially implemented
- Authorization enhanced types created but not fully integrated
- User auth methods table exists but not fully utilized

#### Application Management
- Dynamic app discovery started but incomplete
- App connection attempts table exists but processing logic is minimal
- Authorization requests workflow partially implemented

## Specific Code Examples

### Database Query Issues

```rust
// In /core/src/types/user.rs - References non-existent team_users table
"SELECT * FROM teams WHERE id IN (SELECT team_id FROM team_users WHERE user_public_key = ?1)"

// In /api/src/api/http/teams.rs - Inserts into non-existent table
"INSERT INTO team_users (team_id, user_public_key, role, created_at, updated_at)"

// In /api/tests/applications_test.rs - References non-existent sessions table
"INSERT INTO sessions (id, user_id, token, expires_at, created_at)"
```

### Type Conflicts

```rust
// In authorization.rs
pub struct Authorization {
    pub id: u32,
    pub stored_key_id: u32,
    // ...
}

// In authorization_enhanced.rs
pub struct AuthorizationEnhanced {
    pub id: u32,
    pub stored_key_id: Option<u32>,  // Now optional
    pub user_id: Option<String>,     // New field
    pub user_key_id: Option<String>, // New field
    pub application_id: Option<u32>, // New field
    // ...
}
```

### Inconsistent Field Names

```rust
// Schema has application_id
pub application_id: Option<u32>,

// But queries use app_id
"INNER JOIN authorizations auth ON auth.app_id = a.id"
```

## Recommendations

### Immediate Actions

1. **Fix Database Schema Mismatches**
   - Add migration to rename columns to match code expectations
   - Remove references to non-existent tables
   - Update all SQL queries to use correct column names

2. **Choose Single Authorization Model**
   - Either complete the migration to personal auth or revert to team-based
   - Remove duplicate type definitions
   - Update all code paths to use single model

3. **Remove Dead Code**
   - Delete team management endpoints if migrating to personal auth
   - Remove unused type definitions
   - Clean up duplicate function implementations

### Short-term Improvements

1. **Standardize Database Access**
   - Use SQLx query macros for type safety
   - Create repository pattern for database access
   - Add proper transaction handling

2. **Consolidate Error Handling**
   - Create single error type per domain
   - Use proper error propagation
   - Add logging for error conditions

3. **Complete Feature Implementation**
   - Finish personal auth migration
   - Complete application management features
   - Implement proper authorization request workflow

### Long-term Architecture

1. **Clear Separation of Concerns**
   - Separate legacy code into deprecated module
   - Create clear boundaries between auth models
   - Document migration path

2. **API Versioning**
   - Version the API to support both models during transition
   - Deprecate old endpoints with clear timeline
   - Provide migration guide for API consumers

3. **Comprehensive Testing**
   - Add integration tests for all database queries
   - Test both auth models if keeping both
   - Add migration tests

## Risk Assessment

- **High Risk**: Database queries failing due to schema mismatches
- **High Risk**: Authorization bypass due to mixed auth models
- **Medium Risk**: Data corruption from incomplete transactions
- **Medium Risk**: Performance issues from inefficient queries
- **Low Risk**: Maintenance burden from duplicate code

## Conclusion

The Keycast codebase is in a transitional state with significant technical debt. The incomplete migration from team-based to personal authentication has left the system in an inconsistent state with numerous issues that could lead to runtime failures. Immediate action is required to stabilize the system and complete the migration to prevent further accumulation of technical debt.