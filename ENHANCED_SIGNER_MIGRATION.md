# Enhanced Signer Migration Guide

## Overview

This guide documents the migration from the team-based signer to the enhanced user-based signer that supports both legacy team authorizations and new personal authorizations.

## What's Been Implemented

### 1. Enhanced Authorization Type (`authorization_enhanced.rs`)
- Supports both team-based (legacy) and user-based authorization models
- Automatically detects which model to use based on data presence
- Provides unified interface for key retrieval (`get_key_secret()`)
- Maintains backward compatibility with existing authorizations

### 2. Enhanced Signer Daemon (`signer_daemon_enhanced.rs`)
- Drop-in replacement for the original signer daemon
- Automatically handles both authorization types
- Logs which model is being used for each authorization
- Uses the same NIP-46 implementation underneath

### 3. Configurable Signer Manager
- Updated to support both daemons via environment variable
- Set `USE_ENHANCED_SIGNER=true` to use the enhanced version
- Defaults to original daemon for backward compatibility

## Migration Steps

### Phase 1: Testing (Recommended First Step)

1. **Test with existing team-based authorizations:**
   ```bash
   # Use enhanced signer with existing data
   export USE_ENHANCED_SIGNER=true
   ./keycast_signer
   ```

2. **Monitor logs to verify:**
   - Enhanced daemon starts correctly
   - Detects legacy authorizations properly
   - Processes NIP-46 requests as expected

### Phase 2: Gradual Rollout

1. **Enable for specific environments:**
   ```bash
   # Development
   USE_ENHANCED_SIGNER=true ./keycast_signer
   
   # Keep production on original until verified
   ./keycast_signer
   ```

2. **Create new user-based authorizations:**
   - New authorizations will have `user_id` and `user_key_id`
   - Enhanced daemon will detect and use user-based flow
   - Legacy authorizations continue working unchanged

### Phase 3: Full Migration

1. **Enable enhanced signer globally:**
   ```bash
   # In your environment configuration
   export USE_ENHANCED_SIGNER=true
   ```

2. **Update Docker/deployment configs:**
   ```dockerfile
   ENV USE_ENHANCED_SIGNER=true
   ```

## Key Differences

### Database Fields
- **Legacy**: Uses `stored_key_id` linked to teams
- **Enhanced**: Uses `user_id` and `user_key_id` for personal keys
- Both modes check `stored_key_id` value (0 or null indicates user-based)

### Authorization Flow
- **Legacy**: Team → StoredKey → Authorization
- **Enhanced**: User → UserKey → Authorization → App

### Relay Handling
- Database stores relays as JSON string
- Enhanced type provides `get_relays()` method for parsing
- Bunker URL generation remains consistent

## Verification Steps

1. **Check authorization detection:**
   ```sql
   -- Find user-based authorizations
   SELECT id, user_id, user_key_id, stored_key_id 
   FROM authorizations 
   WHERE user_id IS NOT NULL;
   
   -- Find legacy authorizations
   SELECT id, stored_key_id 
   FROM authorizations 
   WHERE stored_key_id > 0;
   ```

2. **Monitor signer logs:**
   - Look for "Using user-based authorization model" or "Using legacy team-based authorization model"
   - Verify bunker URLs are generated correctly
   - Check NIP-46 request processing

3. **Test both authorization types:**
   - Create a new user-based authorization through the UI
   - Ensure existing team-based authorizations still work
   - Verify policy validation works for both types

## Rollback Plan

If issues arise, rollback is simple:

1. **Disable enhanced signer:**
   ```bash
   unset USE_ENHANCED_SIGNER
   # or
   export USE_ENHANCED_SIGNER=false
   ```

2. **Restart signer manager:**
   - Original daemon will be used
   - No data changes required
   - All authorizations continue working

## Benefits of Migration

1. **Unified Codebase**: Single implementation supports both models
2. **Future Ready**: New personal auth features work seamlessly
3. **No Breaking Changes**: Existing authorizations continue working
4. **Gradual Transition**: Move at your own pace
5. **Better Logging**: Clear indication of which model is in use

## Troubleshooting

### Common Issues

1. **"No key found for authorization"**
   - Check if authorization has either `stored_key_id` or `user_key_id`
   - Verify the referenced key exists in database

2. **"Binary not found"**
   - Ensure both `signer_daemon` and `signer_daemon_enhanced` are built
   - Check binary is in same directory as main signer

3. **Relay parsing errors**
   - Verify `relays` column contains valid JSON array
   - Check for any data migration issues

### Debug Commands

```bash
# Check which daemon is being used
ps aux | grep signer_daemon

# View authorization details
sqlite3 keycast.db "SELECT * FROM authorizations WHERE id = X"

# Monitor real-time logs
tail -f /path/to/signer.log | grep "authorization model"
```

## Next Steps

After successful migration:

1. **Update documentation** to reflect enhanced signer as default
2. **Remove legacy code** once all authorizations are migrated
3. **Optimize database** by removing unused team-related tables
4. **Update monitoring** to track both authorization types

## Support

For issues or questions:
- Check signer logs for detailed error messages
- Review this migration guide
- Consult the implementation plan in `PERSONAL_NOSTR_AUTH_IMPLEMENTATION_PLAN.md`