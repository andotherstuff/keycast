# Persistent Storage Research Report for Keycast on Cloud Run

**Date**: 2025-10-14
**Status**: Current deployment has NO persistent storage - all data lost on each deployment
**Priority**: CRITICAL - blocks production deployment

---

## Executive Summary

The current Keycast deployment on Cloud Run **loses all user data on every deployment**. The SQLite database lives in the ephemeral container filesystem with no persistence configured. This means:

- All user accounts are wiped
- All encrypted Nostr private keys are lost
- All OAuth authorizations are deleted
- All bunker URLs become invalid

This must be fixed before production use.

---

## The Fundamental Problem

### Current Architecture
```
Cloud Run Container (ephemeral)
├── keycast_api binary
├── database/keycast.db (COPIED FROM LOCAL - gets wiped on redeploy)
└── /app filesystem (destroyed on each deployment)
```

### What Happens Now
1. Dockerfile copies `./database` directory (including local `keycast.db`)
2. Container starts, runs migrations on the copied database
3. Users register, OAuth authorizations are created, keys are encrypted
4. **New deployment**: Container destroyed, all data gone
5. New container starts with fresh copy of old local database

### Impact
- **Zero data persistence** across deployments
- **Complete data loss** for all users
- Production deployment is currently **impossible**

---

## Storage Options Analysis

### Option 1: GCS FUSE (Native Cloud Run Volume Mounts)

**How it works**: Mount Google Cloud Storage bucket as a filesystem using FUSE

**Cost**:
- Storage: ~$0.02/GB/month (~$20/TB)
- First 1GB/month FREE
- Network egress: standard rates

**Configuration**:
```yaml
volumes:
- name: database
  cloudStorage:
    bucket: keycast-database
    mountPath: /data

containers:
- name: keycast-api
  volumeMounts:
  - name: database
    mountPath: /app/database
```

**CRITICAL FLAW: DOES NOT WORK FOR SQLITE**

❌ **Why it fails**:
- GCS FUSE does not provide durable POSIX file locking
- Object storage semantics (rename/locking) make SQLite unsafe
- SQLite requires exclusive locks for safe writes
- Concurrent writes will corrupt the database

**Verdict**: ❌ **REJECTED** - Fundamentally incompatible with SQLite

---

### Option 2: Litestream + Cloud Run Sidecar (RECOMMENDED)

**How it works**:
- Run Litestream as sidecar container alongside API
- Both containers share in-memory volume (emptyDir)
- Litestream continuously replicates SQLite to Google Cloud Storage
- On startup, Litestream restores database from GCS
- Database persists via backup/restore cycle

**Architecture**:
```
Cloud Run Service (multi-container)
├── Container 1: keycast-api
│   ├── Reads/writes to /data/keycast.db
│   └── Shared volume: /data (emptyDir in-memory)
└── Container 2: litestream
    ├── Monitors /data/keycast.db
    ├── Streams WAL pages to GCS
    ├── Restores on startup
    └── Shared volume: /data (emptyDir in-memory)
```

**Cost**:
- GCS storage: $0.02/GB/month (~$20/TB)
- Litestream sidecar: ~0.1-0.2 CPU, 128-256MB memory
- **Total estimated**: $0.03-0.50/month for typical usage
- Quote: "only costs pennies per day"

**Pros**:
- ✅ Extremely cheap (cheaper than Cloud SQL by 10-100x)
- ✅ Keeps SQLite - no architecture changes
- ✅ Proven in production (Fly.io, multiple deployments)
- ✅ Cloud Run native multi-container support (since 2023)
- ✅ Automatic disaster recovery (point-in-time restore)
- ✅ Continuous replication (sub-second backup)
- ✅ Load tested to 5000 QPS with 60 Cloud Run instances

**Cons**:
- ⚠️ More complex setup (multi-container deployment)
- ⚠️ Database lives in memory (counts against memory limits)
- ⚠️ **SINGLE WRITER ONLY** - must set max-instances=1
- ⚠️ Checkpoint management complexity under high load
- ⚠️ Requires autocheckpointing disabled for safety
- ⚠️ Container startup time increased (database restore)

**Technical Concerns**:

1. **Memory Management**
   - emptyDir volumes count against container memory
   - Default size: (Memory Container A + Memory Container B) / 2
   - Google recommends explicit size limit to prevent OOM crashes
   - Example: 2Gi API + 256Mi Litestream = 1.1Gi emptyDir max
   - Need to size for: database file + WAL file + SQLite cache

2. **WAL Mode Requirements**
   - Litestream requires SQLite in WAL mode
   - Litestream takes over checkpoint management
   - Under high load, need to disable autocheckpointing
   - Risk: Application checkpoint can cause Litestream to miss WAL file
   - Mitigation: Explicitly set `PRAGMA auto_vacuum = NONE`

3. **Container Lifecycle**
   - **Cloud Run doesn't support inter-container dependencies**
   - Use startup/readiness probes + app-level DB open retry (30s) to tolerate restore timing
   - Litestream's restore creates `/data/keycast.db` if missing
   - Shutdown: SIGTERM gives 10 seconds before SIGKILL
   - Risk: Incomplete replication if shutdown too fast
   - Mitigation: Litestream hooks into SIGTERM for final flush

4. **Single Instance Limitation**
   - Litestream is NOT multi-instance compatible
   - Must set `--max-instances=1` on Cloud Run
   - Multiple instances = SQLITE_BUSY errors + corruption
   - This limits horizontal scaling

5. **Consistency Model**
   - Litestream provides **eventually consistent** replicas
   - Replication lag typically <1 second
   - On crash: may lose last few transactions
   - Not a distributed database - disaster recovery focused

**Implementation Steps**:

1. Create GCS bucket for Litestream replication
2. Configure Litestream sidecar in Cloud Run YAML
3. Add shared emptyDir volume
4. Set container startup dependencies
5. Configure Litestream config file
6. Update Dockerfile for multi-container support
7. Set `--max-instances=1` on deployment
8. Test restore process

**Example Cloud Run YAML snippet**:
```yaml
containers:
- name: keycast-api
  image: us-central1-docker.pkg.dev/PROJECT/docker/keycast:latest
  args: ["api"]
  depends_on:
  - litestream
  volumeMounts:
  - name: database
    mountPath: /app/database

- name: litestream
  image: litestream/litestream:latest
  args: ["replicate"]
  volumeMounts:
  - name: database
    mountPath: /app/database
  - name: litestream-config
    mountPath: /etc/litestream.yml
    subPath: litestream.yml

volumes:
- name: database
  emptyDir:
    sizeLimit: 500Mi
- name: litestream-config
  secret:
    secretName: litestream-config
```

**Verdict**: ✅ **RECOMMENDED** - Best balance of cost, simplicity, and reliability

---

### Option 3: Cloud Filestore (NFS)

**How it works**: Mount managed NFS share from Cloud Filestore

**Cost**:
- Basic HDD (Standard): $0.16/GB/month minimum
- Minimum instance: 1TB = **$163.84/month**
- Basic SSD (Premium): $0.20/GB/month minimum
- Zonal: $0.12/GB/month, minimum 1TB = **$122.88/month**

**Pros**:
- ✅ True persistent filesystem
- ✅ Multi-instance writes (NFS locking)
- ✅ No data loss on deployment
- ✅ Cloud Run native NFS mount support

**Cons**:
- ❌ **EXTREMELY EXPENSIVE** - minimum $122/month
- ❌ 1TB minimum capacity (way more than needed)
- ❌ Overkill for small SQLite database
- ❌ Network latency for all database operations
- ❌ You explicitly rejected expensive options

**Verdict**: ❌ **REJECTED** - Too expensive for this use case

---

### Option 4: Cloud SQL (Managed PostgreSQL/MySQL)

**Cost**:
- Shared-core instance: $7-30+/month minimum
- db-f1-micro: ~$9.37/month (0.6GB RAM)
- db-g1-small: ~$25.55/month (1.7GB RAM)
- Plus storage: ~$0.17/GB/month

**Pros**:
- ✅ Fully managed
- ✅ True persistence
- ✅ Multi-instance support
- ✅ Automated backups

**Cons**:
- ❌ Requires complete rewrite (SQLite → Postgres/MySQL)
- ❌ Migration overhead for existing data
- ❌ More expensive than Litestream
- ❌ You explicitly said "cloud sql is fuckign epxneisve crap"

**Verdict**: ❌ **REJECTED** - Too expensive, requires rewrite

---

### Option 5: Turso (Hosted libSQL)

**How it works**: Managed SQLite-compatible database service (libSQL fork)

**Cost**:
- Free tier: 500M rows read, 10M rows written, 5GB storage
- Developer plan: $4.99/month (2.5B rows read)
- First 500 databases FREE

**Pros**:
- ✅ SQLite-compatible (minimal code changes)
- ✅ Generous free tier
- ✅ Multi-region replication built-in
- ✅ No infrastructure management
- ✅ True multi-instance support
- ✅ Designed for edge/serverless

**Cons**:
- ⚠️ External dependency (third-party service)
- ⚠️ Requires changing connection string
- ⚠️ libSQL is a fork (not pure SQLite)
- ⚠️ Vendor lock-in concerns
- ⚠️ Network latency for all queries
- ⚠️ Need to evaluate API compatibility with sqlx

**Verdict**: ⚠️ **VIABLE ALTERNATIVE** - Worth considering if Litestream proves problematic

---

## Current Database State Analysis

### Local Database File
```bash
# Check current database status
cd /Users/rabble/code/andotherstuff/keycast/database
ls -lh keycast.db
```

### Migration Status
- Migrations 1-5: Already applied to local database
- Migration 6: Currently failing with "duplicate column name: email_verified"
- Root cause: Dockerfile copies database WITH migrations already applied

### The Migration Conflict Problem
```
Local keycast.db (has migrations 1-5 applied)
    ↓ (copied via Dockerfile)
Container keycast.db (has migrations 1-5)
    ↓ (migrations run on startup)
Migration 6 tries to add email_verified column
    ❌ FAILS: column already exists
```

**Solution**: Once persistent storage is implemented, DO NOT copy the database file. Only copy migration files.

---

## Critical Questions

### 1. How many concurrent users do you expect?
- **Why it matters**: Litestream requires single-instance mode
- Cloud Run max-instances=1 means limited concurrency
- Need to understand if this is acceptable

### 2. What's your acceptable data loss window?
- **Litestream**: May lose 1-2 seconds of data on crash
- **Turso**: No data loss (managed service)
- **Filestore**: No data loss (persistent NFS)

### 3. What's your database size projection?
- **Current**: Empty/test data only
- **1 year**: How many users? How many OAuth authorizations?
- **Why it matters**: Affects memory allocation for emptyDir

### 4. What's your uptime requirement?
- **Litestream**: Single instance = single point of failure
- During deployment: brief downtime while database restores
- **Turso**: Multi-region, high availability

### 5. Can you tolerate single-instance limitation?
- **Litestream**: Forces max-instances=1
- This means:
  - One container handles all requests
  - Limited to that container's CPU/memory
  - No horizontal scaling
  - But: Can still vertically scale (more CPU/memory)

---

## Cost Comparison

### Scenario: Small production deployment (1-100 users)

| Option | Monthly Cost | Setup Complexity | Data Safety | Scaling |
|--------|-------------|------------------|-------------|---------|
| **GCS FUSE** | $0.02 | Low | ❌ Corrupts | Good |
| **Litestream** | $0.03-0.50 | Medium | ✅ 1-2s loss | Limited (single instance) |
| **Filestore** | $122.88 | Medium | ✅ No loss | Excellent |
| **Cloud SQL** | $9.37+ | High | ✅ No loss | Excellent |
| **Turso** | FREE | Low | ✅ No loss | Excellent |

### Scenario: Medium production (100-1000 users)

| Option | Monthly Cost | Notes |
|--------|-------------|-------|
| **Litestream** | $1-5 | Still pennies, but need bigger emptyDir |
| **Filestore** | $122.88 | Same minimum cost |
| **Cloud SQL** | $25-50 | Need larger instance |
| **Turso** | $4.99 | Still within free/dev tier |

**Winner**: Litestream or Turso (both <$5/month vs $122+ for alternatives)

---

## Technical Risks

### Litestream Risks

1. **Single Instance Bottleneck**
   - Can't scale horizontally
   - All traffic goes through one container
   - Mitigation: Vertical scaling (more CPU/memory)

2. **Checkpoint Race Conditions**
   - High write load can trigger application checkpoints
   - Litestream may miss WAL file
   - Mitigation: Disable autocheckpointing explicitly

3. **Restore Time on Cold Start**
   - Container startup delayed by database restore
   - Depends on database size
   - Mitigation: Keep database small, optimize restore

4. **Memory Pressure**
   - Database + WAL live in memory
   - Large databases consume container memory
   - Mitigation: Set explicit emptyDir size limits

5. **Data Loss Window**
   - Catastrophic crash may lose 1-2 seconds
   - Not suitable for financial transactions
   - Acceptable for user profiles/OAuth?

### Turso Risks

1. **External Dependency**
   - Service outage = your app is down
   - Network latency for every query
   - Trust third-party with encrypted keys

2. **API Compatibility**
   - libSQL is a fork of SQLite
   - Need to verify sqlx compatibility
   - May have subtle differences

3. **Vendor Lock-in**
   - Migrating away requires data export
   - Less control than self-hosted

---

## Recommended Path Forward

### Phase 1: Immediate Fix (Litestream)

**Why**:
- Cheapest option (~$0.50/month)
- Keeps existing SQLite code
- Proven in production
- Fast to implement

**Constraints accepted**:
- Single instance limitation (max-instances=1)
- 1-2 second data loss window on catastrophic crash
- More complex deployment configuration

**Implementation time**: 1-2 days

---

### Phase 2: Evaluate Performance

**After Litestream deployed**:
- Monitor single-instance performance
- Measure request latency
- Track memory usage
- Evaluate restore times

**Decision point**:
- If single instance is sufficient → keep Litestream
- If need multi-instance → evaluate Turso or Cloud SQL

---

### Phase 3: Scale Options

**If traffic grows beyond single instance**:

1. **Vertical scaling** (try first)
   - Increase CPU: 2 → 4 → 8 vCPU
   - Increase memory: 2Gi → 4Gi → 8Gi
   - May handle 100s of concurrent requests

2. **Migrate to Turso** (if vertical scaling insufficient)
   - Minimal code changes (SQLite-compatible)
   - Free tier supports significant load
   - Native multi-instance support

3. **Cloud SQL** (last resort)
   - Requires full rewrite
   - Most expensive option
   - Maximum scalability

---

## Implementation Checklist (Litestream)

### Prerequisites
- [ ] Create GCS bucket: `keycast-database-backups`
- [ ] Grant Cloud Run service account access to bucket
- [ ] Decide emptyDir volume size (recommend: 500Mi initially)
- [ ] Choose CPU throttling mode:
  - [ ] `cpu-throttling: false` = continuous replication (slightly higher cost)
  - [ ] `cpu-throttling: true` = save $ (replication may lag between requests)

### Code Changes
- [ ] Create `litestream.yml` configuration
- [ ] Update Dockerfile for multi-container support
- [ ] Create Cloud Run service YAML with sidecars
- [ ] Update `cloudbuild.yaml` for new deployment config
- [ ] Add startup dependency: API depends on Litestream
- [ ] Configure SQLite WAL mode in Database::new()
- [ ] Disable SQLite autocheckpointing

### Deployment Changes
- [ ] Set `--max-instances=1` on keycast-oauth service
- [ ] Set `--min-instances=1` (keeps warm instance, continuous replication, slightly higher cost)
- [ ] Add emptyDir volume definition
- [ ] Add Litestream sidecar container
- [ ] Add startup/readiness probes (no inter-container dependencies in Cloud Run)
- [ ] Update health checks for both containers

### Testing
- [ ] Test restore on fresh deployment
- [ ] Verify replication to GCS
- [ ] Test data persists across deployments
- [ ] Measure startup time (restore performance)
- [ ] Load test with concurrent writes
- [ ] Test graceful shutdown (SIGTERM handling)

### Migration
- [ ] Export current database (if any production data exists)
- [ ] Upload to GCS bucket
- [ ] Deploy new Litestream-based setup
- [ ] Verify data restore
- [ ] Run production verification tests

---

## Open Questions for Rabble

1. **Are you okay with single-instance limitation?**
   - Litestream requires max-instances=1
   - Limits horizontal scaling
   - Alternative: Turso (multi-instance, but external service)

2. **What's your expected database size in 6 months?**
   - Affects memory allocation
   - Need to size emptyDir volume appropriately

3. **Is 1-2 second data loss acceptable on catastrophic crash?**
   - Litestream's consistency model
   - Not suitable for financial data
   - Probably fine for user profiles/OAuth

4. **Do you want to try Litestream first, or go straight to Turso?**
   - Litestream: Cheaper, self-hosted, single-instance
   - Turso: Still cheap, managed, multi-instance

5. **What's your priority: cost or scalability?**
   - Cost → Litestream ($0.50/mo)
   - Scalability → Turso ($5/mo) or Cloud SQL ($25+/mo)

---

## Conclusion

**Critical takeaway**: Current deployment LOSES ALL DATA on every deploy. Must fix immediately.

**Recommended solution**: **Litestream + Cloud Run sidecar**
- Cheapest option (~$0.50/month vs $122+ for alternatives)
- Keeps SQLite (no code rewrite)
- Proven in production
- Acceptable trade-offs for this use case

**Trade-offs accepted**:
- Single instance limitation
- 1-2 second data loss window on crash
- More complex deployment

**Alternative if single-instance is problematic**: **Turso**
- Still very cheap ($0-5/month)
- Multi-instance support
- SQLite-compatible
- Managed service

**Next step**: Need your decision on which path to take.
