# Database Architecture Decision: SQLite vs PostgreSQL

**Decision Date:** 2025-10-17
**Status:** STAY ON SQLITE (for now)

## TL;DR

**Stay on SQLite** until we hit 1,000+ users or see SQLITE_BUSY errors in production. Current scale (dev, no users) doesn't justify PostgreSQL migration.

**Migration Trigger:** Move to PostgreSQL when:
- 1,000+ active users OR
- SQLITE_BUSY errors >1% of queries OR
- 3+ active tenants with regular traffic

## Key Research Findings

### 1. Database-Level Encryption: NOT NEEDED
- **We already use GCP KMS** to encrypt private keys at application level
- Database stores encrypted blobs (not plaintext keys)
- Database-level encryption adds minimal security value
- Key custody providers (Fireblocks, BitGo) use application-level encryption, not DB encryption

### 2. SQLite Write Performance: MORE THAN SUFFICIENT
- **SQLite capacity:** 3,600 writes/sec (proven in production)
- **Our projected load:** ~0.01 writes/sec (1,100 writes/day for 5 tenants × 20 users)
- **Headroom:** 360,000x capacity
- **Won't be a bottleneck until:** 10,000+ users with high concurrent activity

### 3. PostgreSQL Row-Level Security: NICE BUT NOT REQUIRED
- RLS provides runtime safety (not compile-time)
- Prevents developer bugs (forgot tenant_id in WHERE)
- Can implement same safety with integration tests on SQLite
- RLS is defense-in-depth, not a forcing function for migration

### 4. Cost Comparison

| Setup | Monthly Cost | Annual Cost |
|-------|--------------|-------------|
| SQLite + Litestream (current) | $5-10 | $60-120 |
| PostgreSQL (Neon) | $19 | $228 |
| PostgreSQL (Supabase) | $25 | $300 |
| PostgreSQL (Cloud SQL) | $50-100 | $600-1,200 |

**Migration cost:** 2-3 developer days (~$1,000-2,000)

### 5. Multi-Tenant Architecture Options

**Option A: Shared Schema with tenant_id (CURRENT)**
- Single database, tenant_id column on all tables
- Application-level filtering in queries
- Pros: Simple, cost-effective, scales to 100+ tenants
- Cons: Requires discipline (every query must filter by tenant_id)

**Option B: Database-Per-Tenant**
- Separate SQLite file per tenant
- Complete isolation
- Pros: Strong isolation, easier tenant deletion
- Cons: Operational complexity (50+ tenants)
- Viable range: 10-50 tenants

**Option C: PostgreSQL with RLS**
- Shared database, RLS policies enforce tenant isolation
- Automatic tenant_id filtering
- Pros: Defense-in-depth, prevents bugs
- Cons: Migration effort, higher cost

**Recommendation:** Option A (current) until scale justifies Option C

## Decision Matrix

| Criteria | SQLite | PostgreSQL | Winner |
|----------|--------|------------|--------|
| Current scale (0 users) | ✅ Perfect | ❌ Overkill | **SQLite** |
| Future scale (1,000 users) | ⚠️ Approaching limit | ✅ Easy | PostgreSQL |
| Write performance | 3,600/sec | Unlimited | Tie |
| Multi-tenant safety | Manual filtering | RLS auto-filtering | PostgreSQL |
| Development velocity | ✅ Simple | ⚠️ Docker setup | **SQLite** |
| Cost (first year) | $60-120 | $228-300 | **SQLite** |
| Migration effort | N/A | 2-3 days | **SQLite** |
| Team collaboration | ⚠️ Harder | ✅ Easier | PostgreSQL |

**Winner for Current Stage:** SQLite (5-2)

## Action Plan

### Immediate (Now)
✅ **Stay on SQLite + Litestream**
✅ **Add tenant isolation integration tests**
✅ **Monitor for SQLITE_BUSY errors**
✅ **Set alerts:** Error rate >1%, p95 latency >500ms

### When to Migrate (Future)
Migrate to PostgreSQL when ANY of these trigger:
- Active users >1,000
- SQLITE_BUSY errors >1% of queries
- Team size >3 developers
- Planning SOC 2 compliance audit

### Migration Target (When Triggered)
**Provider:** Neon Launch ($19/mo)
**Compute:** 0.25 CU (serverless)
**Storage:** 10GB
**Effort:** 2-3 days (query updates, RLS policies, testing)

## Why NOT Database-Level Encryption?

**Your threat model:**
1. SQL injection → KMS encryption protects (attacker gets encrypted blobs)
2. Database backup theft → KMS encryption protects (backups are encrypted blobs)
3. Malicious admin → KMS encryption protects (admin sees encrypted blobs)
4. Physical disk theft → Cloud Run uses ephemeral storage (non-issue)

**Database encryption would protect:**
- Physical disk theft (already mitigated by Cloud Run)
- GCS bucket compromise (server-side encryption already enabled)

**Marginal value:** Database encryption adds ~5% additional security for 3-10x cost increase.

**Industry practice:** Key custody providers use application-level encryption (HSM/KMS), not database-level encryption.

## Why NOT PostgreSQL (Right Now)?

1. **No users:** Optimizing for scale you don't have
2. **No write bottleneck:** Using 0.0003% of SQLite capacity
3. **Cost:** 3-5x more expensive ($228/year vs $60/year)
4. **Migration time:** 2-3 dev days better spent on features
5. **Litestream works:** Current backup/restore is solid

## Why PostgreSQL (Eventually)?

1. **Unlimited concurrent writes:** SQLite bottleneck removed
2. **RLS for tenant isolation:** Defense against developer bugs
3. **Team collaboration:** Easier than sharing .db files
4. **Industry standard:** More familiar for hiring
5. **Compliance:** Better audit trail for SOC 2

## References

- **SQLite Performance:** High Performance SQLite, fractaledmind.com
- **PostgreSQL RLS:** Crunchy Data, Supabase blog, Logto blog (2024)
- **Multi-Tenant Patterns:** Neon blog, AWS Prescriptive Guidance
- **Key Custody:** Fireblocks, BitGo architecture (application-level encryption)
- **Pricing:** Neon, Supabase, Render, Cloud SQL (2025 pricing)

---

**Bottom Line:** SQLite is the right choice today. PostgreSQL is the right choice at scale. Let scale tell you when to migrate.
