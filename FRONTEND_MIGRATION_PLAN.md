# Keycast Frontend Migration Plan: Team-based to Personal Authentication

**Created**: July 23, 2025  
**Status**: Planning Phase  
**Estimated Duration**: 6-8 weeks

## Executive Summary

This document outlines the comprehensive plan for migrating the Keycast frontend from a team-based authentication system to a personal authentication system. The migration will transform the entire user interface while maintaining backward compatibility during the transition period.

## Current State Analysis

### Existing Frontend Architecture
- **Framework**: [To be determined - need to check]
- **UI Components**: Team-centric (team creation, member management, team keys)
- **Authentication**: Team-based login and authorization
- **State Management**: Team context throughout application

### Backend Readiness
- ✅ API Layer: 90% complete (missing only app management)
- ✅ Database: Dual-model support ready
- ✅ Core Types: Enhanced authorization supporting both models
- ✅ Authentication: Session-based auth implemented

## Migration Strategy

### Phase 1: Foundation (Week 1-2)
**Goal**: Set up infrastructure for gradual migration

1. **Feature Flag System**
   - Implement `PERSONAL_AUTH_ENABLED` flag
   - Create context provider for auth mode
   - Build mode detection logic

2. **Routing Architecture**
   - Duplicate route structure for personal mode
   - `/personal/*` routes alongside `/teams/*`
   - Gradual redirect logic

3. **Component Abstraction Layer**
   - Create auth-agnostic base components
   - Build adapter pattern for team/personal modes
   - Shared UI components library

### Phase 2: Core UI Components (Week 3-4)
**Goal**: Build personal authentication UI components

1. **Authentication Pages**
   - [ ] Login page (email/password)
   - [ ] Registration page
   - [ ] Password reset flow
   - [ ] Two-factor setup (future)

2. **Personal Dashboard**
   - [ ] User profile overview
   - [ ] Quick stats (keys, apps, policies)
   - [ ] Recent activity feed
   - [ ] Action buttons (create key, manage apps)

3. **Navigation Structure**
   ```
   Personal Mode:
   - Dashboard
   - My Keys
   - My Policies  
   - Connected Apps
   - Settings
   
   Team Mode (Legacy):
   - Teams
   - Team Keys
   - Team Members
   - Settings
   ```

### Phase 3: Key Management UI (Week 4-5)
**Goal**: Implement personal key management interface

1. **Key List View**
   - [ ] Display all user keys
   - [ ] Status indicators (primary, active, rotating)
   - [ ] Quick actions (set primary, rotate, delete)
   - [ ] Search and filter

2. **Key Creation Flow**
   - [ ] Step-by-step wizard
   - [ ] Key type selection
   - [ ] Name and metadata input
   - [ ] Success confirmation with backup reminder

3. **Key Details Page**
   - [ ] Full key information
   - [ ] Usage statistics
   - [ ] Rotation history
   - [ ] Associated authorizations

### Phase 4: Policy Management UI (Week 5)
**Goal**: Create intuitive policy editor

1. **Policy List View**
   - [ ] Template gallery
   - [ ] Custom policies list
   - [ ] Quick create from template
   - [ ] Active/inactive status

2. **Policy Editor**
   - [ ] Visual rule builder
   - [ ] JSON editor fallback
   - [ ] Permission matrix
   - [ ] Test policy feature

3. **Policy Templates**
   - [ ] Pre-built templates showcase
   - [ ] One-click apply
   - [ ] Customization wizard

### Phase 5: Application Management UI (Week 6)
**Goal**: Build application authorization interface

1. **Connected Apps View**
   - [ ] App cards with icons
   - [ ] Authorization count
   - [ ] Last used timestamp
   - [ ] Quick revoke action

2. **App Authorization Flow**
   - [ ] Authorization request page
   - [ ] Permission review
   - [ ] Policy selection
   - [ ] Confirmation screen

3. **App Discovery**
   - [ ] Browse verified apps
   - [ ] Search functionality
   - [ ] App details modal

### Phase 6: Settings & Profile (Week 7)
**Goal**: Complete user management features

1. **Profile Management**
   - [ ] Edit profile info
   - [ ] Upload avatar
   - [ ] NIP-05 configuration
   - [ ] Account deletion

2. **Security Settings**
   - [ ] Active sessions list
   - [ ] Auth method management
   - [ ] Security alerts config
   - [ ] Export account data

3. **Preferences**
   - [ ] UI theme selection
   - [ ] Notification settings
   - [ ] Default policies
   - [ ] Advanced options

### Phase 7: Migration & Rollout (Week 8)
**Goal**: Deploy and monitor migration

1. **Migration Tools**
   - [ ] Team to personal migration wizard
   - [ ] Bulk key import
   - [ ] Policy conversion
   - [ ] Data validation

2. **Rollout Strategy**
   - Beta users (10%)
   - Gradual rollout (25%, 50%, 100%)
   - A/B testing setup
   - Rollback procedures

3. **Monitoring**
   - User adoption metrics
   - Error tracking
   - Performance monitoring
   - Feedback collection

## Technical Considerations

### State Management
```typescript
interface AuthContext {
  mode: 'personal' | 'team';
  user?: PersonalUser;
  team?: TeamUser;
  switchMode: (mode: AuthMode) => void;
}
```

### API Integration
```typescript
// Unified API client
class KeycastAPI {
  // Mode-aware endpoints
  async getKeys() {
    return this.mode === 'personal' 
      ? this.get('/api/users/keys')
      : this.get('/api/teams/:id/keys');
  }
}
```

### Component Architecture
```
components/
├── shared/          # Mode-agnostic components
├── personal/        # Personal-mode specific
├── team/           # Team-mode specific (legacy)
└── adapters/       # Mode adapters
```

## UI/UX Guidelines

### Design Principles
1. **Simplicity First**: Personal auth should feel simpler than team auth
2. **Progressive Disclosure**: Advanced features hidden until needed
3. **Mobile-First**: All features must work on mobile
4. **Accessibility**: WCAG 2.1 AA compliance

### Visual Design
- Clean, modern interface
- Clear visual hierarchy
- Consistent color scheme
- Intuitive iconography
- Helpful empty states

### User Flows
1. **First-Time User**
   - Welcome screen → Register → Create first key → Connect first app

2. **Returning User**
   - Login → Dashboard → Quick actions

3. **Power User**
   - Dashboard → Manage multiple keys → Complex policies → Bulk operations

## Testing Strategy

### Unit Tests
- Component isolation tests
- API integration tests
- State management tests

### Integration Tests
- Full user flows
- Cross-mode compatibility
- Migration scenarios

### E2E Tests
- Critical path coverage
- Performance benchmarks
- Error handling

### User Testing
- Beta user feedback
- Usability studies
- A/B test results

## Rollback Plan

### Triggers
- Critical bugs affecting > 5% users
- Performance degradation > 20%
- User adoption < 10% after 2 weeks

### Procedures
1. Feature flag disable (immediate)
2. Route redirection (5 minutes)
3. Full code rollback (30 minutes)

### Data Preservation
- All personal data retained
- Team data untouched
- Migration state saved

## Success Metrics

### Adoption
- 50% users try personal mode (Week 1)
- 80% users switch permanently (Week 4)
- 95% satisfaction rating

### Performance
- Page load < 2s
- API response < 200ms
- 99.9% uptime

### Engagement
- 2x key creation rate
- 3x app connections
- 50% policy customization

## Risk Mitigation

### Technical Risks
- **Risk**: Frontend framework incompatibility
  - **Mitigation**: Gradual component migration

- **Risk**: State management complexity
  - **Mitigation**: Comprehensive testing, phased rollout

### User Risks
- **Risk**: Confusion during transition
  - **Mitigation**: Clear mode indicators, help documentation

- **Risk**: Data loss fears
  - **Mitigation**: Explicit data preservation guarantees

## Next Steps

1. **Immediate Actions**
   - Identify frontend framework and current architecture
   - Set up feature flag system
   - Create component inventory

2. **Week 1 Goals**
   - Design mockups for key screens
   - Set up new routing structure
   - Build first personal mode component

3. **Stakeholder Communication**
   - Weekly progress updates
   - Beta user recruitment
   - Documentation preparation

## Appendix

### A. Component Inventory
[To be completed after frontend analysis]

### B. Route Mapping
[To be completed after route planning]

### C. API Endpoint Usage
[Reference to implemented endpoints]

### D. Migration Checklist
[Detailed checklist for migration day]