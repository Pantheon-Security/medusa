# Cost Management Notes

## Website Updates - Credit Usage

**Status:** Near monthly limit
**Date:** 2025-01-19

### Guidelines:
- ❌ **Avoid unnecessary website updates** (pantheonsecurity.io, docs, etc.)
- ✅ Only update website when specifically requested
- ✅ Test changes locally first
- ✅ Batch multiple updates together when possible

### pantheonsecurity.io Strategy:
- **Current status:** Development on Netlify
- **Next update:** Go live (production launch) - FINAL UPDATE
- **After go live:** Site is stable, minimal/no updates needed
- **Result:** Near-zero Netlify build minutes after launch

### What costs credits:
- **Netlify build minutes** for pantheonsecurity.io
  - Free tier: 300 build minutes/month
  - Currently: Near limit
- Website deployments trigger builds
- Documentation rebuilds
- CI/CD pipeline runs

### Notes:
- Can purchase more credits if absolutely needed, but not ideal
- Focus on core MEDUSA development (PyPI, GitHub)
- Website updates should be intentional, not automatic

---
*Last updated: 2025-01-19*
