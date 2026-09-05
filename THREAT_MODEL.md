# Threat Model (draft — pre-build)

This file will track deliberate deferrals and trust assumptions as Orizu is
built, following the same practice as Aegis's THREAT_MODEL.md.

## Decided so far

- **Guardian custody over automated custody.** Shares are held by human
  guardians rather than servers or automated systems. Rationale: a fully
  automated release mechanism risks firing at the wrong time, or releasing
  to the wrong or least-relevant party. This trades convenience for requiring
  a human judgment call at the moment of release.
- **Active proof-of-life requirement.** A "checked in" state must be backed
  by active proof that it is genuinely the owner, not a passive device
  heartbeat — a device that is seized but still powered/connected could
  otherwise keep signaling "alive" after compromise. The exact mechanism for
  this proof is not yet designed.

## Open questions (not yet resolved)

- What constitutes "active proof of life" (mechanism TBD)
- Check-in interval and grace period
- Guardian threshold (how many of N guardians needed to act on trigger)
- How trigger state hands off into Sentinel's escrow