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
- **Guardian threshold: 3-of-3.** All three guardians must act to trigger
  release — a deliberately higher bar than Kinga's 2-of-3 recovery threshold.
  For a dead-man's-switch, a false or coerced trigger is a worse failure mode
  than requiring full guardian consensus; this trades resilience against a
  single unreachable guardian for resistance to a single compromised or
  coerced one.

## Open questions (not yet resolved)

- What constitutes "active proof of life" (mechanism TBD)
- Check-in interval and grace period
- How trigger state hands off into Sentinel's escrow