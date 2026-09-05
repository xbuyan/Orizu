# Orizu

A dead man's switch for evidence and secrets, built on Shamir's Secret Sharing.

Orizu holds no automated trust: shares are held by human guardians, not
servers, and release only follows failure to prove continued, active control
— not a passive device heartbeat. On trigger, Orizu feeds conditional release
into [Sentinel](https://github.com/xbuyan/sentinel)'s evidence escrow.

Third project in a sequential security infrastructure roadmap:
Kinga → [Aegis](https://github.com/xbuyan/aegis) → Orizu → Sentinel → Deni → Msafiri.

## Status

Early scaffold. No components built yet.

## Design principles

- **Guardians, not infrastructure.** Shares are held by people who must act,
  not automated custody that could release at the wrong time or to the wrong
  party.
- **Active proof of life, not a heartbeat.** "Checked in" must require
  something that demonstrates it's genuinely you — a passive device signal
  can keep pinging even after the device itself is seized or compromised.

## License

MIT