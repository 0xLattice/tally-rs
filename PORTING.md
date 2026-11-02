# Port coverage

Reference source: 0xLattice/Tally f8b80ee09a1ed5768f2263ff71c7c745bf946922.

| Swift source | Rust implementation | Evidence |
| --- | --- | --- |
| PeerID, KeyDifficulty | PeerId, canonical_raw_hex, trailing_zero_bits, key_work_bits, base_trust | 105 Swift cases; malformed and multikey alias tests |
| PeerEvidence | internal Evidence | 100 Swift decay/score cases; violation test |
| AdmissionController | Tally pressure/buckets | refill, saturation, pressured and idle admission tests |
| BoundedMap | internal Bounded | peer and challenge eviction tests |
| TallyConfig | Config validate/default | invalid finite/range/bound tests |
| Tally, TallyMetrics | Tally, Metrics | state/standing, reset, ignored nonpositive traffic, saturating metrics behavior |
| Challenge, ChallengeSolver | Challenge, Challenge::solve | 100 Swift first-solution cases; live solve/verify |
| ChallengeService | Tally issue/verify | binding, metadata tamper, successful-use replay, expiry/reset/eviction |
| CreditLine | CreditLine | 480 Swift operation-sequence cases; numeric extreme tests |
| CreditLineLedger | CreditLineLedger | establish/relay operations, concurrent updates |
| Lock | Arc/Mutex | concurrent ledger test |

Intentional Rust adaptations: recoverable configuration errors instead of Swift precondition traps; methods use snake_case; immutable identity fields are getters; solver is a Challenge method; thread-safe ledger is synchronous instead of a Swift actor; native Int accounting uses i64. Only little-endian solver representation is emitted, matching supported Swift hosts. No serialization protocol is introduced by this crate.

Remaining integration verification: network/node attribution of useful content, end-to-end admission and settlement traffic, Linux/Windows CI. These are not claimed complete by source-level port or fixture parity.
