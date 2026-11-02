# lattice-tally

Rust port of the 0xLattice Tally peer accounting and admission library. Original MIT license is retained.

Reference: `https://github.com/0xLattice/Tally` at `f8b80ee09a1ed5768f2263ff71c7c745bf946922`.

Implemented public behavior:

- Canonical raw Ed25519 hex and `ed01` multikey aliases; identity work is SHA-256 of the **hex text**, measured from trailing bits. Malformed or opaque strings remain unchanged.
- Half-life-decayed sent/received evidence, violations, challenge work, admission score, global rate pressure, per-peer refill buckets, bounded access-order eviction.
- Nondecaying positive standing, useful-content credits, saturating signed 64-bit counters, restoration snapshots, serving priority, peer resets that preserve standing.
- Cryptographically random peer-bound challenge nonces, expiry, metadata matching, successful-use replay protection, bounded outstanding state, little-endian counter solver.
- Saturating signed balances, sequence numbers, logarithmic settlement threshold growth, partial/missed settlement, shared thread-safe credit ledger.

`Tally` and `CreditLineLedger` clones share mutex-protected state. `PeerId` constructors enforce immutable canonical identity; getters expose its string and work. Duration/Instant use Rust monotonic clocks. The `_at` methods provide deterministic time injection. Blocking methods perform only local bounded accounting; ledger and standing sizes intentionally follow upstream's unbounded positive-state semantics.

```rust
use lattice_tally::{PeerId,Tally};
let tally = Tally::default();
let peer = PeerId::new("opaque-peer");
tally.record_received(&peer, 1024);
tally.record_useful_received(&peer, 1024); // caller must establish usefulness
assert_eq!(tally.standing(&peer), 1024);
```

Validation: `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`.

`tools/generate-vectors.sh` compiles the pinned original Swift source and regenerates `tests/fixtures/swift.tsv`. On macOS it substitutes CryptoKit's compatible SHA256 import for swift-crypto, leaving the algorithms intact. The 785 cases cover identity spellings/work (105), credit sequences and numeric extremes (480), evidence decay/score (100), and challenge digests/first valid solutions (100). Invariant tests additionally cover buckets, rate pressure, independent standing, replay/tampering/expiry, bounds, and concurrent ledger updates.

Coverage is recorded in [PORTING.md](PORTING.md). This repository is local and depends on no chain-specific types. Live node/network integration and non-macOS CI remain platform integration work, not established by these library tests.
