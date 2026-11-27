# o1-netconfd-rs

A memory-safe, zero-C-dependency, platform-agnostic **Rust NETCONF-over-SSH server** (`RFC 6241`, `RFC 6242`, `RFC 6470`, `RFC 5277`) designed for O-RAN **O1** and **M-Plane** write provenance.

## Why This Exists

Testing two widely used C NETCONF servers ([`o1-evidence-demo`](https://github.com/mgunjan/o1-evidence-demo)) exposed two failure modes under lost-reply and restart faults:
1. **`netopeer2` (`T3a`, `T3c`):** Rolls back a pending persistent confirmed commit on restart, but still accepts the stale `persist-id` afterward—and logs the server rollback as `username=root, session-id=0` instead of `<server/>`.
2. **`Clixon` (`T2`, `T3b`, `T3c`, `T5`):** Omits `RFC 6470` notifications and accepts a confirming `<commit>` carrying a `persist-id` that was **never issued** (an omission in `RFC 6241 §8.4.5.1`).

`o1-netconfd-rs` eliminates both failure classes by construction:
- **Algebraic Confirmed-Commit State Machine (`PendingCommitState`):** Atomic `fsync` + `rename` persistence ensures startup rollback and `PendingCommitState::Idle` clearing happen in a single indivisible transition. Unissued and rolled-back `persist-id` values are deterministically rejected with `invalid-value`.
- **Durable `RFC 6470` + `RFC 5277` Replay Log:** Monotonic, crash-persisted `session-id` allocation + `<changed-by><server/></changed-by>` on server-initiated rollbacks.
- **Optional Principal-Scoped Tokens (`--strict-persist-owner`):** Prevents `T6` cross-principal bearer-token cancellation.
- **Pure Rust, Zero C Dependencies:** Built on `tokio` + `russh` + `quick-xml`—compiles natively to a single binary on macOS Apple Silicon, Linux `x86_64`/`aarch64` (`musl`), NVIDIA Grace/BlueField ARM64, and embedded O-RU targets without Docker, OpenSSL, `libssh`, or POSIX `/dev/shm`.

## Build & Test

```bash
cargo test
cargo build --release
./target/release/o1-netconfd-rs --listen 127.0.0.1:8831 --state-file /tmp/o1-netconfd-rs/state.json
```
