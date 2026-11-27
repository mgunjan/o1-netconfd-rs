# o1-netconfd-rs

A memory-safe, zero-C-dependency, platform-agnostic **Rust NETCONF-over-SSH server** (`RFC 6241`, `RFC 6242`, `RFC 6470`, `RFC 5277`, `RFC 7952`) designed for O-RAN **O1** and **M-Plane** causal write provenance.

## Why This Exists

Testing two widely used C NETCONF servers ([`o1-evidence-demo`](https://github.com/mgunjan/o1-evidence-demo)) exposed two failure modes under lost-reply and restart faults:
1. **`netopeer2` (`T3a`, `T3c`):** Rolls back a pending persistent confirmed commit on restart, but still accepts the stale `persist-id` afterward—and logs the server rollback as `username=root, session-id=0` instead of `<server/>`.
2. **`Clixon` (`T2`, `T3b`, `T3c`, `T5`):** Omits `RFC 6470` notifications and accepts a confirming `<commit>` carrying a `persist-id` that was **never issued** (an omission in `RFC 6241 §8.4.5.1`).

`o1-netconfd-rs` eliminates both failure classes by construction and extends O1 with `v0.2` causal provenance:
- **Algebraic Confirmed-Commit State Machine (`PendingCommitState`):** Atomic `fsync` + `rename` persistence ensures startup rollback and `PendingCommitState::Idle` clearing happen in a single indivisible transition. Unissued and rolled-back `persist-id` values are deterministically rejected with `invalid-value`.
- **Per-Leaf RFC 7952 Provenance + IETF `tx-id` / W3C `traceparent` (`v0.2`):** Tracks `LeafProvenance` (`owner_principal`, `owner_session_id`, `tx_id`, `traceparent`, `updated_at`), echoes `tx-id` on `<rpc-reply>`, and supports `<get-config><with-provenance/></get-config>` (`urn:o1:provenance:1.0`, `o1p:*` attributes) so a single read distinguishes `H1` (`MINE`) from `H2` (`NOT_MINE`) without notification replay.
- **Tamper-Evident SHA-256 Hash-Chained WAL (`v0.2`):** Links every `NotificationRecord` with `seq`, `prev_hash`, and `entry_hash = SHA256(seq || prev_hash || event_time || payload)` backed by pure-Rust ACID `redb`. Verify integrity via `--verify-audit-chain` or `<verify-provenance-chain/>`.
- **3GPP TS 28.532 `notifyMOIChanges` VES 7.x Emitter (`v0.2`):** `--ves-endpoint <http://host:port/eventListener/v7>` emits standard VES `stndDefined` `notifyMOIChanges` JSON (`sourceIndicator` + `additionalInformation` with `writerPrincipal`, `sessionId`, `txId`, `traceparent`, `auditEntryHash`).
- **Durable `RFC 6470` + `RFC 5277` Replay Log:** Monotonic, crash-persisted `session-id` allocation + `<changed-by><server/></changed-by>` on server-initiated rollbacks.
- **Wire-Level L4 Fault Proxy & Principal-Scoped Tokens:** Built-in `FaultProxy` (`PassThrough`, `DropServerToClientAfterRpcCommit`, `DropClientToServerBeforeRpc`) and `--strict-persist-owner` preventing `T6` bearer-token hijacking.
- **Pure Rust, Zero C Dependencies:** Built on `tokio` + `russh` + `quick-xml` + `redb` + `sha2`—compiles natively to a single binary on macOS Apple Silicon, Linux `x86_64`/`aarch64` (`musl`), NVIDIA Grace/BlueField ARM64, and embedded O-RU targets without Docker, OpenSSL, `libssh`, or POSIX `/dev/shm`.

## Build & Test

```bash
cargo test
cargo build --release
./target/release/o1-netconfd-rs --listen 127.0.0.1:8831 --state-file /tmp/o1-netconfd-rs/state.json

# Optional v0.2 flags:
./target/release/o1-netconfd-rs --strict-persist-owner --ves-endpoint http://127.0.0.1:30417/eventListener/v7
./target/release/o1-netconfd-rs --verify-audit-chain --state-file /tmp/o1-netconfd-rs/state.json
```
