# o1-netconfd-rs

A memory-safe, zero-C-dependency, platform-agnostic **Rust NETCONF-over-SSH reference server** (`RFC 6241`, `RFC 6242`, `RFC 6470`, `RFC 5277`, `RFC 7952`) demonstrating session-bound O1 / M-Plane change provenance across server-process restarts and lost replies.

## Operator Persistence & Recovery Guarantee

In this codebase, **process-restart consistency** means:

1. **Authoritative Single-Commit Persistence & Write-Before-Notify (`#12`, `#16`):**
   - Mutations and `NotificationRecord`s are staged in memory first.
   - `state.json.tmp` is written and `fsync`ed, and **a single `redb` ACID write transaction** commits both `state_meta` (`PersistedStore` with monotonic `commit_seq`) and `audit_wal` (`NotificationRecord` SHA-256 hash chain) as the authoritative durability point before renaming `state.json.tmp` -> `state.json` and syncing the parent directory.
   - In-memory `running` state is swapped and live `RFC 6470` / `VES` notifications are broadcast **only after** the `redb` transaction commits. If snapshot or `redb` persistence fails before durability, the RPC returns `operation-failed`, `running` is unchanged, and zero live or replayed notifications are emitted.
2. **Post-Recovery Configuration–Attribution Agreement (`#18`):**
   - On server-process restart (`DatastoreEngine::open`), if `state.redb` carries a higher valid `commit_seq` than `state.json`, recovery restores from `state.redb` and re-synchronizes `state.json`.
   - Any unconfirmed `PendingCommitState::Pending` is atomically rolled back to `PendingCommitState::Idle` in a single durable transition while recording `<changed-by><server/></changed-by>` (`writer-origin = server-rollback`), so stale `persist-id` values (`T3a`, `T3c`) and never-issued `persist-id` values (`T2`, `T3b`, `T5`) are deterministically rejected with `invalid-value`.
3. **Gapless Subscription Lag Recovery (`#13`, `#17`):**
   - If a live `RFC 5277` subscriber lags behind a burst on the in-memory broadcast channel (`RecvError::Lagged`), the SSH forwarder recovers missed records (`seq > last_sent_seq`) directly from the persisted WAL in monotonic sequence before resuming live delivery, and emits `<replayComplete/>` if and only if `<startTime>` was requested (`RFC 5277` §3.3.3).

*(Scope note: Tests verify server-process restart and injected snapshot/`redb`/L4-TCP stream failures on a healthy filesystem; host power-loss / kernel-panic / torn-block media faults are outside scope.)*

## Key Capabilities

- **Algebraic Confirmed-Commit State Machine (`PendingCommitState`):** Eliminates both `netopeer2`'s post-restart stale `persist-id` acceptance (`T3a`, `T3c`) and `Clixon`'s acceptance of unissued `persist-id` values when no confirmed commit is pending (`RFC 6241` §8.4.1 / Appendix C vs. §8.4.5.1).
- **Per-Leaf RFC 7952 Provenance + IETF `tx-id` / W3C `traceparent` (`#1`):** Tracks `LeafProvenance` (`owner_principal`, `owner_session_id`, `writer_origin`, `tx_id`, `traceparent`, `updated_at`), echoes `tx-id` on `<rpc-reply>`, and supports `<get-config><with-provenance/></get-config>` (`urn:o1:provenance:1.0`, `o1p:*` attributes).
- **Tamper-Evident SHA-256 Hash-Chained WAL (`#2`):** Links every `NotificationRecord` with `seq`, `prev_hash`, and `entry_hash` in `redb`. Verify via `--verify-audit-chain` or `<verify-provenance-chain/>`.
- **3GPP TS 28.532 `notifyMOIChanges` VES 7.x Emitter (`#3`):** `--ves-endpoint <http://host:port/eventListener/v7>` emits standard VES `stndDefined` `notifyMOIChanges` JSON enriched with `writerPrincipal`, `sessionId`, `writerOrigin`, `txId`, `traceparent`, and `auditEntryHash`.
- **3GPP TS 28.541 O-CU & GPU AI-RAN Sidecar Profile (`#8`):** Supports `<GNBCUCPFunction>`, `<GNBCUUPFunction>`, and `<NRCellCU>` alongside `<NRCellDU>` (`administrativeState`, `gpuAcceleratorProfile` [`NONE` | `AERIAL_CUDA` | `DOCA_DPU`], `aiRrmPolicyId`) with zero POSIX `/dev/shm` contention against CUDA IPC or DPDK hugepages.
- **Wire-Level L4 Fault Proxy & Principal-Scoped Tokens:** Built-in `FaultProxy` (`PassThrough`, `DropServerToClientAfterRpcCommit`, `DropClientToServerBeforeRpc`) and `--strict-persist-owner` (`T6` mitigation).

## Build & Test

```bash
cargo test --locked
cargo build --release --locked
./target/release/o1-netconfd-rs --listen 127.0.0.1:8831 --state-file /tmp/o1-netconfd-rs/state.json
```
