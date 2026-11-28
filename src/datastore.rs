//! Crash-consistent NETCONF datastore, algebraic confirmed-commit state machine,
//! and durable RFC 6470 / RFC 5277 notification log.

use anyhow::Result;
use chrono::{DateTime, SecondsFormat, Utc};
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};

pub const DEMO_NS: &str = "urn:demo:o1:nrcelldu";
pub const OCU_NRM_NS: &str = "urn:3gpp:sa5:_3gpp-nr-nrm-nrcellcu";
pub const PROVENANCE_NS: &str = "urn:o1:provenance:1.0";
pub const NOTIF_WRAP_NS: &str = "urn:ietf:params:xml:ns:netconf:notification:1.0";
pub const REPLAY_MOD_NS: &str = "urn:ietf:params:xml:ns:netmod:notification";
pub const RFC6470_NS: &str = "urn:ietf:params:xml:ns:yang:ietf-netconf-notifications";
pub const GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
const AUDIT_WAL_TABLE: TableDefinition<u64, &str> = TableDefinition::new("audit_wal");
const STATE_META_TABLE: TableDefinition<&str, &str> = TableDefinition::new("state_meta");
const STATE_META_KEY: &str = "persisted_store";

/// Deterministic failure-injection modes for testing the authoritative persistence boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FailPersistMode {
    None = 0,
    FailSnapshot = 1,
    FailRedb = 2,
}

impl FailPersistMode {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::FailSnapshot,
            2 => Self::FailRedb,
            _ => Self::None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetconfError {
    pub error_type: &'static str,
    pub error_tag: &'static str,
    pub message: String,
}

impl NetconfError {
    pub fn invalid_value(msg: impl Into<String>) -> Self {
        Self {
            error_type: "protocol",
            error_tag: "invalid-value",
            message: msg.into(),
        }
    }

    pub fn lock_denied(msg: impl Into<String>) -> Self {
        Self {
            error_type: "protocol",
            error_tag: "lock-denied",
            message: msg.into(),
        }
    }

    pub fn access_denied(msg: impl Into<String>) -> Self {
        Self {
            error_type: "protocol",
            error_tag: "access-denied",
            message: msg.into(),
        }
    }

    pub fn operation_failed(msg: impl Into<String>) -> Self {
        Self {
            error_type: "application",
            error_tag: "operation-failed",
            message: msg.into(),
        }
    }

    pub fn to_rpc_error_xml(&self) -> String {
        format!(
            "<rpc-error>\
               <error-type>{}</error-type>\
               <error-tag>{}</error-tag>\
               <error-severity>error</error-severity>\
               <error-message>{}</error-message>\
             </rpc-error>",
            xml_escape(self.error_type),
            xml_escape(self.error_tag),
            xml_escape(&self.message),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChangedBy {
    Server,
    Session {
        username: String,
        session_id: u64,
        source_host: Option<String>,
    },
}

/// Origin loop that authored a configuration transition across O-RAN control timescales.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum WriterOrigin {
    #[default]
    O1Client,
    ServerRollback,
    E2Xapp,
    GpuDapp,
}

impl WriterOrigin {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::O1Client => "o1-client",
            Self::ServerRollback => "server-rollback",
            Self::E2Xapp => "e2-xapp",
            Self::GpuDapp => "gpu-dapp",
        }
    }

    pub fn parse_str(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "o1-client" | "o1_client" | "o1" => Some(Self::O1Client),
            "server-rollback" | "server_rollback" | "server" => Some(Self::ServerRollback),
            "e2-xapp" | "e2_xapp" | "e2" => Some(Self::E2Xapp),
            "gpu-dapp" | "gpu_dapp" | "dapp" => Some(Self::GpuDapp),
            _ => None,
        }
    }
}

/// Supported 3GPP TS 28.541 O-DU / O-CU NRM managed functions.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ManagedFunctionKind {
    GNBCUCPFunction,
    GNBCUUPFunction,
    NRCellCU,
    NRCellDU,
}

impl ManagedFunctionKind {
    pub fn xml_tag(&self) -> &'static str {
        match self {
            Self::GNBCUCPFunction => "GNBCUCPFunction",
            Self::GNBCUUPFunction => "GNBCUUPFunction",
            Self::NRCellCU => "NRCellCU",
            Self::NRCellDU => "NRCellDU",
        }
    }

    pub fn module_prefix(&self) -> &'static str {
        match self {
            Self::NRCellDU => "/demo-nrcelldu:managed-element",
            _ => "/_3gpp-nr-nrm-nrcellcu:ManagedElement",
        }
    }
}

/// Optional GPU AI-RAN operational & policy attributes on O-DU/O-CU managed functions.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManagedAttributes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub administrative_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_accelerator_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai_rrm_policy_id: Option<String>,
}

/// Persisted O-CU managed function record (`GNBCUCPFunction`, `GNBCUUPFunction`, `NRCellCU`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CuObjectRecord {
    pub kind: ManagedFunctionKind,
    pub id: String,
    #[serde(default)]
    pub attrs: ManagedAttributes,
}

/// Parsed edit payload targeting an O-DU or O-CU managed function.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectEdit {
    pub kind: ManagedFunctionKind,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub administrative_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_accelerator_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai_rrm_policy_id: Option<String>,
}

/// Optional IETF transaction-id, W3C traceparent, and control-loop `writer-origin`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WriteMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traceparent: Option<String>,
    #[serde(default)]
    pub writer_origin: WriterOrigin,
}

/// Per-leaf RFC 7952 causal ownership metadata persisted alongside running state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeafProvenance {
    pub owner_principal: String,
    pub owner_session_id: u64,
    #[serde(default)]
    pub writer_origin: WriterOrigin,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traceparent: Option<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationPayload {
    ConfigChange {
        changed_by: ChangedBy,
        datastore: String,
        targets: Vec<String>,
        #[serde(default)]
        writer_origin: WriterOrigin,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tx_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        traceparent: Option<String>,
    },
    ConfirmedCommit {
        confirm_event: String,
        username: Option<String>,
        session_id: Option<u64>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationRecord {
    #[serde(default)]
    pub seq: u64,
    #[serde(default)]
    pub prev_hash: String,
    #[serde(default)]
    pub entry_hash: String,
    pub event_time: DateTime<Utc>,
    pub payload: NotificationPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditChainReport {
    pub valid: bool,
    pub entries: usize,
    pub head_hash: String,
    pub tampered_seq: Option<u64>,
    pub reason: Option<String>,
}

impl NotificationRecord {
    pub fn to_notification_xml(&self) -> String {
        let ts = self.event_time.to_rfc3339_opts(SecondsFormat::Millis, true);
        let inner = match &self.payload {
            NotificationPayload::ConfigChange {
                changed_by,
                datastore,
                targets,
                writer_origin,
                tx_id,
                traceparent,
            } => {
                let cb_xml = match changed_by {
                    ChangedBy::Server => "<changed-by><server/></changed-by>".to_string(),
                    ChangedBy::Session {
                        username,
                        session_id,
                        source_host,
                    } => {
                        let sh = source_host
                            .as_ref()
                            .map(|h| format!("<source-host>{}</source-host>", xml_escape(h)))
                            .unwrap_or_default();
                        format!(
                            "<changed-by><username>{}</username><session-id>{}</session-id>{}</changed-by>",
                            xml_escape(username),
                            session_id,
                            sh
                        )
                    }
                };
                let edits_xml: String = targets
                    .iter()
                    .map(|t| format!("<edit><target>{}</target><operation>replace</operation></edit>", xml_escape(t)))
                    .collect();
                let wo_xml = format!("<writer-origin>{}</writer-origin>", writer_origin.as_str());
                let tx_xml = tx_id
                    .as_ref()
                    .map(|t| format!("<tx-id>{}</tx-id>", xml_escape(t)))
                    .unwrap_or_default();
                let tp_xml = traceparent
                    .as_ref()
                    .map(|t| format!("<traceparent>{}</traceparent>", xml_escape(t)))
                    .unwrap_or_default();
                format!(
                    "<netconf-config-change xmlns=\"{RFC6470_NS}\">{cb_xml}<datastore>{}</datastore>{edits_xml}{wo_xml}{tx_xml}{tp_xml}</netconf-config-change>",
                    xml_escape(datastore)
                )
            }
            NotificationPayload::ConfirmedCommit {
                confirm_event,
                username,
                session_id,
            } => {
                let u_xml = username
                    .as_ref()
                    .map(|u| format!("<username>{}</username>", xml_escape(u)))
                    .unwrap_or_default();
                let s_xml = session_id
                    .map(|s| format!("<session-id>{s}</session-id>"))
                    .unwrap_or_default();
                format!(
                    "<netconf-confirmed-commit xmlns=\"{RFC6470_NS}\">{u_xml}{s_xml}<confirm-event>{}</confirm-event></netconf-confirmed-commit>",
                    xml_escape(confirm_event)
                )
            }
        };
        format!(
            "<notification xmlns=\"{NOTIF_WRAP_NS}\"><eventTime>{ts}</eventTime>{inner}</notification>"
        )
    }
}

/// Algebraic confirmed-commit state: makes stale or unissued persist-id acceptance unrepresentable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PendingCommitState {
    Idle,
    Pending {
        persist_id: Option<String>,
        owner_user: String,
        owner_session_id: u64,
        deadline_ms: i64,
        rollback_cells: BTreeMap<String, String>,
        #[serde(default)]
        rollback_du_ext: BTreeMap<String, ManagedAttributes>,
        #[serde(default)]
        rollback_cu_objects: BTreeMap<String, CuObjectRecord>,
        #[serde(default)]
        rollback_provenance: BTreeMap<String, LeafProvenance>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedStore {
    #[serde(default)]
    pub commit_seq: u64,
    pub next_session_id: u64,
    pub running_cells: BTreeMap<String, String>,
    #[serde(default)]
    pub running_du_ext: BTreeMap<String, ManagedAttributes>,
    #[serde(default)]
    pub running_cu_objects: BTreeMap<String, CuObjectRecord>,
    #[serde(default)]
    pub running_provenance: BTreeMap<String, LeafProvenance>,
    pub pending_commit: PendingCommitState,
    pub notifications: Vec<NotificationRecord>,
}

impl Default for PersistedStore {
    fn default() -> Self {
        let mut running_cells = BTreeMap::new();
        running_cells.insert("cell-1".to_string(), "LOCKED".to_string());
        Self {
            commit_seq: 0,
            next_session_id: 1,
            running_cells,
            running_du_ext: BTreeMap::new(),
            running_cu_objects: BTreeMap::new(),
            running_provenance: BTreeMap::new(),
            pending_commit: PendingCommitState::Idle,
            notifications: Vec::new(),
        }
    }
}

#[derive(Clone)]
struct DatastoreSnapshot {
    persisted: PersistedStore,
    candidate_cells: BTreeMap<String, String>,
    candidate_du_ext: BTreeMap<String, ManagedAttributes>,
    candidate_cu_objects: BTreeMap<String, CuObjectRecord>,
    candidate_provenance: BTreeMap<String, LeafProvenance>,
    candidate_dirty: std::collections::BTreeSet<String>,
}

impl DatastoreSnapshot {
    fn from_persisted(persisted: PersistedStore) -> Self {
        let candidate_cells = persisted.running_cells.clone();
        let candidate_du_ext = persisted.running_du_ext.clone();
        let candidate_cu_objects = persisted.running_cu_objects.clone();
        let candidate_provenance = persisted.running_provenance.clone();
        Self {
            persisted,
            candidate_cells,
            candidate_du_ext,
            candidate_cu_objects,
            candidate_provenance,
            candidate_dirty: std::collections::BTreeSet::new(),
        }
    }
}

struct InnerState {
    snapshot: DatastoreSnapshot,
    candidate_lock: Option<u64>,
    running_lock: Option<u64>,
}

#[derive(Clone)]
pub struct DatastoreEngine {
    state_path: PathBuf,
    strict_persist_owner: bool,
    inner: Arc<Mutex<InnerState>>,
    wal_db: Arc<std::sync::Mutex<Database>>,
    notif_tx: broadcast::Sender<NotificationRecord>,
    startup_events: Arc<Vec<NotificationRecord>>,
    fail_next_persist: Arc<AtomicU8>,
}

impl DatastoreEngine {
    /// Open or initialize the crash-safe datastore at `state_path` with default broadcast capacity (256).
    ///
    /// Authoritative commit boundary:
    ///   1. Temp JSON snapshot (`state.json.tmp`) is written and synced (`fsync`).
    ///   2. `state.redb` commits both `state_meta` (`PersistedStore`) and `audit_wal` (`NotificationRecord`s)
    ///      in a single ACID transaction.
    ///   3. `state.json.tmp` is atomically renamed over `state.json` and the parent directory is synced.
    ///   4. Only after durability succeeds are in-memory state swapped and live notifications broadcast.
    ///
    /// On startup, if `state.redb` contains a valid committed `state_meta` snapshot newer than `state.json`
    /// (`redb.commit_seq > json.commit_seq`), recovery restores from `state.redb` and re-syncs `state.json`.
    /// Any pending unconfirmed commit from before a crash/restart is atomically rolled back to `Idle`.
    pub fn open(state_path: impl AsRef<Path>, strict_persist_owner: bool) -> Result<Self> {
        Self::open_with_capacity(state_path, strict_persist_owner, 256)
    }

    /// Open or initialize the datastore with an explicit broadcast channel capacity (useful for lag testing).
    pub fn open_with_capacity(
        state_path: impl AsRef<Path>,
        strict_persist_owner: bool,
        notif_capacity: usize,
    ) -> Result<Self> {
        let state_path = state_path.as_ref().to_path_buf();
        let wal_path = state_path.with_extension("redb");
        if let Some(parent) = state_path.parent() {
            fs::create_dir_all(parent)?;
        }

        if !state_path.exists() && wal_path.exists() {
            let _ = fs::remove_file(&wal_path);
        }

        let mut persisted: PersistedStore = if state_path.exists() {
            let raw = fs::read_to_string(&state_path)?;
            serde_json::from_str(&raw)?
        } else {
            PersistedStore::default()
        };

        // Migrate legacy pre-v0.2 notification logs that lack SHA-256 hash links
        if !persisted.notifications.is_empty()
            && persisted
                .notifications
                .iter()
                .all(|r| r.seq == 0 && r.entry_hash.is_empty())
        {
            backfill_hash_chain(&mut persisted.notifications);
        }

        let initial_chain_valid = verify_notifications_chain(&persisted.notifications).valid;
        let wal_db = Database::create(&wal_path)?;

        // Reconcile if crash happened after redb commit but before state.json rename
        if initial_chain_valid {
            if let Ok(read_txn) = wal_db.begin_read() {
                if let Ok(meta_table) = read_txn.open_table(STATE_META_TABLE) {
                    if let Ok(Some(meta_val)) = meta_table.get(STATE_META_KEY) {
                        if let Ok(redb_store) =
                            serde_json::from_str::<PersistedStore>(meta_val.value())
                        {
                            if redb_store.commit_seq > persisted.commit_seq
                                && verify_notifications_chain(&redb_store.notifications).valid
                            {
                                persisted = redb_store;
                            }
                        }
                    }
                }
            }
        }

        let pre_recovery_len = persisted.notifications.len();

        // Crash / restart recovery: atomic rollback + PendingCommitState::Idle clearing
        if let PendingCommitState::Pending {
            rollback_cells,
            rollback_du_ext,
            rollback_cu_objects,
            rollback_provenance,
            owner_user,
            owner_session_id,
            ..
        } = persisted.pending_commit.clone()
        {
            let changed_leaves = diff_changed_leaves(
                &persisted.running_cells,
                &persisted.running_du_ext,
                &persisted.running_cu_objects,
                &rollback_cells,
                &rollback_du_ext,
                &rollback_cu_objects,
            );
            persisted.running_cells = rollback_cells;
            persisted.running_du_ext = rollback_du_ext;
            persisted.running_cu_objects = rollback_cu_objects;
            persisted.running_provenance = rollback_provenance;
            persisted.pending_commit = PendingCommitState::Idle;

            let now = Utc::now();
            for (prov_key, _) in &changed_leaves {
                persisted
                    .running_provenance
                    .entry(prov_key.clone())
                    .or_insert_with(|| LeafProvenance {
                        owner_principal: "server".to_string(),
                        owner_session_id: 0,
                        writer_origin: WriterOrigin::ServerRollback,
                        tx_id: None,
                        traceparent: None,
                        updated_at: now,
                    });
            }

            append_notification(
                &mut persisted,
                now,
                NotificationPayload::ConfirmedCommit {
                    confirm_event: "cancel".to_string(),
                    username: Some(owner_user),
                    session_id: Some(owner_session_id),
                },
            );
            if !changed_leaves.is_empty() {
                let changed_targets: Vec<String> =
                    changed_leaves.into_iter().map(|(_, p)| p).collect();
                append_notification(
                    &mut persisted,
                    now,
                    NotificationPayload::ConfigChange {
                        changed_by: ChangedBy::Server,
                        datastore: "running".to_string(),
                        targets: changed_targets,
                        writer_origin: WriterOrigin::ServerRollback,
                        tx_id: None,
                        traceparent: None,
                    },
                );
            }
            persisted.commit_seq = persisted.commit_seq.saturating_add(1);
        }

        // Write authoritative redb tables + synchronized JSON mirror atomically on open
        {
            let write_txn = wal_db.begin_write()?;
            {
                let mut meta_table = write_txn.open_table(STATE_META_TABLE)?;
                if initial_chain_valid || meta_table.get(STATE_META_KEY)?.is_none() {
                    let encoded_store = serde_json::to_string(&persisted)?;
                    meta_table.insert(STATE_META_KEY, encoded_store.as_str())?;
                }
                let mut wal_table = write_txn.open_table(AUDIT_WAL_TABLE)?;
                if initial_chain_valid {
                    for rec in &persisted.notifications {
                        if wal_table.get(rec.seq)?.is_none() {
                            let encoded = serde_json::to_string(rec)?;
                            wal_table.insert(rec.seq, encoded.as_str())?;
                        }
                    }
                } else if persisted.notifications.len() > pre_recovery_len {
                    for rec in &persisted.notifications[pre_recovery_len..] {
                        let encoded = serde_json::to_string(rec)?;
                        wal_table.insert(rec.seq, encoded.as_str())?;
                    }
                }
            }
            write_txn.commit()?;
        }
        atomic_write_json(&state_path, &persisted)?;

        let startup_events = Arc::new(persisted.notifications[pre_recovery_len..].to_vec());
        let snapshot = DatastoreSnapshot::from_persisted(persisted);
        let (notif_tx, _) = broadcast::channel(notif_capacity.max(1));
        let engine = Self {
            state_path,
            strict_persist_owner,
            inner: Arc::new(Mutex::new(InnerState {
                snapshot,
                candidate_lock: None,
                running_lock: None,
            })),
            wal_db: Arc::new(std::sync::Mutex::new(wal_db)),
            notif_tx,
            startup_events,
            fail_next_persist: Arc::new(AtomicU8::new(FailPersistMode::None as u8)),
        };

        Ok(engine)
    }

    /// Arm a one-shot persistence failure injection on the next durable write (for tests).
    pub fn set_fail_next_persist(&self, mode: FailPersistMode) {
        self.fail_next_persist.store(mode as u8, Ordering::Release);
    }

    /// Spawn a background async VES 7.x `notifyMOIChanges` HTTP JSON emitter for every
    /// committed `running` change (including startup crash-recovery rollbacks).
    pub fn spawn_ves_emitter(&self, endpoint_url: &str) -> Result<tokio::task::JoinHandle<()>> {
        let endpoint = crate::ves::VesEndpoint::parse(endpoint_url)?;
        let mut rx = self.notif_tx.subscribe();
        let startup = self.startup_events.clone();
        Ok(tokio::spawn(async move {
            for ev in startup.iter() {
                if let Err(err) = crate::ves::emit_record_if_config_change(&endpoint, ev).await {
                    tracing::warn!(error = %err, "Failed to emit startup VES notifyMOIChanges");
                }
            }
            loop {
                match rx.recv().await {
                    Ok(ev) => {
                        if let Err(err) =
                            crate::ves::emit_record_if_config_change(&endpoint, &ev).await
                        {
                            tracing::warn!(error = %err, "Failed to emit VES notifyMOIChanges");
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::warn!(skipped, "VES emitter lagged behind broadcast stream");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }))
    }

    fn persist_with_wal(&self, persisted: &mut PersistedStore, prev_len: usize) -> Result<()> {
        let mode = FailPersistMode::from_u8(self.fail_next_persist.swap(0, Ordering::AcqRel));
        persisted.commit_seq = persisted.commit_seq.saturating_add(1);

        let tmp = self.state_path.with_extension("json.tmp");
        let data = serde_json::to_vec_pretty(persisted)?;
        {
            let mut f = File::create(&tmp)?;
            f.write_all(&data)?;
            f.sync_all()?;
        }
        if mode == FailPersistMode::FailSnapshot {
            let _ = fs::remove_file(&tmp);
            anyhow::bail!("Injected snapshot persistence failure");
        }

        let db = self
            .wal_db
            .lock()
            .map_err(|_| anyhow::anyhow!("WAL database lock poisoned"))?;
        let state_json = serde_json::to_string(persisted)?;
        let write_txn = db.begin_write()?;
        {
            let mut meta_table = write_txn.open_table(STATE_META_TABLE)?;
            meta_table.insert(STATE_META_KEY, state_json.as_str())?;
            let mut wal_table = write_txn.open_table(AUDIT_WAL_TABLE)?;
            if persisted.notifications.len() > prev_len {
                for rec in &persisted.notifications[prev_len..] {
                    let encoded = serde_json::to_string(rec)?;
                    wal_table.insert(rec.seq, encoded.as_str())?;
                }
            }
        }
        if mode == FailPersistMode::FailRedb {
            drop(write_txn);
            let _ = fs::remove_file(&tmp);
            anyhow::bail!("Injected redb ACID commit failure");
        }
        // AUTHORITATIVE COMMIT POINT: once the single redb ACID transaction commits, the change
        // (state_meta snapshot + audit WAL entries) is durable and will be recovered by `open()`.
        write_txn.commit()?;

        // The JSON file is a synchronized mirror. A mirror failure after the redb commit must not
        // report the change as failed (it is durable); `open()` reconciles via `commit_seq`.
        match fs::rename(&tmp, &self.state_path) {
            Ok(()) => {
                if let Err(err) = sync_parent_dir(&self.state_path) {
                    tracing::warn!(error = %err, "parent dir sync failed after durable redb commit");
                }
            }
            Err(err) => {
                tracing::warn!(error = %err, "state.json mirror rename failed after durable redb commit; will reconcile on open");
            }
        }
        Ok(())
    }

    fn commit_staged(
        &self,
        guard: &mut InnerState,
        mut staged: DatastoreSnapshot,
        prev_len: usize,
    ) -> Result<()> {
        self.persist_with_wal(&mut staged.persisted, prev_len)?;
        let new_events = staged.persisted.notifications[prev_len..].to_vec();
        guard.snapshot = staged;
        for ev in new_events {
            let _ = self.notif_tx.send(ev);
        }
        Ok(())
    }

    /// Verify integrity of the SHA-256 hash-chained audit WAL and `redb` ACID store.
    pub async fn verify_audit_chain(&self) -> AuditChainReport {
        let guard = self.inner.lock().await;
        let report = verify_notifications_chain(&guard.snapshot.persisted.notifications);
        if !report.valid {
            return report;
        }
        let Ok(db) = self.wal_db.lock() else {
            return AuditChainReport {
                valid: false,
                entries: guard.snapshot.persisted.notifications.len(),
                head_hash: report.head_hash,
                tampered_seq: Some(1),
                reason: Some("WAL database lock poisoned".to_string()),
            };
        };
        cross_check_redb(&db, &guard.snapshot.persisted.notifications, report)
    }

    pub fn spawn_timeout_watcher(&self) {
        let eng = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(250));
            loop {
                interval.tick().await;
                let _ = eng.check_expired_commit().await;
            }
        });
    }

    async fn check_expired_commit(&self) -> Result<()> {
        let mut guard = self.inner.lock().await;
        let now_ms = Utc::now().timestamp_millis();
        if let PendingCommitState::Pending {
            deadline_ms,
            rollback_cells,
            rollback_du_ext,
            rollback_cu_objects,
            rollback_provenance,
            owner_user,
            owner_session_id,
            ..
        } = guard.snapshot.persisted.pending_commit.clone()
        {
            if now_ms >= deadline_ms {
                let prev_len = guard.snapshot.persisted.notifications.len();
                let mut staged = guard.snapshot.clone();
                apply_rollback_snapshot(
                    &mut staged,
                    rollback_cells,
                    rollback_du_ext,
                    rollback_cu_objects,
                    rollback_provenance,
                    "timeout",
                    &owner_user,
                    owner_session_id,
                    ChangedBy::Server,
                    WriterOrigin::ServerRollback,
                    true,
                );
                self.commit_staged(&mut guard, staged, prev_len)?;
            }
        }
        Ok(())
    }

    /// Allocate a strictly monotonic, crash-persisted NETCONF session ID (RFC 6470 non-zero).
    pub async fn allocate_session_id(&self) -> Result<u64> {
        let mut guard = self.inner.lock().await;
        let prev_len = guard.snapshot.persisted.notifications.len();
        let mut staged = guard.snapshot.clone();
        let sid = staged.persisted.next_session_id.max(1);
        staged.persisted.next_session_id = sid + 1;
        self.commit_staged(&mut guard, staged, prev_len)?;
        Ok(sid)
    }

    /// Release locks and roll back any ephemeral (non-persistent) confirmed commit on session close/drop.
    pub async fn on_session_closed(&self, session_id: u64) -> Result<()> {
        let mut guard = self.inner.lock().await;
        if guard.candidate_lock == Some(session_id) {
            guard.candidate_lock = None;
        }
        if guard.running_lock == Some(session_id) {
            guard.running_lock = None;
        }
        if let PendingCommitState::Pending {
            persist_id: None,
            owner_session_id,
            rollback_cells,
            rollback_du_ext,
            rollback_cu_objects,
            rollback_provenance,
            owner_user,
            ..
        } = guard.snapshot.persisted.pending_commit.clone()
        {
            if owner_session_id == session_id {
                let prev_len = guard.snapshot.persisted.notifications.len();
                let mut staged = guard.snapshot.clone();
                apply_rollback_snapshot(
                    &mut staged,
                    rollback_cells,
                    rollback_du_ext,
                    rollback_cu_objects,
                    rollback_provenance,
                    "cancel",
                    &owner_user,
                    session_id,
                    ChangedBy::Server,
                    WriterOrigin::ServerRollback,
                    true,
                );
                self.commit_staged(&mut guard, staged, prev_len)?;
            }
        }
        Ok(())
    }

    pub async fn get_config_xml(&self, source: &str) -> Result<String, NetconfError> {
        self.get_config_xml_with_provenance(source, false).await
    }

    pub async fn get_config_xml_with_provenance(
        &self,
        source: &str,
        with_provenance: bool,
    ) -> Result<String, NetconfError> {
        let guard = self.inner.lock().await;
        let snap = &guard.snapshot;
        let (du, du_ext, cu, prov) = match source {
            "running" => (
                &snap.persisted.running_cells,
                &snap.persisted.running_du_ext,
                &snap.persisted.running_cu_objects,
                &snap.persisted.running_provenance,
            ),
            "candidate" => (
                &snap.candidate_cells,
                &snap.candidate_du_ext,
                &snap.candidate_cu_objects,
                &snap.candidate_provenance,
            ),
            other => return Err(NetconfError::invalid_value(format!("Unsupported datastore: {other}"))),
        };
        Ok(render_datastore_xml_with_provenance(
            du,
            du_ext,
            cu,
            if with_provenance { Some(prov) } else { None },
        ))
    }

    pub async fn lock(&self, target: &str, session_id: u64) -> Result<(), NetconfError> {
        let mut guard = self.inner.lock().await;
        let slot = match target {
            "candidate" => &mut guard.candidate_lock,
            "running" => &mut guard.running_lock,
            other => return Err(NetconfError::invalid_value(format!("Unsupported lock target: {other}"))),
        };
        if let Some(holder) = *slot {
            if holder != session_id {
                return Err(NetconfError::lock_denied(format!(
                    "Datastore {target} is locked by session {holder}"
                )));
            }
        }
        *slot = Some(session_id);
        Ok(())
    }

    pub async fn unlock(&self, target: &str, session_id: u64) -> Result<(), NetconfError> {
        let mut guard = self.inner.lock().await;
        let slot = match target {
            "candidate" => &mut guard.candidate_lock,
            "running" => &mut guard.running_lock,
            other => return Err(NetconfError::invalid_value(format!("Unsupported unlock target: {other}"))),
        };
        if *slot != Some(session_id) {
            return Err(NetconfError::lock_denied(format!(
                "Session {session_id} does not hold lock on {target}"
            )));
        }
        *slot = None;
        Ok(())
    }

    pub async fn discard_changes(&self, session_id: u64) -> Result<(), NetconfError> {
        let mut guard = self.inner.lock().await;
        if let Some(holder) = guard.candidate_lock {
            if holder != session_id {
                return Err(NetconfError::lock_denied("Candidate datastore is locked"));
            }
        }
        let persisted = guard.snapshot.persisted.clone();
        guard.snapshot = DatastoreSnapshot::from_persisted(persisted);
        Ok(())
    }

    pub async fn edit_config(
        &self,
        target: &str,
        cell_id: &str,
        admin_state: &str,
        username: &str,
        session_id: u64,
        source_host: Option<String>,
    ) -> Result<(), NetconfError> {
        self.edit_config_with_meta(
            target,
            cell_id,
            admin_state,
            username,
            session_id,
            source_host,
            WriteMeta::default(),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn edit_config_with_meta(
        &self,
        target: &str,
        cell_id: &str,
        admin_state: &str,
        username: &str,
        session_id: u64,
        source_host: Option<String>,
        meta: WriteMeta,
    ) -> Result<(), NetconfError> {
        let edit = ObjectEdit {
            kind: ManagedFunctionKind::NRCellDU,
            id: cell_id.to_string(),
            administrative_state: Some(admin_state.to_string()),
            gpu_accelerator_profile: None,
            ai_rrm_policy_id: None,
        };
        self.edit_objects_with_meta(target, &[edit], username, session_id, source_host, meta)
            .await
    }

    /// Apply one or more O-DU / O-CU managed-object edits to `candidate` or `running`
    /// with per-leaf causal provenance (`owner_principal`, `session_id`, `writer_origin`, `tx_id`, `traceparent`).
    pub async fn edit_objects_with_meta(
        &self,
        target: &str,
        edits: &[ObjectEdit],
        username: &str,
        session_id: u64,
        source_host: Option<String>,
        meta: WriteMeta,
    ) -> Result<(), NetconfError> {
        if edits.is_empty() {
            return Err(NetconfError::invalid_value("Missing managed object edits in edit-config"));
        }
        for edit in edits {
            validate_object_edit(edit)?;
        }

        let mut guard = self.inner.lock().await;
        let now = Utc::now();
        let prov = LeafProvenance {
            owner_principal: username.to_string(),
            owner_session_id: session_id,
            writer_origin: meta.writer_origin,
            tx_id: meta.tx_id.clone(),
            traceparent: meta.traceparent.clone(),
            updated_at: now,
        };

        match target {
            "candidate" => {
                if let Some(holder) = guard.candidate_lock {
                    if holder != session_id {
                        return Err(NetconfError::lock_denied("Candidate datastore is locked"));
                    }
                }
                apply_edits_to_candidate(&mut guard.snapshot, edits, &prov);
                Ok(())
            }
            "running" => {
                if let Some(holder) = guard.running_lock {
                    if holder != session_id {
                        return Err(NetconfError::lock_denied("Running datastore is locked"));
                    }
                }
                let prev_len = guard.snapshot.persisted.notifications.len();
                let mut staged = guard.snapshot.clone();
                let changed_targets = apply_edits_to_running(&mut staged, edits, &prov);
                if !changed_targets.is_empty() {
                    let changed_by = if session_id == 0 {
                        ChangedBy::Server
                    } else {
                        ChangedBy::Session {
                            username: username.to_string(),
                            session_id,
                            source_host,
                        }
                    };
                    append_notification(
                        &mut staged.persisted,
                        now,
                        NotificationPayload::ConfigChange {
                            changed_by,
                            datastore: "running".to_string(),
                            targets: changed_targets,
                            writer_origin: meta.writer_origin,
                            tx_id: meta.tx_id,
                            traceparent: meta.traceparent,
                        },
                    );
                }
                self.commit_staged(&mut guard, staged, prev_len)
                    .map_err(|e| NetconfError::operation_failed(e.to_string()))?;
                Ok(())
            }
            other => Err(NetconfError::invalid_value(format!("Unsupported target: {other}"))),
        }
    }

    /// Apply a southbound E2 xApp or on-GPU dApp state sync to `running` with explicit `writer_origin`.
    pub async fn apply_southbound_sync(
        &self,
        edits: &[ObjectEdit],
        actor: &str,
        origin: WriterOrigin,
        meta: WriteMeta,
    ) -> Result<(), NetconfError> {
        let mut sync_meta = meta;
        sync_meta.writer_origin = origin;
        self.edit_objects_with_meta("running", edits, actor, 0, None, sync_meta)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn commit(
        &self,
        confirmed: bool,
        timeout_secs: u64,
        persist: Option<String>,
        persist_id: Option<String>,
        username: &str,
        session_id: u64,
        source_host: Option<String>,
    ) -> Result<(), NetconfError> {
        self.commit_with_meta(
            confirmed,
            timeout_secs,
            persist,
            persist_id,
            username,
            session_id,
            source_host,
            WriteMeta::default(),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn commit_with_meta(
        &self,
        confirmed: bool,
        timeout_secs: u64,
        persist: Option<String>,
        persist_id: Option<String>,
        username: &str,
        session_id: u64,
        source_host: Option<String>,
        meta: WriteMeta,
    ) -> Result<(), NetconfError> {
        let mut guard = self.inner.lock().await;

        // Case 1: Confirming / extending commit carrying <persist-id> (RFC 6241 §8.4.5.1 strict check!)
        if let Some(ref req_pid) = persist_id {
            let prev_len = guard.snapshot.persisted.notifications.len();
            match &guard.snapshot.persisted.pending_commit {
                PendingCommitState::Idle => {
                    return Err(NetconfError::invalid_value(
                        "Confirming commit does not match any pending confirmed commit",
                    ));
                }
                PendingCommitState::Pending {
                    persist_id: active_pid,
                    owner_user,
                    ..
                } => {
                    if active_pid.as_deref() != Some(req_pid.as_str()) {
                        return Err(NetconfError::invalid_value(
                            "Confirming commit persist-id does not match pending confirmed commit",
                        ));
                    }
                    if self.strict_persist_owner && owner_user != username {
                        return Err(NetconfError::access_denied(
                            "Confirming commit persist-id belongs to a different principal",
                        ));
                    }
                }
            }

            let mut staged = guard.snapshot.clone();
            if confirmed {
                if let PendingCommitState::Pending {
                    rollback_cells,
                    rollback_du_ext,
                    rollback_cu_objects,
                    rollback_provenance,
                    owner_user,
                    owner_session_id,
                    ..
                } = staged.persisted.pending_commit.clone()
                {
                    let new_pid = persist.or_else(|| Some(req_pid.clone()));
                    let deadline_ms = Utc::now().timestamp_millis() + (timeout_secs as i64 * 1000);
                    staged.persisted.pending_commit = PendingCommitState::Pending {
                        persist_id: new_pid,
                        owner_user,
                        owner_session_id,
                        deadline_ms,
                        rollback_cells,
                        rollback_du_ext,
                        rollback_cu_objects,
                        rollback_provenance,
                    };
                    append_notification(
                        &mut staged.persisted,
                        Utc::now(),
                        NotificationPayload::ConfirmedCommit {
                            confirm_event: "extend".to_string(),
                            username: Some(username.to_string()),
                            session_id: Some(session_id),
                        },
                    );
                }
            } else {
                let (changed_targets, resolved_meta) =
                    promote_candidate_to_running(&mut staged, username, session_id, &meta);
                staged.persisted.pending_commit = PendingCommitState::Idle;

                if !changed_targets.is_empty() {
                    append_notification(
                        &mut staged.persisted,
                        Utc::now(),
                        NotificationPayload::ConfigChange {
                            changed_by: ChangedBy::Session {
                                username: username.to_string(),
                                session_id,
                                source_host,
                            },
                            datastore: "running".to_string(),
                            targets: changed_targets,
                            writer_origin: resolved_meta.writer_origin,
                            tx_id: resolved_meta.tx_id,
                            traceparent: resolved_meta.traceparent,
                        },
                    );
                }
                append_notification(
                    &mut staged.persisted,
                    Utc::now(),
                    NotificationPayload::ConfirmedCommit {
                        confirm_event: "complete".to_string(),
                        username: Some(username.to_string()),
                        session_id: Some(session_id),
                    },
                );
            }

            self.commit_staged(&mut guard, staged, prev_len)
                .map_err(|e| NetconfError::operation_failed(e.to_string()))?;
            return Ok(());
        }

        // Case 2: Starting a new confirmed commit (<commit><confirmed/>...</commit>)
        if confirmed {
            let prev_len = guard.snapshot.persisted.notifications.len();
            let mut staged = guard.snapshot.clone();
            let (rollback_cells, rollback_du_ext, rollback_cu_objects, rollback_provenance) =
                match &staged.persisted.pending_commit {
                    PendingCommitState::Idle => (
                        staged.persisted.running_cells.clone(),
                        staged.persisted.running_du_ext.clone(),
                        staged.persisted.running_cu_objects.clone(),
                        staged.persisted.running_provenance.clone(),
                    ),
                    PendingCommitState::Pending {
                        rollback_cells,
                        rollback_du_ext,
                        rollback_cu_objects,
                        rollback_provenance,
                        ..
                    } => (
                        rollback_cells.clone(),
                        rollback_du_ext.clone(),
                        rollback_cu_objects.clone(),
                        rollback_provenance.clone(),
                    ),
                };
            let (changed_targets, resolved_meta) =
                promote_candidate_to_running(&mut staged, username, session_id, &meta);
            let deadline_ms = Utc::now().timestamp_millis() + (timeout_secs as i64 * 1000);
            staged.persisted.pending_commit = PendingCommitState::Pending {
                persist_id: persist,
                owner_user: username.to_string(),
                owner_session_id: session_id,
                deadline_ms,
                rollback_cells,
                rollback_du_ext,
                rollback_cu_objects,
                rollback_provenance,
            };

            if !changed_targets.is_empty() {
                append_notification(
                    &mut staged.persisted,
                    Utc::now(),
                    NotificationPayload::ConfigChange {
                        changed_by: ChangedBy::Session {
                            username: username.to_string(),
                            session_id,
                            source_host,
                        },
                        datastore: "running".to_string(),
                        targets: changed_targets,
                        writer_origin: resolved_meta.writer_origin,
                        tx_id: resolved_meta.tx_id,
                        traceparent: resolved_meta.traceparent,
                    },
                );
            }

            append_notification(
                &mut staged.persisted,
                Utc::now(),
                NotificationPayload::ConfirmedCommit {
                    confirm_event: "start".to_string(),
                    username: Some(username.to_string()),
                    session_id: Some(session_id),
                },
            );

            self.commit_staged(&mut guard, staged, prev_len)
                .map_err(|e| NetconfError::operation_failed(e.to_string()))?;
            return Ok(());
        }

        // Case 3: Plain <commit/> (completes non-persistent confirmed commit if same session, or commits candidate)
        let prev_len = guard.snapshot.persisted.notifications.len();
        let mut staged = guard.snapshot.clone();
        let was_pending = matches!(
            &staged.persisted.pending_commit,
            PendingCommitState::Pending { persist_id: None, owner_session_id, .. } if *owner_session_id == session_id
        );
        let (changed_targets, resolved_meta) =
            promote_candidate_to_running(&mut staged, username, session_id, &meta);
        if was_pending {
            staged.persisted.pending_commit = PendingCommitState::Idle;
        }
        if !changed_targets.is_empty() {
            append_notification(
                &mut staged.persisted,
                Utc::now(),
                NotificationPayload::ConfigChange {
                    changed_by: ChangedBy::Session {
                        username: username.to_string(),
                        session_id,
                        source_host,
                    },
                    datastore: "running".to_string(),
                    targets: changed_targets,
                    writer_origin: resolved_meta.writer_origin,
                    tx_id: resolved_meta.tx_id,
                    traceparent: resolved_meta.traceparent,
                },
            );
        }
        if was_pending {
            append_notification(
                &mut staged.persisted,
                Utc::now(),
                NotificationPayload::ConfirmedCommit {
                    confirm_event: "complete".to_string(),
                    username: Some(username.to_string()),
                    session_id: Some(session_id),
                },
            );
        }
        self.commit_staged(&mut guard, staged, prev_len)
            .map_err(|e| NetconfError::operation_failed(e.to_string()))?;
        Ok(())
    }

    pub async fn cancel_commit(
        &self,
        persist_id: Option<String>,
        username: &str,
        session_id: u64,
    ) -> Result<(), NetconfError> {
        let mut guard = self.inner.lock().await;
        let prev_len = guard.snapshot.persisted.notifications.len();
        let (rollback_cells, rollback_du_ext, rollback_cu_objects, rollback_provenance) =
            match &guard.snapshot.persisted.pending_commit {
                PendingCommitState::Idle => {
                    return Err(NetconfError::invalid_value("No confirmed commit is pending"));
                }
                PendingCommitState::Pending {
                    persist_id: active_pid,
                    owner_user,
                    owner_session_id,
                    rollback_cells,
                    rollback_du_ext,
                    rollback_cu_objects,
                    rollback_provenance,
                    ..
                } => {
                    match (&persist_id, active_pid) {
                        (Some(req), Some(act)) if req == act => {}
                        (None, None) if *owner_session_id == session_id => {}
                        _ => {
                            return Err(NetconfError::invalid_value(
                                "cancel-commit persist-id does not match pending confirmed commit",
                            ));
                        }
                    }
                    if self.strict_persist_owner && owner_user != username {
                        return Err(NetconfError::access_denied(
                            "cancel-commit persist-id belongs to a different principal",
                        ));
                    }
                    (
                        rollback_cells.clone(),
                        rollback_du_ext.clone(),
                        rollback_cu_objects.clone(),
                        rollback_provenance.clone(),
                    )
                }
            };

        let mut staged = guard.snapshot.clone();
        apply_rollback_snapshot(
            &mut staged,
            rollback_cells,
            rollback_du_ext,
            rollback_cu_objects,
            rollback_provenance,
            "cancel",
            username,
            session_id,
            ChangedBy::Session {
                username: username.to_string(),
                session_id,
                source_host: None,
            },
            WriterOrigin::O1Client,
            false,
        );
        self.commit_staged(&mut guard, staged, prev_len)
            .map_err(|e| NetconfError::operation_failed(e.to_string()))?;
        Ok(())
    }

    pub async fn replay_and_subscribe(
        &self,
        start_time: Option<DateTime<Utc>>,
    ) -> (Vec<NotificationRecord>, broadcast::Receiver<NotificationRecord>) {
        let (replayed, _, rx) = self.replay_and_subscribe_with_watermark(start_time).await;
        (replayed, rx)
    }

    pub async fn replay_and_subscribe_with_watermark(
        &self,
        start_time: Option<DateTime<Utc>>,
    ) -> (Vec<NotificationRecord>, u64, broadcast::Receiver<NotificationRecord>) {
        let guard = self.inner.lock().await;
        let rx = self.notif_tx.subscribe();
        let replayed: Vec<NotificationRecord> = guard
            .snapshot
            .persisted
            .notifications
            .iter()
            .filter(|n| start_time.map(|st| n.event_time >= st).unwrap_or(false))
            .cloned()
            .collect();
        let watermark = replayed
            .last()
            .map(|r| r.seq)
            .unwrap_or_else(|| guard.snapshot.persisted.notifications.last().map(|r| r.seq).unwrap_or(0));
        (replayed, watermark, rx)
    }

    /// Fetch all durable `NotificationRecord`s with `seq > after_seq` in order (used for lag recovery).
    pub async fn notifications_after_seq(&self, after_seq: u64) -> Vec<NotificationRecord> {
        let guard = self.inner.lock().await;
        guard
            .snapshot
            .persisted
            .notifications
            .iter()
            .filter(|r| r.seq > after_seq)
            .cloned()
            .collect()
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn compute_entry_hash(
    seq: u64,
    prev_hash: &str,
    event_time: &DateTime<Utc>,
    payload: &NotificationPayload,
) -> String {
    let payload_json = serde_json::to_string(payload).unwrap_or_default();
    let ts = event_time.to_rfc3339_opts(SecondsFormat::Nanos, true);
    let mut hasher = Sha256::new();
    hasher.update(seq.to_le_bytes());
    hasher.update(b"|");
    hasher.update(prev_hash.as_bytes());
    hasher.update(b"|");
    hasher.update(ts.as_bytes());
    hasher.update(b"|");
    hasher.update(payload_json.as_bytes());
    bytes_to_hex(&hasher.finalize())
}

fn append_notification(
    persisted: &mut PersistedStore,
    event_time: DateTime<Utc>,
    payload: NotificationPayload,
) -> NotificationRecord {
    let seq = persisted.notifications.len() as u64 + 1;
    let prev_hash = persisted
        .notifications
        .last()
        .map(|r| r.entry_hash.clone())
        .unwrap_or_else(|| GENESIS_HASH.to_string());
    let entry_hash = compute_entry_hash(seq, &prev_hash, &event_time, &payload);
    let rec = NotificationRecord {
        seq,
        prev_hash,
        entry_hash,
        event_time,
        payload,
    };
    persisted.notifications.push(rec.clone());
    rec
}

fn backfill_hash_chain(records: &mut [NotificationRecord]) {
    let mut prev = GENESIS_HASH.to_string();
    for (idx, rec) in records.iter_mut().enumerate() {
        let seq = (idx as u64) + 1;
        rec.seq = seq;
        rec.prev_hash = prev.clone();
        rec.entry_hash = compute_entry_hash(seq, &prev, &rec.event_time, &rec.payload);
        prev = rec.entry_hash.clone();
    }
}

pub fn verify_notifications_chain(records: &[NotificationRecord]) -> AuditChainReport {
    let mut expected_prev = GENESIS_HASH.to_string();
    for (idx, rec) in records.iter().enumerate() {
        let expected_seq = (idx as u64) + 1;
        if rec.seq != expected_seq {
            return AuditChainReport {
                valid: false,
                entries: records.len(),
                head_hash: expected_prev,
                tampered_seq: Some(expected_seq),
                reason: Some(format!(
                    "Sequence mismatch at index {idx}: expected seq {expected_seq}, found {}",
                    rec.seq
                )),
            };
        }
        if rec.prev_hash != expected_prev {
            return AuditChainReport {
                valid: false,
                entries: records.len(),
                head_hash: expected_prev,
                tampered_seq: Some(rec.seq),
                reason: Some(format!(
                    "Previous hash link broken at seq {}",
                    rec.seq
                )),
            };
        }
        let expected_hash = compute_entry_hash(
            rec.seq,
            &rec.prev_hash,
            &rec.event_time,
            &rec.payload,
        );
        if rec.entry_hash != expected_hash {
            return AuditChainReport {
                valid: false,
                entries: records.len(),
                head_hash: expected_prev,
                tampered_seq: Some(rec.seq),
                reason: Some(format!("SHA-256 digest mismatch at seq {}", rec.seq)),
            };
        }
        expected_prev = rec.entry_hash.clone();
    }
    AuditChainReport {
        valid: true,
        entries: records.len(),
        head_hash: expected_prev,
        tampered_seq: None,
        reason: None,
    }
}

fn cross_check_redb(
    db: &Database,
    records: &[NotificationRecord],
    json_report: AuditChainReport,
) -> AuditChainReport {
    let Ok(read_txn) = db.begin_read() else {
        return AuditChainReport {
            valid: false,
            entries: records.len(),
            head_hash: json_report.head_hash,
            tampered_seq: Some(1),
            reason: Some("Failed to open redb read transaction".to_string()),
        };
    };
    let Ok(table) = read_txn.open_table(AUDIT_WAL_TABLE) else {
        return AuditChainReport {
            valid: false,
            entries: records.len(),
            head_hash: json_report.head_hash,
            tampered_seq: Some(1),
            reason: Some("Missing audit_wal table in redb".to_string()),
        };
    };
    for rec in records {
        match table.get(rec.seq) {
            Ok(Some(val)) => {
                if let Ok(wal_rec) = serde_json::from_str::<NotificationRecord>(val.value()) {
                    if wal_rec.entry_hash != rec.entry_hash {
                        return AuditChainReport {
                            valid: false,
                            entries: records.len(),
                            head_hash: json_report.head_hash,
                            tampered_seq: Some(rec.seq),
                            reason: Some(format!(
                                "redb WAL entry_hash mismatch at seq {}",
                                rec.seq
                            )),
                        };
                    }
                } else {
                    return AuditChainReport {
                        valid: false,
                        entries: records.len(),
                        head_hash: json_report.head_hash,
                        tampered_seq: Some(rec.seq),
                        reason: Some(format!("Corrupt JSON in redb WAL at seq {}", rec.seq)),
                    };
                }
            }
            _ => {
                return AuditChainReport {
                    valid: false,
                    entries: records.len(),
                    head_hash: json_report.head_hash,
                    tampered_seq: Some(rec.seq),
                    reason: Some(format!("Missing seq {} in redb WAL", rec.seq)),
                };
            }
        }
    }
    json_report
}

/// Offline / CLI verification helper reading `state_path` (and sidecar `.redb` if unlocked).
pub fn verify_audit_chain_file(state_path: &Path) -> Result<AuditChainReport> {
    if !state_path.exists() {
        return Ok(AuditChainReport {
            valid: true,
            entries: 0,
            head_hash: GENESIS_HASH.to_string(),
            tampered_seq: None,
            reason: None,
        });
    }
    let raw = fs::read_to_string(state_path)?;
    let persisted: PersistedStore = serde_json::from_str(&raw)?;
    let report = verify_notifications_chain(&persisted.notifications);
    if !report.valid {
        return Ok(report);
    }
    let wal_path = state_path.with_extension("redb");
    if wal_path.exists() {
        if let Ok(db) = Database::open(&wal_path) {
            return Ok(cross_check_redb(&db, &persisted.notifications, report));
        }
    }
    Ok(report)
}

fn leaf_target_path(kind: ManagedFunctionKind, id: &str, attr: &str) -> String {
    format!(
        "{}/{}[id='{id}']/attributes/{attr}",
        kind.module_prefix(),
        kind.xml_tag()
    )
}

fn cu_object_key(kind: ManagedFunctionKind, id: &str) -> String {
    format!("{}:{id}", kind.xml_tag())
}

fn leaf_prov_key(kind: ManagedFunctionKind, id: &str, attr: &str) -> String {
    if kind == ManagedFunctionKind::NRCellDU && attr == "administrativeState" {
        id.to_string()
    } else {
        format!("{}:{id}:{attr}", kind.xml_tag())
    }
}

fn validate_object_edit(edit: &ObjectEdit) -> Result<(), NetconfError> {
    if edit.id.trim().is_empty() {
        return Err(NetconfError::invalid_value("Missing managed function id"));
    }
    if edit.administrative_state.is_none()
        && edit.gpu_accelerator_profile.is_none()
        && edit.ai_rrm_policy_id.is_none()
    {
        return Err(NetconfError::invalid_value(
            "Missing administrativeState or GPU AI-RAN attributes in edit-config",
        ));
    }
    if let Some(ref admin_state) = edit.administrative_state {
        if !matches!(admin_state.as_str(), "LOCKED" | "UNLOCKED" | "SHUTTINGDOWN") {
            return Err(NetconfError::invalid_value(format!(
                "Invalid administrativeState: {admin_state}"
            )));
        }
    }
    if let Some(ref gpu_profile) = edit.gpu_accelerator_profile {
        if !matches!(gpu_profile.as_str(), "NONE" | "AERIAL_CUDA" | "DOCA_DPU") {
            return Err(NetconfError::invalid_value(format!(
                "Invalid gpuAcceleratorProfile: {gpu_profile}"
            )));
        }
    }
    if let Some(ref policy_id) = edit.ai_rrm_policy_id {
        if policy_id.trim().is_empty() {
            return Err(NetconfError::invalid_value(
                "aiRrmPolicyId must not be empty",
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn apply_rollback_snapshot(
    staged: &mut DatastoreSnapshot,
    rollback_cells: BTreeMap<String, String>,
    rollback_du_ext: BTreeMap<String, ManagedAttributes>,
    rollback_cu_objects: BTreeMap<String, CuObjectRecord>,
    rollback_provenance: BTreeMap<String, LeafProvenance>,
    confirm_event: &str,
    owner_user: &str,
    owner_session_id: u64,
    changed_by: ChangedBy,
    writer_origin: WriterOrigin,
    record_server_provenance: bool,
) {
    let changed_leaves = diff_changed_leaves(
        &staged.persisted.running_cells,
        &staged.persisted.running_du_ext,
        &staged.persisted.running_cu_objects,
        &rollback_cells,
        &rollback_du_ext,
        &rollback_cu_objects,
    );
    let now = Utc::now();
    staged.persisted.running_cells = rollback_cells.clone();
    staged.persisted.running_du_ext = rollback_du_ext.clone();
    staged.persisted.running_cu_objects = rollback_cu_objects.clone();
    staged.persisted.running_provenance = rollback_provenance;
    if record_server_provenance {
        for (prov_key, _) in &changed_leaves {
            staged
                .persisted
                .running_provenance
                .entry(prov_key.clone())
                .or_insert_with(|| LeafProvenance {
                    owner_principal: "server".to_string(),
                    owner_session_id: 0,
                    writer_origin,
                    tx_id: None,
                    traceparent: None,
                    updated_at: now,
                });
        }
    }
    staged.candidate_cells = rollback_cells;
    staged.candidate_du_ext = rollback_du_ext;
    staged.candidate_cu_objects = rollback_cu_objects;
    staged.candidate_provenance = staged.persisted.running_provenance.clone();
    staged.candidate_dirty.clear();
    staged.persisted.pending_commit = PendingCommitState::Idle;

    append_notification(
        &mut staged.persisted,
        now,
        NotificationPayload::ConfirmedCommit {
            confirm_event: confirm_event.to_string(),
            username: Some(owner_user.to_string()),
            session_id: Some(owner_session_id),
        },
    );
    if !changed_leaves.is_empty() {
        let changed_targets: Vec<String> = changed_leaves.into_iter().map(|(_, p)| p).collect();
        append_notification(
            &mut staged.persisted,
            now,
            NotificationPayload::ConfigChange {
                changed_by,
                datastore: "running".to_string(),
                targets: changed_targets,
                writer_origin,
                tx_id: None,
                traceparent: None,
            },
        );
    }
}

fn apply_edits_to_candidate(
    snap: &mut DatastoreSnapshot,
    edits: &[ObjectEdit],
    prov: &LeafProvenance,
) {
    for edit in edits {
        match edit.kind {
            ManagedFunctionKind::NRCellDU => {
                if let Some(ref st) = edit.administrative_state {
                    snap.candidate_cells.insert(edit.id.clone(), st.clone());
                    let k = leaf_prov_key(edit.kind, &edit.id, "administrativeState");
                    snap.candidate_provenance.insert(k.clone(), prov.clone());
                    snap.candidate_dirty.insert(k);
                }
                if edit.gpu_accelerator_profile.is_some() || edit.ai_rrm_policy_id.is_some() {
                    let ext = snap
                        .candidate_du_ext
                        .entry(edit.id.clone())
                        .or_default();
                    if let Some(ref g) = edit.gpu_accelerator_profile {
                        ext.gpu_accelerator_profile = Some(g.clone());
                        let k = leaf_prov_key(edit.kind, &edit.id, "gpuAcceleratorProfile");
                        snap.candidate_provenance.insert(k.clone(), prov.clone());
                        snap.candidate_dirty.insert(k);
                    }
                    if let Some(ref p) = edit.ai_rrm_policy_id {
                        ext.ai_rrm_policy_id = Some(p.clone());
                        let k = leaf_prov_key(edit.kind, &edit.id, "aiRrmPolicyId");
                        snap.candidate_provenance.insert(k.clone(), prov.clone());
                        snap.candidate_dirty.insert(k);
                    }
                }
            }
            kind => {
                let obj_key = cu_object_key(kind, &edit.id);
                let rec = snap
                    .candidate_cu_objects
                    .entry(obj_key)
                    .or_insert_with(|| CuObjectRecord {
                        kind,
                        id: edit.id.clone(),
                        attrs: ManagedAttributes::default(),
                    });
                if let Some(ref st) = edit.administrative_state {
                    rec.attrs.administrative_state = Some(st.clone());
                    let k = leaf_prov_key(kind, &edit.id, "administrativeState");
                    snap.candidate_provenance.insert(k.clone(), prov.clone());
                    snap.candidate_dirty.insert(k);
                }
                if let Some(ref g) = edit.gpu_accelerator_profile {
                    rec.attrs.gpu_accelerator_profile = Some(g.clone());
                    let k = leaf_prov_key(kind, &edit.id, "gpuAcceleratorProfile");
                    snap.candidate_provenance.insert(k.clone(), prov.clone());
                    snap.candidate_dirty.insert(k);
                }
                if let Some(ref p) = edit.ai_rrm_policy_id {
                    rec.attrs.ai_rrm_policy_id = Some(p.clone());
                    let k = leaf_prov_key(kind, &edit.id, "aiRrmPolicyId");
                    snap.candidate_provenance.insert(k.clone(), prov.clone());
                    snap.candidate_dirty.insert(k);
                }
            }
        }
    }
}

fn apply_edits_to_running(
    snap: &mut DatastoreSnapshot,
    edits: &[ObjectEdit],
    prov: &LeafProvenance,
) -> Vec<String> {
    let mut changed_targets = Vec::new();
    for edit in edits {
        match edit.kind {
            ManagedFunctionKind::NRCellDU => {
                if let Some(ref st) = edit.administrative_state {
                    let prev = snap.persisted.running_cells.get(&edit.id).cloned();
                    snap.persisted.running_cells.insert(edit.id.clone(), st.clone());
                    snap.candidate_cells.insert(edit.id.clone(), st.clone());
                    let k = leaf_prov_key(edit.kind, &edit.id, "administrativeState");
                    snap.persisted.running_provenance.insert(k.clone(), prov.clone());
                    snap.candidate_provenance.insert(k.clone(), prov.clone());
                    snap.candidate_dirty.remove(&k);
                    if prev.as_deref() != Some(st.as_str()) {
                        changed_targets.push(leaf_target_path(edit.kind, &edit.id, "administrativeState"));
                    }
                }
                if edit.gpu_accelerator_profile.is_some() || edit.ai_rrm_policy_id.is_some() {
                    let run_ext = snap
                        .persisted
                        .running_du_ext
                        .entry(edit.id.clone())
                        .or_default();
                    let cand_ext = snap
                        .candidate_du_ext
                        .entry(edit.id.clone())
                        .or_default();
                    if let Some(ref g) = edit.gpu_accelerator_profile {
                        if run_ext.gpu_accelerator_profile.as_deref() != Some(g.as_str()) {
                            changed_targets.push(leaf_target_path(edit.kind, &edit.id, "gpuAcceleratorProfile"));
                        }
                        run_ext.gpu_accelerator_profile = Some(g.clone());
                        cand_ext.gpu_accelerator_profile = Some(g.clone());
                        let k = leaf_prov_key(edit.kind, &edit.id, "gpuAcceleratorProfile");
                        snap.persisted.running_provenance.insert(k.clone(), prov.clone());
                        snap.candidate_provenance.insert(k.clone(), prov.clone());
                        snap.candidate_dirty.remove(&k);
                    }
                    if let Some(ref p) = edit.ai_rrm_policy_id {
                        if run_ext.ai_rrm_policy_id.as_deref() != Some(p.as_str()) {
                            changed_targets.push(leaf_target_path(edit.kind, &edit.id, "aiRrmPolicyId"));
                        }
                        run_ext.ai_rrm_policy_id = Some(p.clone());
                        cand_ext.ai_rrm_policy_id = Some(p.clone());
                        let k = leaf_prov_key(edit.kind, &edit.id, "aiRrmPolicyId");
                        snap.persisted.running_provenance.insert(k.clone(), prov.clone());
                        snap.candidate_provenance.insert(k.clone(), prov.clone());
                        snap.candidate_dirty.remove(&k);
                    }
                }
            }
            kind => {
                let obj_key = cu_object_key(kind, &edit.id);
                let run_rec = snap
                    .persisted
                    .running_cu_objects
                    .entry(obj_key.clone())
                    .or_insert_with(|| CuObjectRecord {
                        kind,
                        id: edit.id.clone(),
                        attrs: ManagedAttributes::default(),
                    });
                let cand_rec = snap
                    .candidate_cu_objects
                    .entry(obj_key)
                    .or_insert_with(|| CuObjectRecord {
                        kind,
                        id: edit.id.clone(),
                        attrs: ManagedAttributes::default(),
                    });
                if let Some(ref st) = edit.administrative_state {
                    if run_rec.attrs.administrative_state.as_deref() != Some(st.as_str()) {
                        changed_targets.push(leaf_target_path(kind, &edit.id, "administrativeState"));
                    }
                    run_rec.attrs.administrative_state = Some(st.clone());
                    cand_rec.attrs.administrative_state = Some(st.clone());
                    let k = leaf_prov_key(kind, &edit.id, "administrativeState");
                    snap.persisted.running_provenance.insert(k.clone(), prov.clone());
                    snap.candidate_provenance.insert(k.clone(), prov.clone());
                    snap.candidate_dirty.remove(&k);
                }
                if let Some(ref g) = edit.gpu_accelerator_profile {
                    if run_rec.attrs.gpu_accelerator_profile.as_deref() != Some(g.as_str()) {
                        changed_targets.push(leaf_target_path(kind, &edit.id, "gpuAcceleratorProfile"));
                    }
                    run_rec.attrs.gpu_accelerator_profile = Some(g.clone());
                    cand_rec.attrs.gpu_accelerator_profile = Some(g.clone());
                    let k = leaf_prov_key(kind, &edit.id, "gpuAcceleratorProfile");
                    snap.persisted.running_provenance.insert(k.clone(), prov.clone());
                    snap.candidate_provenance.insert(k.clone(), prov.clone());
                    snap.candidate_dirty.remove(&k);
                }
                if let Some(ref p) = edit.ai_rrm_policy_id {
                    if run_rec.attrs.ai_rrm_policy_id.as_deref() != Some(p.as_str()) {
                        changed_targets.push(leaf_target_path(kind, &edit.id, "aiRrmPolicyId"));
                    }
                    run_rec.attrs.ai_rrm_policy_id = Some(p.clone());
                    cand_rec.attrs.ai_rrm_policy_id = Some(p.clone());
                    let k = leaf_prov_key(kind, &edit.id, "aiRrmPolicyId");
                    snap.persisted.running_provenance.insert(k.clone(), prov.clone());
                    snap.candidate_provenance.insert(k.clone(), prov.clone());
                    snap.candidate_dirty.remove(&k);
                }
            }
        }
    }
    changed_targets
}

fn collect_leaf_snapshot(
    du_cells: &BTreeMap<String, String>,
    du_ext: &BTreeMap<String, ManagedAttributes>,
    cu_objects: &BTreeMap<String, CuObjectRecord>,
) -> BTreeMap<String, (String, Option<String>)> {
    let mut out = BTreeMap::new();
    for (id, val) in du_cells {
        out.insert(
            leaf_prov_key(ManagedFunctionKind::NRCellDU, id, "administrativeState"),
            (
                leaf_target_path(ManagedFunctionKind::NRCellDU, id, "administrativeState"),
                Some(val.clone()),
            ),
        );
    }
    for (id, ext) in du_ext {
        if let Some(ref g) = ext.gpu_accelerator_profile {
            out.insert(
                leaf_prov_key(ManagedFunctionKind::NRCellDU, id, "gpuAcceleratorProfile"),
                (
                    leaf_target_path(ManagedFunctionKind::NRCellDU, id, "gpuAcceleratorProfile"),
                    Some(g.clone()),
                ),
            );
        }
        if let Some(ref p) = ext.ai_rrm_policy_id {
            out.insert(
                leaf_prov_key(ManagedFunctionKind::NRCellDU, id, "aiRrmPolicyId"),
                (
                    leaf_target_path(ManagedFunctionKind::NRCellDU, id, "aiRrmPolicyId"),
                    Some(p.clone()),
                ),
            );
        }
    }
    for rec in cu_objects.values() {
        if let Some(ref st) = rec.attrs.administrative_state {
            out.insert(
                leaf_prov_key(rec.kind, &rec.id, "administrativeState"),
                (
                    leaf_target_path(rec.kind, &rec.id, "administrativeState"),
                    Some(st.clone()),
                ),
            );
        }
        if let Some(ref g) = rec.attrs.gpu_accelerator_profile {
            out.insert(
                leaf_prov_key(rec.kind, &rec.id, "gpuAcceleratorProfile"),
                (
                    leaf_target_path(rec.kind, &rec.id, "gpuAcceleratorProfile"),
                    Some(g.clone()),
                ),
            );
        }
        if let Some(ref p) = rec.attrs.ai_rrm_policy_id {
            out.insert(
                leaf_prov_key(rec.kind, &rec.id, "aiRrmPolicyId"),
                (
                    leaf_target_path(rec.kind, &rec.id, "aiRrmPolicyId"),
                    Some(p.clone()),
                ),
            );
        }
    }
    out
}

fn diff_changed_leaves(
    before_du: &BTreeMap<String, String>,
    before_du_ext: &BTreeMap<String, ManagedAttributes>,
    before_cu: &BTreeMap<String, CuObjectRecord>,
    after_du: &BTreeMap<String, String>,
    after_du_ext: &BTreeMap<String, ManagedAttributes>,
    after_cu: &BTreeMap<String, CuObjectRecord>,
) -> Vec<(String, String)> {
    let b = collect_leaf_snapshot(before_du, before_du_ext, before_cu);
    let a = collect_leaf_snapshot(after_du, after_du_ext, after_cu);
    let mut keys: std::collections::BTreeSet<&str> = b.keys().map(|s| s.as_str()).collect();
    keys.extend(a.keys().map(|s| s.as_str()));

    let mut changed = Vec::new();
    for k in keys {
        let bv = b.get(k).and_then(|(_, v)| v.as_deref());
        let av = a.get(k).and_then(|(_, v)| v.as_deref());
        if bv != av {
            let path = a
                .get(k)
                .or_else(|| b.get(k))
                .map(|(p, _)| p.clone())
                .unwrap_or_default();
            changed.push((k.to_string(), path));
        }
    }
    changed
}

fn promote_candidate_to_running(
    snap: &mut DatastoreSnapshot,
    username: &str,
    session_id: u64,
    commit_meta: &WriteMeta,
) -> (Vec<String>, WriteMeta) {
    let changed_leaves = diff_changed_leaves(
        &snap.persisted.running_cells,
        &snap.persisted.running_du_ext,
        &snap.persisted.running_cu_objects,
        &snap.candidate_cells,
        &snap.candidate_du_ext,
        &snap.candidate_cu_objects,
    );
    let now = Utc::now();
    let mut resolved_tx = commit_meta.tx_id.clone();
    let mut resolved_tp = commit_meta.traceparent.clone();
    let mut resolved_origin = commit_meta.writer_origin;

    let before_snap = collect_leaf_snapshot(
        &snap.persisted.running_cells,
        &snap.persisted.running_du_ext,
        &snap.persisted.running_cu_objects,
    );
    let after_snap = collect_leaf_snapshot(
        &snap.candidate_cells,
        &snap.candidate_du_ext,
        &snap.candidate_cu_objects,
    );

    for (leaf_key, (_, new_val)) in &after_snap {
        let old_val = before_snap.get(leaf_key).and_then(|(_, v)| v.as_ref());
        let value_changed = old_val != new_val.as_ref();
        let dirty = snap.candidate_dirty.contains(leaf_key);
        if value_changed || dirty {
            let cand_prov = snap.candidate_provenance.get(leaf_key);
            let tx_id = commit_meta
                .tx_id
                .clone()
                .or_else(|| cand_prov.and_then(|p| p.tx_id.clone()));
            let traceparent = commit_meta
                .traceparent
                .clone()
                .or_else(|| cand_prov.and_then(|p| p.traceparent.clone()));
            let origin = if commit_meta.writer_origin != WriterOrigin::O1Client {
                commit_meta.writer_origin
            } else {
                cand_prov.map(|p| p.writer_origin).unwrap_or(WriterOrigin::O1Client)
            };
            if resolved_tx.is_none() {
                resolved_tx = tx_id.clone();
            }
            if resolved_tp.is_none() {
                resolved_tp = traceparent.clone();
            }
            if resolved_origin == WriterOrigin::O1Client && origin != WriterOrigin::O1Client {
                resolved_origin = origin;
            }
            let prov = LeafProvenance {
                owner_principal: username.to_string(),
                owner_session_id: session_id,
                writer_origin: origin,
                tx_id,
                traceparent,
                updated_at: now,
            };
            snap
                .persisted
                .running_provenance
                .insert(leaf_key.clone(), prov.clone());
            snap.candidate_provenance.insert(leaf_key.clone(), prov);
        }
    }

    snap.persisted.running_cells = snap.candidate_cells.clone();
    snap.persisted.running_du_ext = snap.candidate_du_ext.clone();
    snap.persisted.running_cu_objects = snap.candidate_cu_objects.clone();
    snap.candidate_dirty.clear();
    let changed_targets: Vec<String> = changed_leaves.into_iter().map(|(_, p)| p).collect();
    (
        changed_targets,
        WriteMeta {
            tx_id: resolved_tx,
            traceparent: resolved_tp,
            writer_origin: resolved_origin,
        },
    )
}

pub fn render_cells_xml(cells: &BTreeMap<String, String>) -> String {
    render_datastore_xml_with_provenance(cells, &BTreeMap::new(), &BTreeMap::new(), None)
}

fn format_prov_attrs(
    provenance: Option<&BTreeMap<String, LeafProvenance>>,
    leaf_key: &str,
) -> String {
    provenance
        .and_then(|map| map.get(leaf_key))
        .map(|p| {
            let mut attrs = format!(
                " xmlns:o1p=\"{PROVENANCE_NS}\" o1p:owner=\"{}\" o1p:session-id=\"{}\" o1p:writer-origin=\"{}\" o1p:updated-at=\"{}\"",
                xml_escape(&p.owner_principal),
                p.owner_session_id,
                p.writer_origin.as_str(),
                p.updated_at.to_rfc3339_opts(SecondsFormat::Millis, true),
            );
            if let Some(ref tx) = p.tx_id {
                attrs.push_str(&format!(" o1p:tx-id=\"{}\"", xml_escape(tx)));
            }
            if let Some(ref tp) = p.traceparent {
                attrs.push_str(&format!(" o1p:traceparent=\"{}\"", xml_escape(tp)));
            }
            attrs
        })
        .unwrap_or_default()
}

pub fn render_datastore_xml_with_provenance(
    du_cells: &BTreeMap<String, String>,
    du_ext: &BTreeMap<String, ManagedAttributes>,
    cu_objects: &BTreeMap<String, CuObjectRecord>,
    provenance: Option<&BTreeMap<String, LeafProvenance>>,
) -> String {
    let mut du_inner = String::new();
    for (id, state) in du_cells {
        let admin_attrs = format_prov_attrs(
            provenance,
            &leaf_prov_key(ManagedFunctionKind::NRCellDU, id, "administrativeState"),
        );
        let mut extra_tags = String::new();
        if let Some(ext) = du_ext.get(id) {
            if let Some(ref gpu) = ext.gpu_accelerator_profile {
                let gpu_attrs = format_prov_attrs(
                    provenance,
                    &leaf_prov_key(ManagedFunctionKind::NRCellDU, id, "gpuAcceleratorProfile"),
                );
                extra_tags.push_str(&format!(
                    "<gpuAcceleratorProfile{gpu_attrs}>{}</gpuAcceleratorProfile>",
                    xml_escape(gpu)
                ));
            }
            if let Some(ref pol) = ext.ai_rrm_policy_id {
                let pol_attrs = format_prov_attrs(
                    provenance,
                    &leaf_prov_key(ManagedFunctionKind::NRCellDU, id, "aiRrmPolicyId"),
                );
                extra_tags.push_str(&format!(
                    "<aiRrmPolicyId{pol_attrs}>{}</aiRrmPolicyId>",
                    xml_escape(pol)
                ));
            }
        }
        du_inner.push_str(&format!(
            "<NRCellDU><id>{}</id><attributes><administrativeState{admin_attrs}>{}</administrativeState>{extra_tags}</attributes></NRCellDU>",
            xml_escape(id),
            xml_escape(state)
        ));
    }

    let mut xml = format!("<managed-element xmlns=\"{DEMO_NS}\">{du_inner}</managed-element>");

    if !cu_objects.is_empty() {
        let mut cu_inner = String::new();
        for rec in cu_objects.values() {
            let tag = rec.kind.xml_tag();
            let mut attrs_xml = String::new();
            if let Some(ref st) = rec.attrs.administrative_state {
                let a = format_prov_attrs(
                    provenance,
                    &leaf_prov_key(rec.kind, &rec.id, "administrativeState"),
                );
                attrs_xml.push_str(&format!(
                    "<administrativeState{a}>{}</administrativeState>",
                    xml_escape(st)
                ));
            }
            if let Some(ref gpu) = rec.attrs.gpu_accelerator_profile {
                let a = format_prov_attrs(
                    provenance,
                    &leaf_prov_key(rec.kind, &rec.id, "gpuAcceleratorProfile"),
                );
                attrs_xml.push_str(&format!(
                    "<gpuAcceleratorProfile{a}>{}</gpuAcceleratorProfile>",
                    xml_escape(gpu)
                ));
            }
            if let Some(ref pol) = rec.attrs.ai_rrm_policy_id {
                let a = format_prov_attrs(
                    provenance,
                    &leaf_prov_key(rec.kind, &rec.id, "aiRrmPolicyId"),
                );
                attrs_xml.push_str(&format!(
                    "<aiRrmPolicyId{a}>{}</aiRrmPolicyId>",
                    xml_escape(pol)
                ));
            }
            cu_inner.push_str(&format!(
                "<{tag}><id>{}</id><attributes>{attrs_xml}</attributes></{tag}>",
                xml_escape(&rec.id)
            ));
        }
        xml.push_str(&format!(
            "<ManagedElement xmlns=\"{OCU_NRM_NS}\">{cu_inner}</ManagedElement>"
        ));
    }

    xml
}

fn sync_parent_dir(target: &Path) -> Result<()> {
    if let Some(parent) = target.parent() {
        if !parent.as_os_str().is_empty() {
            let dir = File::open(parent)?;
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

fn atomic_write_json<T: Serialize>(target: &Path, value: &T) -> Result<()> {
    let tmp = target.with_extension("json.tmp");
    let data = serde_json::to_vec_pretty(value)?;
    {
        let mut f = File::create(&tmp)?;
        f.write_all(&data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, target)?;
    sync_parent_dir(target)?;
    Ok(())
}

pub fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn rejects_unissued_and_rolled_back_persist_ids() {
        let dir = tempdir().unwrap();
        let state_file = dir.path().join("state.json");

        let eng = DatastoreEngine::open(&state_file, false).unwrap();
        let sid1 = eng.allocate_session_id().await.unwrap();

        // 1. Unissued persist-id on <commit> MUST fail with invalid-value (fixes Clixon T2/T3b/T5 bug)
        let err = eng
            .commit(false, 300, None, Some("never-issued".into()), "smo", sid1, None)
            .await
            .unwrap_err();
        assert_eq!(err.error_tag, "invalid-value");

        // 2. Start persistent confirmed commit, then simulate server restart
        eng.edit_config("candidate", "cell-1", "UNLOCKED", "smo", sid1, None)
            .await
            .unwrap();
        eng.commit(true, 300, Some("tok-1".into()), None, "smo", sid1, None)
            .await
            .unwrap();
        assert!(eng.get_config_xml("running").await.unwrap().contains("UNLOCKED"));

        drop(eng);

        // Re-open (simulating crash/restart): rolls back to LOCKED and clears tok-1 atomically
        let eng2 = DatastoreEngine::open(&state_file, false).unwrap();
        let sid2 = eng2.allocate_session_id().await.unwrap();
        assert!(sid2 > sid1);
        assert!(eng2.get_config_xml("running").await.unwrap().contains("LOCKED"));

        // 3. Stale persist-id after restart rollback MUST fail with invalid-value (fixes netopeer2 T3a/T3c bug!)
        let err2 = eng2
            .commit(false, 300, None, Some("tok-1".into()), "smo", sid2, None)
            .await
            .unwrap_err();
        assert_eq!(err2.error_tag, "invalid-value");

        // 4. Replay shows rollback attributed to <server/>, NOT session-id 0
        let (events, _rx) = eng2
            .replay_and_subscribe(Some(DateTime::from_timestamp(0, 0).unwrap()))
            .await;
        let last_cc = events
            .iter()
            .filter_map(|e| match &e.payload {
                NotificationPayload::ConfigChange { changed_by, .. } => Some(changed_by),
                _ => None,
            })
            .next_back()
            .unwrap();
        assert_eq!(*last_cc, ChangedBy::Server);
    }

    #[tokio::test]
    async fn strict_persist_owner_rejects_cross_principal_t6() {
        let dir = tempdir().unwrap();

        // 1. With strict_persist_owner = true (--strict-persist-owner), ops2 cannot hijack smo's persist-id
        let strict_path = dir.path().join("strict_state.json");
        let eng = DatastoreEngine::open(&strict_path, true).unwrap();
        let sid_smo = eng.allocate_session_id().await.unwrap();
        let sid_ops2 = eng.allocate_session_id().await.unwrap();

        eng.edit_config("candidate", "cell-1", "UNLOCKED", "smo", sid_smo, None)
            .await
            .unwrap();
        eng.commit(
            true,
            300,
            Some("smo-t6-tok".into()),
            None,
            "smo",
            sid_smo,
            None,
        )
        .await
        .unwrap();
        assert!(eng
            .get_config_xml("running")
            .await
            .unwrap()
            .contains("UNLOCKED"));

        // ops2 attempts <cancel-commit> with smo's persist-id -> rejected with access-denied
        let cancel_err = eng
            .cancel_commit(Some("smo-t6-tok".into()), "ops2", sid_ops2)
            .await
            .unwrap_err();
        assert_eq!(cancel_err.error_tag, "access-denied");
        assert!(eng
            .get_config_xml("running")
            .await
            .unwrap()
            .contains("UNLOCKED"));

        // ops2 attempts confirming <commit> with smo's persist-id -> rejected with access-denied
        let confirm_err = eng
            .commit(
                false,
                300,
                None,
                Some("smo-t6-tok".into()),
                "ops2",
                sid_ops2,
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(confirm_err.error_tag, "access-denied");

        // ops2 attempts extending <commit><confirmed/> with smo's persist-id -> rejected with access-denied
        let extend_err = eng
            .commit(
                true,
                600,
                None,
                Some("smo-t6-tok".into()),
                "ops2",
                sid_ops2,
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(extend_err.error_tag, "access-denied");

        // Original principal (smo) on a new session CAN confirm cleanly
        let sid_smo_2 = eng.allocate_session_id().await.unwrap();
        eng.commit(
            false,
            300,
            None,
            Some("smo-t6-tok".into()),
            "smo",
            sid_smo_2,
            None,
        )
        .await
        .unwrap();
        assert!(eng
            .get_config_xml("running")
            .await
            .unwrap()
            .contains("UNLOCKED"));

        // Also verify smo can cancel its own pending commit while ops2 cannot
        eng.edit_config("candidate", "cell-1", "LOCKED", "smo", sid_smo_2, None)
            .await
            .unwrap();
        eng.commit(
            true,
            300,
            Some("smo-t6-tok-2".into()),
            None,
            "smo",
            sid_smo_2,
            None,
        )
        .await
        .unwrap();
        assert!(eng
            .get_config_xml("running")
            .await
            .unwrap()
            .contains("LOCKED"));
        let cancel_err_2 = eng
            .cancel_commit(Some("smo-t6-tok-2".into()), "ops2", sid_ops2)
            .await
            .unwrap_err();
        assert_eq!(cancel_err_2.error_tag, "access-denied");
        eng.cancel_commit(Some("smo-t6-tok-2".into()), "smo", sid_smo_2)
            .await
            .unwrap();
        assert!(eng
            .get_config_xml("running")
            .await
            .unwrap()
            .contains("UNLOCKED"));

        // 2. Contrast with strict_persist_owner = false (RFC 6241 bearer-token baseline): ops2 can cancel
        let bearer_path = dir.path().join("bearer_state.json");
        let eng_bearer = DatastoreEngine::open(&bearer_path, false).unwrap();
        let b_smo = eng_bearer.allocate_session_id().await.unwrap();
        let b_ops2 = eng_bearer.allocate_session_id().await.unwrap();
        eng_bearer
            .edit_config("candidate", "cell-1", "UNLOCKED", "smo", b_smo, None)
            .await
            .unwrap();
        eng_bearer
            .commit(
                true,
                300,
                Some("bearer-tok".into()),
                None,
                "smo",
                b_smo,
                None,
            )
            .await
            .unwrap();
        eng_bearer
            .cancel_commit(Some("bearer-tok".into()), "ops2", b_ops2)
            .await
            .unwrap();
        assert!(eng_bearer
            .get_config_xml("running")
            .await
            .unwrap()
            .contains("LOCKED"));
    }

    #[tokio::test]
    async fn leaf_provenance_persists_rolls_back_and_migrates_legacy_json() {
        let dir = tempdir().unwrap();
        let state_file = dir.path().join("legacy_state.json");

        // 1. Legacy JSON without running_provenance/rollback_provenance/tx_id loads cleanly
        let legacy_json = r#"{
          "next_session_id": 5,
          "running_cells": { "cell-1": "UNLOCKED" },
          "pending_commit": "Idle",
          "notifications": []
        }"#;
        std::fs::write(&state_file, legacy_json).unwrap();

        let eng = DatastoreEngine::open(&state_file, true).unwrap();
        let sid_smo = eng.allocate_session_id().await.unwrap();
        assert_eq!(sid_smo, 5);
        assert!(eng
            .get_config_xml_with_provenance("running", false)
            .await
            .unwrap()
            .contains("<administrativeState>UNLOCKED</administrativeState>"));

        // 2. Write with tx_id + traceparent on candidate -> confirmed commit -> provenance updated
        eng.edit_config_with_meta(
            "candidate",
            "cell-1",
            "LOCKED",
            "smo",
            sid_smo,
            None,
            WriteMeta {
                tx_id: Some("tx-edit-100".into()),
                traceparent: Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        eng.commit_with_meta(
            true,
            300,
            Some("prov-tok".into()),
            None,
            "smo",
            sid_smo,
            None,
            WriteMeta::default(),
        )
        .await
        .unwrap();

        let with_prov = eng
            .get_config_xml_with_provenance("running", true)
            .await
            .unwrap();
        assert!(with_prov.contains("xmlns:o1p=\"urn:o1:provenance:1.0\""));
        assert!(with_prov.contains("o1p:owner=\"smo\""));
        assert!(with_prov.contains("o1p:session-id=\"5\""));
        assert!(with_prov.contains("o1p:tx-id=\"tx-edit-100\""));
        assert!(with_prov.contains("o1p:traceparent=\"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\""));
        assert!(with_prov.contains("o1p:updated-at="));

        // 3. Cancel commit restores running_cells AND running_provenance back to pre-commit state
        eng.cancel_commit(Some("prov-tok".into()), "smo", sid_smo)
            .await
            .unwrap();
        let after_cancel = eng
            .get_config_xml_with_provenance("running", true)
            .await
            .unwrap();
        assert!(after_cancel.contains("<administrativeState>UNLOCKED</administrativeState>"));
        assert!(!after_cancel.contains("o1p:tx-id=\"tx-edit-100\""));
    }

    #[tokio::test]
    async fn sha256_hash_chain_wal_verifies_and_detects_exact_tampered_seq() {
        let dir = tempdir().unwrap();
        let state_file = dir.path().join("wal_state.json");
        let eng = DatastoreEngine::open(&state_file, false).unwrap();
        let sid = eng.allocate_session_id().await.unwrap();

        // Empty chain verifies cleanly at genesis
        let empty_report = eng.verify_audit_chain().await;
        assert!(empty_report.valid);
        assert_eq!(empty_report.entries, 0);
        assert_eq!(empty_report.head_hash, GENESIS_HASH);

        // Emit 3 records (1: running edit, 2: confirmed commit ConfigChange, 3: ConfirmedCommit start)
        eng.edit_config("running", "cell-1", "UNLOCKED", "smo", sid, None)
            .await
            .unwrap();
        eng.edit_config("candidate", "cell-1", "LOCKED", "smo", sid, None)
            .await
            .unwrap();
        eng.commit(true, 300, Some("wal-tok".into()), None, "smo", sid, None)
            .await
            .unwrap();

        let ok_report = eng.verify_audit_chain().await;
        assert!(ok_report.valid);
        assert_eq!(ok_report.entries, 3);
        assert_eq!(ok_report.tampered_seq, None);
        assert_ne!(ok_report.head_hash, GENESIS_HASH);

        drop(eng);

        // Offline file check passes too (and checks sidecar .redb)
        assert!(verify_audit_chain_file(&state_file).unwrap().valid);

        // Tamper with record seq=2 payload inside state.json without updating hashes
        let raw = std::fs::read_to_string(&state_file).unwrap();
        let mut store: PersistedStore = serde_json::from_str(&raw).unwrap();
        assert_eq!(store.notifications.len(), 3);
        assert_eq!(store.notifications[0].prev_hash, GENESIS_HASH);
        assert_eq!(store.notifications[1].prev_hash, store.notifications[0].entry_hash);
        if let NotificationPayload::ConfigChange { ref mut changed_by, .. } =
            store.notifications[1].payload
        {
            *changed_by = ChangedBy::Session {
                username: "attacker".to_string(),
                session_id: 999,
                source_host: None,
            };
        } else {
            panic!("expected ConfigChange at seq 2");
        }
        std::fs::write(&state_file, serde_json::to_vec_pretty(&store).unwrap()).unwrap();

        // Both offline verification and re-opened engine detect exact tampered seq=2
        let tampered_offline = verify_audit_chain_file(&state_file).unwrap();
        assert!(!tampered_offline.valid);
        assert_eq!(tampered_offline.tampered_seq, Some(2));

        let eng_reopened = DatastoreEngine::open(&state_file, false).unwrap();
        let tampered_live = eng_reopened.verify_audit_chain().await;
        assert!(!tampered_live.valid);
        assert_eq!(tampered_live.tampered_seq, Some(2));
    }

    #[tokio::test]
    async fn ocu_gpu_airan_per_leaf_provenance_southbound_and_pod_restart_rollback() {
        let dir = tempdir().unwrap();
        let state_file = dir.path().join("ocu_state.json");
        let eng = DatastoreEngine::open(&state_file, true).unwrap();
        let sid_smo = eng.allocate_session_id().await.unwrap();

        // 1. Default running XML has only NRCellDU for 100% o1demo.py compatibility
        let initial_xml = eng.get_config_xml("running").await.unwrap();
        assert!(!initial_xml.contains("NRCellCU"));

        // 2. O1 client confirms GNBCUCPFunction, GNBCUUPFunction, NRCellCU + NRCellDU
        eng.edit_objects_with_meta(
            "candidate",
            &[
                ObjectEdit {
                    kind: ManagedFunctionKind::GNBCUCPFunction,
                    id: "cucp-1".into(),
                    administrative_state: Some("UNLOCKED".into()),
                    gpu_accelerator_profile: Some("NONE".into()),
                    ai_rrm_policy_id: Some("rrm-base-v1".into()),
                },
                ObjectEdit {
                    kind: ManagedFunctionKind::GNBCUUPFunction,
                    id: "cuup-1".into(),
                    administrative_state: Some("UNLOCKED".into()),
                    gpu_accelerator_profile: Some("DOCA_DPU".into()),
                    ai_rrm_policy_id: None,
                },
                ObjectEdit {
                    kind: ManagedFunctionKind::NRCellCU,
                    id: "cu-cell-1".into(),
                    administrative_state: Some("UNLOCKED".into()),
                    gpu_accelerator_profile: Some("AERIAL_CUDA".into()),
                    ai_rrm_policy_id: Some("rrm-energy-v1".into()),
                },
                ObjectEdit {
                    kind: ManagedFunctionKind::NRCellDU,
                    id: "cell-1".into(),
                    administrative_state: Some("UNLOCKED".into()),
                    gpu_accelerator_profile: Some("AERIAL_CUDA".into()),
                    ai_rrm_policy_id: None,
                },
            ],
            "smo",
            sid_smo,
            None,
            WriteMeta {
                tx_id: Some("tx-cu-init".into()),
                traceparent: Some("00-33333333333333333333333333333333-4444444444444444-01".into()),
                writer_origin: WriterOrigin::O1Client,
            },
        )
        .await
        .unwrap();
        eng.commit(false, 300, None, None, "smo", sid_smo, None)
            .await
            .unwrap();

        let xml_prov = eng
            .get_config_xml_with_provenance("running", true)
            .await
            .unwrap();
        assert!(xml_prov.contains("<GNBCUCPFunction><id>cucp-1</id>"));
        assert!(xml_prov.contains("<GNBCUUPFunction><id>cuup-1</id>"));
        assert!(xml_prov.contains("DOCA_DPU"));
        assert!(xml_prov.contains("AERIAL_CUDA"));
        assert!(xml_prov.contains("o1p:writer-origin=\"o1-client\""));

        // 3. Southbound GPU dApp updates ONLY aiRrmPolicyId on NRCellCU while E2 xApp updates SHUTTINGDOWN
        eng.apply_southbound_sync(
            &[ObjectEdit {
                kind: ManagedFunctionKind::NRCellCU,
                id: "cu-cell-1".into(),
                administrative_state: None,
                gpu_accelerator_profile: None,
                ai_rrm_policy_id: Some("rrm-slot-gpu-v9".into()),
            }],
            "aerial-dapp",
            WriterOrigin::GpuDapp,
            WriteMeta {
                tx_id: Some("tx-gpu-dapp-9".into()),
                traceparent: None,
                writer_origin: WriterOrigin::GpuDapp,
            },
        )
        .await
        .unwrap();

        eng.apply_southbound_sync(
            &[ObjectEdit {
                kind: ManagedFunctionKind::NRCellCU,
                id: "cu-cell-1".into(),
                administrative_state: Some("SHUTTINGDOWN".into()),
                gpu_accelerator_profile: None,
                ai_rrm_policy_id: None,
            }],
            "ric-xapp-es",
            WriterOrigin::E2Xapp,
            WriteMeta::default(),
        )
        .await
        .unwrap();

        let mixed_prov = eng
            .get_config_xml_with_provenance("running", true)
            .await
            .unwrap();
        assert!(mixed_prov.contains("o1p:owner=\"aerial-dapp\""));
        assert!(mixed_prov.contains("o1p:writer-origin=\"gpu-dapp\""));
        assert!(mixed_prov.contains("o1p:owner=\"ric-xapp-es\""));
        assert!(mixed_prov.contains("o1p:writer-origin=\"e2-xapp\""));
        // gpuAcceleratorProfile on NRCellCU still retains smo's o1-client ownership
        assert!(mixed_prov.contains("o1p:owner=\"smo\""));

        // 4. Concurrent O-CU + O-DU confirmed commit followed by pod crash/restart (T3a/T3c)
        eng.edit_objects_with_meta(
            "candidate",
            &[
                ObjectEdit {
                    kind: ManagedFunctionKind::NRCellCU,
                    id: "cu-cell-1".into(),
                    administrative_state: Some("LOCKED".into()),
                    gpu_accelerator_profile: None,
                    ai_rrm_policy_id: None,
                },
                ObjectEdit {
                    kind: ManagedFunctionKind::NRCellDU,
                    id: "cell-1".into(),
                    administrative_state: Some("LOCKED".into()),
                    gpu_accelerator_profile: None,
                    ai_rrm_policy_id: None,
                },
            ],
            "smo",
            sid_smo,
            None,
            WriteMeta::default(),
        )
        .await
        .unwrap();
        eng.commit(
            true,
            300,
            Some("pod-crash-tok".into()),
            None,
            "smo",
            sid_smo,
            None,
        )
        .await
        .unwrap();
        assert!(eng
            .get_config_xml("running")
            .await
            .unwrap()
            .contains("<administrativeState>LOCKED</administrativeState>"));

        drop(eng);

        // Pod restart rolls back BOTH NRCellCU (to SHUTTINGDOWN) and NRCellDU (to UNLOCKED)
        let eng2 = DatastoreEngine::open(&state_file, true).unwrap();
        let sid2 = eng2.allocate_session_id().await.unwrap();
        let after_restart = eng2
            .get_config_xml_with_provenance("running", true)
            .await
            .unwrap();
        assert!(after_restart.contains("<NRCellCU><id>cu-cell-1</id>"));
        assert!(after_restart.contains("SHUTTINGDOWN"));
        assert!(after_restart.contains("UNLOCKED"));

        // Stale persist-id rejected with invalid-value (T3a/T3c)
        let err = eng2
            .commit(false, 300, None, Some("pod-crash-tok".into()), "smo", sid2, None)
            .await
            .unwrap_err();
        assert_eq!(err.error_tag, "invalid-value");

        // Replay shows <changed-by><server/></changed-by> + <writer-origin>server-rollback</writer-origin>
        let (events, _) = eng2
            .replay_and_subscribe(Some(DateTime::from_timestamp(0, 0).unwrap()))
            .await;
        let last_xml = events.last().unwrap().to_notification_xml();
        assert!(last_xml.contains("<changed-by><server/></changed-by>"));
        assert!(last_xml.contains("<writer-origin>server-rollback</writer-origin>"));
        assert!(eng2.verify_audit_chain().await.valid);
    }

    #[tokio::test]
    async fn persistence_boundary_rejects_snapshot_and_redb_failures_without_notifying_or_mutating() {
        let dir = tempdir().unwrap();
        let state_file = dir.path().join("state.json");
        let eng = DatastoreEngine::open(&state_file, false).unwrap();
        let sid = eng.allocate_session_id().await.unwrap();
        let (_, mut live_rx) = eng.replay_and_subscribe(None).await;

        // 1. Inject FailSnapshot on direct running edit -> operation-failed, zero live notif, state stays LOCKED
        eng.set_fail_next_persist(FailPersistMode::FailSnapshot);
        let err1 = eng
            .edit_config("running", "cell-1", "UNLOCKED", "smo", sid, None)
            .await
            .unwrap_err();
        assert_eq!(err1.error_tag, "operation-failed");
        assert!(live_rx.try_recv().is_err());
        assert!(eng.get_config_xml("running").await.unwrap().contains("LOCKED"));

        // 2. Inject FailRedb on candidate + commit -> operation-failed, zero live notif, state stays LOCKED
        eng.edit_config("candidate", "cell-1", "UNLOCKED", "smo", sid, None)
            .await
            .unwrap();
        eng.set_fail_next_persist(FailPersistMode::FailRedb);
        let err2 = eng
            .commit(false, 300, None, None, "smo", sid, None)
            .await
            .unwrap_err();
        assert_eq!(err2.error_tag, "operation-failed");
        assert!(live_rx.try_recv().is_err());
        assert!(eng.get_config_xml("running").await.unwrap().contains("LOCKED"));

        // Reopen from disk and confirm zero phantom records were persisted
        drop(eng);
        let eng_reopen = DatastoreEngine::open(&state_file, false).unwrap();
        assert!(eng_reopen.get_config_xml("running").await.unwrap().contains("LOCKED"));
        let (replayed_zero, mut live_rx2) = eng_reopen
            .replay_and_subscribe(Some(DateTime::from_timestamp(0, 0).unwrap()))
            .await;
        assert!(replayed_zero.is_empty());

        // 3. Normal success path produces exactly one logical ConfigChange record
        let sid2 = eng_reopen.allocate_session_id().await.unwrap();
        eng_reopen
            .edit_config("running", "cell-1", "UNLOCKED", "smo", sid2, None)
            .await
            .unwrap();
        let live_ev = live_rx2.try_recv().expect("exactly one live ConfigChange expected");
        assert!(live_rx2.try_recv().is_err());
        assert_eq!(live_ev.seq, 1);

        // 4. Simulate crash after authoritative redb commit where state.json lags behind redb commit_seq
        let stale_json = PersistedStore::default(); // commit_seq == 0, cell-1 == LOCKED
        fs::write(&state_file, serde_json::to_vec_pretty(&stale_json).unwrap()).unwrap();
        drop(eng_reopen);

        let eng_reconciled = DatastoreEngine::open(&state_file, false).unwrap();
        assert!(eng_reconciled
            .get_config_xml("running")
            .await
            .unwrap()
            .contains("UNLOCKED"));
        assert!(eng_reconciled.verify_audit_chain().await.valid);
    }

    #[tokio::test]
    async fn three_boundary_multi_cell_concurrent_writer_isolates_cell1_from_cell2() {
        let dir = tempdir().unwrap();
        let state_file = dir.path().join("state.json");
        let eng = DatastoreEngine::open(&state_file, false).unwrap();
        let sid_smo = eng.allocate_session_id().await.unwrap();
        let sid_ops2 = eng.allocate_session_id().await.unwrap();

        // SMO commits cell-1 = UNLOCKED (simulating lost reply before reconnect)
        eng.edit_config_with_meta(
            "candidate",
            "cell-1",
            "UNLOCKED",
            "smo",
            sid_smo,
            Some("127.0.0.1".into()),
            WriteMeta {
                tx_id: Some("tx-smo-cell1".into()),
                traceparent: None,
                writer_origin: WriterOrigin::O1Client,
            },
        )
        .await
        .unwrap();
        eng.commit(
            true,
            300,
            Some("cell1-tok".into()),
            None,
            "smo",
            sid_smo,
            Some("127.0.0.1".into()),
        )
        .await
        .unwrap();

        // Before SMO reconnects, competing writer ops2 modifies unrelated cell-2 = UNLOCKED on running
        eng.edit_config_with_meta(
            "running",
            "cell-2",
            "UNLOCKED",
            "ops2",
            sid_ops2,
            Some("127.0.0.1".into()),
            WriteMeta {
                tx_id: Some("tx-ops2-cell2".into()),
                traceparent: None,
                writer_origin: WriterOrigin::O1Client,
            },
        )
        .await
        .unwrap();

        // Both per-leaf provenance and target-specific RFC 6470 replay isolate cell-1 (smo) from cell-2 (ops2)
        let prov_xml = eng.get_config_xml_with_provenance("running", true).await.unwrap();
        assert!(prov_xml.contains(&format!(
            "<NRCellDU><id>cell-1</id><attributes><administrativeState xmlns:o1p=\"{PROVENANCE_NS}\" o1p:owner=\"smo\""
        )));
        assert!(prov_xml.contains(&format!(
            "<NRCellDU><id>cell-2</id><attributes><administrativeState xmlns:o1p=\"{PROVENANCE_NS}\" o1p:owner=\"ops2\""
        )));

        let (events, _) = eng
            .replay_and_subscribe(Some(DateTime::from_timestamp(0, 0).unwrap()))
            .await;
        let cell1_events: Vec<&NotificationRecord> = events
            .iter()
            .filter(|r| match &r.payload {
                NotificationPayload::ConfigChange { targets, .. } => {
                    targets.iter().any(|t| t.contains("NRCellDU[id='cell-1']"))
                }
                _ => false,
            })
            .collect();
        assert_eq!(cell1_events.len(), 1);
        assert!(cell1_events[0]
            .to_notification_xml()
            .contains(&format!("<username>smo</username><session-id>{sid_smo}</session-id>")));
    }
}
