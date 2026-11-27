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
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};

pub const DEMO_NS: &str = "urn:demo:o1:nrcelldu";
pub const PROVENANCE_NS: &str = "urn:o1:provenance:1.0";
pub const NOTIF_WRAP_NS: &str = "urn:ietf:params:xml:ns:netconf:notification:1.0";
pub const REPLAY_MOD_NS: &str = "urn:ietf:params:xml:ns:netmod:notification";
pub const RFC6470_NS: &str = "urn:ietf:params:xml:ns:yang:ietf-netconf-notifications";
pub const GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
const AUDIT_WAL_TABLE: TableDefinition<u64, &str> = TableDefinition::new("audit_wal");

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

/// Optional IETF transaction-id and W3C traceparent propagated on NETCONF write RPCs.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WriteMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traceparent: Option<String>,
}

/// Per-cell RFC 7952 causal ownership metadata persisted alongside running state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeafProvenance {
    pub owner_principal: String,
    pub owner_session_id: u64,
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
                let tx_xml = tx_id
                    .as_ref()
                    .map(|t| format!("<tx-id>{}</tx-id>", xml_escape(t)))
                    .unwrap_or_default();
                let tp_xml = traceparent
                    .as_ref()
                    .map(|t| format!("<traceparent>{}</traceparent>", xml_escape(t)))
                    .unwrap_or_default();
                format!(
                    "<netconf-config-change xmlns=\"{RFC6470_NS}\">{cb_xml}<datastore>{}</datastore>{edits_xml}{tx_xml}{tp_xml}</netconf-config-change>",
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
        rollback_provenance: BTreeMap<String, LeafProvenance>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedStore {
    pub next_session_id: u64,
    pub running_cells: BTreeMap<String, String>,
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
            next_session_id: 1,
            running_cells,
            running_provenance: BTreeMap::new(),
            pending_commit: PendingCommitState::Idle,
            notifications: Vec::new(),
        }
    }
}

struct InnerState {
    persisted: PersistedStore,
    candidate_cells: BTreeMap<String, String>,
    candidate_provenance: BTreeMap<String, LeafProvenance>,
    candidate_dirty: std::collections::BTreeSet<String>,
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
}

impl DatastoreEngine {
    /// Open or initialize the crash-safe datastore at `state_path`.
    /// On startup, any unconfirmed commit from before a crash/restart is atomically rolled back
    /// AND its `PendingCommitState` is reset to `Idle`, emitting `<changed-by><server/></changed-by>`.
    pub fn open(state_path: impl AsRef<Path>, strict_persist_owner: bool) -> Result<Self> {
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
        let pre_recovery_len = persisted.notifications.len();

        // Crash / restart recovery: atomic rollback + PendingCommitState::Idle clearing
        if let PendingCommitState::Pending {
            rollback_cells,
            rollback_provenance,
            owner_user,
            owner_session_id,
            ..
        } = persisted.pending_commit.clone()
        {
            let changed_targets = diff_cell_targets(&persisted.running_cells, &rollback_cells);
            persisted.running_cells = rollback_cells;
            persisted.running_provenance = rollback_provenance;
            persisted.pending_commit = PendingCommitState::Idle;

            let now = Utc::now();
            append_notification(
                &mut persisted,
                now,
                NotificationPayload::ConfirmedCommit {
                    confirm_event: "cancel".to_string(),
                    username: Some(owner_user),
                    session_id: Some(owner_session_id),
                },
            );
            if !changed_targets.is_empty() {
                append_notification(
                    &mut persisted,
                    now,
                    NotificationPayload::ConfigChange {
                        changed_by: ChangedBy::Server,
                        datastore: "running".to_string(),
                        targets: changed_targets,
                        tx_id: None,
                        traceparent: None,
                    },
                );
            }
        }

        atomic_write_json(&state_path, &persisted)?;

        let wal_db = Database::create(&wal_path)?;
        {
            let write_txn = wal_db.begin_write()?;
            {
                let mut table = write_txn.open_table(AUDIT_WAL_TABLE)?;
                if initial_chain_valid {
                    for rec in &persisted.notifications {
                        if table.get(rec.seq)?.is_none() {
                            let encoded = serde_json::to_string(rec)?;
                            table.insert(rec.seq, encoded.as_str())?;
                        }
                    }
                } else if persisted.notifications.len() > pre_recovery_len {
                    for rec in &persisted.notifications[pre_recovery_len..] {
                        let encoded = serde_json::to_string(rec)?;
                        table.insert(rec.seq, encoded.as_str())?;
                    }
                }
            }
            write_txn.commit()?;
        }

        let candidate_cells = persisted.running_cells.clone();
        let candidate_provenance = persisted.running_provenance.clone();
        let (notif_tx, _) = broadcast::channel(256);
        let engine = Self {
            state_path,
            strict_persist_owner,
            inner: Arc::new(Mutex::new(InnerState {
                persisted,
                candidate_cells,
                candidate_provenance,
                candidate_dirty: std::collections::BTreeSet::new(),
                candidate_lock: None,
                running_lock: None,
            })),
            wal_db: Arc::new(std::sync::Mutex::new(wal_db)),
            notif_tx,
        };

        Ok(engine)
    }

    fn persist_with_wal(&self, persisted: &PersistedStore, prev_len: usize) -> Result<()> {
        atomic_write_json(&self.state_path, persisted)?;
        if persisted.notifications.len() > prev_len {
            let db = self
                .wal_db
                .lock()
                .map_err(|_| anyhow::anyhow!("WAL database lock poisoned"))?;
            let write_txn = db.begin_write()?;
            {
                let mut table = write_txn.open_table(AUDIT_WAL_TABLE)?;
                for rec in &persisted.notifications[prev_len..] {
                    let encoded = serde_json::to_string(rec)?;
                    table.insert(rec.seq, encoded.as_str())?;
                }
            }
            write_txn.commit()?;
        }
        Ok(())
    }

    /// Verify integrity of the SHA-256 hash-chained audit WAL and `redb` ACID store.
    pub async fn verify_audit_chain(&self) -> AuditChainReport {
        let guard = self.inner.lock().await;
        let report = verify_notifications_chain(&guard.persisted.notifications);
        if !report.valid {
            return report;
        }
        let Ok(db) = self.wal_db.lock() else {
            return AuditChainReport {
                valid: false,
                entries: guard.persisted.notifications.len(),
                head_hash: report.head_hash,
                tampered_seq: Some(1),
                reason: Some("WAL database lock poisoned".to_string()),
            };
        };
        cross_check_redb(&db, &guard.persisted.notifications, report)
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
            rollback_provenance,
            owner_user,
            owner_session_id,
            ..
        } = guard.persisted.pending_commit.clone()
        {
            if now_ms >= deadline_ms {
                let prev_len = guard.persisted.notifications.len();
                let changed_targets = diff_cell_targets(&guard.persisted.running_cells, &rollback_cells);
                guard.persisted.running_cells = rollback_cells.clone();
                guard.persisted.running_provenance = rollback_provenance.clone();
                guard.candidate_cells = rollback_cells;
                guard.candidate_provenance = rollback_provenance;
                guard.candidate_dirty.clear();
                guard.persisted.pending_commit = PendingCommitState::Idle;

                let ev1 = append_notification(
                    &mut guard.persisted,
                    Utc::now(),
                    NotificationPayload::ConfirmedCommit {
                        confirm_event: "timeout".to_string(),
                        username: Some(owner_user),
                        session_id: Some(owner_session_id),
                    },
                );
                let _ = self.notif_tx.send(ev1);

                if !changed_targets.is_empty() {
                    let ev2 = append_notification(
                        &mut guard.persisted,
                        Utc::now(),
                        NotificationPayload::ConfigChange {
                            changed_by: ChangedBy::Server,
                            datastore: "running".to_string(),
                            targets: changed_targets,
                            tx_id: None,
                            traceparent: None,
                        },
                    );
                    let _ = self.notif_tx.send(ev2);
                }
                self.persist_with_wal(&guard.persisted, prev_len)?;
            }
        }
        Ok(())
    }

    /// Allocate a strictly monotonic, crash-persisted NETCONF session ID (RFC 6470 non-zero).
    pub async fn allocate_session_id(&self) -> Result<u64> {
        let mut guard = self.inner.lock().await;
        let sid = guard.persisted.next_session_id.max(1);
        guard.persisted.next_session_id = sid + 1;
        atomic_write_json(&self.state_path, &guard.persisted)?;
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
            rollback_provenance,
            owner_user,
            ..
        } = guard.persisted.pending_commit.clone()
        {
            if owner_session_id == session_id {
                let prev_len = guard.persisted.notifications.len();
                let changed_targets = diff_cell_targets(&guard.persisted.running_cells, &rollback_cells);
                guard.persisted.running_cells = rollback_cells.clone();
                guard.persisted.running_provenance = rollback_provenance.clone();
                guard.candidate_cells = rollback_cells;
                guard.candidate_provenance = rollback_provenance;
                guard.candidate_dirty.clear();
                guard.persisted.pending_commit = PendingCommitState::Idle;
                let ev1 = append_notification(
                    &mut guard.persisted,
                    Utc::now(),
                    NotificationPayload::ConfirmedCommit {
                        confirm_event: "cancel".to_string(),
                        username: Some(owner_user),
                        session_id: Some(session_id),
                    },
                );
                let _ = self.notif_tx.send(ev1);
                if !changed_targets.is_empty() {
                    let ev2 = append_notification(
                        &mut guard.persisted,
                        Utc::now(),
                        NotificationPayload::ConfigChange {
                            changed_by: ChangedBy::Server,
                            datastore: "running".to_string(),
                            targets: changed_targets,
                            tx_id: None,
                            traceparent: None,
                        },
                    );
                    let _ = self.notif_tx.send(ev2);
                }
                self.persist_with_wal(&guard.persisted, prev_len)?;
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
        let (map, prov) = match source {
            "running" => (&guard.persisted.running_cells, &guard.persisted.running_provenance),
            "candidate" => (&guard.candidate_cells, &guard.candidate_provenance),
            other => return Err(NetconfError::invalid_value(format!("Unsupported datastore: {other}"))),
        };
        Ok(render_cells_xml_with_provenance(
            map,
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
        guard.candidate_cells = guard.persisted.running_cells.clone();
        guard.candidate_provenance = guard.persisted.running_provenance.clone();
        guard.candidate_dirty.clear();
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
        if !matches!(admin_state, "LOCKED" | "UNLOCKED" | "SHUTTINGDOWN") {
            return Err(NetconfError::invalid_value(format!(
                "Invalid administrativeState: {admin_state}"
            )));
        }
        let mut guard = self.inner.lock().await;
        let now = Utc::now();
        let prov = LeafProvenance {
            owner_principal: username.to_string(),
            owner_session_id: session_id,
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
                guard.candidate_cells.insert(cell_id.to_string(), admin_state.to_string());
                guard.candidate_provenance.insert(cell_id.to_string(), prov);
                guard.candidate_dirty.insert(cell_id.to_string());
                Ok(())
            }
            "running" => {
                if let Some(holder) = guard.running_lock {
                    if holder != session_id {
                        return Err(NetconfError::lock_denied("Running datastore is locked"));
                    }
                }
                let prev_len = guard.persisted.notifications.len();
                let prev = guard.persisted.running_cells.get(cell_id).cloned();
                guard.persisted.running_cells.insert(cell_id.to_string(), admin_state.to_string());
                guard.persisted.running_provenance.insert(cell_id.to_string(), prov.clone());
                guard.candidate_cells.insert(cell_id.to_string(), admin_state.to_string());
                guard.candidate_provenance.insert(cell_id.to_string(), prov);
                guard.candidate_dirty.remove(cell_id);

                if prev.as_deref() != Some(admin_state) {
                    let ev = append_notification(
                        &mut guard.persisted,
                        now,
                        NotificationPayload::ConfigChange {
                            changed_by: ChangedBy::Session {
                                username: username.to_string(),
                                session_id,
                                source_host,
                            },
                            datastore: "running".to_string(),
                            targets: vec![cell_target_path(cell_id)],
                            tx_id: meta.tx_id,
                            traceparent: meta.traceparent,
                        },
                    );
                    let _ = self.notif_tx.send(ev);
                }
                self.persist_with_wal(&guard.persisted, prev_len)
                    .map_err(|e| NetconfError::operation_failed(e.to_string()))?;
                Ok(())
            }
            other => Err(NetconfError::invalid_value(format!("Unsupported target: {other}"))),
        }
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
            let prev_len = guard.persisted.notifications.len();
            match &guard.persisted.pending_commit {
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

            if confirmed {
                // Extending timeout on an active persistent confirmed commit
                if let PendingCommitState::Pending {
                    rollback_cells,
                    rollback_provenance,
                    owner_user,
                    owner_session_id,
                    ..
                } = guard.persisted.pending_commit.clone()
                {
                    let new_pid = persist.or_else(|| Some(req_pid.clone()));
                    let deadline_ms = Utc::now().timestamp_millis() + (timeout_secs as i64 * 1000);
                    guard.persisted.pending_commit = PendingCommitState::Pending {
                        persist_id: new_pid,
                        owner_user,
                        owner_session_id,
                        deadline_ms,
                        rollback_cells,
                        rollback_provenance,
                    };
                    let ev = append_notification(
                        &mut guard.persisted,
                        Utc::now(),
                        NotificationPayload::ConfirmedCommit {
                            confirm_event: "extend".to_string(),
                            username: Some(username.to_string()),
                            session_id: Some(session_id),
                        },
                    );
                    let _ = self.notif_tx.send(ev);
                }
            } else {
                // Finalizing the pending confirmed commit
                let (changed_targets, resolved_meta) =
                    promote_candidate_to_running(&mut guard, username, session_id, &meta);
                guard.persisted.pending_commit = PendingCommitState::Idle;

                if !changed_targets.is_empty() {
                    let ev_cc = append_notification(
                        &mut guard.persisted,
                        Utc::now(),
                        NotificationPayload::ConfigChange {
                            changed_by: ChangedBy::Session {
                                username: username.to_string(),
                                session_id,
                                source_host,
                            },
                            datastore: "running".to_string(),
                            targets: changed_targets,
                            tx_id: resolved_meta.tx_id,
                            traceparent: resolved_meta.traceparent,
                        },
                    );
                    let _ = self.notif_tx.send(ev_cc);
                }
                let ev_done = append_notification(
                    &mut guard.persisted,
                    Utc::now(),
                    NotificationPayload::ConfirmedCommit {
                        confirm_event: "complete".to_string(),
                        username: Some(username.to_string()),
                        session_id: Some(session_id),
                    },
                );
                let _ = self.notif_tx.send(ev_done);
            }

            self.persist_with_wal(&guard.persisted, prev_len)
                .map_err(|e| NetconfError::operation_failed(e.to_string()))?;
            return Ok(());
        }

        // Case 2: Starting a new confirmed commit (<commit><confirmed/>...</commit>)
        if confirmed {
            let prev_len = guard.persisted.notifications.len();
            let (rollback_cells, rollback_provenance) = match &guard.persisted.pending_commit {
                PendingCommitState::Idle => (
                    guard.persisted.running_cells.clone(),
                    guard.persisted.running_provenance.clone(),
                ),
                PendingCommitState::Pending {
                    rollback_cells,
                    rollback_provenance,
                    ..
                } => (rollback_cells.clone(), rollback_provenance.clone()),
            };
            let (changed_targets, resolved_meta) =
                promote_candidate_to_running(&mut guard, username, session_id, &meta);
            let deadline_ms = Utc::now().timestamp_millis() + (timeout_secs as i64 * 1000);
            guard.persisted.pending_commit = PendingCommitState::Pending {
                persist_id: persist,
                owner_user: username.to_string(),
                owner_session_id: session_id,
                deadline_ms,
                rollback_cells,
                rollback_provenance,
            };

            if !changed_targets.is_empty() {
                let ev_cc = append_notification(
                    &mut guard.persisted,
                    Utc::now(),
                    NotificationPayload::ConfigChange {
                        changed_by: ChangedBy::Session {
                            username: username.to_string(),
                            session_id,
                            source_host,
                        },
                        datastore: "running".to_string(),
                        targets: changed_targets,
                        tx_id: resolved_meta.tx_id,
                        traceparent: resolved_meta.traceparent,
                    },
                );
                let _ = self.notif_tx.send(ev_cc);
            }

            let ev_start = append_notification(
                &mut guard.persisted,
                Utc::now(),
                NotificationPayload::ConfirmedCommit {
                    confirm_event: "start".to_string(),
                    username: Some(username.to_string()),
                    session_id: Some(session_id),
                },
            );
            let _ = self.notif_tx.send(ev_start);

            self.persist_with_wal(&guard.persisted, prev_len)
                .map_err(|e| NetconfError::operation_failed(e.to_string()))?;
            return Ok(());
        }

        // Case 3: Plain <commit/> (completes non-persistent confirmed commit if same session, or commits candidate)
        let prev_len = guard.persisted.notifications.len();
        let was_pending = matches!(
            &guard.persisted.pending_commit,
            PendingCommitState::Pending { persist_id: None, owner_session_id, .. } if *owner_session_id == session_id
        );
        let (changed_targets, resolved_meta) =
            promote_candidate_to_running(&mut guard, username, session_id, &meta);
        if was_pending {
            guard.persisted.pending_commit = PendingCommitState::Idle;
        }
        if !changed_targets.is_empty() {
            let ev_cc = append_notification(
                &mut guard.persisted,
                Utc::now(),
                NotificationPayload::ConfigChange {
                    changed_by: ChangedBy::Session {
                        username: username.to_string(),
                        session_id,
                        source_host,
                    },
                    datastore: "running".to_string(),
                    targets: changed_targets,
                    tx_id: resolved_meta.tx_id,
                    traceparent: resolved_meta.traceparent,
                },
            );
            let _ = self.notif_tx.send(ev_cc);
        }
        if was_pending {
            let ev_done = append_notification(
                &mut guard.persisted,
                Utc::now(),
                NotificationPayload::ConfirmedCommit {
                    confirm_event: "complete".to_string(),
                    username: Some(username.to_string()),
                    session_id: Some(session_id),
                },
            );
            let _ = self.notif_tx.send(ev_done);
        }
        self.persist_with_wal(&guard.persisted, prev_len)
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
        let prev_len = guard.persisted.notifications.len();
        let (rollback_cells, rollback_provenance, owner_user) = match &guard.persisted.pending_commit {
            PendingCommitState::Idle => {
                return Err(NetconfError::invalid_value("No confirmed commit is pending"));
            }
            PendingCommitState::Pending {
                persist_id: active_pid,
                owner_user,
                owner_session_id,
                rollback_cells,
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
                    rollback_provenance.clone(),
                    owner_user.clone(),
                )
            }
        };

        let changed_targets = diff_cell_targets(&guard.persisted.running_cells, &rollback_cells);
        guard.persisted.running_cells = rollback_cells.clone();
        guard.persisted.running_provenance = rollback_provenance.clone();
        guard.candidate_cells = rollback_cells;
        guard.candidate_provenance = rollback_provenance;
        guard.candidate_dirty.clear();
        guard.persisted.pending_commit = PendingCommitState::Idle;

        let ev1 = append_notification(
            &mut guard.persisted,
            Utc::now(),
            NotificationPayload::ConfirmedCommit {
                confirm_event: "cancel".to_string(),
                username: Some(username.to_string()),
                session_id: Some(session_id),
            },
        );
        let _ = self.notif_tx.send(ev1);

        if !changed_targets.is_empty() {
            let ev2 = append_notification(
                &mut guard.persisted,
                Utc::now(),
                NotificationPayload::ConfigChange {
                    changed_by: ChangedBy::Session {
                        username: username.to_string(),
                        session_id,
                        source_host: None,
                    },
                    datastore: "running".to_string(),
                    targets: changed_targets,
                    tx_id: None,
                    traceparent: None,
                },
            );
            let _ = self.notif_tx.send(ev2);
        }
        let _ = owner_user;
        self.persist_with_wal(&guard.persisted, prev_len)
            .map_err(|e| NetconfError::operation_failed(e.to_string()))?;
        Ok(())
    }

    pub async fn replay_and_subscribe(
        &self,
        start_time: Option<DateTime<Utc>>,
    ) -> (Vec<NotificationRecord>, broadcast::Receiver<NotificationRecord>) {
        let guard = self.inner.lock().await;
        let rx = self.notif_tx.subscribe();
        let replayed: Vec<NotificationRecord> = guard
            .persisted
            .notifications
            .iter()
            .filter(|n| start_time.map(|st| n.event_time >= st).unwrap_or(false))
            .cloned()
            .collect();
        (replayed, rx)
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

fn cell_target_path(cell_id: &str) -> String {
    format!(
        "/demo-nrcelldu:managed-element/NRCellDU[id='{cell_id}']/attributes/administrativeState"
    )
}

fn diff_cell_targets(
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut keys: std::collections::BTreeSet<&str> = before.keys().map(|s| s.as_str()).collect();
    keys.extend(after.keys().map(|s| s.as_str()));
    keys.into_iter()
        .filter(|k| before.get(*k) != after.get(*k))
        .map(cell_target_path)
        .collect()
}

fn promote_candidate_to_running(
    guard: &mut InnerState,
    username: &str,
    session_id: u64,
    commit_meta: &WriteMeta,
) -> (Vec<String>, WriteMeta) {
    let changed_targets = diff_cell_targets(&guard.persisted.running_cells, &guard.candidate_cells);
    let now = Utc::now();
    let mut resolved_tx = commit_meta.tx_id.clone();
    let mut resolved_tp = commit_meta.traceparent.clone();

    let candidate_snapshot = guard.candidate_cells.clone();
    for (cell_id, val) in &candidate_snapshot {
        let value_changed = guard.persisted.running_cells.get(cell_id) != Some(val);
        let dirty = guard.candidate_dirty.contains(cell_id);
        if value_changed || dirty {
            let cand_prov = guard.candidate_provenance.get(cell_id);
            let tx_id = commit_meta
                .tx_id
                .clone()
                .or_else(|| cand_prov.and_then(|p| p.tx_id.clone()));
            let traceparent = commit_meta
                .traceparent
                .clone()
                .or_else(|| cand_prov.and_then(|p| p.traceparent.clone()));
            if resolved_tx.is_none() {
                resolved_tx = tx_id.clone();
            }
            if resolved_tp.is_none() {
                resolved_tp = traceparent.clone();
            }
            let prov = LeafProvenance {
                owner_principal: username.to_string(),
                owner_session_id: session_id,
                tx_id,
                traceparent,
                updated_at: now,
            };
            guard
                .persisted
                .running_provenance
                .insert(cell_id.clone(), prov.clone());
            guard.candidate_provenance.insert(cell_id.clone(), prov);
        }
    }

    guard.persisted.running_cells = candidate_snapshot;
    guard.candidate_dirty.clear();
    (
        changed_targets,
        WriteMeta {
            tx_id: resolved_tx,
            traceparent: resolved_tp,
        },
    )
}

pub fn render_cells_xml(cells: &BTreeMap<String, String>) -> String {
    render_cells_xml_with_provenance(cells, None)
}

pub fn render_cells_xml_with_provenance(
    cells: &BTreeMap<String, String>,
    provenance: Option<&BTreeMap<String, LeafProvenance>>,
) -> String {
    let mut inner = String::new();
    for (id, state) in cells {
        let prov_attrs = provenance
            .and_then(|map| map.get(id))
            .map(|p| {
                let mut attrs = format!(
                    " xmlns:o1p=\"{PROVENANCE_NS}\" o1p:owner=\"{}\" o1p:session-id=\"{}\" o1p:updated-at=\"{}\"",
                    xml_escape(&p.owner_principal),
                    p.owner_session_id,
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
            .unwrap_or_default();

        inner.push_str(&format!(
            "<NRCellDU><id>{}</id><attributes><administrativeState{prov_attrs}>{}</administrativeState></attributes></NRCellDU>",
            xml_escape(id),
            xml_escape(state)
        ));
    }
    format!("<managed-element xmlns=\"{DEMO_NS}\">{inner}</managed-element>")
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
}
