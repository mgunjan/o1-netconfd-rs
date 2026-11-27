//! Crash-consistent NETCONF datastore, algebraic confirmed-commit state machine,
//! and durable RFC 6470 / RFC 5277 notification log.

use anyhow::Result;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};

pub const DEMO_NS: &str = "urn:demo:o1:nrcelldu";
pub const NOTIF_WRAP_NS: &str = "urn:ietf:params:xml:ns:netconf:notification:1.0";
pub const REPLAY_MOD_NS: &str = "urn:ietf:params:xml:ns:netmod:notification";
pub const RFC6470_NS: &str = "urn:ietf:params:xml:ns:yang:ietf-netconf-notifications";

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationPayload {
    ConfigChange {
        changed_by: ChangedBy,
        datastore: String,
        targets: Vec<String>,
    },
    ConfirmedCommit {
        confirm_event: String,
        username: Option<String>,
        session_id: Option<u64>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationRecord {
    pub event_time: DateTime<Utc>,
    pub payload: NotificationPayload,
}

impl NotificationRecord {
    pub fn to_notification_xml(&self) -> String {
        let ts = self.event_time.to_rfc3339_opts(SecondsFormat::Millis, true);
        let inner = match &self.payload {
            NotificationPayload::ConfigChange {
                changed_by,
                datastore,
                targets,
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
                format!(
                    "<netconf-config-change xmlns=\"{RFC6470_NS}\">{cb_xml}<datastore>{}</datastore>{edits_xml}</netconf-config-change>",
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
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedStore {
    pub next_session_id: u64,
    pub running_cells: BTreeMap<String, String>,
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
            pending_commit: PendingCommitState::Idle,
            notifications: Vec::new(),
        }
    }
}

struct InnerState {
    persisted: PersistedStore,
    candidate_cells: BTreeMap<String, String>,
    candidate_lock: Option<u64>,
    running_lock: Option<u64>,
}

#[derive(Clone)]
pub struct DatastoreEngine {
    state_path: PathBuf,
    strict_persist_owner: bool,
    inner: Arc<Mutex<InnerState>>,
    notif_tx: broadcast::Sender<NotificationRecord>,
}

impl DatastoreEngine {
    /// Open or initialize the crash-safe datastore at `state_path`.
    /// On startup, any unconfirmed commit from before a crash/restart is atomically rolled back
    /// AND its `PendingCommitState` is reset to `Idle`, emitting `<changed-by><server/></changed-by>`.
    pub fn open(state_path: impl AsRef<Path>, strict_persist_owner: bool) -> Result<Self> {
        let state_path = state_path.as_ref().to_path_buf();
        if let Some(parent) = state_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut persisted: PersistedStore = if state_path.exists() {
            let raw = fs::read_to_string(&state_path)?;
            serde_json::from_str(&raw)?
        } else {
            PersistedStore::default()
        };

        // Crash / restart recovery: atomic rollback + PendingCommitState::Idle clearing
        if let PendingCommitState::Pending {
            rollback_cells,
            owner_user,
            owner_session_id,
            ..
        } = persisted.pending_commit.clone()
        {
            let changed = persisted.running_cells != rollback_cells;
            persisted.running_cells = rollback_cells;
            persisted.pending_commit = PendingCommitState::Idle;

            let now = Utc::now();
            persisted.notifications.push(NotificationRecord {
                event_time: now,
                payload: NotificationPayload::ConfirmedCommit {
                    confirm_event: "cancel".to_string(),
                    username: Some(owner_user),
                    session_id: Some(owner_session_id),
                },
            });
            if changed {
                persisted.notifications.push(NotificationRecord {
                    event_time: now,
                    payload: NotificationPayload::ConfigChange {
                        changed_by: ChangedBy::Server,
                        datastore: "running".to_string(),
                        targets: vec!["/demo-nrcelldu:managed-element/NRCellDU[id='cell-1']/attributes/administrativeState".to_string()],
                    },
                });
            }
        }

        atomic_write_json(&state_path, &persisted)?;

        let candidate_cells = persisted.running_cells.clone();
        let (notif_tx, _) = broadcast::channel(256);
        let engine = Self {
            state_path,
            strict_persist_owner,
            inner: Arc::new(Mutex::new(InnerState {
                persisted,
                candidate_cells,
                candidate_lock: None,
                running_lock: None,
            })),
            notif_tx,
        };

        Ok(engine)
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
            owner_user,
            owner_session_id,
            ..
        } = guard.persisted.pending_commit.clone()
        {
            if now_ms >= deadline_ms {
                let changed = guard.persisted.running_cells != rollback_cells;
                guard.persisted.running_cells = rollback_cells.clone();
                guard.candidate_cells = rollback_cells;
                guard.persisted.pending_commit = PendingCommitState::Idle;

                let ev1 = NotificationRecord {
                    event_time: Utc::now(),
                    payload: NotificationPayload::ConfirmedCommit {
                        confirm_event: "timeout".to_string(),
                        username: Some(owner_user),
                        session_id: Some(owner_session_id),
                    },
                };
                guard.persisted.notifications.push(ev1.clone());
                let _ = self.notif_tx.send(ev1);

                if changed {
                    let ev2 = NotificationRecord {
                        event_time: Utc::now(),
                        payload: NotificationPayload::ConfigChange {
                            changed_by: ChangedBy::Server,
                            datastore: "running".to_string(),
                            targets: vec!["/demo-nrcelldu:managed-element/NRCellDU[id='cell-1']/attributes/administrativeState".to_string()],
                        },
                    };
                    guard.persisted.notifications.push(ev2.clone());
                    let _ = self.notif_tx.send(ev2);
                }
                atomic_write_json(&self.state_path, &guard.persisted)?;
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
            owner_user,
            ..
        } = guard.persisted.pending_commit.clone()
        {
            if owner_session_id == session_id {
                let changed = guard.persisted.running_cells != rollback_cells;
                guard.persisted.running_cells = rollback_cells.clone();
                guard.candidate_cells = rollback_cells;
                guard.persisted.pending_commit = PendingCommitState::Idle;
                let ev1 = NotificationRecord {
                    event_time: Utc::now(),
                    payload: NotificationPayload::ConfirmedCommit {
                        confirm_event: "cancel".to_string(),
                        username: Some(owner_user),
                        session_id: Some(session_id),
                    },
                };
                guard.persisted.notifications.push(ev1.clone());
                let _ = self.notif_tx.send(ev1);
                if changed {
                    let ev2 = NotificationRecord {
                        event_time: Utc::now(),
                        payload: NotificationPayload::ConfigChange {
                            changed_by: ChangedBy::Server,
                            datastore: "running".to_string(),
                            targets: vec!["/demo-nrcelldu:managed-element/NRCellDU[id='cell-1']/attributes/administrativeState".to_string()],
                        },
                    };
                    guard.persisted.notifications.push(ev2.clone());
                    let _ = self.notif_tx.send(ev2);
                }
                atomic_write_json(&self.state_path, &guard.persisted)?;
            }
        }
        Ok(())
    }

    pub async fn get_config_xml(&self, source: &str) -> Result<String, NetconfError> {
        let guard = self.inner.lock().await;
        let map = match source {
            "running" => &guard.persisted.running_cells,
            "candidate" => &guard.candidate_cells,
            other => return Err(NetconfError::invalid_value(format!("Unsupported datastore: {other}"))),
        };
        Ok(render_cells_xml(map))
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
        if !matches!(admin_state, "LOCKED" | "UNLOCKED" | "SHUTTINGDOWN") {
            return Err(NetconfError::invalid_value(format!(
                "Invalid administrativeState: {admin_state}"
            )));
        }
        let mut guard = self.inner.lock().await;
        match target {
            "candidate" => {
                if let Some(holder) = guard.candidate_lock {
                    if holder != session_id {
                        return Err(NetconfError::lock_denied("Candidate datastore is locked"));
                    }
                }
                guard.candidate_cells.insert(cell_id.to_string(), admin_state.to_string());
                Ok(())
            }
            "running" => {
                if let Some(holder) = guard.running_lock {
                    if holder != session_id {
                        return Err(NetconfError::lock_denied("Running datastore is locked"));
                    }
                }
                let prev = guard.persisted.running_cells.get(cell_id).cloned();
                guard.persisted.running_cells.insert(cell_id.to_string(), admin_state.to_string());
                guard.candidate_cells.insert(cell_id.to_string(), admin_state.to_string());

                if prev.as_deref() != Some(admin_state) {
                    let ev = NotificationRecord {
                        event_time: Utc::now(),
                        payload: NotificationPayload::ConfigChange {
                            changed_by: ChangedBy::Session {
                                username: username.to_string(),
                                session_id,
                                source_host,
                            },
                            datastore: "running".to_string(),
                            targets: vec![format!(
                                "/demo-nrcelldu:managed-element/NRCellDU[id='{cell_id}']/attributes/administrativeState"
                            )],
                        },
                    };
                    guard.persisted.notifications.push(ev.clone());
                    let _ = self.notif_tx.send(ev);
                }
                atomic_write_json(&self.state_path, &guard.persisted)
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
        let mut guard = self.inner.lock().await;

        // Case 1: Confirming / extending commit carrying <persist-id> (RFC 6241 §8.4.5.1 strict check!)
        if let Some(ref req_pid) = persist_id {
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
                    };
                    let ev = NotificationRecord {
                        event_time: Utc::now(),
                        payload: NotificationPayload::ConfirmedCommit {
                            confirm_event: "extend".to_string(),
                            username: Some(username.to_string()),
                            session_id: Some(session_id),
                        },
                    };
                    guard.persisted.notifications.push(ev.clone());
                    let _ = self.notif_tx.send(ev);
                }
            } else {
                // Finalizing the pending confirmed commit
                let changed = guard.persisted.running_cells != guard.candidate_cells;
                guard.persisted.running_cells = guard.candidate_cells.clone();
                guard.persisted.pending_commit = PendingCommitState::Idle;

                if changed {
                    let ev_cc = NotificationRecord {
                        event_time: Utc::now(),
                        payload: NotificationPayload::ConfigChange {
                            changed_by: ChangedBy::Session {
                                username: username.to_string(),
                                session_id,
                                source_host,
                            },
                            datastore: "running".to_string(),
                            targets: vec!["/demo-nrcelldu:managed-element/NRCellDU[id='cell-1']/attributes/administrativeState".to_string()],
                        },
                    };
                    guard.persisted.notifications.push(ev_cc.clone());
                    let _ = self.notif_tx.send(ev_cc);
                }
                let ev_done = NotificationRecord {
                    event_time: Utc::now(),
                    payload: NotificationPayload::ConfirmedCommit {
                        confirm_event: "complete".to_string(),
                        username: Some(username.to_string()),
                        session_id: Some(session_id),
                    },
                };
                guard.persisted.notifications.push(ev_done.clone());
                let _ = self.notif_tx.send(ev_done);
            }

            atomic_write_json(&self.state_path, &guard.persisted)
                .map_err(|e| NetconfError::operation_failed(e.to_string()))?;
            return Ok(());
        }

        // Case 2: Starting a new confirmed commit (<commit><confirmed/>...</commit>)
        if confirmed {
            let rollback_cells = match &guard.persisted.pending_commit {
                PendingCommitState::Idle => guard.persisted.running_cells.clone(),
                PendingCommitState::Pending { rollback_cells, .. } => rollback_cells.clone(),
            };
            let changed = guard.persisted.running_cells != guard.candidate_cells;
            guard.persisted.running_cells = guard.candidate_cells.clone();
            let deadline_ms = Utc::now().timestamp_millis() + (timeout_secs as i64 * 1000);
            guard.persisted.pending_commit = PendingCommitState::Pending {
                persist_id: persist,
                owner_user: username.to_string(),
                owner_session_id: session_id,
                deadline_ms,
                rollback_cells,
            };

            if changed {
                let ev_cc = NotificationRecord {
                    event_time: Utc::now(),
                    payload: NotificationPayload::ConfigChange {
                        changed_by: ChangedBy::Session {
                            username: username.to_string(),
                            session_id,
                            source_host,
                        },
                        datastore: "running".to_string(),
                        targets: vec!["/demo-nrcelldu:managed-element/NRCellDU[id='cell-1']/attributes/administrativeState".to_string()],
                    },
                };
                guard.persisted.notifications.push(ev_cc.clone());
                let _ = self.notif_tx.send(ev_cc);
            }

            let ev_start = NotificationRecord {
                event_time: Utc::now(),
                payload: NotificationPayload::ConfirmedCommit {
                    confirm_event: "start".to_string(),
                    username: Some(username.to_string()),
                    session_id: Some(session_id),
                },
            };
            guard.persisted.notifications.push(ev_start.clone());
            let _ = self.notif_tx.send(ev_start);

            atomic_write_json(&self.state_path, &guard.persisted)
                .map_err(|e| NetconfError::operation_failed(e.to_string()))?;
            return Ok(());
        }

        // Case 3: Plain <commit/> (completes non-persistent confirmed commit if same session, or commits candidate)
        let was_pending = matches!(
            &guard.persisted.pending_commit,
            PendingCommitState::Pending { persist_id: None, owner_session_id, .. } if *owner_session_id == session_id
        );
        let changed = guard.persisted.running_cells != guard.candidate_cells;
        guard.persisted.running_cells = guard.candidate_cells.clone();
        if was_pending {
            guard.persisted.pending_commit = PendingCommitState::Idle;
        }
        if changed {
            let ev_cc = NotificationRecord {
                event_time: Utc::now(),
                payload: NotificationPayload::ConfigChange {
                    changed_by: ChangedBy::Session {
                        username: username.to_string(),
                        session_id,
                        source_host,
                    },
                    datastore: "running".to_string(),
                    targets: vec!["/demo-nrcelldu:managed-element/NRCellDU[id='cell-1']/attributes/administrativeState".to_string()],
                },
            };
            guard.persisted.notifications.push(ev_cc.clone());
            let _ = self.notif_tx.send(ev_cc);
        }
        if was_pending {
            let ev_done = NotificationRecord {
                event_time: Utc::now(),
                payload: NotificationPayload::ConfirmedCommit {
                    confirm_event: "complete".to_string(),
                    username: Some(username.to_string()),
                    session_id: Some(session_id),
                },
            };
            guard.persisted.notifications.push(ev_done.clone());
            let _ = self.notif_tx.send(ev_done);
        }
        atomic_write_json(&self.state_path, &guard.persisted)
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
        let (rollback_cells, owner_user) = match &guard.persisted.pending_commit {
            PendingCommitState::Idle => {
                return Err(NetconfError::invalid_value("No confirmed commit is pending"));
            }
            PendingCommitState::Pending {
                persist_id: active_pid,
                owner_user,
                owner_session_id,
                rollback_cells,
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
                (rollback_cells.clone(), owner_user.clone())
            }
        };

        let changed = guard.persisted.running_cells != rollback_cells;
        guard.persisted.running_cells = rollback_cells.clone();
        guard.candidate_cells = rollback_cells;
        guard.persisted.pending_commit = PendingCommitState::Idle;

        let ev1 = NotificationRecord {
            event_time: Utc::now(),
            payload: NotificationPayload::ConfirmedCommit {
                confirm_event: "cancel".to_string(),
                username: Some(username.to_string()),
                session_id: Some(session_id),
            },
        };
        guard.persisted.notifications.push(ev1.clone());
        let _ = self.notif_tx.send(ev1);

        if changed {
            let ev2 = NotificationRecord {
                event_time: Utc::now(),
                payload: NotificationPayload::ConfigChange {
                    changed_by: ChangedBy::Session {
                        username: username.to_string(),
                        session_id,
                        source_host: None,
                    },
                    datastore: "running".to_string(),
                    targets: vec!["/demo-nrcelldu:managed-element/NRCellDU[id='cell-1']/attributes/administrativeState".to_string()],
                },
            };
            guard.persisted.notifications.push(ev2.clone());
            let _ = self.notif_tx.send(ev2);
        }
        let _ = owner_user;
        atomic_write_json(&self.state_path, &guard.persisted)
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

pub fn render_cells_xml(cells: &BTreeMap<String, String>) -> String {
    let mut inner = String::new();
    for (id, state) in cells {
        inner.push_str(&format!(
            "<NRCellDU><id>{}</id><attributes><administrativeState>{}</administrativeState></attributes></NRCellDU>",
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
}
