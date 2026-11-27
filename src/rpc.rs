//! RFC 6241 + RFC 5277 XML RPC parser and dispatcher using `quick-xml`.

use crate::datastore::{
    xml_escape, DatastoreEngine, NetconfError, NotificationRecord, WriteMeta, NOTIF_WRAP_NS,
    REPLAY_MOD_NS,
};
use chrono::{DateTime, SecondsFormat, Utc};
use quick_xml::events::Event;
use quick_xml::Reader;
use tokio::sync::broadcast;

pub const NETCONF_BASE_NS: &str = "urn:ietf:params:xml:ns:netconf:base:1.0";

pub struct RpcOutcome {
    pub reply_xml: String,
    pub close_after: bool,
    pub subscription: Option<(Vec<NotificationRecord>, broadcast::Receiver<NotificationRecord>)>,
}

pub fn build_server_hello(session_id: u64) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <hello xmlns=\"{NETCONF_BASE_NS}\">\
           <capabilities>\
             <capability>urn:ietf:params:netconf:base:1.0</capability>\
             <capability>urn:ietf:params:netconf:base:1.1</capability>\
             <capability>urn:ietf:params:netconf:capability:writable-running:1.0</capability>\
             <capability>urn:ietf:params:netconf:capability:candidate:1.0</capability>\
             <capability>urn:ietf:params:netconf:capability:confirmed-commit:1.1</capability>\
             <capability>urn:ietf:params:netconf:capability:with-provenance:1.0</capability>\
             <capability>urn:ietf:params:netconf:capability:txid:1.0</capability>\
             <capability>urn:ietf:params:netconf:capability:notification:1.0</capability>\
             <capability>urn:ietf:params:netconf:capability:interleave:1.0</capability>\
             <capability>urn:ietf:params:xml:ns:yang:ietf-netconf-notifications?module=ietf-netconf-notifications&amp;revision=2012-02-06</capability>\
             <capability>urn:demo:o1:nrcelldu?module=demo-nrcelldu&amp;revision=2026-11-25</capability>\
           </capabilities>\
           <session-id>{session_id}</session-id>\
         </hello>"
    )
}

pub fn client_hello_supports_base11(hello_xml: &str) -> bool {
    hello_xml.contains("urn:ietf:params:netconf:base:1.1")
}

pub fn build_replay_complete_xml() -> String {
    let ts = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    format!(
        "<notification xmlns=\"{NOTIF_WRAP_NS}\"><eventTime>{ts}</eventTime><replayComplete xmlns=\"{REPLAY_MOD_NS}\"/></notification>"
    )
}

pub async fn handle_rpc(
    xml: &str,
    engine: &DatastoreEngine,
    username: &str,
    session_id: u64,
    source_host: Option<String>,
) -> RpcOutcome {
    let parsed = parse_rpc(xml);
    let msg_id = parsed.message_id.as_deref().unwrap_or("1");
    let tx_attr = parsed
        .tx_id
        .as_deref()
        .map(|t| format!(" tx-id=\"{}\"", xml_escape(t)))
        .unwrap_or_default();

    let wrap_ok = || {
        format!(
            "<rpc-reply xmlns=\"{NETCONF_BASE_NS}\" message-id=\"{msg_id}\"{tx_attr}><ok/></rpc-reply>"
        )
    };
    let wrap_err = |err: NetconfError| {
        format!(
            "<rpc-reply xmlns=\"{NETCONF_BASE_NS}\" message-id=\"{msg_id}\"{tx_attr}>{}</rpc-reply>",
            err.to_rpc_error_xml()
        )
    };

    match parsed.op.as_deref() {
        Some("close-session") => RpcOutcome {
            reply_xml: wrap_ok(),
            close_after: true,
            subscription: None,
        },
        Some("get-config") | Some("get") => {
            let src = parsed.source.as_deref().unwrap_or("running");
            match engine
                .get_config_xml_with_provenance(src, parsed.with_provenance)
                .await
            {
                Ok(data_inner) => RpcOutcome {
                    reply_xml: format!(
                        "<rpc-reply xmlns=\"{NETCONF_BASE_NS}\" message-id=\"{msg_id}\"{tx_attr}><data>{data_inner}</data></rpc-reply>"
                    ),
                    close_after: false,
                    subscription: None,
                },
                Err(e) => RpcOutcome {
                    reply_xml: wrap_err(e),
                    close_after: false,
                    subscription: None,
                },
            }
        }
        Some("lock") => {
            let target = parsed.target.as_deref().unwrap_or("candidate");
            let reply_xml = match engine.lock(target, session_id).await {
                Ok(()) => wrap_ok(),
                Err(e) => wrap_err(e),
            };
            RpcOutcome {
                reply_xml,
                close_after: false,
                subscription: None,
            }
        }
        Some("unlock") => {
            let target = parsed.target.as_deref().unwrap_or("candidate");
            let reply_xml = match engine.unlock(target, session_id).await {
                Ok(()) => wrap_ok(),
                Err(e) => wrap_err(e),
            };
            RpcOutcome {
                reply_xml,
                close_after: false,
                subscription: None,
            }
        }
        Some("discard-changes") => {
            let reply_xml = match engine.discard_changes(session_id).await {
                Ok(()) => wrap_ok(),
                Err(e) => wrap_err(e),
            };
            RpcOutcome {
                reply_xml,
                close_after: false,
                subscription: None,
            }
        }
        Some("edit-config") => {
            let target = parsed.target.as_deref().unwrap_or("candidate");
            let cell_id = parsed.cell_id.as_deref().unwrap_or("cell-1");
            let Some(admin_state) = parsed.admin_state.as_deref() else {
                return RpcOutcome {
                    reply_xml: wrap_err(NetconfError::invalid_value(
                        "Missing administrativeState in edit-config",
                    )),
                    close_after: false,
                    subscription: None,
                };
            };
            let meta = WriteMeta {
                tx_id: parsed.tx_id.clone(),
                traceparent: parsed.traceparent.clone(),
            };
            let reply_xml = match engine
                .edit_config_with_meta(target, cell_id, admin_state, username, session_id, source_host, meta)
                .await
            {
                Ok(()) => wrap_ok(),
                Err(e) => wrap_err(e),
            };
            RpcOutcome {
                reply_xml,
                close_after: false,
                subscription: None,
            }
        }
        Some("commit") => {
            let timeout = parsed
                .confirm_timeout
                .as_deref()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(600);
            let meta = WriteMeta {
                tx_id: parsed.tx_id.clone(),
                traceparent: parsed.traceparent.clone(),
            };
            let reply_xml = match engine
                .commit_with_meta(
                    parsed.confirmed,
                    timeout,
                    parsed.persist,
                    parsed.persist_id,
                    username,
                    session_id,
                    source_host,
                    meta,
                )
                .await
            {
                Ok(()) => wrap_ok(),
                Err(e) => wrap_err(e),
            };
            RpcOutcome {
                reply_xml,
                close_after: false,
                subscription: None,
            }
        }
        Some("cancel-commit") => {
            let reply_xml = match engine
                .cancel_commit(parsed.persist_id, username, session_id)
                .await
            {
                Ok(()) => wrap_ok(),
                Err(e) => wrap_err(e),
            };
            RpcOutcome {
                reply_xml,
                close_after: false,
                subscription: None,
            }
        }
        Some("create-subscription") => {
            let start_dt = parsed
                .start_time
                .as_deref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|d| d.with_timezone(&Utc));
            let sub = engine.replay_and_subscribe(start_dt).await;
            RpcOutcome {
                reply_xml: wrap_ok(),
                close_after: false,
                subscription: Some(sub),
            }
        }
        other => RpcOutcome {
            reply_xml: wrap_err(NetconfError::invalid_value(format!(
                "Unsupported RPC operation: {:?}",
                other
            ))),
            close_after: false,
            subscription: None,
        },
    }
}

#[derive(Default, Debug)]
struct ParsedRpc {
    message_id: Option<String>,
    op: Option<String>,
    source: Option<String>,
    target: Option<String>,
    cell_id: Option<String>,
    admin_state: Option<String>,
    confirmed: bool,
    confirm_timeout: Option<String>,
    persist: Option<String>,
    persist_id: Option<String>,
    start_time: Option<String>,
    tx_id: Option<String>,
    traceparent: Option<String>,
    with_provenance: bool,
}

fn local_name(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    s.rsplit(':').next().unwrap_or(&s).to_string()
}

fn extract_meta_attrs(e: &quick_xml::events::BytesStart<'_>, out: &mut ParsedRpc) {
    for attr in e.attributes().flatten() {
        let key = local_name(attr.key.as_ref());
        let val = String::from_utf8_lossy(&attr.value).into_owned();
        match key.as_str() {
            "message-id" if local_name(e.name().as_ref()) == "rpc" => out.message_id = Some(val),
            "tx-id" | "txid" | "etag" => out.tx_id = Some(val),
            "traceparent" => out.traceparent = Some(val),
            "with-provenance" | "with-metadata" if val == "true" || val == "1" => {
                out.with_provenance = true;
            }
            _ => {}
        }
    }
}

fn parse_rpc(xml: &str) -> ParsedRpc {
    let mut out = ParsedRpc::default();
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut stack: Vec<String> = Vec::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                extract_meta_attrs(&e, &mut out);
                let name = local_name(e.name().as_ref());
                if name == "with-provenance" || name == "with-metadata" {
                    out.with_provenance = true;
                } else if stack.len() == 1 && stack[0] == "rpc" && out.op.is_none() {
                    out.op = Some(name.clone());
                } else if stack.last().map(|s| s.as_str()) == Some("source") {
                    out.source = Some(name.clone());
                } else if stack.last().map(|s| s.as_str()) == Some("target") {
                    out.target = Some(name.clone());
                } else if name == "confirmed" {
                    out.confirmed = true;
                }
                stack.push(name);
            }
            Ok(Event::Empty(e)) => {
                extract_meta_attrs(&e, &mut out);
                let name = local_name(e.name().as_ref());
                if name == "with-provenance" || name == "with-metadata" {
                    out.with_provenance = true;
                } else if stack.len() == 1 && stack[0] == "rpc" && out.op.is_none() {
                    out.op = Some(name);
                } else if stack.last().map(|s| s.as_str()) == Some("source") {
                    out.source = Some(name);
                } else if stack.last().map(|s| s.as_str()) == Some("target") {
                    out.target = Some(name);
                } else if name == "confirmed" {
                    out.confirmed = true;
                }
            }
            Ok(Event::Text(t)) => {
                let val = t.unescape().map(|c| c.into_owned()).unwrap_or_default();
                if val.is_empty() {
                    continue;
                }
                match stack.last().map(|s| s.as_str()) {
                    Some("id") => out.cell_id = Some(val),
                    Some("administrativeState") => out.admin_state = Some(val),
                    Some("confirm-timeout") => out.confirm_timeout = Some(val),
                    Some("persist") => out.persist = Some(val),
                    Some("persist-id") => out.persist_id = Some(val),
                    Some("startTime") => out.start_time = Some(val),
                    Some("tx-id") | Some("txid") => out.tx_id = Some(val),
                    Some("traceparent") => out.traceparent = Some(val),
                    _ => {}
                }
            }
            Ok(Event::End(_)) => {
                stack.pop();
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn edit_cell_rpc(msg_id: &str, target: &str, state: &str) -> String {
        format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"{msg_id}\">\
               <edit-config>\
                 <target><{target}/></target>\
                 <config>\
                   <managed-element xmlns=\"urn:demo:o1:nrcelldu\">\
                     <NRCellDU><id>cell-1</id><attributes><administrativeState>{state}</administrativeState></attributes></NRCellDU>\
                   </managed-element>\
                 </config>\
               </edit-config>\
             </rpc>"
        )
    }

    #[tokio::test]
    async fn rpc_lifecycle_get_edit_confirmed_commit_persist_and_subscription() {
        let dir = tempdir().unwrap();
        let engine = DatastoreEngine::open(dir.path().join("state.json"), false).unwrap();
        let sid = engine.allocate_session_id().await.unwrap();
        let host = Some("127.0.0.1".to_string());

        // 1. <get-config> on running shows initial LOCKED state
        let get_running = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"101\"><get-config><source><running/></source></get-config></rpc>"
        );
        let res = handle_rpc(&get_running, &engine, "smo", sid, host.clone()).await;
        assert!(res.reply_xml.contains("message-id=\"101\""));
        assert!(res.reply_xml.contains("<data>"));
        assert!(res.reply_xml.contains("<administrativeState>LOCKED</administrativeState>"));

        // 2. <edit-config> on candidate updates candidate to UNLOCKED without touching running
        let edit_cand = edit_cell_rpc("102", "candidate", "UNLOCKED");
        let res = handle_rpc(&edit_cand, &engine, "smo", sid, host.clone()).await;
        assert!(res.reply_xml.contains("message-id=\"102\""));
        assert!(res.reply_xml.contains("<ok/>"));

        let get_cand = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"103\"><get-config><source><candidate/></source></get-config></rpc>"
        );
        let res_cand = handle_rpc(&get_cand, &engine, "smo", sid, host.clone()).await;
        assert!(res_cand.reply_xml.contains("<administrativeState>UNLOCKED</administrativeState>"));
        let res_run = handle_rpc(&get_running, &engine, "smo", sid, host.clone()).await;
        assert!(res_run.reply_xml.contains("<administrativeState>LOCKED</administrativeState>"));

        // 3. <commit><confirmed/><persist>...</persist></commit> applies candidate to running
        let confirmed_commit = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"104\">\
               <commit><confirmed/><confirm-timeout>300</confirm-timeout><persist>tok-rpc-1</persist></commit>\
             </rpc>"
        );
        let res = handle_rpc(&confirmed_commit, &engine, "smo", sid, host.clone()).await;
        assert!(res.reply_xml.contains("message-id=\"104\""));
        assert!(res.reply_xml.contains("<ok/>"));

        let res_run2 = handle_rpc(&get_running, &engine, "smo", sid, host.clone()).await;
        assert!(res_run2.reply_xml.contains("<administrativeState>UNLOCKED</administrativeState>"));

        // 4. <commit><persist-id>wrong</persist-id></commit> MUST fail with <error-tag>invalid-value</error-tag>
        let bad_confirm = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"105\">\
               <commit><persist-id>wrong-tok</persist-id></commit>\
             </rpc>"
        );
        let res = handle_rpc(&bad_confirm, &engine, "smo", sid, host.clone()).await;
        assert!(res.reply_xml.contains("message-id=\"105\""));
        assert!(res.reply_xml.contains("<rpc-error>"));
        assert!(res.reply_xml.contains("<error-tag>invalid-value</error-tag>"));

        // 5. <commit><persist-id>tok-rpc-1</persist-id></commit> confirms cleanly
        let ok_confirm = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"106\">\
               <commit><persist-id>tok-rpc-1</persist-id></commit>\
             </rpc>"
        );
        let res = handle_rpc(&ok_confirm, &engine, "smo", sid, host.clone()).await;
        assert!(res.reply_xml.contains("message-id=\"106\""));
        assert!(res.reply_xml.contains("<ok/>"));

        // 6. Reusing already-completed persist-id MUST return <error-tag>invalid-value</error-tag>
        let replay_confirm = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"107\">\
               <commit><persist-id>tok-rpc-1</persist-id></commit>\
             </rpc>"
        );
        let res = handle_rpc(&replay_confirm, &engine, "smo", sid, host.clone()).await;
        assert!(res.reply_xml.contains("<error-tag>invalid-value</error-tag>"));

        // 7. <create-subscription> replays RFC 6470 notifications + supports live stream
        let sub_rpc = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"108\">\
               <create-subscription xmlns=\"urn:ietf:params:xml:ns:netconf:notification:1.0\">\
                 <stream>NETCONF</stream>\
                 <startTime>1970-01-01T00:00:00Z</startTime>\
               </create-subscription>\
             </rpc>"
        );
        let res = handle_rpc(&sub_rpc, &engine, "smo", sid, host.clone()).await;
        assert!(res.reply_xml.contains("message-id=\"108\""));
        assert!(res.reply_xml.contains("<ok/>"));

        let (replayed, mut live_rx) = res.subscription.expect("subscription should be established");
        let xmls: Vec<String> = replayed.iter().map(|n| n.to_notification_xml()).collect();
        assert_eq!(xmls.len(), 3);
        assert!(xmls[0].contains("<netconf-config-change xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"));
        assert!(xmls[0].contains(&format!("<changed-by><username>smo</username><session-id>{sid}</session-id><source-host>127.0.0.1</source-host></changed-by>")));
        assert!(xmls[0].contains("<datastore>running</datastore>"));
        assert!(xmls[1].contains("<netconf-confirmed-commit xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"));
        assert!(xmls[1].contains("<confirm-event>start</confirm-event>"));
        assert!(xmls[2].contains("<confirm-event>complete</confirm-event>"));
        assert!(build_replay_complete_xml().contains("<replayComplete xmlns=\"urn:ietf:params:xml:ns:netmod:notification\"/>"));

        // Live edit on running pushes a live notification to live_rx
        let edit_run = edit_cell_rpc("109", "running", "LOCKED");
        let res = handle_rpc(&edit_run, &engine, "ops2", sid + 1, host).await;
        assert!(res.reply_xml.contains("<ok/>"));
        let live_ev = live_rx.recv().await.unwrap().to_notification_xml();
        assert!(live_ev.contains("<username>ops2</username>"));
        assert!(live_ev.contains("<netconf-config-change"));
    }

    #[tokio::test]
    async fn rpc_rejects_unissued_persist_id_and_invalid_inputs() {
        let dir = tempdir().unwrap();
        let engine = DatastoreEngine::open(dir.path().join("state.json"), false).unwrap();
        let sid = engine.allocate_session_id().await.unwrap();

        let idle_confirm = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"201\">\
               <commit><persist-id>never-issued</persist-id></commit>\
             </rpc>"
        );
        let res = handle_rpc(&idle_confirm, &engine, "smo", sid, None).await;
        assert!(res.reply_xml.contains("<error-tag>invalid-value</error-tag>"));

        let missing_state = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"202\">\
               <edit-config><target><candidate/></target><config/></edit-config>\
             </rpc>"
        );
        let res = handle_rpc(&missing_state, &engine, "smo", sid, None).await;
        assert!(res.reply_xml.contains("<error-tag>invalid-value</error-tag>"));

        let unsupported = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"203\"><kill-session/></rpc>"
        );
        let res = handle_rpc(&unsupported, &engine, "smo", sid, None).await;
        assert!(res.reply_xml.contains("<error-tag>invalid-value</error-tag>"));
    }

    #[tokio::test]
    async fn rpc_strict_persist_owner_denies_cross_principal_t6() {
        let dir = tempdir().unwrap();
        let engine = DatastoreEngine::open(dir.path().join("state.json"), true).unwrap();
        let sid_smo = engine.allocate_session_id().await.unwrap();
        let sid_ops2 = engine.allocate_session_id().await.unwrap();

        let edit_cand = edit_cell_rpc("301", "candidate", "UNLOCKED");
        assert!(handle_rpc(&edit_cand, &engine, "smo", sid_smo, None)
            .await
            .reply_xml
            .contains("<ok/>"));

        let confirmed = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"302\">\
               <commit><confirmed/><confirm-timeout>300</confirm-timeout><persist>rpc-t6-tok</persist></commit>\
             </rpc>"
        );
        assert!(handle_rpc(&confirmed, &engine, "smo", sid_smo, None)
            .await
            .reply_xml
            .contains("<ok/>"));

        let hijack_cancel = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"303\">\
               <cancel-commit><persist-id>rpc-t6-tok</persist-id></cancel-commit>\
             </rpc>"
        );
        let res_cancel = handle_rpc(&hijack_cancel, &engine, "ops2", sid_ops2, None).await;
        assert!(res_cancel.reply_xml.contains("<error-tag>access-denied</error-tag>"));

        let hijack_confirm = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"304\">\
               <commit><persist-id>rpc-t6-tok</persist-id></commit>\
             </rpc>"
        );
        let res_confirm = handle_rpc(&hijack_confirm, &engine, "ops2", sid_ops2, None).await;
        assert!(res_confirm.reply_xml.contains("<error-tag>access-denied</error-tag>"));

        // Owner smo succeeds
        let owner_confirm = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"305\">\
               <commit><persist-id>rpc-t6-tok</persist-id></commit>\
             </rpc>"
        );
        let res_ok = handle_rpc(&owner_confirm, &engine, "smo", sid_smo, None).await;
        assert!(res_ok.reply_xml.contains("<ok/>"));
    }

    #[tokio::test]
    async fn rpc_txid_traceparent_and_with_provenance_distinguish_h1_vs_h2() {
        let dir = tempdir().unwrap();
        let engine = DatastoreEngine::open(dir.path().join("state.json"), false).unwrap();
        let sid_smo = engine.allocate_session_id().await.unwrap();
        let sid_ops2 = engine.allocate_session_id().await.unwrap();

        assert!(build_server_hello(sid_smo).contains("urn:ietf:params:netconf:capability:with-provenance:1.0"));
        assert!(build_server_hello(sid_smo).contains("urn:ietf:params:netconf:capability:txid:1.0"));

        // H1: smo edits candidate with tx-id + traceparent attributes, commits with child elements
        let edit_h1 = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"401\" tx-id=\"tx-h1-edit\" traceparent=\"00-11111111111111111111111111111111-2222222222222222-01\">\
               <edit-config><target><candidate/></target><config>\
                 <managed-element xmlns=\"urn:demo:o1:nrcelldu\">\
                   <NRCellDU><id>cell-1</id><attributes><administrativeState>UNLOCKED</administrativeState></attributes></NRCellDU>\
                 </managed-element>\
               </config></edit-config>\
             </rpc>"
        );
        let res_edit = handle_rpc(&edit_h1, &engine, "smo", sid_smo, None).await;
        assert!(res_edit.reply_xml.contains("tx-id=\"tx-h1-edit\""));
        assert!(res_edit.reply_xml.contains("<ok/>"));

        let commit_h1 = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"402\">\
               <commit><tx-id>tx-h1-commit</tx-id><confirmed/><persist>p-h1</persist></commit>\
             </rpc>"
        );
        let res_commit = handle_rpc(&commit_h1, &engine, "smo", sid_smo, None).await;
        assert!(res_commit.reply_xml.contains("tx-id=\"tx-h1-commit\""));
        assert!(res_commit.reply_xml.contains("<ok/>"));

        // Default <get-config> remains clean without o1p:* attributes
        let default_get = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"403\"><get-config><source><running/></source></get-config></rpc>"
        );
        let res_default = handle_rpc(&default_get, &engine, "smo", sid_smo, None).await;
        assert!(res_default.reply_xml.contains("<administrativeState>UNLOCKED</administrativeState>"));
        assert!(!res_default.reply_xml.contains("o1p:"));

        // Single <get-config><with-provenance/></get-config> proves H1 (MINE) without replay
        let prov_get = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"404\">\
               <get-config><source><running/></source><with-provenance/></get-config>\
             </rpc>"
        );
        let res_h1 = handle_rpc(&prov_get, &engine, "smo", sid_smo, None).await;
        assert!(res_h1.reply_xml.contains("xmlns:o1p=\"urn:o1:provenance:1.0\""));
        assert!(res_h1.reply_xml.contains("o1p:owner=\"smo\""));
        assert!(res_h1.reply_xml.contains(&format!("o1p:session-id=\"{sid_smo}\"")));
        assert!(res_h1.reply_xml.contains("o1p:tx-id=\"tx-h1-commit\""));
        assert!(res_h1.reply_xml.contains("o1p:traceparent=\"00-11111111111111111111111111111111-2222222222222222-01\""));

        // H2: ops2 writes running with its own tx-id -> single <get><with-provenance/></get> shows NOT_MINE
        let edit_ops2 = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"405\">\
               <edit-config tx-id=\"tx-h2-ops2\"><target><running/></target><config>\
                 <managed-element xmlns=\"urn:demo:o1:nrcelldu\">\
                   <NRCellDU><id>cell-1</id><attributes><administrativeState>UNLOCKED</administrativeState></attributes></NRCellDU>\
                 </managed-element>\
               </config></edit-config>\
             </rpc>"
        );
        let res_ops2 = handle_rpc(&edit_ops2, &engine, "ops2", sid_ops2, None).await;
        assert!(res_ops2.reply_xml.contains("tx-id=\"tx-h2-ops2\""));

        let prov_get_nested = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"406\">\
               <get><source><running/><with-provenance/></source></get>\
             </rpc>"
        );
        let res_h2 = handle_rpc(&prov_get_nested, &engine, "smo", sid_smo, None).await;
        assert!(res_h2.reply_xml.contains("o1p:owner=\"ops2\""));
        assert!(res_h2.reply_xml.contains(&format!("o1p:session-id=\"{sid_ops2}\"")));
        assert!(res_h2.reply_xml.contains("o1p:tx-id=\"tx-h2-ops2\""));
    }
}
