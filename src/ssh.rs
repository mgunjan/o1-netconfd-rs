//! Pure-Rust SSH2 transport for RFC 6242 NETCONF (`netconf` subsystem) via `russh`.

use crate::datastore::DatastoreEngine;
use crate::framing::{encode_frame, try_decode_frame, FramingMode};
use crate::rpc::{build_replay_complete_xml, build_server_hello, client_hello_supports_base11, handle_rpc};
use anyhow::Result;
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{Auth, Handler, Msg, Server as _, Session};
use russh::{Channel, ChannelId, CryptoVec};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone)]
pub struct NetconfSshServer {
    pub engine: DatastoreEngine,
    pub users: Arc<HashMap<String, String>>,
}

impl russh::server::Server for NetconfSshServer {
    type Handler = NetconfConnection;

    fn new_client(&mut self, peer_addr: Option<SocketAddr>) -> Self::Handler {
        NetconfConnection {
            engine: self.engine.clone(),
            users: self.users.clone(),
            peer_ip: peer_addr.map(|a| a.ip().to_string()),
            authenticated_user: None,
            session_id: None,
            framing: FramingMode::Base10,
            hello_received: false,
            rx_buf: Vec::new(),
            netconf_channel: None,
        }
    }
}

pub struct NetconfConnection {
    engine: DatastoreEngine,
    users: Arc<HashMap<String, String>>,
    peer_ip: Option<String>,
    authenticated_user: Option<String>,
    session_id: Option<u64>,
    framing: FramingMode,
    hello_received: bool,
    rx_buf: Vec<u8>,
    netconf_channel: Option<ChannelId>,
}

#[async_trait::async_trait]
impl Handler for NetconfConnection {
    type Error = anyhow::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if self.users.get(user).map(|p| p.as_str()) == Some(password) {
            self.authenticated_user = Some(user.to_string());
            Ok(Auth::Accept)
        } else {
            Ok(Auth::Reject {
                proceed_with_methods: None,
            })
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.netconf_channel = Some(channel.id());
        Ok(true)
    }

    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name != "netconf" {
            session.channel_failure(channel_id)?;
            return Ok(());
        }
        let sid = self.engine.allocate_session_id().await?;
        self.session_id = Some(sid);
        session.channel_success(channel_id)?;

        // Server <hello> MUST always be framed with :base:1.0 EOM (RFC 6242 §4.1)
        let hello = build_server_hello(sid);
        let framed = encode_frame(&hello, FramingMode::Base10);
        session.data(channel_id, CryptoVec::from_slice(&framed))?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel_id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.rx_buf.extend_from_slice(data);

        loop {
            // Client <hello> is always framed in Base10; switch to Base11 afterward if negotiated
            let decode_mode = if !self.hello_received {
                FramingMode::Base10
            } else {
                self.framing
            };

            let Some(msg) = try_decode_frame(&mut self.rx_buf, decode_mode)? else {
                break;
            };

            if !self.hello_received {
                self.hello_received = true;
                if client_hello_supports_base11(&msg) {
                    self.framing = FramingMode::Base11;
                }
                continue;
            }

            let Some(sid) = self.session_id else {
                break;
            };
            let user = self.authenticated_user.as_deref().unwrap_or("unknown");
            let outcome = handle_rpc(&msg, &self.engine, user, sid, self.peer_ip.clone()).await;

            let reply_bytes = encode_frame(&outcome.reply_xml, self.framing);
            session.data(channel_id, CryptoVec::from_slice(&reply_bytes))?;

            if let Some((replayed, mut live_rx)) = outcome.subscription {
                for ev in replayed {
                    let n_bytes = encode_frame(&ev.to_notification_xml(), self.framing);
                    session.data(channel_id, CryptoVec::from_slice(&n_bytes))?;
                }
                let rc_bytes = encode_frame(&build_replay_complete_xml(), self.framing);
                session.data(channel_id, CryptoVec::from_slice(&rc_bytes))?;

                // Spawn live notification forwarder using Session::handle()
                let handle = session.handle();
                let mode = self.framing;
                tokio::spawn(async move {
                    while let Ok(ev) = live_rx.recv().await {
                        let bytes = encode_frame(&ev.to_notification_xml(), mode);
                        if handle.data(channel_id, CryptoVec::from_slice(&bytes)).await.is_err() {
                            break;
                        }
                    }
                });
            }

            if outcome.close_after {
                if let Some(sid) = self.session_id.take() {
                    let _ = self.engine.on_session_closed(sid).await;
                }
                session.eof(channel_id)?;
                session.close(channel_id)?;
                break;
            }
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(sid) = self.session_id.take() {
            let _ = self.engine.on_session_closed(sid).await;
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl Drop for NetconfConnection {
    fn drop(&mut self) {
        if let Some(sid) = self.session_id.take() {
            let eng = self.engine.clone();
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                rt.spawn(async move {
                    let _ = eng.on_session_closed(sid).await;
                });
            }
        }
    }
}

fn build_server_config() -> Result<russh::server::Config> {
    let host_key = PrivateKey::random(&mut russh::keys::ssh_key::rand_core::OsRng, Algorithm::Ed25519)?;
    Ok(russh::server::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(600)),
        auth_rejection_time: std::time::Duration::from_millis(50),
        auth_rejection_time_initial: Some(std::time::Duration::from_millis(0)),
        keys: vec![host_key],
        ..Default::default()
    })
}

pub async fn run_ssh_server(
    listen_addr: &str,
    engine: DatastoreEngine,
    users: HashMap<String, String>,
) -> Result<()> {
    let config = build_server_config()?;
    let mut srv = NetconfSshServer {
        engine,
        users: Arc::new(users),
    };
    srv.run_on_address(Arc::new(config), listen_addr).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::NETCONF_BASE_NS;
    use russh::ChannelMsg;
    use std::time::Duration;
    use tempfile::tempdir;
    use tokio::time::timeout;

    struct TestClient;

    #[async_trait::async_trait]
    impl russh::client::Handler for TestClient {
        type Error = anyhow::Error;

        async fn check_server_key(
            &mut self,
            _server_public_key: &russh::keys::ssh_key::PublicKey,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    async fn read_netconf_frame(
        channel: &mut russh::Channel<russh::client::Msg>,
        rx_buf: &mut Vec<u8>,
        mode: FramingMode,
    ) -> String {
        loop {
            if let Some(frame) = try_decode_frame(rx_buf, mode).unwrap() {
                return frame;
            }
            let msg = timeout(Duration::from_secs(5), channel.wait())
                .await
                .expect("timed out waiting for SSH channel message")
                .expect("channel closed before receiving full NETCONF frame");
            match msg {
                ChannelMsg::Data { data } => rx_buf.extend_from_slice(&data),
                ChannelMsg::Success | ChannelMsg::WindowAdjusted { .. } => {}
                other => panic!("unexpected SSH channel message: {other:?}"),
            }
        }
    }

    async fn send_rpc(
        channel: &mut russh::Channel<russh::client::Msg>,
        rx_buf: &mut Vec<u8>,
        rpc_xml: &str,
    ) -> String {
        let framed = encode_frame(rpc_xml, FramingMode::Base11);
        channel.data(&framed[..]).await.unwrap();
        read_netconf_frame(channel, rx_buf, FramingMode::Base11).await
    }

    #[tokio::test]
    async fn ssh_netconf_wire_rpc_and_subscription_roundtrip() {
        let dir = tempdir().unwrap();
        let engine = DatastoreEngine::open(dir.path().join("state.json"), false).unwrap();
        let mut users = HashMap::new();
        users.insert("smo".to_string(), "smopass".to_string());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = Arc::new(build_server_config().unwrap());
        let mut srv = NetconfSshServer {
            engine,
            users: Arc::new(users),
        };
        let srv_task = tokio::spawn(async move {
            let _ = srv.run_on_socket(config, &listener).await;
        });

        let mut session = timeout(
            Duration::from_secs(5),
            russh::client::connect(Arc::new(russh::client::Config::default()), addr, TestClient),
        )
        .await
        .unwrap()
        .unwrap();

        assert!(session.authenticate_password("smo", "smopass").await.unwrap());
        let mut channel = session.channel_open_session().await.unwrap();
        channel.request_subsystem(true, "netconf").await.unwrap();

        let mut rx_buf = Vec::new();
        let server_hello = read_netconf_frame(&mut channel, &mut rx_buf, FramingMode::Base10).await;
        assert!(server_hello.contains("<hello"));
        assert!(server_hello.contains("urn:ietf:params:netconf:base:1.1"));
        assert!(server_hello.contains("<session-id>1</session-id>"));

        let client_hello = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <hello xmlns=\"{NETCONF_BASE_NS}\">\
               <capabilities>\
                 <capability>urn:ietf:params:netconf:base:1.0</capability>\
                 <capability>urn:ietf:params:netconf:base:1.1</capability>\
               </capabilities>\
             </hello>"
        );
        channel
            .data(&encode_frame(&client_hello, FramingMode::Base10)[..])
            .await
            .unwrap();

        // 1. <get-config>
        let rpc_get = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"1\"><get-config><source><running/></source></get-config></rpc>"
        );
        let reply = send_rpc(&mut channel, &mut rx_buf, &rpc_get).await;
        assert!(reply.contains("<administrativeState>LOCKED</administrativeState>"));

        // 2. <edit-config> candidate -> UNLOCKED
        let rpc_edit = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"2\">\
               <edit-config><target><candidate/></target><config>\
                 <managed-element xmlns=\"urn:demo:o1:nrcelldu\">\
                   <NRCellDU><id>cell-1</id><attributes><administrativeState>UNLOCKED</administrativeState></attributes></NRCellDU>\
                 </managed-element>\
               </config></edit-config>\
             </rpc>"
        );
        let reply = send_rpc(&mut channel, &mut rx_buf, &rpc_edit).await;
        assert!(reply.contains("<ok/>"));

        // 3. <commit><confirmed/><persist>wire-tok-1</persist></commit>
        let rpc_confirmed = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"3\">\
               <commit><confirmed/><confirm-timeout>300</confirm-timeout><persist>wire-tok-1</persist></commit>\
             </rpc>"
        );
        let reply = send_rpc(&mut channel, &mut rx_buf, &rpc_confirmed).await;
        assert!(reply.contains("<ok/>"));

        // 4. Invalid persist-id -> <error-tag>invalid-value</error-tag>
        let rpc_bad_confirm = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"4\"><commit><persist-id>bad-tok</persist-id></commit></rpc>"
        );
        let reply = send_rpc(&mut channel, &mut rx_buf, &rpc_bad_confirm).await;
        assert!(reply.contains("<error-tag>invalid-value</error-tag>"));

        // 5. Valid persist-id -> <ok/>
        let rpc_good_confirm = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"5\"><commit><persist-id>wire-tok-1</persist-id></commit></rpc>"
        );
        let reply = send_rpc(&mut channel, &mut rx_buf, &rpc_good_confirm).await;
        assert!(reply.contains("<ok/>"));

        // 6. <create-subscription> -> <ok/>, replayed notifications, and <replayComplete/>
        let rpc_sub = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"6\">\
               <create-subscription xmlns=\"urn:ietf:params:xml:ns:netconf:notification:1.0\">\
                 <stream>NETCONF</stream>\
                 <startTime>1970-01-01T00:00:00Z</startTime>\
               </create-subscription>\
             </rpc>"
        );
        let sub_ok = send_rpc(&mut channel, &mut rx_buf, &rpc_sub).await;
        assert!(sub_ok.contains("message-id=\"6\"") && sub_ok.contains("<ok/>"));

        let notif_cc = read_netconf_frame(&mut channel, &mut rx_buf, FramingMode::Base11).await;
        assert!(notif_cc.contains("<netconf-config-change"));
        assert!(notif_cc.contains("<username>smo</username>"));

        let notif_start = read_netconf_frame(&mut channel, &mut rx_buf, FramingMode::Base11).await;
        assert!(notif_start.contains("<confirm-event>start</confirm-event>"));

        let notif_done = read_netconf_frame(&mut channel, &mut rx_buf, FramingMode::Base11).await;
        assert!(notif_done.contains("<confirm-event>complete</confirm-event>"));

        let replay_done = read_netconf_frame(&mut channel, &mut rx_buf, FramingMode::Base11).await;
        assert!(replay_done.contains("<replayComplete"));

        // 7. <close-session>
        let rpc_close = format!("<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"7\"><close-session/></rpc>");
        let close_ok = send_rpc(&mut channel, &mut rx_buf, &rpc_close).await;
        assert!(close_ok.contains("message-id=\"7\"") && close_ok.contains("<ok/>"));

        let _ = session.disconnect(russh::Disconnect::ByApplication, "done", "en").await;
        srv_task.abort();
    }

    #[tokio::test]
    async fn ssh_wire_with_provenance_distinguishes_h1_from_h2_without_replay() {
        let dir = tempdir().unwrap();
        let engine = DatastoreEngine::open(dir.path().join("state.json"), false).unwrap();
        let mut users = HashMap::new();
        users.insert("smo".to_string(), "smopass".to_string());
        users.insert("ops2".to_string(), "ops2pass".to_string());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = Arc::new(build_server_config().unwrap());
        let mut srv = NetconfSshServer {
            engine,
            users: Arc::new(users),
        };
        let srv_task = tokio::spawn(async move {
            let _ = srv.run_on_socket(config, &listener).await;
        });

        // Helper closure to connect an SSH NETCONF session
        let connect_user = |user: &'static str, pass: &'static str| async move {
            let mut session = timeout(
                Duration::from_secs(5),
                russh::client::connect(Arc::new(russh::client::Config::default()), addr, TestClient),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(session.authenticate_password(user, pass).await.unwrap());
            let mut channel = session.channel_open_session().await.unwrap();
            channel.request_subsystem(true, "netconf").await.unwrap();
            let mut rx_buf = Vec::new();
            let server_hello = read_netconf_frame(&mut channel, &mut rx_buf, FramingMode::Base10).await;
            assert!(server_hello.contains("urn:ietf:params:netconf:capability:with-provenance:1.0"));
            assert!(server_hello.contains("urn:ietf:params:netconf:capability:txid:1.0"));
            let client_hello = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                 <hello xmlns=\"{NETCONF_BASE_NS}\">\
                   <capabilities>\
                     <capability>urn:ietf:params:netconf:base:1.0</capability>\
                     <capability>urn:ietf:params:netconf:base:1.1</capability>\
                   </capabilities>\
                 </hello>"
            );
            channel
                .data(&encode_frame(&client_hello, FramingMode::Base10)[..])
                .await
                .unwrap();
            (session, channel, rx_buf)
        };

        // === H1: smo applies UNLOCKED with tx-id + traceparent ===
        let (sess_smo1, mut ch_smo1, mut rx_smo1) = connect_user("smo", "smopass").await;
        let rpc_edit = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"1\" tx-id=\"wire-tx-h1\" traceparent=\"00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01\">\
               <edit-config><target><candidate/></target><config>\
                 <managed-element xmlns=\"urn:demo:o1:nrcelldu\">\
                   <NRCellDU><id>cell-1</id><attributes><administrativeState>UNLOCKED</administrativeState></attributes></NRCellDU>\
                 </managed-element>\
               </config></edit-config>\
             </rpc>"
        );
        let r1 = send_rpc(&mut ch_smo1, &mut rx_smo1, &rpc_edit).await;
        assert!(r1.contains("tx-id=\"wire-tx-h1\"") && r1.contains("<ok/>"));
        let rpc_commit = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"2\"><commit/></rpc>"
        );
        assert!(send_rpc(&mut ch_smo1, &mut rx_smo1, &rpc_commit).await.contains("<ok/>"));
        let _ = sess_smo1.disconnect(russh::Disconnect::ByApplication, "done", "en").await;

        // Reconnect as smo: single <get-config><with-provenance/></get-config> proves MINE (H1)
        let (sess_smo2, mut ch_smo2, mut rx_smo2) = connect_user("smo", "smopass").await;
        let rpc_get_prov = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"3\">\
               <get-config><source><running/></source><with-provenance/></get-config>\
             </rpc>"
        );
        let h1_read = send_rpc(&mut ch_smo2, &mut rx_smo2, &rpc_get_prov).await;
        assert!(h1_read.contains("o1p:owner=\"smo\""));
        assert!(h1_read.contains("o1p:session-id=\"1\""));
        assert!(h1_read.contains("o1p:tx-id=\"wire-tx-h1\""));
        assert!(h1_read.contains("o1p:traceparent=\"00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01\""));

        // === H2: ops2 overwrites running with its own tx-id ===
        let (sess_ops2, mut ch_ops2, mut rx_ops2) = connect_user("ops2", "ops2pass").await;
        let rpc_ops2 = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"4\" tx-id=\"wire-tx-h2\">\
               <edit-config><target><running/></target><config>\
                 <managed-element xmlns=\"urn:demo:o1:nrcelldu\">\
                   <NRCellDU><id>cell-1</id><attributes><administrativeState>UNLOCKED</administrativeState></attributes></NRCellDU>\
                 </managed-element>\
               </config></edit-config>\
             </rpc>"
        );
        let r2 = send_rpc(&mut ch_ops2, &mut rx_ops2, &rpc_ops2).await;
        assert!(r2.contains("tx-id=\"wire-tx-h2\"") && r2.contains("<ok/>"));
        let _ = sess_ops2.disconnect(russh::Disconnect::ByApplication, "done", "en").await;

        // Same single <get-config><with-provenance/></get-config> proves NOT_MINE (H2) without replay!
        let h2_read = send_rpc(&mut ch_smo2, &mut rx_smo2, &rpc_get_prov).await;
        assert!(h2_read.contains("o1p:owner=\"ops2\""));
        assert!(h2_read.contains("o1p:session-id=\"3\""));
        assert!(h2_read.contains("o1p:tx-id=\"wire-tx-h2\""));

        let _ = sess_smo2.disconnect(russh::Disconnect::ByApplication, "done", "en").await;
        srv_task.abort();
    }

    #[tokio::test]
    async fn ssh_wire_concurrent_ocu_odu_confirmed_commits_gpu_profile_and_restart_rollback() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("ocu_wire_state.json");
        let mut users = HashMap::new();
        users.insert("smo".to_string(), "smopass".to_string());
        users.insert("ops2".to_string(), "ops2pass".to_string());
        let users_arc = Arc::new(users);

        let spawn_server = |eng: DatastoreEngine, users: Arc<HashMap<String, String>>| async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let config = Arc::new(build_server_config().unwrap());
            let mut srv = NetconfSshServer {
                engine: eng,
                users,
            };
            let task = tokio::spawn(async move {
                let _ = srv.run_on_socket(config, &listener).await;
            });
            (addr, task)
        };

        let connect_client = |addr: SocketAddr, user: &'static str, pass: &'static str| async move {
            let mut session = timeout(
                Duration::from_secs(5),
                russh::client::connect(Arc::new(russh::client::Config::default()), addr, TestClient),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(session.authenticate_password(user, pass).await.unwrap());
            let mut channel = session.channel_open_session().await.unwrap();
            channel.request_subsystem(true, "netconf").await.unwrap();
            let mut rx_buf = Vec::new();
            let hello = read_netconf_frame(&mut channel, &mut rx_buf, FramingMode::Base10).await;
            assert!(hello.contains("urn:3gpp:sa5:_3gpp-nr-nrm-nrcellcu"));
            let client_hello = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                 <hello xmlns=\"{NETCONF_BASE_NS}\">\
                   <capabilities>\
                     <capability>urn:ietf:params:netconf:base:1.0</capability>\
                     <capability>urn:ietf:params:netconf:base:1.1</capability>\
                   </capabilities>\
                 </hello>"
            );
            channel
                .data(&encode_frame(&client_hello, FramingMode::Base10)[..])
                .await
                .unwrap();
            (session, channel, rx_buf)
        };

        // Phase 1: Boot server, commit GPU O-CU + O-DU baseline, then start confirmed commit & simulate pod crash
        let eng1 = DatastoreEngine::open(&state_path, true).unwrap();
        let (addr1, srv_task1) = spawn_server(eng1, users_arc.clone()).await;

        let (sess_smo, mut ch_smo, mut rx_smo) = connect_client(addr1, "smo", "smopass").await;
        let baseline_rpc = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"1\" tx-id=\"tx-cu-base\">\
               <edit-config><target><running/></target><config>\
                 <ManagedElement xmlns=\"urn:3gpp:sa5:_3gpp-nr-nrm-nrcellcu\">\
                   <GNBCUCPFunction><id>cucp-1</id><attributes><administrativeState>UNLOCKED</administrativeState></attributes></GNBCUCPFunction>\
                   <GNBCUUPFunction><id>cuup-1</id><attributes><gpuAcceleratorProfile>DOCA_DPU</gpuAcceleratorProfile></attributes></GNBCUUPFunction>\
                   <NRCellCU><id>cu-cell-1</id><attributes><administrativeState>UNLOCKED</administrativeState><gpuAcceleratorProfile>AERIAL_CUDA</gpuAcceleratorProfile><aiRrmPolicyId>rrm-base</aiRrmPolicyId></attributes></NRCellCU>\
                 </ManagedElement>\
               </config></edit-config>\
             </rpc>"
        );
        assert!(send_rpc(&mut ch_smo, &mut rx_smo, &baseline_rpc).await.contains("<ok/>"));

        // ops2 updates NRCellDU while smo starts a confirmed commit across NRCellCU + NRCellDU
        let (sess_ops2, mut ch_ops2, mut rx_ops2) = connect_client(addr1, "ops2", "ops2pass").await;
        let ops2_du_rpc = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"2\" tx-id=\"tx-du-ops2\">\
               <edit-config><target><running/></target><config>\
                 <managed-element xmlns=\"urn:demo:o1:nrcelldu\">\
                   <NRCellDU><id>cell-1</id><attributes><administrativeState>UNLOCKED</administrativeState></attributes></NRCellDU>\
                 </managed-element>\
               </config></edit-config>\
             </rpc>"
        );
        assert!(send_rpc(&mut ch_ops2, &mut rx_ops2, &ops2_du_rpc).await.contains("<ok/>"));

        // smo issues confirmed commit changing both NRCellCU -> LOCKED and NRCellDU -> LOCKED
        let cand_rpc = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"3\" tx-id=\"tx-pod-crash\">\
               <edit-config><target><candidate/></target><config>\
                 <managed-element xmlns=\"urn:demo:o1:nrcelldu\">\
                   <NRCellDU><id>cell-1</id><attributes><administrativeState>LOCKED</administrativeState></attributes></NRCellDU>\
                 </managed-element>\
                 <ManagedElement xmlns=\"urn:3gpp:sa5:_3gpp-nr-nrm-nrcellcu\">\
                   <NRCellCU><id>cu-cell-1</id><attributes><administrativeState>LOCKED</administrativeState></attributes></NRCellCU>\
                 </ManagedElement>\
               </config></edit-config>\
             </rpc>"
        );
        assert!(send_rpc(&mut ch_smo, &mut rx_smo, &cand_rpc).await.contains("<ok/>"));
        let confirmed_rpc = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"4\">\
               <commit><confirmed/><confirm-timeout>300</confirm-timeout><persist>ocu-pod-tok</persist></commit>\
             </rpc>"
        );
        assert!(send_rpc(&mut ch_smo, &mut rx_smo, &confirmed_rpc).await.contains("<ok/>"));

        let _ = sess_smo.disconnect(russh::Disconnect::ByApplication, "crash", "en").await;
        let _ = sess_ops2.disconnect(russh::Disconnect::ByApplication, "done", "en").await;
        drop(ch_smo);
        drop(ch_ops2);
        drop(sess_smo);
        drop(sess_ops2);
        srv_task1.abort();
        let _ = srv_task1.await;

        // Phase 2: Pod restart on same state_path -> rolls back both NRCellCU & NRCellDU, rejects stale token
        let mut eng2_opt = None;
        for _ in 0..40 {
            if let Ok(e) = DatastoreEngine::open(&state_path, true) {
                eng2_opt = Some(e);
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let eng2 = eng2_opt.expect("reopened DatastoreEngine after server shutdown");
        let (addr2, srv_task2) = spawn_server(eng2, users_arc).await;
        let (sess_check, mut ch_check, mut rx_check) = connect_client(addr2, "smo", "smopass").await;

        let stale_confirm = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"5\"><commit><persist-id>ocu-pod-tok</persist-id></commit></rpc>"
        );
        let stale_reply = send_rpc(&mut ch_check, &mut rx_check, &stale_confirm).await;
        assert!(stale_reply.contains("<error-tag>invalid-value</error-tag>"));

        let get_prov = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"6\">\
               <get-config><source><running/></source><with-provenance/></get-config>\
             </rpc>"
        );
        let prov_reply = send_rpc(&mut ch_check, &mut rx_check, &get_prov).await;
        assert!(prov_reply.contains("o1p:owner=\"ops2\""));
        assert!(prov_reply.contains("o1p:tx-id=\"tx-du-ops2\""));
        assert!(prov_reply.contains("o1p:owner=\"smo\""));
        assert!(prov_reply.contains("AERIAL_CUDA"));
        assert!(prov_reply.contains("DOCA_DPU"));

        // Verify replay contains <changed-by><server/></changed-by> + server-rollback
        let sub_rpc = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"7\">\
               <create-subscription xmlns=\"urn:ietf:params:xml:ns:netconf:notification:1.0\">\
                 <stream>NETCONF</stream><startTime>1970-01-01T00:00:00Z</startTime>\
               </create-subscription>\
             </rpc>"
        );
        assert!(send_rpc(&mut ch_check, &mut rx_check, &sub_rpc).await.contains("<ok/>"));
        let mut saw_server_rollback = false;
        loop {
            let msg = read_netconf_frame(&mut ch_check, &mut rx_check, FramingMode::Base11).await;
            if msg.contains("<replayComplete") {
                break;
            }
            if msg.contains("<changed-by><server/></changed-by>")
                && msg.contains("<writer-origin>server-rollback</writer-origin>")
            {
                saw_server_rollback = true;
            }
        }
        assert!(saw_server_rollback);

        let _ = sess_check.disconnect(russh::Disconnect::ByApplication, "done", "en").await;
        srv_task2.abort();
    }
}
