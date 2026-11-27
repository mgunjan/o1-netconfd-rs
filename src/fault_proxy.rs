//! Lightweight async L4 TCP fault-injection proxy for wire-level H1/H2 NETCONF tests.

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::task::JoinHandle;

/// Programmable L4 fault-injection behavior for [`FaultProxy`].
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultMode {
    /// Forward all client-to-server and server-to-client bytes unmodified.
    PassThrough,
    /// Network-level H1 lost-reply injection:
    /// Forward the client's commit RPC to the server, then drop the
    /// server-to-client reply stream once the server writes its reply.
    DropServerToClientAfterRpcCommit,
    /// Network-level H2 lost-request injection:
    /// Drop the client-to-server stream before the next RPC reaches the server.
    DropClientToServerBeforeRpc,
}

/// Cumulative byte and fault counters observed by [`FaultProxy`].
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FaultProxyStats {
    pub connections_accepted: u64,
    pub forwarded_c2s_bytes: u64,
    pub forwarded_s2c_bytes: u64,
    pub dropped_c2s_bytes: u64,
    pub dropped_s2c_bytes: u64,
    pub faults_triggered: u64,
}

struct AtomicStats {
    connections_accepted: AtomicU64,
    forwarded_c2s_bytes: AtomicU64,
    forwarded_s2c_bytes: AtomicU64,
    dropped_c2s_bytes: AtomicU64,
    dropped_s2c_bytes: AtomicU64,
    faults_triggered: AtomicU64,
}

impl Default for AtomicStats {
    fn default() -> Self {
        Self {
            connections_accepted: AtomicU64::new(0),
            forwarded_c2s_bytes: AtomicU64::new(0),
            forwarded_s2c_bytes: AtomicU64::new(0),
            dropped_c2s_bytes: AtomicU64::new(0),
            dropped_s2c_bytes: AtomicU64::new(0),
            faults_triggered: AtomicU64::new(0),
        }
    }
}

struct ProxyShared {
    mode_state: Mutex<(FaultMode, u64)>,
    stats: AtomicStats,
}

impl ProxyShared {
    fn new(initial_mode: FaultMode) -> Self {
        Self {
            mode_state: Mutex::new((initial_mode, 0)),
            stats: AtomicStats::default(),
        }
    }

    fn mode_with_epoch(&self) -> (FaultMode, u64) {
        *self.mode_state.lock().expect("proxy mode lock poisoned")
    }

    fn set_mode(&self, mode: FaultMode) {
        let mut guard = self.mode_state.lock().expect("proxy mode lock poisoned");
        guard.0 = mode;
        guard.1 = guard.1.wrapping_add(1);
    }

    fn snapshot_stats(&self) -> FaultProxyStats {
        FaultProxyStats {
            connections_accepted: self.stats.connections_accepted.load(Ordering::Relaxed),
            forwarded_c2s_bytes: self.stats.forwarded_c2s_bytes.load(Ordering::Relaxed),
            forwarded_s2c_bytes: self.stats.forwarded_s2c_bytes.load(Ordering::Relaxed),
            dropped_c2s_bytes: self.stats.dropped_c2s_bytes.load(Ordering::Relaxed),
            dropped_s2c_bytes: self.stats.dropped_s2c_bytes.load(Ordering::Relaxed),
            faults_triggered: self.stats.faults_triggered.load(Ordering::Relaxed),
        }
    }

    fn reset_stats(&self) {
        self.stats.connections_accepted.store(0, Ordering::Relaxed);
        self.stats.forwarded_c2s_bytes.store(0, Ordering::Relaxed);
        self.stats.forwarded_s2c_bytes.store(0, Ordering::Relaxed);
        self.stats.dropped_c2s_bytes.store(0, Ordering::Relaxed);
        self.stats.dropped_s2c_bytes.store(0, Ordering::Relaxed);
        self.stats.faults_triggered.store(0, Ordering::Relaxed);
    }
}

struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Async L4 TCP proxy forwarding traffic to an upstream NETCONF/SSH server
/// with programmable H1/H2 fault injection.
#[allow(dead_code)]
#[derive(Clone)]
pub struct FaultProxy {
    listen_addr: SocketAddr,
    upstream_addr: SocketAddr,
    shared: Arc<ProxyShared>,
    _accept_task: Arc<AbortOnDrop>,
}

#[allow(dead_code)]
impl FaultProxy {
    /// Start listening on `listen_addr` and proxy connections to `upstream_addr`.
    pub async fn start(
        listen_addr: impl ToSocketAddrs,
        upstream_addr: SocketAddr,
        initial_mode: FaultMode,
    ) -> Result<Self> {
        let listener = TcpListener::bind(listen_addr).await?;
        let local_addr = listener.local_addr()?;
        let shared = Arc::new(ProxyShared::new(initial_mode));
        let accept_shared = shared.clone();

        let handle = tokio::spawn(async move {
            loop {
                let Ok((client_stream, _peer)) = listener.accept().await else {
                    break;
                };
                accept_shared
                    .stats
                    .connections_accepted
                    .fetch_add(1, Ordering::Relaxed);
                let conn_shared = accept_shared.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(client_stream, upstream_addr, conn_shared).await;
                });
            }
        });

        Ok(Self {
            listen_addr: local_addr,
            upstream_addr,
            shared,
            _accept_task: Arc::new(AbortOnDrop(handle)),
        })
    }

    /// Convenience helper binding an ephemeral `127.0.0.1:0` listener.
    pub async fn start_on_loopback(
        upstream_addr: SocketAddr,
        initial_mode: FaultMode,
    ) -> Result<Self> {
        Self::start("127.0.0.1:0", upstream_addr, initial_mode).await
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    pub fn upstream_addr(&self) -> SocketAddr {
        self.upstream_addr
    }

    pub fn set_mode(&self, mode: FaultMode) {
        self.shared.set_mode(mode);
    }

    pub fn mode(&self) -> FaultMode {
        self.shared.mode_with_epoch().0
    }

    pub fn stats(&self) -> FaultProxyStats {
        self.shared.snapshot_stats()
    }

    pub fn reset_stats(&self) {
        self.shared.reset_stats();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnProto {
    Unknown,
    Ssh,
    Xml,
    Opaque,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExitReason {
    NormalEof,
    FaultDropped,
}

fn detect_proto(first_chunk: &[u8]) -> ConnProto {
    if first_chunk.starts_with(b"SSH-") {
        ConnProto::Ssh
    } else if first_chunk
        .iter()
        .copied()
        .find(|b| !b.is_ascii_whitespace())
        == Some(b'<')
    {
        ConnProto::Xml
    } else {
        ConnProto::Opaque
    }
}

fn contains_commit_tag(buf: &[u8]) -> bool {
    buf.windows(7).any(|w| w == b"<commit" || w == b":commit")
}

async fn handle_connection(
    client_stream: TcpStream,
    upstream_addr: SocketAddr,
    shared: Arc<ProxyShared>,
) -> Result<()> {
    let server_stream = TcpStream::connect(upstream_addr).await?;
    let _ = client_stream.set_nodelay(true);
    let _ = server_stream.set_nodelay(true);

    let (mut client_read, mut client_write) = client_stream.into_split();
    let (mut server_read, mut server_write) = server_stream.into_split();

    let drop_s2c_armed = Arc::new(AtomicBool::new(false));
    let c2s_armed = drop_s2c_armed.clone();
    let c2s_shared = shared.clone();

    let mut c2s = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        let mut proto = ConnProto::Unknown;
        let mut xml_tail: Vec<u8> = Vec::new();
        let mut armed_at_epoch: Option<u64> = None;

        loop {
            let n = client_read.read(&mut buf).await?;
            if n == 0 {
                let _ = server_write.shutdown().await;
                return Ok::<ExitReason, std::io::Error>(ExitReason::NormalEof);
            }
            let chunk = &buf[..n];
            if proto == ConnProto::Unknown {
                proto = detect_proto(chunk);
            }

            let (mode, epoch) = c2s_shared.mode_with_epoch();
            match mode {
                FaultMode::PassThrough => {
                    server_write.write_all(chunk).await?;
                    server_write.flush().await?;
                    c2s_shared
                        .stats
                        .forwarded_c2s_bytes
                        .fetch_add(n as u64, Ordering::Relaxed);
                }
                FaultMode::DropClientToServerBeforeRpc => {
                    c2s_shared
                        .stats
                        .dropped_c2s_bytes
                        .fetch_add(n as u64, Ordering::Relaxed);
                    c2s_shared
                        .stats
                        .faults_triggered
                        .fetch_add(1, Ordering::Relaxed);
                    let _ = server_write.shutdown().await;
                    return Ok(ExitReason::FaultDropped);
                }
                FaultMode::DropServerToClientAfterRpcCommit => {
                    let should_arm = match proto {
                        ConnProto::Xml => {
                            xml_tail.extend_from_slice(chunk);
                            let matched = contains_commit_tag(&xml_tail);
                            if matched {
                                xml_tail.clear();
                            } else if xml_tail.len() > 64 {
                                let excess = xml_tail.len() - 64;
                                xml_tail.drain(..excess);
                            }
                            matched
                        }
                        ConnProto::Ssh | ConnProto::Opaque | ConnProto::Unknown => {
                            if armed_at_epoch != Some(epoch) {
                                armed_at_epoch = Some(epoch);
                                true
                            } else {
                                false
                            }
                        }
                    };
                    if should_arm {
                        // Store before forwarding so s2c observes armed=true before server replies.
                        c2s_armed.store(true, Ordering::Release);
                    }
                    server_write.write_all(chunk).await?;
                    server_write.flush().await?;
                    c2s_shared
                        .stats
                        .forwarded_c2s_bytes
                        .fetch_add(n as u64, Ordering::Relaxed);
                }
            }
        }
    });

    let mut s2c = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            let m = server_read.read(&mut buf).await?;
            if m == 0 {
                let _ = client_write.shutdown().await;
                return Ok::<ExitReason, std::io::Error>(ExitReason::NormalEof);
            }
            if drop_s2c_armed.load(Ordering::Acquire) {
                shared
                    .stats
                    .dropped_s2c_bytes
                    .fetch_add(m as u64, Ordering::Relaxed);
                shared
                    .stats
                    .faults_triggered
                    .fetch_add(1, Ordering::Relaxed);
                let _ = client_write.shutdown().await;
                return Ok(ExitReason::FaultDropped);
            }
            client_write.write_all(&buf[..m]).await?;
            client_write.flush().await?;
            shared
                .stats
                .forwarded_s2c_bytes
                .fetch_add(m as u64, Ordering::Relaxed);
        }
    });

    tokio::select! {
        res = &mut c2s => {
            match res {
                Ok(Ok(ExitReason::FaultDropped)) | Ok(Err(_)) | Err(_) => {
                    s2c.abort();
                }
                Ok(Ok(ExitReason::NormalEof)) => {
                    let _ = s2c.await;
                }
            }
        }
        res = &mut s2c => {
            match res {
                Ok(Ok(ExitReason::FaultDropped)) | Ok(Ok(ExitReason::NormalEof)) | Ok(Err(_)) | Err(_) => {
                    c2s.abort();
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datastore::DatastoreEngine;
    use crate::framing::{encode_frame, try_decode_frame, FramingMode, EOM_1_0};
    use crate::rpc::NETCONF_BASE_NS;
    use crate::ssh::NetconfSshServer;
    use russh::keys::{Algorithm, PrivateKey};
    use russh::server::Server as _;
    use russh::ChannelMsg;
    use std::collections::HashMap;
    use std::sync::atomic::AtomicUsize;
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
    ) -> Option<String> {
        loop {
            if let Some(frame) = try_decode_frame(rx_buf, mode).unwrap() {
                return Some(frame);
            }
            let msg = timeout(Duration::from_secs(5), channel.wait()).await.ok()??;
            match msg {
                ChannelMsg::Data { data } => rx_buf.extend_from_slice(&data),
                ChannelMsg::Success | ChannelMsg::WindowAdjusted { .. } => {}
                ChannelMsg::Eof | ChannelMsg::Close => return None,
                _ => return None,
            }
        }
    }

    async fn open_ssh_netconf_session(
        addr: SocketAddr,
        user: &str,
        pass: &str,
    ) -> (
        russh::client::Handle<TestClient>,
        russh::Channel<russh::client::Msg>,
        Vec<u8>,
        String,
    ) {
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
        let server_hello = read_netconf_frame(&mut channel, &mut rx_buf, FramingMode::Base10)
            .await
            .expect("server hello expected");
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
        (session, channel, rx_buf, server_hello)
    }

    #[tokio::test]
    async fn proxy_passthrough_forwards_bidirectional_traffic() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();

        let echo_task = tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap();
            sock.shutdown().await.unwrap();
        });

        let proxy = FaultProxy::start_on_loopback(upstream_addr, FaultMode::PassThrough)
            .await
            .unwrap();
        assert_eq!(proxy.mode(), FaultMode::PassThrough);
        assert_eq!(proxy.upstream_addr(), upstream_addr);

        let mut client = TcpStream::connect(proxy.listen_addr()).await.unwrap();
        let payload = b"ping-netconf-payload";
        client.write_all(payload).await.unwrap();
        client.shutdown().await.unwrap();

        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();
        assert_eq!(&reply, payload);
        echo_task.await.unwrap();

        let stats = proxy.stats();
        assert_eq!(stats.connections_accepted, 1);
        assert_eq!(stats.forwarded_c2s_bytes, payload.len() as u64);
        assert_eq!(stats.forwarded_s2c_bytes, payload.len() as u64);
        assert_eq!(stats.dropped_c2s_bytes, 0);
        assert_eq!(stats.dropped_s2c_bytes, 0);
        assert_eq!(stats.faults_triggered, 0);
    }

    #[tokio::test]
    async fn proxy_drops_server_reply_after_plaintext_rpc_commit() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let commits_received = Arc::new(AtomicUsize::new(0));
        let commits_seen = commits_received.clone();

        let srv_task = tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 512];
            loop {
                let n = sock.read(&mut tmp).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                while let Some(msg) = try_decode_frame(&mut buf, FramingMode::Base10).unwrap() {
                    let reply = if msg.contains("<commit") {
                        commits_seen.fetch_add(1, Ordering::SeqCst);
                        "<rpc-reply message-id=\"2\"><ok/></rpc-reply>"
                    } else {
                        "<rpc-reply message-id=\"1\"><ok/></rpc-reply>"
                    };
                    let _ = sock.write_all(&encode_frame(reply, FramingMode::Base10)).await;
                }
            }
        });

        let proxy = FaultProxy::start_on_loopback(
            upstream_addr,
            FaultMode::DropServerToClientAfterRpcCommit,
        )
        .await
        .unwrap();

        let mut client = TcpStream::connect(proxy.listen_addr()).await.unwrap();
        let mut rx_buf = Vec::new();

        // Non-commit RPC passes through and receives its reply even while armed
        let edit_rpc = "<rpc message-id=\"1\"><edit-config><target><candidate/></target></edit-config></rpc>";
        client
            .write_all(&encode_frame(edit_rpc, FramingMode::Base10))
            .await
            .unwrap();
        let mut tmp = [0u8; 512];
        let edit_reply = loop {
            let n = client.read(&mut tmp).await.unwrap();
            assert!(n > 0);
            rx_buf.extend_from_slice(&tmp[..n]);
            if let Some(frame) = try_decode_frame(&mut rx_buf, FramingMode::Base10).unwrap() {
                break frame;
            }
        };
        assert!(edit_reply.contains("message-id=\"1\"") && edit_reply.contains("<ok/>"));

        // <commit> reaches the server, but its <rpc-reply> is deterministically dropped
        let commit_rpc = "<rpc message-id=\"2\"><commit><confirmed/></commit></rpc>";
        client
            .write_all(&encode_frame(commit_rpc, FramingMode::Base10))
            .await
            .unwrap();
        let mut post_commit_bytes = Vec::new();
        timeout(Duration::from_secs(2), client.read_to_end(&mut post_commit_bytes))
            .await
            .unwrap()
            .unwrap();
        assert!(
            post_commit_bytes.is_empty(),
            "expected zero reply bytes after commit fault drop, got {:?}",
            String::from_utf8_lossy(&post_commit_bytes)
        );
        assert!(!EOM_1_0.is_empty());
        assert_eq!(commits_received.load(Ordering::SeqCst), 1);

        let _ = timeout(Duration::from_secs(2), srv_task).await;
        let stats = proxy.stats();
        assert!(stats.dropped_s2c_bytes > 0);
        assert_eq!(stats.faults_triggered, 1);
    }

    #[tokio::test]
    async fn proxy_drops_client_request_before_rpc_h2() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let bytes_at_server = Arc::new(AtomicUsize::new(0));
        let bytes_flag = bytes_at_server.clone();

        let srv_task = tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let mut tmp = [0u8; 256];
            while let Ok(n) = sock.read(&mut tmp).await {
                if n == 0 {
                    break;
                }
                bytes_flag.fetch_add(n, Ordering::SeqCst);
            }
        });

        let proxy = FaultProxy::start_on_loopback(
            upstream_addr,
            FaultMode::DropClientToServerBeforeRpc,
        )
        .await
        .unwrap();

        let mut client = TcpStream::connect(proxy.listen_addr()).await.unwrap();
        let rpc = encode_frame("<rpc message-id=\"9\"><commit/></rpc>", FramingMode::Base10);
        client.write_all(&rpc).await.unwrap();

        let mut reply = Vec::new();
        timeout(Duration::from_secs(2), client.read_to_end(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert!(reply.is_empty());
        srv_task.await.unwrap();

        assert_eq!(bytes_at_server.load(Ordering::SeqCst), 0);
        let stats = proxy.stats();
        assert_eq!(stats.dropped_c2s_bytes, rpc.len() as u64);
        assert_eq!(stats.faults_triggered, 1);
    }

    #[tokio::test]
    async fn ssh_netconf_wire_h1_lost_reply_and_h2_lost_request_via_fault_proxy() {
        let dir = tempdir().unwrap();
        let engine = DatastoreEngine::open(dir.path().join("state.json"), true).unwrap();
        let mut users = HashMap::new();
        users.insert("smo".to_string(), "smopass".to_string());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ssh_addr = listener.local_addr().unwrap();
        let host_key =
            PrivateKey::random(&mut russh::keys::ssh_key::rand_core::OsRng, Algorithm::Ed25519)
                .unwrap();
        let ssh_cfg = Arc::new(russh::server::Config {
            inactivity_timeout: Some(Duration::from_secs(600)),
            auth_rejection_time: Duration::from_millis(50),
            auth_rejection_time_initial: Some(Duration::from_millis(0)),
            keys: vec![host_key],
            ..Default::default()
        });
        let mut srv = NetconfSshServer {
            engine: engine.clone(),
            users: Arc::new(users),
        };
        let srv_task = tokio::spawn(async move {
            let _ = srv.run_on_socket(ssh_cfg, &listener).await;
        });

        let proxy = FaultProxy::start_on_loopback(ssh_addr, FaultMode::PassThrough)
            .await
            .unwrap();

        // === Part 1: True Wire-Level H1 (Commit applied at server, reply dropped by proxy) ===
        let (session1, mut ch1, mut rx1, hello1) =
            open_ssh_netconf_session(proxy.listen_addr(), "smo", "smopass").await;
        assert!(hello1.contains("<session-id>1</session-id>"));

        let rpc_edit = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"1\">\
               <edit-config><target><candidate/></target><config>\
                 <managed-element xmlns=\"urn:demo:o1:nrcelldu\">\
                   <NRCellDU><id>cell-1</id><attributes><administrativeState>UNLOCKED</administrativeState></attributes></NRCellDU>\
                 </managed-element>\
               </config></edit-config>\
             </rpc>"
        );
        ch1.data(&encode_frame(&rpc_edit, FramingMode::Base11)[..])
            .await
            .unwrap();
        let edit_reply = read_netconf_frame(&mut ch1, &mut rx1, FramingMode::Base11)
            .await
            .expect("edit-config reply expected");
        assert!(edit_reply.contains("<ok/>"));

        // Arm wire-level H1 lost-reply fault right before sending <commit>
        proxy.set_mode(FaultMode::DropServerToClientAfterRpcCommit);
        let rpc_commit_h1 = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"2\">\
               <commit><confirmed/><confirm-timeout>300</confirm-timeout><persist>h1-wire-tok</persist></commit>\
             </rpc>"
        );
        ch1.data(&encode_frame(&rpc_commit_h1, FramingMode::Base11)[..])
            .await
            .unwrap();
        let lost_reply = read_netconf_frame(&mut ch1, &mut rx1, FramingMode::Base11).await;
        assert!(lost_reply.is_none(), "reply must be dropped on the wire");
        drop(ch1);
        drop(session1);

        let h1_stats = proxy.stats();
        assert!(h1_stats.dropped_s2c_bytes > 0);
        assert_eq!(h1_stats.faults_triggered, 1);
        assert!(engine
            .get_config_xml("running")
            .await
            .unwrap()
            .contains("UNLOCKED"));

        // Reconnect in PassThrough and confirm the persisted token cleanly
        proxy.set_mode(FaultMode::PassThrough);
        let (session2, mut ch2, mut rx2, _) =
            open_ssh_netconf_session(proxy.listen_addr(), "smo", "smopass").await;
        let rpc_confirm = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"3\"><commit><persist-id>h1-wire-tok</persist-id></commit></rpc>"
        );
        ch2.data(&encode_frame(&rpc_confirm, FramingMode::Base11)[..])
            .await
            .unwrap();
        let confirm_reply = read_netconf_frame(&mut ch2, &mut rx2, FramingMode::Base11)
            .await
            .expect("confirm reply expected");
        assert!(confirm_reply.contains("<ok/>"));

        // Reset running back to LOCKED for H2 check
        let rpc_reset = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"4\">\
               <edit-config><target><running/></target><config>\
                 <managed-element xmlns=\"urn:demo:o1:nrcelldu\">\
                   <NRCellDU><id>cell-1</id><attributes><administrativeState>LOCKED</administrativeState></attributes></NRCellDU>\
                 </managed-element>\
               </config></edit-config>\
             </rpc>"
        );
        ch2.data(&encode_frame(&rpc_reset, FramingMode::Base11)[..])
            .await
            .unwrap();
        let reset_reply = read_netconf_frame(&mut ch2, &mut rx2, FramingMode::Base11)
            .await
            .unwrap();
        assert!(reset_reply.contains("<ok/>"));
        let _ = session2
            .disconnect(russh::Disconnect::ByApplication, "reset", "en")
            .await;

        // === Part 2: True Wire-Level H2 (Request dropped before reaching server) ===
        proxy.reset_stats();
        let (session3, mut ch3, mut rx3, _) =
            open_ssh_netconf_session(proxy.listen_addr(), "smo", "smopass").await;
        ch3.data(&encode_frame(&rpc_edit, FramingMode::Base11)[..])
            .await
            .unwrap();
        let edit_reply3 = read_netconf_frame(&mut ch3, &mut rx3, FramingMode::Base11)
            .await
            .unwrap();
        assert!(edit_reply3.contains("<ok/>"));

        // Arm H2 lost-request fault right before sending <commit>
        proxy.set_mode(FaultMode::DropClientToServerBeforeRpc);
        let rpc_commit_h2 = format!(
            "<rpc xmlns=\"{NETCONF_BASE_NS}\" message-id=\"5\">\
               <commit><confirmed/><confirm-timeout>300</confirm-timeout><persist>h2-wire-tok</persist></commit>\
             </rpc>"
        );
        ch3.data(&encode_frame(&rpc_commit_h2, FramingMode::Base11)[..])
            .await
            .unwrap();
        let dropped_h2_reply = read_netconf_frame(&mut ch3, &mut rx3, FramingMode::Base11).await;
        assert!(dropped_h2_reply.is_none());
        drop(ch3);
        drop(session3);

        let h2_stats = proxy.stats();
        assert!(h2_stats.dropped_c2s_bytes > 0);
        assert_eq!(h2_stats.faults_triggered, 1);
        assert!(
            engine
                .get_config_xml("running")
                .await
                .unwrap()
                .contains("LOCKED"),
            "running must remain LOCKED because H2 request never reached server"
        );

        srv_task.abort();
    }
}
