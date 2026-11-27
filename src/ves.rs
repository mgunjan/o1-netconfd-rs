//! Pure-Rust async HTTP/1.1 VES 7.x `stndDefined` `notifyMOIChanges` emitter (3GPP TS 28.532)
//! augmented with causal writer provenance (`writerPrincipal`, `sessionId`, `txId`, `traceparent`,
//! `auditEntryHash`).

use crate::datastore::{ChangedBy, NotificationPayload, NotificationRecord};
use anyhow::{bail, Context, Result};
use chrono::SecondsFormat;
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VesEndpoint {
    pub host_port: String,
    pub host_header: String,
    pub path: String,
}

impl VesEndpoint {
    /// Parse an `http://host[:port][/path]` VES collector endpoint URL without C/TLS deps.
    pub fn parse(url: &str) -> Result<Self> {
        let rest = url
            .strip_prefix("http://")
            .ok_or_else(|| anyhow::anyhow!("VES endpoint must start with http://, got: {url}"))?;
        let (authority, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], rest[idx..].to_string()),
            None => (rest, "/".to_string()),
        };
        if authority.is_empty() {
            bail!("Missing host in VES endpoint URL: {url}");
        }
        let host_port = if authority.contains(':') {
            authority.to_string()
        } else {
            format!("{authority}:80")
        };
        Ok(Self {
            host_port,
            host_header: authority.to_string(),
            path,
        })
    }
}

/// Convert a [`NotificationRecord`] into a 3GPP TS 28.532 `notifyMOIChanges` VES 7.x JSON payload.
/// Returns `None` for non-config-change notifications (e.g., `ConfirmedCommit` lifecycle events).
pub fn build_ves_notify_moi_changes(record: &NotificationRecord) -> Option<Value> {
    let NotificationPayload::ConfigChange {
        changed_by,
        datastore,
        targets,
        tx_id,
        traceparent,
    } = &record.payload
    else {
        return None;
    };

    let (source_indicator, writer_principal, session_id, changed_by_kind, source_host) =
        match changed_by {
            ChangedBy::Session {
                username,
                session_id,
                source_host,
            } => (
                "Management_operation",
                username.clone(),
                Value::from(*session_id),
                "session",
                source_host.clone().map(Value::from).unwrap_or(Value::Null),
            ),
            ChangedBy::Server => (
                "Resource_operation",
                "server".to_string(),
                Value::Null,
                "server",
                Value::Null,
            ),
        };

    let event_time = record.event_time.to_rfc3339_opts(SecondsFormat::Millis, true);
    let micros = record.event_time.timestamp_micros();
    let provenance_info = json!({
        "writerPrincipal": writer_principal,
        "sessionId": session_id,
        "changedBy": changed_by_kind,
        "txId": tx_id.clone().map(Value::from).unwrap_or(Value::Null),
        "traceparent": traceparent.clone().map(Value::from).unwrap_or(Value::Null),
        "auditEntryHash": record.entry_hash,
        "auditSeq": record.seq,
        "sourceHost": source_host,
    });

    let moi_changes: Vec<Value> = targets
        .iter()
        .map(|target| {
            json!({
                "notificationId": record.seq,
                "correlatedNotifications": [],
                "additionalText": "o1-netconfd-rs committed running configuration change",
                "sourceIndicator": source_indicator,
                "path": target,
                "operation": "REPLACE",
                "value": { "datastore": datastore },
                "additionalInformation": provenance_info,
            })
        })
        .collect();

    Some(json!({
        "event": {
            "commonEventHeader": {
                "version": "4.1",
                "vesEventListenerVersion": "7.2.1",
                "domain": "stndDefined",
                "stndDefinedNamespace": "3GPP-Provisioning",
                "eventName": "stndDefined_3GPP-Provisioning_notifyMOIChanges",
                "eventId": format!("o1-netconfd-rs-{}", record.seq),
                "sourceName": "o1-netconfd-rs",
                "reportingEntityName": "o1-netconfd-rs",
                "priority": "Normal",
                "startEpochMicrosec": micros,
                "lastEpochMicrosec": micros,
                "sequence": record.seq,
            },
            "stndDefinedFields": {
                "stndDefinedFieldsVersion": "1.0",
                "schemaReference": "https://forge.3gpp.org/rep/sa5/MnS/blob/Rel-18/OpenAPI/TS28532_ProvMnS.yaml#/components/schemas/NotifyMoiChanges",
                "data": {
                    "href": "urn:demo:o1:nrcelldu",
                    "notificationId": record.seq,
                    "notificationType": "notifyMOIChanges",
                    "eventTime": event_time,
                    "systemDN": "ManagedElement=1",
                    "moiChanges": moi_changes,
                    "additionalInformation": provenance_info,
                }
            }
        }
    }))
}

/// POST a JSON payload over HTTP/1.1 to `endpoint` and return the HTTP status code.
pub async fn post_ves_json(endpoint: &VesEndpoint, payload: &Value) -> Result<u16> {
    let body = serde_json::to_vec(payload)?;
    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        endpoint.path,
        endpoint.host_header,
        body.len()
    );

    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(&endpoint.host_port))
        .await
        .context("timed out connecting to VES endpoint")??;
    stream.write_all(req.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await?;

    let mut resp_buf = [0u8; 1024];
    let n = timeout(Duration::from_secs(5), stream.read(&mut resp_buf))
        .await
        .context("timed out reading VES HTTP response")??;
    let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
    let status_line = resp_str.lines().next().unwrap_or("");
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("Invalid HTTP response from VES collector: {status_line:?}"))?;
    if !(200..300).contains(&status_code) {
        bail!("VES collector returned HTTP {status_code}: {status_line}");
    }
    Ok(status_code)
}

/// Format and emit a `NotificationRecord` if it represents a running configuration change.
pub async fn emit_record_if_config_change(
    endpoint: &VesEndpoint,
    record: &NotificationRecord,
) -> Result<Option<u16>> {
    let Some(payload) = build_ves_notify_moi_changes(record) else {
        return Ok(None);
    };
    let status = post_ves_json(endpoint, &payload).await?;
    Ok(Some(status))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datastore::{DatastoreEngine, WriteMeta};
    use tempfile::tempdir;
    use tokio::net::TcpListener;

    #[test]
    fn parses_ves_http_endpoints_and_builds_session_and_server_payloads() {
        let ep = VesEndpoint::parse("http://127.0.0.1:30417/eventListener/v7").unwrap();
        assert_eq!(ep.host_port, "127.0.0.1:30417");
        assert_eq!(ep.host_header, "127.0.0.1:30417");
        assert_eq!(ep.path, "/eventListener/v7");

        let ep_default = VesEndpoint::parse("http://ves-collector").unwrap();
        assert_eq!(ep_default.host_port, "ves-collector:80");
        assert_eq!(ep_default.path, "/");

        assert!(VesEndpoint::parse("https://unsupported:443/v7").is_err());

        let server_rec = NotificationRecord {
            seq: 4,
            prev_hash: "a".repeat(64),
            entry_hash: "b".repeat(64),
            event_time: chrono::Utc::now(),
            payload: NotificationPayload::ConfigChange {
                changed_by: ChangedBy::Server,
                datastore: "running".to_string(),
                targets: vec!["/demo-nrcelldu:managed-element/NRCellDU[id='cell-1']/attributes/administrativeState".to_string()],
                tx_id: None,
                traceparent: None,
            },
        };
        let body = build_ves_notify_moi_changes(&server_rec).unwrap();
        let data = &body["event"]["stndDefinedFields"]["data"];
        assert_eq!(data["notificationType"], "notifyMOIChanges");
        assert_eq!(data["moiChanges"][0]["sourceIndicator"], "Resource_operation");
        assert_eq!(data["additionalInformation"]["writerPrincipal"], "server");
        assert_eq!(data["additionalInformation"]["auditEntryHash"], "b".repeat(64));
    }

    #[tokio::test]
    async fn ves_loopback_http_collector_receives_notify_moi_changes_with_provenance() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let collector_task = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut raw = Vec::new();
            let mut tmp = [0u8; 4096];
            loop {
                let n = sock.read(&mut tmp).await.unwrap();
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&tmp[..n]);
                let text = String::from_utf8_lossy(&raw);
                if let Some(hdr_end) = text.find("\r\n\r\n") {
                    let headers = &text[..hdr_end];
                    let content_len: usize = headers
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            if k.eq_ignore_ascii_case("content-length") {
                                v.trim().parse().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    let body_start = hdr_end + 4;
                    if raw.len() >= body_start + content_len {
                        let body_bytes = raw[body_start..body_start + content_len].to_vec();
                        let _ = sock
                            .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                            .await;
                        let _ = sock.shutdown().await;
                        return (headers.to_string(), body_bytes);
                    }
                }
            }
            panic!("collector connection closed before full HTTP body arrived");
        });

        let dir = tempdir().unwrap();
        let engine = DatastoreEngine::open(dir.path().join("ves_state.json"), false).unwrap();
        let ves_url = format!("http://{addr}/eventListener/v7");
        let emitter_task = engine.spawn_ves_emitter(&ves_url).unwrap();

        let sid = engine.allocate_session_id().await.unwrap();
        engine
            .edit_config_with_meta(
                "candidate",
                "cell-1",
                "UNLOCKED",
                "smo",
                sid,
                Some("10.0.0.5".into()),
                WriteMeta {
                    tx_id: Some("ves-tx-77".into()),
                    traceparent: Some("00-99999999999999999999999999999999-8888888888888888-01".into()),
                },
            )
            .await
            .unwrap();
        engine
            .commit_with_meta(
                false,
                300,
                None,
                None,
                "smo",
                sid,
                Some("10.0.0.5".into()),
                WriteMeta::default(),
            )
            .await
            .unwrap();

        let (headers, body_bytes) = timeout(Duration::from_secs(5), collector_task)
            .await
            .unwrap()
            .unwrap();
        assert!(headers.starts_with("POST /eventListener/v7 HTTP/1.1"));

        let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(parsed["event"]["commonEventHeader"]["domain"], "stndDefined");
        let data = &parsed["event"]["stndDefinedFields"]["data"];
        assert_eq!(data["notificationType"], "notifyMOIChanges");
        assert_eq!(data["moiChanges"][0]["sourceIndicator"], "Management_operation");

        let info = &data["additionalInformation"];
        assert_eq!(info["writerPrincipal"], "smo");
        assert_eq!(info["sessionId"], sid);
        assert_eq!(info["txId"], "ves-tx-77");
        assert_eq!(
            info["traceparent"],
            "00-99999999999999999999999999999999-8888888888888888-01"
        );
        assert_eq!(info["sourceHost"], "10.0.0.5");
        assert_eq!(info["auditSeq"], 1);
        assert_eq!(info["auditEntryHash"].as_str().unwrap().len(), 64);

        emitter_task.abort();
    }
}
