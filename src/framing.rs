//! RFC 6242 NETCONF over SSH framing (:base:1.0 EOM and :base:1.1 chunked).

use anyhow::{bail, Result};

pub const EOM_1_0: &[u8] = b"]]>]]>";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramingMode {
    Base10,
    Base11,
}

/// Encode an outgoing XML payload using the active NETCONF framing mode.
pub fn encode_frame(xml: &str, mode: FramingMode) -> Vec<u8> {
    let bytes = xml.as_bytes();
    match mode {
        FramingMode::Base10 => {
            let mut out = Vec::with_capacity(bytes.len() + EOM_1_0.len());
            out.extend_from_slice(bytes);
            out.extend_from_slice(EOM_1_0);
            out
        }
        FramingMode::Base11 => {
            let header = format!("\n#{}\n", bytes.len());
            let tail = b"\n##\n";
            let mut out = Vec::with_capacity(header.len() + bytes.len() + tail.len());
            out.extend_from_slice(header.as_bytes());
            out.extend_from_slice(bytes);
            out.extend_from_slice(tail);
            out
        }
    }
}

/// Attempt to extract one complete NETCONF message from `buf`, advancing `buf` if found.
pub fn try_decode_frame(buf: &mut Vec<u8>, mode: FramingMode) -> Result<Option<String>> {
    match mode {
        FramingMode::Base10 => {
            if let Some(pos) = find_subslice(buf, EOM_1_0) {
                let msg_bytes: Vec<u8> = buf.drain(..pos).collect();
                buf.drain(..EOM_1_0.len());
                let text = String::from_utf8(msg_bytes)?;
                Ok(Some(text))
            } else {
                Ok(None)
            }
        }
        FramingMode::Base11 => {
            // Also tolerate a trailing 1.0 EOM if a client sends one before switching cleanly
            let mut cursor = 0usize;
            let mut assembled = Vec::new();

            loop {
                // Skip optional CR/LF before '#'
                while cursor < buf.len() && (buf[cursor] == b'\n' || buf[cursor] == b'\r') {
                    cursor += 1;
                }
                if cursor >= buf.len() {
                    return Ok(None);
                }
                if buf[cursor] != b'#' {
                    bail!("Invalid RFC 6242 base:1.1 frame: expected '#' at offset {cursor}");
                }
                let line_end = match buf[cursor..].iter().position(|&b| b == b'\n') {
                    Some(rel) => cursor + rel,
                    None => return Ok(None),
                };
                let marker = std::str::from_utf8(&buf[cursor + 1..line_end])?.trim_end_matches('\r');
                cursor = line_end + 1;

                if marker == "#" {
                    // End-of-chunks marker "##"
                    buf.drain(..cursor);
                    let text = String::from_utf8(assembled)?;
                    return Ok(Some(text));
                }

                let chunk_len: usize = marker.parse().map_err(|_| {
                    anyhow::anyhow!("Invalid RFC 6242 chunk length header: #{marker}")
                })?;
                if buf.len() < cursor + chunk_len {
                    return Ok(None);
                }
                assembled.extend_from_slice(&buf[cursor..cursor + chunk_len]);
                cursor += chunk_len;
            }
        }
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_base10_and_base11() {
        let msg = "<rpc message-id=\"1\"><get-config/></rpc>";

        let mut b10 = encode_frame(msg, FramingMode::Base10);
        assert_eq!(try_decode_frame(&mut b10, FramingMode::Base10).unwrap().as_deref(), Some(msg));
        assert!(b10.is_empty());

        let mut b11 = encode_frame(msg, FramingMode::Base11);
        // Partial read returns None without consuming buffer
        let mut partial = b11[..10].to_vec();
        assert!(try_decode_frame(&mut partial, FramingMode::Base11).unwrap().is_none());
        assert_eq!(partial.len(), 10);

        assert_eq!(try_decode_frame(&mut b11, FramingMode::Base11).unwrap().as_deref(), Some(msg));
        assert!(b11.is_empty());
    }
}
