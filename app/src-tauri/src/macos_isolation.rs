//! The pure half of macOS isolation: the Seatbelt profile text and the DevTools protocol pieces
//! that deliver the page fingerprint into Claude's renderer. Kept free of macOS-only APIs so the
//! profile and the protocol are unit-tested on any build machine; `macos.rs` is the thin layer
//! that runs them.

use std::io::Read;

/// The Seatbelt profile a sandboxed account runs under. `(deny network-outbound)` is the point:
/// the process may only reach this machine, so its only way out is the account's relay on
/// loopback (which resolves the names). The system DNS socket is denied as well, so a name cannot
/// be resolved locally and leak; every other file, mach and process capability is left as the
/// system gives it (Sandboxie's file virtualization has no macOS counterpart here).
pub fn seatbelt_profile(relay_port: Option<u16>) -> String {
    let mut profile = String::from("(version 1)\n(allow default)\n");
    if relay_port.is_some() {
        profile.push_str("(deny network-outbound)\n");
        // `localhost:*` is every address of the loopback interface on every port; a numeric
        // `127.0.0.1:*` is not a valid seatbelt host pattern.
        profile.push_str("(allow network-outbound (remote ip \"localhost:*\"))\n");
        profile.push_str("(allow network-outbound (remote unix-socket))\n");
        profile.push_str("(deny network-outbound (remote unix-socket (path-literal \"/var/run/mDNSResponder\")))\n");
    }
    profile
}

/// The port Chromium wrote into `<user-data-dir>/DevToolsActivePort` (first line).
pub fn devtools_port(text: &str) -> Option<u16> {
    text.lines().next()?.trim().parse().ok()
}

/// JSON from `/json/list`: the WebSocket URL of every page or webview target. Other target types
/// (service workers, shared workers) have no document to inject into.
pub fn page_targets(json: &str) -> Vec<String> {
    let Ok(serde_json::Value::Array(items)) = serde_json::from_str::<serde_json::Value>(json) else { return Vec::new() };
    items
        .iter()
        .filter(|item| matches!(item["type"].as_str(), Some("page" | "webview")))
        .filter_map(|item| item["webSocketDebuggerUrl"].as_str().map(str::to_owned))
        .collect()
}

/// The DevTools messages that install the script for every document this target loads from now
/// on, including the one already loading.
pub fn cdp_commands(script: &str) -> Vec<String> {
    vec![
        serde_json::json!({ "id": 1, "method": "Page.enable" }).to_string(),
        serde_json::json!({ "id": 2, "method": "Page.addScriptToEvaluateOnNewDocument", "params": { "source": script } })
            .to_string(),
    ]
}

/// A client WebSocket handshake. No `Origin` header: Chromium accepts non-browser clients that
/// do not send one, and an invented origin would be rejected by the remote-allow-origins check.
pub fn handshake_request(host: &str, port: u16, path: &str, key: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
}

/// One masked client frame (RFC 6455); clients must mask, servers must not.
pub fn masked_frame(opcode: u8, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 14);
    frame.push(0x80 | (opcode & 0x0f));
    let len = payload.len();
    if len < 126 {
        frame.push(0x80 | len as u8);
    } else if len <= u16::MAX as usize {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&(len as u64).to_be_bytes());
    }
    frame.extend_from_slice(&mask);
    for (i, byte) in payload.iter().enumerate() {
        frame.push(byte ^ mask[i % 4]);
    }
    frame
}

pub struct Frame {
    pub opcode: u8,
    pub payload: Vec<u8>,
}

/// One server frame. Ping and control frames are returned as they are; the caller answers pings.
pub fn read_frame<R: Read>(reader: &mut R) -> std::io::Result<Option<Frame>> {
    let mut head = [0u8; 2];
    if reader.read(&mut head[..1])? == 0 { return Ok(None); }
    reader.read_exact(&mut head[1..])?;
    let opcode = head[0] & 0x0f;
    let masked = head[1] & 0x80 != 0;
    let mut len = (head[1] & 0x7f) as u64;
    if len == 126 {
        let mut bytes = [0u8; 2];
        reader.read_exact(&mut bytes)?;
        len = u16::from_be_bytes(bytes) as u64;
    } else if len == 127 {
        let mut bytes = [0u8; 8];
        reader.read_exact(&mut bytes)?;
        len = u64::from_be_bytes(bytes);
    }
    let mut mask = [0u8; 4];
    if masked { reader.read_exact(&mut mask)?; }
    if len > 16 * 1024 * 1024 { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large")); }
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload)?;
    if masked {
        for (i, byte) in payload.iter_mut().enumerate() { *byte ^= mask[i % 4]; }
    }
    Ok(Some(Frame { opcode, payload }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_only_restricts_network_when_a_relay_is_given() {
        let full = seatbelt_profile(Some(41000));
        assert!(full.starts_with("(version 1)\n(allow default)\n"));
        assert!(full.contains("(deny network-outbound)\n"));
        assert!(full.contains("localhost:*"), "numeric 127.0.0.1:* is not a valid seatbelt pattern");
        assert!(!full.contains("127.0.0.1:*"));
        assert!(full.contains("mDNSResponder"));
        let empty = seatbelt_profile(None);
        assert_eq!(empty, "(version 1)\n(allow default)\n");
    }

    #[test]
    fn devtools_port_comes_from_the_first_line() {
        assert_eq!(devtools_port("9222\n/devtools/browser/abc\n"), Some(9222));
        assert_eq!(devtools_port(""), None);
        assert_eq!(devtools_port("nonsense"), None);
    }

    #[test]
    fn targets_keep_pages_only() {
        let json = r#"[
            {"type":"page","webSocketDebuggerUrl":"ws://127.0.0.1:9222/devtools/page/AAA"},
            {"type":"service_worker","webSocketDebuggerUrl":"ws://127.0.0.1:9222/devtools/page/BBB"},
            {"type":"webview","webSocketDebuggerUrl":"ws://127.0.0.1:9222/devtools/page/CCC"}
        ]"#;
        assert_eq!(page_targets(json), vec![
            "ws://127.0.0.1:9222/devtools/page/AAA".to_string(),
            "ws://127.0.0.1:9222/devtools/page/CCC".to_string()
        ]);
        assert!(page_targets("not json").is_empty());
    }

    #[test]
    fn cdp_commands_install_the_script() {
        let commands = cdp_commands("(() => 1)()");
        assert_eq!(commands.len(), 2);
        assert!(commands[0].contains("Page.enable"));
        assert!(!commands[0].contains("addScriptToEvaluateOnNewDocument"));
        assert!(commands[1].contains("Page.addScriptToEvaluateOnNewDocument"));
        let parsed: serde_json::Value = serde_json::from_str(&commands[1]).unwrap();
        assert_eq!(parsed["params"]["source"], "(() => 1)()");
    }

    #[test]
    fn handshake_has_the_websocket_headers() {
        let request = handshake_request("127.0.0.1", 9222, "/devtools/page/ABC", "abc=");
        assert!(request.starts_with("GET /devtools/page/ABC HTTP/1.1\r\n"));
        assert!(request.contains("Host: 127.0.0.1:9222\r\n"));
        assert!(request.contains("Upgrade: websocket\r\n"));
        assert!(request.contains("Sec-WebSocket-Version: 13\r\n"));
        assert!(!request.contains("Origin:"));
    }

    #[test]
    fn masked_frames_decode_for_every_length_form() {
        for payload in [b"small".to_vec(), vec![7u8; 200], vec![9u8; 70000]] {
            let frame = masked_frame(1, &payload, [1, 2, 3, 4]);
            let mut cursor = std::io::Cursor::new(frame);
            let read = read_frame(&mut cursor).unwrap().unwrap();
            assert_eq!(read.opcode, 1);
            assert_eq!(read.payload, payload);
        }
    }

    #[test]
    fn unmasked_server_frames_decode() {
        // "hi", unmasked: FIN+text, length 2, payload.
        let mut cursor = std::io::Cursor::new(vec![0x81, 0x02, b'h', b'i']);
        let frame = read_frame(&mut cursor).unwrap().unwrap();
        assert_eq!(frame.opcode, 1);
        assert_eq!(frame.payload, b"hi");
        // Empty stream is no frame, not an error.
        assert!(read_frame(&mut std::io::Cursor::new(Vec::new())).unwrap().is_none());
    }
}
