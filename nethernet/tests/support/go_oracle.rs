//! One long-lived `go-peer oracle` process per test binary, speaking length-prefixed JSON.
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use std::io::{BufReader, Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock};

/// Environment variable naming the built `tools/go-peer` binary.
pub const GO_PEER_ENV: &str = "NETHERNET_GO_PEER";

pub struct Oracle {
    _child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

/// Returns the shared oracle, or None after printing the missing-fixture message.
pub fn oracle() -> Option<MutexGuard<'static, Oracle>> {
    static ORACLE: OnceLock<Option<Mutex<Oracle>>> = OnceLock::new();
    let oracle = ORACLE.get_or_init(|| {
        let path = std::env::var_os(GO_PEER_ENV)?;
        let mut child = Command::new(path)
            .arg("oracle")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("{GO_PEER_ENV} is set but does not start: {e}"));
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Some(Mutex::new(Oracle {
            _child: child,
            stdin,
            stdout,
        }))
    });
    match oracle {
        Some(oracle) => Some(oracle.lock().unwrap_or_else(|e| e.into_inner())),
        None => {
            eprintln!(
                "skipping: missing fixture {GO_PEER_ENV} (build it with `go build -C tools/go-peer -o <path> .`)"
            );
            None
        }
    }
}

impl Oracle {
    /// Sends one request and returns the response object; `error` is set when Go refused the input.
    pub fn call(&mut self, request: Value) -> Value {
        let body = serde_json::to_vec(&request).unwrap();
        self.stdin
            .write_all(&(body.len() as u32).to_be_bytes())
            .unwrap();
        self.stdin.write_all(&body).unwrap();
        self.stdin.flush().unwrap();
        let mut len = [0u8; 4];
        self.stdout.read_exact(&mut len).unwrap();
        let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
        self.stdout.read_exact(&mut body).unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    /// Calls an op that must succeed and returns its decoded `bytes`.
    pub fn bytes(&mut self, request: Value) -> Vec<u8> {
        let response = self.call(request);
        assert!(response.get("error").is_none(), "go-peer: {response}");
        bytes_field(&response, "bytes")
    }

    /// Decrypts a datagram's payload without checking its HMAC.
    pub fn open(&mut self, datagram: &[u8]) -> Vec<u8> {
        self.bytes(json!({"op": "lan_open", "data": b64(datagram)}))
    }

    /// Wraps a plaintext payload with HMAC and encryption.
    pub fn seal(&mut self, payload: &[u8]) -> Vec<u8> {
        self.bytes(json!({"op": "lan_seal", "data": b64(payload)}))
    }
}

pub fn b64(data: &[u8]) -> String {
    STANDARD.encode(data)
}

/// Reads a base64 field, treating an omitted one as empty.
pub fn bytes_field(value: &Value, name: &str) -> Vec<u8> {
    value
        .get(name)
        .and_then(Value::as_str)
        .map(|s| STANDARD.decode(s).unwrap())
        .unwrap_or_default()
}

/// Reads a numeric field, treating an omitted one as zero.
pub fn u64_field(value: &Value, name: &str) -> u64 {
    value.get(name).and_then(Value::as_u64).unwrap_or(0)
}
