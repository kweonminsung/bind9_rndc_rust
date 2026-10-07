use rndc::{RndcClient, RndcError, RndcResult};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

fn signed_response() -> Vec<u8> {
    hex::decode(include_str!("fixtures/sha256.hex").trim()).unwrap()
}

fn unsigned_response() -> Vec<u8> {
    let signed = signed_response();
    // The SHA `_auth` field occupies 110 bytes after the eight-byte header.
    let mut unsigned = signed[..8].to_vec();
    unsigned.extend_from_slice(&signed[118..]);
    let len = unsigned.len() as u32 - 4;
    unsigned[..4].copy_from_slice(&len.to_be_bytes());
    unsigned
}

fn read_request(stream: &mut TcpStream) {
    let mut len = [0; 4];
    stream.read_exact(&mut len).unwrap();
    let len = u32::from_be_bytes(len) as usize;
    assert!(len < 4096);
    let mut body = vec![0; len];
    stream.read_exact(&mut body).unwrap();
}

fn exchange(
    handshake: Vec<u8>,
    response: Option<Vec<u8>>,
    key: &str,
) -> Result<RndcResult, RndcError> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        read_request(&mut stream);
        stream.write_all(&handshake).unwrap();
        if let Some(response) = response {
            read_request(&mut stream);
            stream.write_all(&response).unwrap();
        }
        // A rejected handshake must close the connection without a command.
        let mut unexpected = [0];
        assert_eq!(stream.read(&mut unexpected).unwrap(), 0);
    });
    let result = RndcClient::new(&address, "sha256", key)
        .unwrap()
        .rndc_command("status");
    server.join().unwrap();
    result
}

#[test]
fn test_rejects_unsigned_handshake_before_sending_command() {
    let result = exchange(unsigned_response(), None, "dGVzdA==");
    assert!(matches!(result, Err(RndcError::AuthError(_))));
}

#[test]
fn test_rejects_tampered_handshake_before_sending_command() {
    let mut handshake = signed_response();
    let nonce = handshake
        .windows(5)
        .position(|value| value == b"12345")
        .unwrap();
    handshake[nonce] = b'9';
    let result = exchange(handshake, None, "dGVzdA==");
    assert!(matches!(result, Err(RndcError::AuthError(_))));
}

#[test]
fn test_rejects_handshake_signed_with_another_key() {
    let result = exchange(signed_response(), None, "d3Jvbmc=");
    assert!(matches!(result, Err(RndcError::AuthError(_))));
}

#[test]
fn test_rejects_unsigned_command_response() {
    let result = exchange(signed_response(), Some(unsigned_response()), "dGVzdA==");
    assert!(matches!(result, Err(RndcError::AuthError(_))));
}

#[test]
fn test_rejects_tampered_command_response() {
    let mut response = signed_response();
    *response.last_mut().unwrap() ^= 1;
    let result = exchange(signed_response(), Some(response), "dGVzdA==");
    assert!(matches!(result, Err(RndcError::AuthError(_))));
}

#[test]
fn test_accepts_success_response_with_valid_auth() {
    let response = exchange(signed_response(), Some(signed_response()), "dGVzdA==").unwrap();
    assert!(response.result);
    assert_eq!(response.text.as_deref(), Some("authenticated"));
    assert!(response.err.is_none());
}

#[test]
fn test_accepts_error_response_with_valid_auth() {
    let response = hex::decode(include_str!("fixtures/sha256-error.hex").trim()).unwrap();
    let response = exchange(signed_response(), Some(response), "dGVzdA==").unwrap();
    assert!(!response.result);
    assert_eq!(response.err.as_deref(), Some("permission denied"));
}
