use base64::{Engine, engine::general_purpose};
use hmac::{Hmac, KeyInit, Mac};
use rndc::{RndcClient, RndcError, RndcResult};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

const MAX_MESSAGE_LENGTH: usize = 1024 * 1024;

fn fixture() -> Vec<u8> {
    hex::decode(include_str!("fixtures/sha256.hex").trim()).unwrap()
}

fn read_request(stream: &mut TcpStream) {
    let mut length = [0; 4];
    stream.read_exact(&mut length).unwrap();
    let length = u32::from_be_bytes(length) as usize;
    assert!(length < 4096);
    stream.read_exact(&mut vec![0; length]).unwrap();
}

fn exchange(
    responses: Vec<Vec<u8>>,
    fragmented: bool,
    close_write: bool,
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
        for response in responses {
            read_request(&mut stream);
            let chunk_size = if fragmented { 3 } else { response.len().max(1) };
            for chunk in response.chunks(chunk_size) {
                stream.write_all(chunk).unwrap();
            }
        }
        if close_write {
            stream.shutdown(Shutdown::Write).unwrap();
        }
        // Keep the connection open to prove invalid lengths fail without a body.
        let mut unexpected = [0];
        assert_eq!(stream.read(&mut unexpected).unwrap(), 0);
    });
    let result = RndcClient::new(&address, "sha256", "dGVzdA==")
        .unwrap()
        .rndc_command("status");
    server.join().unwrap();
    result
}

fn signed_packet(body: &[u8]) -> Vec<u8> {
    let mut packet = fixture();
    packet.truncate(118);
    packet.extend_from_slice(body);
    let length = packet.len() as u32 - 4;
    packet[..4].copy_from_slice(&length.to_be_bytes());
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(b"test").unwrap();
    mac.update(body);
    let signature = general_purpose::STANDARD.encode(mac.finalize().into_bytes());
    packet[30..74].copy_from_slice(signature.as_bytes());
    packet
}

fn field(name: &[u8], kind: u8, value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![name.len() as u8];
    bytes.extend_from_slice(name);
    bytes.push(kind);
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value);
    bytes
}

fn response_body(text: &[u8]) -> Vec<u8> {
    let mut body = field(b"_ctrl", 2, &field(b"_nonce", 1, b"12345"));
    let mut data = field(b"result", 1, b"0");
    data.extend(field(b"text", 1, text));
    body.extend(field(b"_data", 2, &data));
    body
}

#[test]
fn test_rejects_invalid_frame_lengths_without_waiting_for_a_body() {
    for length in [0u32, 1, 2, 3, MAX_MESSAGE_LENGTH as u32 + 1, u32::MAX] {
        let result = exchange(vec![length.to_be_bytes().to_vec()], false, false);
        assert!(
            matches!(result, Err(RndcError::DecodingError(_))),
            "{result:?}"
        );
    }
}

#[test]
fn test_rejects_truncated_length_prefixes() {
    for len in 0..4 {
        let result = exchange(vec![fixture()[..len].to_vec()], false, true);
        assert!(
            matches!(result, Err(RndcError::NetworkError(_))),
            "{result:?}"
        );
    }
}

#[test]
fn test_rejects_truncated_message_bodies() {
    let packet = fixture();
    for len in [4, 7, 8, packet.len() - 1] {
        let result = exchange(vec![packet[..len].to_vec()], false, true);
        assert!(
            matches!(result, Err(RndcError::NetworkError(_))),
            "{result:?}"
        );
    }
}

#[test]
fn test_rejects_invalid_field_lengths_with_valid_auth() {
    for kind in [0, 1, 2, 3] {
        let mut body = vec![1, b'x', kind];
        body.extend_from_slice(&16u32.to_be_bytes());
        let result = exchange(vec![signed_packet(&body)], false, false);
        assert!(
            matches!(result, Err(RndcError::DecodingError(ref message))
            if message.contains("field length exceeds remaining data")),
            "{result:?}"
        );
    }
}

#[test]
fn test_accepts_fragmented_responses_with_valid_auth() {
    let response = exchange(vec![fixture(), fixture()], true, false).unwrap();
    assert!(response.result);
    assert_eq!(response.text.as_deref(), Some("authenticated"));
}

#[test]
fn test_accepts_a_response_at_the_message_size_limit() {
    let overhead = signed_packet(&response_body(b"")).len() - 4;
    let text_length = MAX_MESSAGE_LENGTH - overhead;
    let packet = signed_packet(&response_body(&vec![b'a'; text_length]));
    assert_eq!(packet.len() - 4, MAX_MESSAGE_LENGTH);
    let response = exchange(vec![fixture(), packet], false, false).unwrap();
    assert!(response.result);
    assert_eq!(response.text.as_deref().unwrap().len(), text_length);
}
