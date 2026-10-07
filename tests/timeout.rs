use rndc::{RndcClient, RndcError};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

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

fn assert_timeout(server_action: impl FnOnce(&mut TcpStream, mpsc::Receiver<()>) + Send + 'static) {
    assert_timeout_after(Duration::from_millis(200), server_action);
}

fn assert_timeout_after(
    timeout: Duration,
    server_action: impl FnOnce(&mut TcpStream, mpsc::Receiver<()>) + Send + 'static,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let (finished, done) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        read_request(&mut stream);
        server_action(&mut stream, done);
    });
    let client = RndcClient::new(&address, "sha256", "dGVzdA==")
        .unwrap()
        .with_timeout(Some(timeout))
        .unwrap();
    let started = Instant::now();
    let result = client.rndc_command("status");
    let elapsed = started.elapsed();
    let _ = finished.send(());
    server.join().unwrap();
    assert!(
        matches!(result, Err(RndcError::TimeoutError(_))),
        "{result:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "timed out too late: {elapsed:?}"
    );
}

#[test]
fn test_rejects_invalid_timeouts() {
    for timeout in [Duration::ZERO, Duration::MAX] {
        let client = RndcClient::new("127.0.0.1:953", "sha256", "dGVzdA==").unwrap();
        for result in [
            client.clone().with_timeout(timeout),
            client.with_timeout(Some(timeout)),
        ] {
            assert!(matches!(result, Err(RndcError::InvalidTimeout(_))));
        }
    }
}

#[test]
fn test_disabled_timeout_allows_delayed_handshake_and_command_responses() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        for _ in 0..2 {
            read_request(&mut stream);
            thread::sleep(Duration::from_millis(150));
            stream.write_all(&fixture()).unwrap();
        }
        // Keep the peer alive until the client closes the authenticated exchange.
        assert_eq!(stream.read(&mut [0]).unwrap(), 0);
    });
    let client = RndcClient::new(&address, "sha256", "dGVzdA==")
        .unwrap()
        .with_timeout(Duration::from_millis(50))
        .unwrap()
        .with_timeout(None)
        .unwrap();
    let result = client.rndc_command("status");
    server.join().unwrap();
    let response = result.unwrap();
    assert!(response.result);
    assert_eq!(response.text.as_deref(), Some("authenticated"));
}

#[test]
fn test_times_out_when_handshake_response_stalls() {
    assert_timeout(|_, done| {
        let _ = done.recv_timeout(Duration::from_secs(3));
    });
}

#[test]
fn test_times_out_when_response_length_is_partial() {
    assert_timeout(|stream, done| {
        stream.write_all(&fixture()[..2]).unwrap();
        let _ = done.recv_timeout(Duration::from_secs(3));
    });
}

#[test]
fn test_times_out_when_response_body_is_partial() {
    assert_timeout(|stream, done| {
        stream.write_all(&fixture()[..12]).unwrap();
        let _ = done.recv_timeout(Duration::from_secs(3));
    });
}

#[test]
fn test_times_out_when_command_response_stalls() {
    assert_timeout(|stream, done| {
        stream.write_all(&fixture()).unwrap();
        read_request(stream);
        let _ = done.recv_timeout(Duration::from_secs(3));
    });
}

#[test]
fn test_partial_reads_do_not_reset_the_deadline() {
    assert_timeout(|stream, done| {
        for byte in fixture() {
            if stream.write_all(&[byte]).is_err() {
                break;
            }
            if done.recv_timeout(Duration::from_millis(20)).is_ok() {
                break;
            }
        }
    });
}

#[test]
fn test_handshake_and_command_share_one_deadline() {
    assert_timeout_after(Duration::from_millis(500), |stream, done| {
        assert!(done.recv_timeout(Duration::from_millis(300)).is_err());
        stream.write_all(&fixture()).unwrap();
        read_request(stream);
        if done.recv_timeout(Duration::from_millis(300)).is_err() {
            // Each phase fits within 500 ms; together they exceed the deadline.
            let _ = stream.write_all(&fixture());
        }
    });
}
