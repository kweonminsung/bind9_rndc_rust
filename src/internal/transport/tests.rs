use super::*;
use std::net::TcpListener;

#[test]
fn test_expired_deadline_prevents_io() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (_peer, _) = listener.accept().unwrap();
    let mut connection = Connection {
        stream,
        deadline: Some(Instant::now()),
    };
    assert_eq!(
        connection.read(&mut [0]).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        connection.write(b"x").unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
}

#[test]
fn test_write_times_out_when_peer_does_not_read() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (_peer, _) = listener.accept().unwrap();
    let mut connection = Connection {
        stream,
        deadline: Some(Instant::now() + Duration::from_millis(200)),
    };
    // Exceed socket buffers so a peer that does not read applies backpressure.
    let error = connection
        .write_all(&vec![0; 32 * 1024 * 1024])
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}

#[test]
fn test_no_deadline_clears_socket_timeouts_and_allows_io() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut connection =
        Connection::connect(&listener.local_addr().unwrap().to_string(), None).unwrap();
    let (mut peer, _) = listener.accept().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    peer.set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    connection
        .stream
        .set_read_timeout(Some(Duration::from_millis(1)))
        .unwrap();
    connection
        .stream
        .set_write_timeout(Some(Duration::from_millis(1)))
        .unwrap();

    peer.write_all(b"x").unwrap();
    let mut byte = [0];
    connection.read_exact(&mut byte).unwrap();
    assert_eq!(&byte, b"x");
    assert_eq!(connection.stream.read_timeout().unwrap(), None);
    connection.write_all(b"y").unwrap();
    peer.read_exact(&mut byte).unwrap();
    assert_eq!(&byte, b"y");
    assert_eq!(connection.stream.write_timeout().unwrap(), None);
}
