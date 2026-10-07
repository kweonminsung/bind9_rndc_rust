use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use crate::RndcError;

pub(crate) struct Connection {
    stream: TcpStream,
    deadline: Instant,
}

impl Connection {
    pub(crate) fn connect(server: &str, timeout: Duration) -> io::Result<Self> {
        // The system resolver is synchronous and has no portable timeout API.
        let addresses = server.to_socket_addrs()?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Timeout is too large"))?;
        let mut last_error = io::Error::new(
            io::ErrorKind::InvalidInput,
            "Server address resolved to no socket addresses",
        );
        for address in addresses {
            match TcpStream::connect_timeout(&address, remaining(deadline)?) {
                Ok(stream) => return Ok(Self { stream, deadline }),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }

    pub(crate) fn shutdown(&self) -> io::Result<()> {
        self.stream.shutdown(Shutdown::Both)
    }
}

impl Read for Connection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream
            .set_read_timeout(Some(remaining(self.deadline)?))?;
        self.stream.read(buf).map_err(normalize_timeout)
    }
}

impl Write for Connection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream
            .set_write_timeout(Some(remaining(self.deadline)?))?;
        self.stream.write(buf).map_err(normalize_timeout)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "RNDC command deadline exceeded"))
}

fn normalize_timeout(error: io::Error) -> io::Error {
    // Socket timeouts are reported as WouldBlock on Unix and TimedOut on Windows.
    if error.kind() == io::ErrorKind::WouldBlock {
        io::Error::new(io::ErrorKind::TimedOut, error)
    } else {
        error
    }
}

pub(crate) fn map_io_error(context: &str, error: io::Error) -> RndcError {
    let message = format!("{context}: {error}");
    if matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) {
        RndcError::TimeoutError(message)
    } else {
        RndcError::NetworkError(message)
    }
}

#[cfg(test)]
mod tests;
