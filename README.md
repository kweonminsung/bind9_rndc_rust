# BIND9 rndc for Rust

A synchronous Rust client for BIND9's RNDC management protocol.

Requires Rust 1.88 or later. No async runtime is required.

## Installation

```toml
[dependencies]
rndc = "0.1.7"
```

## Example usage

The example below sends `reload` and `status` commands to the default RNDC port
on `localhost`. Pass the server address, HMAC algorithm, and base64-encoded shared
key (`tsig_key_b64`) directly to `RndcClient::new`, using values from your BIND RNDC
key configuration.

```no_run
use rndc::RndcClient;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // Public Docker test key; replace with your server's base64-encoded shared key.
    let tsig_key_b64 = "YmluZGl6cg==";
    let client = RndcClient::new(
        "127.0.0.1:953", // RNDC server address
        "sha256",       // HMAC algorithm
        tsig_key_b64,
    )?;

    for command in ["reload", "status"] {
        let response = client.rndc_command(command)?;
        if !response.result {
            return Err(response.err.unwrap_or_else(|| "RNDC command failed".into()).into());
        }
        if let Some(text) = response.text {
            println!("{text}");
        }
    }
    Ok(())
}
```

Example output (`status` details depend on the server):

```text
server reload successful
version: BIND ...
...
server is up and running
```

## Operations

`rndc_command(command)` sends an RNDC command string, such as `reload` or `status`,
and returns the server's result and optional text.

Transport, auth, and decoding failures return `Err(RndcError)`; a command rejected
by BIND returns `Ok(RndcResult)` with `result == false` and optional `err` text.

## Authentication and transport

Requests and responses use HMAC authentication with the configured shared key.
Supported algorithms are `md5`, `sha1`, `sha224`, `sha256`, `sha384`, and `sha512`.
The `hmac-` prefix is also accepted, for example `hmac-sha256`. Client debug
output redacts the secret key.

Each command opens a new TCP connection for the handshake and command exchange.
Server addresses use `host:port` or `[IPv6]:port`, such as `[::1]:953`.

Calls block the calling thread. In a Tokio application, run them through
[`tokio::task::spawn_blocking`](https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html).

## Timeouts and limits

Each command has a default 30-second time limit. `with_timeout(Duration)` and
`with_timeout(Some(Duration))` change it; `with_timeout(None)` disables it.

Set a five-second time limit:

```no_run
use rndc::{RndcClient, RndcError};
use std::time::Duration;

fn main() -> Result<(), RndcError> {
    let client = RndcClient::new("127.0.0.1:953", "sha256", "YmluZGl6cg==")?
        .with_timeout(Duration::from_secs(5))?;
    println!("{:?}", client.rndc_command("status")?);
    Ok(())
}
```

Or create a client with no time limit:

```no_run
use rndc::{RndcClient, RndcError};

fn main() -> Result<(), RndcError> {
    let client = RndcClient::new("127.0.0.1:953", "sha256", "YmluZGl6cg==")?
        .with_timeout(None)?;
    println!("{:?}", client.rndc_command("status")?);
    Ok(())
}
```

When a time limit is set, connecting to resolved addresses, the handshake, and
command reads and writes share one deadline. Partial reads and writes do not
restart it. Expiration returns `RndcError::TimeoutError`; zero or excessively
large durations return `RndcError::InvalidTimeout`.

With `None`, no client deadline or socket read/write timeout is set; operating
system connection errors and server-side limits still apply.

System DNS resolution is synchronous and is outside this time limit. Use an IP
address when you need to avoid DNS lookup delays.

Responses larger than 1 MiB (excluding the four-byte length prefix), fields
outside their containing buffer, and tables or lists nested more than 32 levels
below the root response table are rejected.

## Tests

Run the unit tests, mock-server integration tests, and README compile checks:

```sh
cargo test --locked
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
```

The tests in `tests/rndc.rs` require a local BIND server and are ignored by
default. Start the repository's Docker test server:

```sh
docker build -t rndc-bind-test ./docker
docker run -d --name rndc-bind-test -p 127.0.0.1:953:953 rndc-bind-test
```

Wait for the following command to succeed, then run the BIND tests:

```sh
docker exec rndc-bind-test rndc -s 127.0.0.1 -k /etc/bind/rndc.key status
cargo test --locked --test rndc -- --ignored
```

This server uses the same public test secret `YmluZGl6cg==` and `sha256` algorithm
as the usage example. Remove the server after testing:

```sh
docker rm -f rndc-bind-test
```

## Publishing

To check the package before publishing:

```sh
cargo package --locked --list
cargo publish --locked --dry-run
```

## License

Mozilla Public License 2.0. See [LICENSE](https://github.com/kweonminsung/bind9_rndc_rust/blob/main/LICENSE).
