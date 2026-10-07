# BIND9 rndc for Rust

A synchronous Rust client for BIND9's RNDC management protocol.

## Usage

Set `RNDC_SECRET` to the base64-encoded secret from your BIND RNDC key configuration.
The address and algorithm must match the server configuration.

```no_run
use rndc::RndcClient;
use std::{error::Error, time::Duration};

fn main() -> Result<(), Box<dyn Error>> {
    let secret = std::env::var("RNDC_SECRET")?;
    let client = RndcClient::new("127.0.0.1:953", "sha256", &secret)?
        .with_timeout(Duration::from_secs(10))?;

    let response = client.rndc_command("status")?;
    if !response.result {
        return Err(response.err.unwrap_or_else(|| "RNDC command failed".into()).into());
    }
    if let Some(text) = response.text {
        println!("{text}");
    }
    Ok(())
}
```

Pass another command, such as `"reload"`, to `rndc_command` as needed.
Transport, auth, and decoding failures return `Err(RndcError)`; a command rejected
by BIND returns `Ok(RndcResult)` with `result == false` and optional `err` text.

Supported algorithms are `md5`, `sha1`, `sha224`, `sha256`, `sha384`, and `sha512`.
The `hmac-` prefix is also accepted, for example `hmac-sha256`.

## Timeouts and response limits

Each command has a default 30-second time limit, configurable with `with_timeout`.
Connecting to resolved addresses, the handshake, and command reads and writes
share this deadline. Partial reads and writes do not restart it. Expiration
returns `RndcError::TimeoutError`; zero or excessively large durations return
`RndcError::InvalidTimeout`.

System DNS resolution is synchronous and is outside this time limit. Use an IP
address when you need to avoid DNS lookup delays.

Server responses must pass HMAC verification. Responses larger than 1 MiB
(excluding the four-byte length prefix), fields outside their containing buffer,
and tables or lists nested more than 32 levels below the root response table are
rejected. Client debug output redacts the secret key.

## Tests

Run the unit tests, mock-server integration tests, and README compile check:

```sh
cargo test --locked
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
```

The two tests in `tests/rndc.rs` require a local BIND server and are ignored by
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

This server uses the public test secret `YmluZGl6cg==` with `sha256`; use that value
for `RNDC_SECRET` when running the usage example against it. Remove the server
after testing:

```sh
docker rm -f rndc-bind-test
```
