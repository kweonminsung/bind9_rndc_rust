# BIND9 rndc for Rust

This module is a rust binding for [bind9-rndc-node](https://github.com/isc-projects/bind9-rndc-node/tree/master).

This module implements the BIND9 rndc management protocol and is
compatible with BIND 9.9 and later.

## Example usage

The code below sends the "status" command to the default rndc port
on the machine `localhost`. The key data is base64 encoded, as per
the usual `rndc.conf` syntax.

```rust
    let client = RndcClient::new(
        "127.0.0.1:953", // rndc server URL
        "sha256", // supported algorithms: md5, sha1, sha224, sha256, sha384, sha512
        "secret_key", // base64 encrypted secret_key
    );

    dbg!(client.rndc_command("status").unwrap());
```

Valid crypto algorithms are `md5`, `sha1`, `sha224`, `sha256`,
`sha384`, and `sha512`.
