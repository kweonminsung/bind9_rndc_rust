```rust
    let mut client = RndcClient::new(
        "server_url", // rndc server URL
        "algorithm", // md5, sha1, sha224, sha256, sha384, sha512
        "secret_key", // base64 encrypted secret_key
    );

    dbg!(client.rndc_command("reload").unwrap());
```
