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

    println!(client.rndc_command("reload").unwrap());
    /*
        Output:

        server reload successful
    */

    println!(client.rndc_command("status").unwrap());
    /*
        Output:

        version: BIND 9.18.30-0ubuntu0.24.04.2-Ubuntu (Extended Support Version) <id:>
        running on localhost: Linux x86_64 5.15.167.4-microsoft-standard-WSL2 #1 SMP Tue Nov 5 00:21:55 UTC 2024
        boot time: Mon, 11 Aug 2025 13:32:16 GMT
        last configured: Mon, 11 Aug 2025 13:32:16 GMT
        configuration file: /etc/bind/named.conf
        CPUs found: 8
        worker threads: 8
        UDP listeners per interface: 8
        number of zones: 105 (98 automatic)
        debug level: 0
        xfers running: 0
        xfers deferred: 0
        soa queries in progress: 0
        query logging is OFF
        recursive clients: 0/900/1000
        tcp clients: 0/150
        TCP high-water: 0
        server is up and running

    */
```

Valid crypto algorithms are `md5`, `sha1`, `sha224`, `sha256`,
`sha384`, and `sha512`.
