use super::*;

#[test]
fn test_client_debug_redacts_secret_key() {
    let secret = b"debug-secret-value";
    let encoded = general_purpose::STANDARD.encode(secret);
    let client = RndcClient::new("127.0.0.1:953", "sha256", &encoded).unwrap();
    for client in [client.clone(), client] {
        for output in [format!("{client:?}"), format!("{client:#?}")] {
            assert!(output.contains("[REDACTED]"));
            assert!(output.contains("127.0.0.1:953"));
            assert!(output.contains("SHA256"));
            assert!(!output.contains(&encoded));
            assert!(!output.contains("debug-secret-value"));
            let compact: String = output
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect();
            let raw_bytes: String = format!("{secret:?}")
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect();
            assert!(!compact.contains(&raw_bytes));
        }
    }
}
