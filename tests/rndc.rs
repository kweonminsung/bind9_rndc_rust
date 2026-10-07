use rndc::RndcClient;

fn get_test_client() -> RndcClient {
    let server_url = "127.0.0.1:953".to_string();
    let algorithm = "hmac-sha256";
    let secret_key = "YmluZGl6cg==".to_string(); // "test" in base64

    RndcClient::new(&server_url, algorithm, &secret_key).unwrap()
}

#[test]
#[ignore = "requires the Docker BIND server on 127.0.0.1:953"]
fn test_rndc_status() {
    let client = get_test_client();
    let response = client.rndc_command("status").unwrap();

    assert!(response.result, "rndc command failed: {:?}", &response);
    assert!(
        response.text.is_some(),
        "rndc status response text is missing"
    );
}

#[test]
#[ignore = "requires the Docker BIND server on 127.0.0.1:953"]
fn test_rndc_reload() {
    let client = get_test_client();
    let response = client.rndc_command("reload").unwrap();

    assert!(response.result, "rndc command failed: {:?}", &response);
    assert!(
        response.text.is_some()
            && response
                .text
                .as_ref()
                .unwrap()
                .contains("server reload successful"),
        "rndc reload response text is missing or incorrect"
    );
}
