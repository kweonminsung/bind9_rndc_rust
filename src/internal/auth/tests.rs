use super::*;
use crate::internal::decoder;

// Generated with Python's hmac module, independently of the Rust encoder.
const VECTORS: [(RndcAlg, &str); 6] = [
    (
        RndcAlg::MD5,
        include_str!("../../../tests/fixtures/md5.hex"),
    ),
    (
        RndcAlg::SHA1,
        include_str!("../../../tests/fixtures/sha1.hex"),
    ),
    (
        RndcAlg::SHA224,
        include_str!("../../../tests/fixtures/sha224.hex"),
    ),
    (
        RndcAlg::SHA256,
        include_str!("../../../tests/fixtures/sha256.hex"),
    ),
    (
        RndcAlg::SHA384,
        include_str!("../../../tests/fixtures/sha384.hex"),
    ),
    (
        RndcAlg::SHA512,
        include_str!("../../../tests/fixtures/sha512.hex"),
    ),
];

fn auth_len(algorithm: &RndcAlg) -> usize {
    if *algorithm == RndcAlg::MD5 { 43 } else { 110 }
}

fn assert_auth_error(result: Result<&[u8], RndcError>) {
    assert!(
        matches!(result, Err(RndcError::AuthenticationError(_))),
        "{result:?}"
    );
}

#[test]
fn test_verifies_independent_vectors_for_all_algorithms() {
    for (algorithm, vector) in VECTORS {
        let packet = hex::decode(vector.trim()).unwrap();
        let body = verify(&packet[8..], &algorithm, b"test").unwrap();
        assert_eq!(body, &packet[8 + auth_len(&algorithm)..]);
        assert!(body.ends_with(b"authenticated"));
    }
}

#[test]
fn test_rejects_wrong_keys_for_all_algorithms() {
    for (algorithm, vector) in VECTORS {
        let packet = hex::decode(vector.trim()).unwrap();
        assert_auth_error(verify(&packet[8..], &algorithm, b"wrong"));
    }
}

#[test]
fn test_rejects_modified_bodies_for_all_algorithms() {
    for (algorithm, vector) in VECTORS {
        let mut packet = hex::decode(vector.trim()).unwrap();
        *packet.last_mut().unwrap() ^= 1;
        assert_auth_error(verify(&packet[8..], &algorithm, b"test"));
    }
}

#[test]
fn test_rejects_modified_signatures_for_all_algorithms() {
    for (algorithm, vector) in VECTORS {
        let mut packet = hex::decode(vector.trim()).unwrap();
        let offset = if algorithm == RndcAlg::MD5 { 29 } else { 30 };
        packet[offset] = if packet[offset] == b'A' { b'B' } else { b'A' };
        assert_auth_error(verify(&packet[8..], &algorithm, b"test"));
    }
}

#[test]
fn test_rejects_missing_or_misplaced_authentication() {
    for (algorithm, vector) in VECTORS {
        let packet = hex::decode(vector.trim()).unwrap();
        let body = &packet[8 + auth_len(&algorithm)..];
        assert_auth_error(verify(body, &algorithm, b"test"));
        let mut misplaced = body.to_vec();
        misplaced.extend_from_slice(&packet[8..8 + auth_len(&algorithm)]);
        assert_auth_error(verify(&misplaced, &algorithm, b"test"));
    }
}

#[test]
fn test_rejects_every_truncated_authentication_envelope() {
    for (algorithm, vector) in VECTORS {
        let packet = hex::decode(vector.trim()).unwrap();
        for len in 0..auth_len(&algorithm) {
            assert_auth_error(verify(&packet[8..8 + len], &algorithm, b"test"));
        }
    }
}

#[test]
fn test_rejects_malformed_authentication_fields() {
    let packet = hex::decode(VECTORS[3].1.trim()).unwrap();
    let body = &packet[8..];
    // Outer name/type, inner name/type, and signature encoding.
    for (offset, value) in [(1, b'x'), (6, 1), (12, b'x'), (16, 2), (22, b'!')] {
        let mut malformed = body.to_vec();
        malformed[offset] = value;
        assert_auth_error(verify(&malformed, &RndcAlg::SHA256, b"test"));
    }
    // Both length fields are untrusted and must be checked before slicing.
    for offset in [7, 17] {
        let mut malformed = body.to_vec();
        malformed[offset..offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_auth_error(verify(&malformed, &RndcAlg::SHA256, b"test"));
    }
}

#[test]
fn test_rejects_additional_authentication_table_fields() {
    let mut packet = hex::decode(VECTORS[3].1.trim()).unwrap();
    // Extend the authentication table over the following `_ctrl` field.
    let table_len = u32::from_be_bytes(packet[15..19].try_into().unwrap());
    packet[15..19].copy_from_slice(&(table_len + 1).to_be_bytes());
    assert_auth_error(verify(&packet[8..], &RndcAlg::SHA256, b"test"));
}

#[test]
fn test_rejects_wrong_algorithms() {
    for (algorithm, vector) in VECTORS {
        let packet = hex::decode(vector.trim()).unwrap();
        let wrong = if algorithm == RndcAlg::SHA256 {
            RndcAlg::SHA512
        } else {
            RndcAlg::SHA256
        };
        assert_auth_error(verify(&packet[8..], &wrong, b"test"));
    }
}

#[test]
fn test_rejects_modified_sha_padding() {
    for (algorithm, vector) in VECTORS {
        if matches!(algorithm, RndcAlg::MD5 | RndcAlg::SHA512) {
            continue;
        }
        let mut packet = hex::decode(vector.trim()).unwrap();
        packet[117] = 1;
        assert_auth_error(verify(&packet[8..], &algorithm, b"test"));
    }
}

#[test]
fn test_authenticates_before_decoding_untrusted_body() {
    for (algorithm, vector) in VECTORS {
        let mut packet = hex::decode(vector.trim()).unwrap();
        packet[8 + auth_len(&algorithm)..].fill(0xff);
        assert!(matches!(
            decoder::decode(&packet, &algorithm, b"test"),
            Err(RndcError::AuthenticationError(_))
        ));
    }
}
