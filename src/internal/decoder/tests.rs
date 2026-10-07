use super::*;

fn assert_decoding_error<T: std::fmt::Debug>(result: Result<T, RndcError>) {
    assert!(
        matches!(result, Err(RndcError::DecodingError(_))),
        "{result:?}"
    );
}

#[test]
fn test_accepts_message_length_boundaries() {
    assert_eq!(validate_message_length(4).unwrap(), 4);
    assert_eq!(
        validate_message_length(MAX_MESSAGE_LENGTH as u32).unwrap(),
        MAX_MESSAGE_LENGTH
    );
}

#[test]
fn test_rejects_message_lengths_outside_bounds() {
    for length in [0, 1, 2, 3, MAX_MESSAGE_LENGTH as u32 + 1, u32::MAX] {
        assert_decoding_error(validate_message_length(length));
    }
}

#[test]
fn test_rejects_truncated_headers() {
    let packet = hex::decode(include_str!("../../../tests/fixtures/sha256.hex").trim()).unwrap();
    for len in 0..8 {
        assert_decoding_error(decode(&packet[..len], &RndcAlg::SHA256, b"test"));
    }
}

#[test]
fn test_rejects_mismatched_packet_lengths() {
    let packet = hex::decode(include_str!("../../../tests/fixtures/sha256.hex").trim()).unwrap();
    for len in [packet.len() as u32 - 5, packet.len() as u32 - 3] {
        let mut malformed = packet.clone();
        malformed[..4].copy_from_slice(&len.to_be_bytes());
        assert_decoding_error(decode(&malformed, &RndcAlg::SHA256, b"test"));
    }
}

#[test]
fn test_rejects_value_lengths_exceeding_remaining_data() {
    for kind in [
        MSGTYPE_STRING,
        MSGTYPE_BINARYDATA,
        MSGTYPE_TABLE,
        MSGTYPE_LIST,
    ] {
        for len in [1u32, 16, u32::MAX] {
            let mut value = vec![kind];
            value.extend_from_slice(&len.to_be_bytes());
            assert_decoding_error(value_fromwire(&mut Cursor::new(value.as_slice()), 0));
        }
    }
}

#[test]
fn test_rejects_truncated_values() {
    let value = b"\x01\x00\x00\x00\x03abc";
    for len in 0..value.len() {
        assert_decoding_error(value_fromwire(&mut Cursor::new(&value[..len]), 0));
    }
}

#[test]
fn test_nested_values_cannot_read_beyond_their_container() {
    for (kind, contents) in [
        (MSGTYPE_TABLE, b"\x01x\x01\x00\x00\x00\x01".as_slice()),
        (MSGTYPE_LIST, b"\x01\x00\x00\x00\x01".as_slice()),
    ] {
        let mut value = vec![kind];
        value.extend_from_slice(&(contents.len() as u32).to_be_bytes());
        value.extend_from_slice(contents);
        // This byte is outside the container and cannot satisfy its inner value.
        value.push(b'x');
        assert_decoding_error(value_fromwire(&mut Cursor::new(value.as_slice()), 0));
    }
}

#[test]
fn test_preserves_text_and_binary_values_in_lists() {
    let value = b"\x03\x00\x00\x00\x0c\x01\x00\x00\x00\x01a\x01\x00\x00\x00\x01\xff";
    let mut cursor = Cursor::new(value.as_slice());
    let RNDCPayload::List(values) = value_fromwire(&mut cursor, 0).unwrap() else {
        panic!("expected a list");
    };
    assert!(matches!(&values[0], RNDCPayload::String(value) if value == "a"));
    assert!(matches!(&values[1], RNDCPayload::Binary(value) if value == &[0xff]));
    assert_eq!(cursor.position() as usize, value.len());
}

#[test]
fn test_rejects_truncated_keys() {
    assert_decoding_error(key_fromwire(&mut Cursor::new(b"\x03ab".as_slice())));
}

fn nested_value(kinds: &[u8]) -> Vec<u8> {
    let mut value = b"\x01\x00\x00\x00\x01x".to_vec();
    for &kind in kinds.iter().rev() {
        let mut contents = Vec::new();
        if kind == MSGTYPE_TABLE {
            contents.extend_from_slice(b"\x01x");
        }
        contents.extend(value);
        value = vec![kind];
        value.extend_from_slice(&(contents.len() as u32).to_be_bytes());
        value.extend(contents);
    }
    value
}

#[test]
fn test_accepts_nesting_at_the_depth_limit() {
    for kind in [MSGTYPE_TABLE, MSGTYPE_LIST] {
        let value = nested_value(&[kind; MAX_NESTING_DEPTH]);
        let mut cursor = Cursor::new(value.as_slice());
        value_fromwire(&mut cursor, 0).unwrap();
        assert_eq!(cursor.position() as usize, value.len());
    }
}

#[test]
fn test_rejects_nesting_beyond_the_depth_limit() {
    for kinds in [
        vec![MSGTYPE_TABLE; MAX_NESTING_DEPTH + 1],
        vec![MSGTYPE_LIST; MAX_NESTING_DEPTH + 1],
        (0..=MAX_NESTING_DEPTH)
            .map(|depth| {
                if depth % 2 == 0 {
                    MSGTYPE_TABLE
                } else {
                    MSGTYPE_LIST
                }
            })
            .collect(),
    ] {
        let value = nested_value(&kinds);
        let result = value_fromwire(&mut Cursor::new(value.as_slice()), 0);
        assert!(matches!(result, Err(RndcError::DecodingError(message))
            if message.contains("nesting depth exceeds")));
    }
}

#[test]
fn test_rejects_empty_containers_beyond_the_depth_limit() {
    for kind in [MSGTYPE_TABLE, MSGTYPE_LIST] {
        let value = [kind, 0, 0, 0, 0];
        assert_decoding_error(value_fromwire(
            &mut Cursor::new(value.as_slice()),
            MAX_NESTING_DEPTH,
        ));
    }
}

#[test]
fn test_nesting_depth_is_independent_for_sibling_values() {
    let value = nested_value(&[MSGTYPE_LIST; MAX_NESTING_DEPTH]);
    let mut body = vec![1, b'a'];
    body.extend_from_slice(&value);
    body.extend_from_slice(&[1, b'b']);
    body.extend_from_slice(&value);
    let decoded = table_fromwire(&mut Cursor::new(body.as_slice()), 0).unwrap();
    assert_eq!(decoded.len(), 2);
}
