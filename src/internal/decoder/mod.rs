use byteorder::{BigEndian, ReadBytesExt};
use indexmap::IndexMap;
use std::io::Cursor;

use crate::error::RndcError;
use crate::internal::auth;
use crate::internal::constants::{
    MAX_MESSAGE_LENGTH, MSGTYPE_BINARYDATA, MSGTYPE_LIST, MSGTYPE_STRING, MSGTYPE_TABLE, RndcAlg,
};

// Count nested tables and lists below the root response table.
const MAX_NESTING_DEPTH: usize = 32;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) enum RNDCPayload {
    String(String),
    Binary(Vec<u8>),
    Table(IndexMap<String, RNDCPayload>),
    List(Vec<RNDCPayload>),
}

fn binary_fromwire(cursor: &mut Cursor<&[u8]>, len: usize) -> Result<RNDCPayload, RndcError> {
    let buf = take_bytes(cursor, len)?.to_vec();
    match String::from_utf8(buf) {
        Ok(s) => Ok(RNDCPayload::String(s)),
        Err(error) => Ok(RNDCPayload::Binary(error.into_bytes())),
    }
}

fn key_fromwire(cursor: &mut Cursor<&[u8]>) -> Result<String, RndcError> {
    let len = cursor
        .read_u8()
        .map_err(|e| RndcError::DecodingError(e.to_string()))? as usize;
    let name = take_bytes(cursor, len)?;
    String::from_utf8(name.to_vec()).map_err(|e| RndcError::DecodingError(e.to_string()))
}

fn value_fromwire(cursor: &mut Cursor<&[u8]>, depth: usize) -> Result<RNDCPayload, RndcError> {
    let typ = cursor
        .read_u8()
        .map_err(|e| RndcError::DecodingError(e.to_string()))?;
    let len = cursor
        .read_u32::<BigEndian>()
        .map_err(|e| RndcError::DecodingError(e.to_string()))? as usize;
    let slice = take_bytes(cursor, len)?;
    let mut sub_cursor = Cursor::new(slice);

    match typ {
        MSGTYPE_STRING | MSGTYPE_BINARYDATA => binary_fromwire(&mut sub_cursor, len),
        MSGTYPE_TABLE | MSGTYPE_LIST if depth >= MAX_NESTING_DEPTH => {
            Err(RndcError::DecodingError(format!(
                "RNDC nesting depth exceeds limit of {MAX_NESTING_DEPTH}"
            )))
        }
        MSGTYPE_TABLE => table_fromwire(&mut sub_cursor, depth + 1).map(RNDCPayload::Table),
        MSGTYPE_LIST => list_fromwire(&mut sub_cursor, depth + 1).map(RNDCPayload::List),
        _ => Err(RndcError::DecodingError(format!(
            "Unknown RNDC message type: {}",
            typ
        ))),
    }
}

fn take_bytes<'a>(cursor: &mut Cursor<&'a [u8]>, len: usize) -> Result<&'a [u8], RndcError> {
    let bounds_error =
        || RndcError::DecodingError("RNDC field length exceeds remaining data".into());
    let pos = usize::try_from(cursor.position()).map_err(|_| bounds_error())?;
    let end = pos.checked_add(len).ok_or_else(bounds_error)?;
    let buffer = *cursor.get_ref();
    let bytes = buffer.get(pos..end).ok_or_else(bounds_error)?;
    cursor.set_position(end as u64);
    Ok(bytes)
}

pub(crate) fn validate_message_length(length: u32) -> Result<usize, RndcError> {
    let length = length as usize;
    // Every message includes a four-byte protocol version after its length.
    if !(4..=MAX_MESSAGE_LENGTH).contains(&length) {
        return Err(RndcError::DecodingError(format!(
            "Invalid RNDC message length: {length} (expected 4..={MAX_MESSAGE_LENGTH})"
        )));
    }
    Ok(length)
}

fn table_fromwire(
    cursor: &mut Cursor<&[u8]>,
    depth: usize,
) -> Result<IndexMap<String, RNDCPayload>, RndcError> {
    let mut map = IndexMap::new();
    while (cursor.position() as usize) < cursor.get_ref().len() {
        let key = key_fromwire(cursor)?;
        let value = value_fromwire(cursor, depth)?;
        map.insert(key, value);
    }
    Ok(map)
}

fn list_fromwire(cursor: &mut Cursor<&[u8]>, depth: usize) -> Result<Vec<RNDCPayload>, RndcError> {
    let mut list = Vec::new();
    while (cursor.position() as usize) < cursor.get_ref().len() {
        let value = value_fromwire(cursor, depth)?;
        list.push(value);
    }
    Ok(list)
}

pub(crate) fn decode(
    buf: &[u8],
    algorithm: &RndcAlg,
    secret: &[u8],
) -> Result<IndexMap<String, RNDCPayload>, RndcError> {
    let mut cursor = Cursor::new(buf);

    let len = cursor
        .read_u32::<BigEndian>()
        .map_err(|e| RndcError::DecodingError(e.to_string()))?;
    let len = validate_message_length(len)?;
    if len != buf.len() - 4 {
        return Err(RndcError::DecodingError(
            "RNDC buffer length mismatch".to_string(),
        ));
    }

    let version = cursor
        .read_u32::<BigEndian>()
        .map_err(|e| RndcError::DecodingError(e.to_string()))?;
    if version != 1 {
        return Err(RndcError::DecodingError(format!(
            "Unknown RNDC protocol version: {}",
            version
        )));
    }

    let body = auth::verify(&buf[cursor.position() as usize..], algorithm, secret)?;
    let res = table_fromwire(&mut Cursor::new(body), 0)?;
    if res.contains_key("_auth") {
        return Err(RndcError::AuthError(
            "Multiple RNDC auth fields".to_string(),
        ));
    }

    Ok(res)
}

#[cfg(test)]
mod tests;
