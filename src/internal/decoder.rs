use byteorder::{BigEndian, ReadBytesExt};
use indexmap::IndexMap;
use std::io::{Cursor, Read};

use crate::internal::constants::{MSGTYPE_BINARYDATA, MSGTYPE_LIST, MSGTYPE_STRING, MSGTYPE_TABLE};

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) enum RNDCPayload {
    String(String),
    Binary(Vec<u8>),
    Table(IndexMap<String, RNDCPayload>),
    List(Vec<RNDCPayload>),
}

fn binary_fromwire(cursor: &mut Cursor<&[u8]>, len: usize) -> Result<RNDCPayload, String> {
    let mut buf = vec![0u8; len];
    cursor.read_exact(&mut buf).map_err(|e| e.to_string())?;

    match String::from_utf8(buf.clone()) {
        Ok(s) => Ok(RNDCPayload::String(s)),
        Err(_) => Ok(RNDCPayload::Binary(buf)),
    }
}

fn key_fromwire(cursor: &mut Cursor<&[u8]>) -> Result<String, String> {
    let len = cursor.read_u8().map_err(|e| e.to_string())? as usize;
    let mut buf = vec![0u8; len];
    cursor.read_exact(&mut buf).map_err(|e| e.to_string())?;
    String::from_utf8(buf).map_err(|e| e.to_string())
}

fn value_fromwire(cursor: &mut Cursor<&[u8]>) -> Result<RNDCPayload, String> {
    let typ = cursor.read_u8().map_err(|e| e.to_string())?;
    let len = cursor.read_u32::<BigEndian>().map_err(|e| e.to_string())? as usize;
    let pos = cursor.position() as usize;

    let slice = &cursor.get_ref()[pos..pos + len];
    let mut sub_cursor = Cursor::new(slice);

    let result = match typ {
        MSGTYPE_STRING | MSGTYPE_BINARYDATA => binary_fromwire(&mut sub_cursor, len),
        MSGTYPE_TABLE => table_fromwire(&mut sub_cursor).map(RNDCPayload::Table),
        MSGTYPE_LIST => list_fromwire(&mut sub_cursor).map(RNDCPayload::List),
        _ => Err(format!("Unknown RNDC message type: {}", typ)),
    };

    cursor.set_position((pos + len) as u64);
    result
}

fn table_fromwire(cursor: &mut Cursor<&[u8]>) -> Result<IndexMap<String, RNDCPayload>, String> {
    let mut map = IndexMap::new();
    while (cursor.position() as usize) < cursor.get_ref().len() {
        let key = key_fromwire(cursor)?;
        let value = value_fromwire(cursor)?;
        map.insert(key, value);
    }
    Ok(map)
}

fn list_fromwire(cursor: &mut Cursor<&[u8]>) -> Result<Vec<RNDCPayload>, String> {
    let mut list = Vec::new();
    while (cursor.position() as usize) < cursor.get_ref().len() {
        let value = value_fromwire(cursor)?;
        list.push(value);
    }
    Ok(list)
}

pub(crate) fn decode(buf: &[u8]) -> Result<IndexMap<String, RNDCPayload>, String> {
    let mut cursor = Cursor::new(buf);

    let len = cursor.read_u32::<BigEndian>().map_err(|e| e.to_string())? as usize;
    if len != buf.len() - 4 {
        return Err("RNDC buffer length mismatch".to_string());
    }

    let version = cursor.read_u32::<BigEndian>().map_err(|e| e.to_string())?;
    if version != 1 {
        return Err(format!("Unknown RNDC protocol version: {}", version));
    }

    let res = table_fromwire(&mut cursor)?;

    Ok(res)
}
