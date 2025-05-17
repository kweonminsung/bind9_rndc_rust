use base64::{Engine, engine::general_purpose};
use hmac::Mac;
use indexmap::IndexMap;

use crate::HmacSha256;

use super::constants::{ISCCC_ALG_HMAC_SHA256, MSGTYPE_BINARYDATA, MSGTYPE_LIST, MSGTYPE_TABLE};

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub enum RNDCValue {
    Binary(Vec<u8>),
    Table(IndexMap<String, RNDCValue>),
    List(Vec<RNDCValue>),
}

fn raw_towire(type_byte: u8, buffer: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(5 + buffer.len());
    buf.push(type_byte);
    buf.extend_from_slice(&(buffer.len() as u32).to_be_bytes());
    buf.extend_from_slice(buffer);
    buf
}

fn binary_towire(val: &[u8]) -> Vec<u8> {
    raw_towire(MSGTYPE_BINARYDATA, val)
}

fn list_towire(vals: &[RNDCValue]) -> Vec<u8> {
    let mut bufs = Vec::new();
    for v in vals {
        bufs.extend(value_towire(v));
    }
    raw_towire(MSGTYPE_LIST, &bufs)
}

fn key_towire(key: &str) -> Vec<u8> {
    let key_bytes = key.as_bytes();
    let mut buf = Vec::with_capacity(1 + key_bytes.len());
    buf.push(key_bytes.len() as u8);
    buf.extend_from_slice(key_bytes);
    buf
}

fn value_towire(val: &RNDCValue) -> Vec<u8> {
    match val {
        RNDCValue::List(list) => list_towire(list),
        RNDCValue::Table(map) => table_towire(map, false),
        RNDCValue::Binary(data) => binary_towire(data),
    }
}

fn table_towire(val: &IndexMap<String, RNDCValue>, no_header: bool) -> Vec<u8> {
    let mut bufs = Vec::new();
    for (key, value) in val.iter() {
        bufs.extend(key_towire(key));
        bufs.extend(value_towire(value));
    }
    if no_header {
        bufs
    } else {
        raw_towire(MSGTYPE_TABLE, &bufs)
    }
}

fn make_signature(
    secret: &[u8],
    message_body: &IndexMap<String, RNDCValue>,
) -> Result<RNDCValue, String> {
    let databuf = table_towire(message_body, true);

    let mut mac = match HmacSha256::new_from_slice(secret) {
        Ok(m) => m,
        Err(_) => return Err("Failed to create HMAC SHA256 instance".to_string()),
    };
    mac.update(&databuf);
    let digest = mac.finalize().into_bytes();

    let sig_b64 = general_purpose::STANDARD.encode(&digest);

    let mut sig_buf = vec![0u8; 89];
    sig_buf[0] = ISCCC_ALG_HMAC_SHA256; // 163
    sig_buf[1..(1 + sig_b64.len())].copy_from_slice(sig_b64.as_bytes());

    // _auth: { hsha: sig_buf }
    let mut hsha_map = IndexMap::new();
    hsha_map.insert("hsha".to_string(), RNDCValue::Binary(sig_buf));

    Ok(RNDCValue::Table(hsha_map))
}

pub fn encode(obj: &mut IndexMap<String, RNDCValue>, secret: &[u8]) -> Result<Vec<u8>, String> {
    obj.shift_remove("_auth");

    let databuf = table_towire(obj, true);

    let sig_value = make_signature(secret, obj)?;

    let mut sig_map = IndexMap::new();
    sig_map.insert("_auth".to_string(), sig_value);
    let sigbuf = table_towire(&sig_map, true);

    let length = 8 + sigbuf.len() + databuf.len();
    let mut res = Vec::with_capacity(length);

    res.extend(&(length as u32 - 4).to_be_bytes());
    res.extend(&1u32.to_be_bytes());

    res.extend(&sigbuf);
    res.extend(&databuf);

    Ok(res)
}
