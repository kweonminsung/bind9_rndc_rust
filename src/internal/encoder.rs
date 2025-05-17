use base64::{Engine, engine::general_purpose};
use hmac::{Hmac, Mac};
use indexmap::IndexMap;

use super::constants::{
    ISCCC_ALG_HMAC_SHA1, ISCCC_ALG_HMAC_SHA224, ISCCC_ALG_HMAC_SHA256, ISCCC_ALG_HMAC_SHA384,
    ISCCC_ALG_HMAC_SHA512, MSGTYPE_BINARYDATA, MSGTYPE_LIST, MSGTYPE_TABLE, RNDCALG,
};

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
    algorithm: &RNDCALG,
    secret: &[u8],
    message_body: &IndexMap<String, RNDCValue>,
) -> Result<RNDCValue, String> {
    let databuf = table_towire(message_body, true);

    let (sig_type, sig_b64, alg_code) = match algorithm {
        RNDCALG::MD5 => {
            let mut mac = match Hmac::<md5::Md5>::new_from_slice(secret) {
                Ok(m) => m,
                Err(_) => return Err("Failed to create HMAC MD5 instance".to_string()),
            };
            mac.update(&databuf);
            let digest = mac.finalize().into_bytes();
            let mut sig_b64 = general_purpose::STANDARD.encode(&digest);

            // no padding on hmd5
            sig_b64 = sig_b64.trim_end_matches('=').to_string();
            ("hmd5".to_string(), sig_b64, 157u8)
        }
        RNDCALG::SHA1 => {
            let mut mac = match Hmac::<sha1::Sha1>::new_from_slice(secret) {
                Ok(m) => m,
                Err(_) => return Err("Failed to create HMAC SHA1 instance".to_string()),
            };
            mac.update(&databuf);
            let digest = mac.finalize().into_bytes();
            (
                "hsha".to_string(),
                general_purpose::STANDARD.encode(&digest),
                ISCCC_ALG_HMAC_SHA1,
            )
        }
        RNDCALG::SHA224 => {
            let mut mac = match Hmac::<sha2::Sha224>::new_from_slice(secret) {
                Ok(m) => m,
                Err(_) => return Err("Failed to create HMAC SHA224 instance".to_string()),
            };
            mac.update(&databuf);
            let digest = mac.finalize().into_bytes();
            (
                "hsha".to_string(),
                general_purpose::STANDARD.encode(&digest),
                ISCCC_ALG_HMAC_SHA224,
            )
        }
        RNDCALG::SHA256 => {
            let mut mac = match Hmac::<sha2::Sha256>::new_from_slice(secret) {
                Ok(m) => m,
                Err(_) => return Err("Failed to create HMAC SHA256 instance".to_string()),
            };
            mac.update(&databuf);
            let digest = mac.finalize().into_bytes();
            (
                "hsha".to_string(),
                general_purpose::STANDARD.encode(&digest),
                ISCCC_ALG_HMAC_SHA256,
            )
        }
        RNDCALG::SHA384 => {
            let mut mac = match Hmac::<sha2::Sha384>::new_from_slice(secret) {
                Ok(m) => m,
                Err(_) => return Err("Failed to create HMAC SHA384 instance".to_string()),
            };
            mac.update(&databuf);
            let digest = mac.finalize().into_bytes();
            (
                "hsha".to_string(),
                general_purpose::STANDARD.encode(&digest),
                ISCCC_ALG_HMAC_SHA384,
            )
        }
        RNDCALG::SHA512 => {
            let mut mac = match Hmac::<sha2::Sha512>::new_from_slice(secret) {
                Ok(m) => m,
                Err(_) => return Err("Failed to create HMAC SHA512 instance".to_string()),
            };
            mac.update(&databuf);
            let digest = mac.finalize().into_bytes();
            (
                "hsha".to_string(),
                general_purpose::STANDARD.encode(&digest),
                ISCCC_ALG_HMAC_SHA512,
            )
        }
    };

    let sig_buf = if sig_type == "hmd5" {
        RNDCValue::Binary(sig_b64.as_bytes().to_vec())
    } else {
        let mut buf = vec![0u8; 89];
        buf[0] = alg_code;
        buf[1..(1 + sig_b64.len())].copy_from_slice(sig_b64.as_bytes());
        RNDCValue::Binary(buf)
    };

    let mut auth_map = IndexMap::new();
    auth_map.insert(sig_type, sig_buf);

    Ok(RNDCValue::Table(auth_map))
}

pub fn encode(
    obj: &mut IndexMap<String, RNDCValue>,
    algorithm: &RNDCALG,
    secret: &[u8],
) -> Result<Vec<u8>, String> {
    obj.shift_remove("_auth");

    let databuf = table_towire(obj, true);

    let sig_value = make_signature(algorithm, secret, obj)?;

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
