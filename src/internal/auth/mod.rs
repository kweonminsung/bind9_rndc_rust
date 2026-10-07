use base64::{Engine, engine::general_purpose};
use hmac::{Hmac, KeyInit, Mac};

use super::constants::{
    ISCCC_ALG_HMAC_MD5, ISCCC_ALG_HMAC_SHA1, ISCCC_ALG_HMAC_SHA224, ISCCC_ALG_HMAC_SHA256,
    ISCCC_ALG_HMAC_SHA384, ISCCC_ALG_HMAC_SHA512, MSGTYPE_BINARYDATA, MSGTYPE_TABLE, RndcAlg,
};
use crate::error::RndcError;

/// Authenticate the original bytes following the leading RNDC `_auth` field.
/// Only the fixed authentication envelope is parsed before verification.
pub(crate) fn verify<'a>(
    mut body: &'a [u8],
    algorithm: &RndcAlg,
    secret: &[u8],
) -> Result<&'a [u8], RndcError> {
    let mut auth = take_field(&mut body, b"_auth", MSGTYPE_TABLE)?;
    let (name, algorithm_id, encoded_len): (&[u8], u8, usize) = match algorithm {
        RndcAlg::MD5 => (b"hmd5", ISCCC_ALG_HMAC_MD5, 22),
        RndcAlg::SHA1 => (b"hsha", ISCCC_ALG_HMAC_SHA1, 28),
        RndcAlg::SHA224 => (b"hsha", ISCCC_ALG_HMAC_SHA224, 40),
        RndcAlg::SHA256 => (b"hsha", ISCCC_ALG_HMAC_SHA256, 44),
        RndcAlg::SHA384 => (b"hsha", ISCCC_ALG_HMAC_SHA384, 64),
        RndcAlg::SHA512 => (b"hsha", ISCCC_ALG_HMAC_SHA512, 88),
    };
    let signature = take_field(&mut auth, name, MSGTYPE_BINARYDATA)?;
    if !auth.is_empty() {
        return Err(auth_error("Unexpected fields in RNDC authentication table"));
    }

    let digest = if *algorithm == RndcAlg::MD5 {
        if signature.len() != encoded_len {
            return Err(auth_error("Invalid RNDC signature length"));
        }
        general_purpose::STANDARD_NO_PAD.decode(signature)
    } else {
        // SHA signatures contain an algorithm byte and an 88-byte field:
        // a padded base64 digest followed by zero bytes.
        if signature.len() != 89 {
            return Err(auth_error("Invalid RNDC signature length"));
        }
        if signature[0] != algorithm_id {
            return Err(auth_error("RNDC signature algorithm mismatch"));
        }
        if signature[1 + encoded_len..].iter().any(|&byte| byte != 0) {
            return Err(auth_error("Invalid RNDC signature padding"));
        }
        general_purpose::STANDARD.decode(&signature[1..1 + encoded_len])
    }
    .map_err(|_| auth_error("Invalid RNDC signature encoding"))?;

    match algorithm {
        RndcAlg::MD5 => verify_mac::<Hmac<md5::Md5>>(secret, body, &digest),
        RndcAlg::SHA1 => verify_mac::<Hmac<sha1::Sha1>>(secret, body, &digest),
        RndcAlg::SHA224 => verify_mac::<Hmac<sha2::Sha224>>(secret, body, &digest),
        RndcAlg::SHA256 => verify_mac::<Hmac<sha2::Sha256>>(secret, body, &digest),
        RndcAlg::SHA384 => verify_mac::<Hmac<sha2::Sha384>>(secret, body, &digest),
        RndcAlg::SHA512 => verify_mac::<Hmac<sha2::Sha512>>(secret, body, &digest),
    }?;

    Ok(body)
}

fn verify_mac<M: Mac + KeyInit>(
    secret: &[u8],
    body: &[u8],
    digest: &[u8],
) -> Result<(), RndcError> {
    let mut mac = M::new_from_slice(secret)
        .map_err(|_| auth_error("Failed to initialize RNDC signature verification"))?;
    mac.update(body);
    // RustCrypto verifies the complete digest using a constant-time comparison.
    mac.verify_slice(digest)
        .map_err(|_| auth_error("RNDC signature verification failed"))
}

fn take_field<'a>(
    input: &mut &'a [u8],
    expected_name: &[u8],
    expected_type: u8,
) -> Result<&'a [u8], RndcError> {
    let name_len = usize::from(take(input, 1)?[0]);
    let name = take(input, name_len)?;
    let field_type = take(input, 1)?[0];
    if name != expected_name || field_type != expected_type {
        return Err(auth_error("Missing or invalid RNDC authentication field"));
    }
    let len = take(input, 4)?;
    let len = u32::from_be_bytes([len[0], len[1], len[2], len[3]]) as usize;
    take(input, len)
}

fn take<'a>(input: &mut &'a [u8], len: usize) -> Result<&'a [u8], RndcError> {
    let value = input
        .get(..len)
        .ok_or_else(|| auth_error("Incomplete RNDC authentication field"))?;
    *input = &input[len..];
    Ok(value)
}

fn auth_error(message: &str) -> RndcError {
    RndcError::AuthenticationError(message.to_string())
}

#[cfg(test)]
mod tests;
