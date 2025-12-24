use crate::error::RndcError;

// Message types
pub(crate) const MSGTYPE_STRING: u8 = 0;
pub(crate) const MSGTYPE_BINARYDATA: u8 = 1;
pub(crate) const MSGTYPE_TABLE: u8 = 2;
pub(crate) const MSGTYPE_LIST: u8 = 3;

// ISCCC Algorithm Identifiers
pub(crate) const ISCCC_ALG_HMAC_MD5: u8 = 157;
pub(crate) const ISCCC_ALG_HMAC_SHA1: u8 = 161;
pub(crate) const ISCCC_ALG_HMAC_SHA224: u8 = 162;
pub(crate) const ISCCC_ALG_HMAC_SHA256: u8 = 163;
pub(crate) const ISCCC_ALG_HMAC_SHA384: u8 = 164;
pub(crate) const ISCCC_ALG_HMAC_SHA512: u8 = 165;

/// Supported RNDC HMAC Algorithms
#[derive(Debug, PartialEq, Clone)]
pub(crate) enum RndcAlg {
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
}
impl RndcAlg {
    pub(crate) fn from_string(alg: &str) -> Result<Self, RndcError> {
        match alg {
            "md5" => Ok(RndcAlg::MD5),
            "hmd5" => Ok(RndcAlg::MD5),
            "hmac-md5" => Ok(RndcAlg::MD5),
            "sha1" => Ok(RndcAlg::SHA1),
            "hsha1" => Ok(RndcAlg::SHA1),
            "hmac-sha1" => Ok(RndcAlg::SHA1),
            "sha224" => Ok(RndcAlg::SHA224),
            "hsha224" => Ok(RndcAlg::SHA224),
            "hmac-sha224" => Ok(RndcAlg::SHA224),
            "sha256" => Ok(RndcAlg::SHA256),
            "hsha256" => Ok(RndcAlg::SHA256),
            "hmac-sha256" => Ok(RndcAlg::SHA256),
            "sha384" => Ok(RndcAlg::SHA384),
            "hsha384" => Ok(RndcAlg::SHA384),
            "hmac-sha384" => Ok(RndcAlg::SHA384),
            "sha512" => Ok(RndcAlg::SHA512),
            "hsha512" => Ok(RndcAlg::SHA512),
            "hmac-sha512" => Ok(RndcAlg::SHA512),
            _ => Err(RndcError::InvalidAlgorithm(format!(
                "Unknown algorithm: {}",
                alg
            ))),
        }
    }
}
