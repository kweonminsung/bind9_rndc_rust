// Message types
pub(crate) const MSGTYPE_STRING: u8 = 0;
pub(crate) const MSGTYPE_BINARYDATA: u8 = 1;
pub(crate) const MSGTYPE_TABLE: u8 = 2;
pub(crate) const MSGTYPE_LIST: u8 = 3;

pub(crate) const ISCCC_ALG_HMAC_MD5: u8 = 157;
pub(crate) const ISCCC_ALG_HMAC_SHA1: u8 = 161;
pub(crate) const ISCCC_ALG_HMAC_SHA224: u8 = 162;
pub(crate) const ISCCC_ALG_HMAC_SHA256: u8 = 163;
pub(crate) const ISCCC_ALG_HMAC_SHA384: u8 = 164;
pub(crate) const ISCCC_ALG_HMAC_SHA512: u8 = 165;

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
    pub(crate) fn from_string(alg: &str) -> Option<Self> {
        match alg {
            "md5" => Some(RndcAlg::MD5),
            "hmac-md5" => Some(RndcAlg::MD5),
            "sha1" => Some(RndcAlg::SHA1),
            "hmac-sha1" => Some(RndcAlg::SHA1),
            "sha224" => Some(RndcAlg::SHA224),
            "hmac-sha224" => Some(RndcAlg::SHA224),
            "sha256" => Some(RndcAlg::SHA256),
            "hmac-sha256" => Some(RndcAlg::SHA256),
            "sha384" => Some(RndcAlg::SHA384),
            "hmac-sha384" => Some(RndcAlg::SHA384),
            "sha512" => Some(RndcAlg::SHA512),
            "hmac-sha512" => Some(RndcAlg::SHA512),
            _ => None,
        }
    }
}
