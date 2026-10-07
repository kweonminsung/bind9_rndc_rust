mod error;
mod internal;

use base64::Engine;
use base64::engine::general_purpose;
use indexmap::IndexMap;
use std::io::{Read, Write};
use std::time::{Duration, Instant};

pub use crate::error::RndcError;
use crate::internal::constants::RndcAlg;
use crate::internal::transport::{Connection, map_io_error};
use crate::internal::{decoder, decoder::RNDCPayload, encoder, encoder::RNDCValue, utils};

#[derive(Debug, Clone)]
pub struct RndcResult {
    pub result: bool,
    pub text: Option<String>,
    pub err: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RndcClient {
    server_url: String,
    algorithm: RndcAlg,
    secret_key: Vec<u8>,
    timeout: Duration,
}

impl RndcClient {
    /// Create a client with a 30-second command timeout.
    pub fn new(server_url: &str, algorithm: &str, secret_key_b64: &str) -> Result<Self, RndcError> {
        let secret_key = general_purpose::STANDARD
            .decode(secret_key_b64.as_bytes())
            .map_err(|e| RndcError::Base64DecodeError(e.to_string()))?;

        Ok(RndcClient {
            server_url: server_url.to_string(),
            algorithm: RndcAlg::from_string(algorithm)?,
            secret_key,
            timeout: Duration::from_secs(30),
        })
    }

    /// Set the shared time limit for connecting, the handshake, and command I/O.
    ///
    /// The default is 30 seconds. Each command gets a new deadline after address
    /// resolution; synchronous system DNS lookup is not covered by this timeout.
    /// Zero and durations too large for the platform are rejected.
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, RndcError> {
        if timeout.is_zero() || Instant::now().checked_add(timeout).is_none() {
            return Err(RndcError::InvalidTimeout(
                "Timeout must be positive and fit the platform clock".to_string(),
            ));
        }
        self.timeout = timeout;
        Ok(self)
    }

    fn get_stream(&self) -> Result<Connection, RndcError> {
        Connection::connect(&self.server_url, self.timeout)
            .map_err(|e| map_io_error("Failed to connect to server", e))
    }

    fn close_stream(&self, stream: &Connection) -> Result<(), RndcError> {
        stream
            .shutdown()
            .map_err(|e| map_io_error("Failed to shutdown stream", e))?;

        Ok(())
    }

    fn rndc_handshake(&self) -> Result<(Connection, String), RndcError> {
        let msg = Self::build_message(
            "null",
            &self.algorithm,
            &self.secret_key,
            None,
            rand::random(),
        )?;

        let mut stream = self.get_stream()?;
        stream
            .write_all(&msg)
            .map_err(|e| map_io_error("Failed to write handshake", e))?;

        let res = RndcClient::read_packet(&mut stream)?;

        let nonce = self.get_nonce(&res)?;

        Ok((stream, nonce))
    }

    /// Execute a command and authenticate the server response.
    ///
    /// Responses larger than 1 MiB (excluding the length prefix) are rejected.
    /// Tables and lists may nest at most 32 levels below the root response table.
    /// See [`Self::with_timeout`] for the command I/O time limit.
    pub fn rndc_command(&self, command: &str) -> Result<RndcResult, RndcError> {
        let (mut stream, nonce) = self.rndc_handshake()?;

        let msg = RndcClient::build_message(
            command,
            &self.algorithm,
            &self.secret_key,
            Some(&nonce),
            rand::random(),
        )?;

        stream
            .write_all(&msg)
            .map_err(|e| map_io_error("Failed to write command", e))?;

        let res = RndcClient::read_packet(&mut stream)?;

        self.close_stream(&stream)?;

        let resp = decoder::decode(&res, &self.algorithm, &self.secret_key)?;

        if let Some(RNDCPayload::Table(data)) = resp.get("_data") {
            // dbg!("Received data: {:?}", data);

            let result = data.get("result").and_then(|v| {
                if let RNDCPayload::String(s) = v {
                    Some(s == "0")
                } else {
                    None
                }
            });
            let text = data.get("text").and_then(|v| {
                if let RNDCPayload::String(s) = v {
                    Some(s.clone())
                } else {
                    None
                }
            });
            let err = data.get("err").and_then(|v| {
                if let RNDCPayload::String(s) = v {
                    Some(s.clone())
                } else {
                    None
                }
            });

            return Ok(RndcResult {
                result: result.unwrap_or(false),
                text,
                err,
            });
        }
        Err(RndcError::DecodingError(
            "Failed to parse status response".to_string(),
        ))
    }

    fn build_message(
        command: &str,
        algorithm: &RndcAlg,
        secret: &[u8],
        nonce: Option<&str>,
        ser: u32,
    ) -> Result<Vec<u8>, RndcError> {
        let now = utils::get_timestamp();
        let exp = now + 60;

        // _ctrl = {type: rndc, _ser, _tim, _exp}
        let mut ctrl_map = IndexMap::new();
        ctrl_map.insert(
            "_ser".to_string(),
            RNDCValue::Binary(ser.to_string().into_bytes()),
        );
        ctrl_map.insert(
            "_tim".to_string(),
            RNDCValue::Binary(now.to_string().into_bytes()),
        );
        ctrl_map.insert(
            "_exp".to_string(),
            RNDCValue::Binary(exp.to_string().into_bytes()),
        );
        if let Some(nonce) = nonce {
            ctrl_map.insert(
                "_nonce".to_string(),
                RNDCValue::Binary(nonce.as_bytes().to_vec()),
            );
        }

        // _data = {type: command}
        let mut data_map = IndexMap::new();
        data_map.insert(
            "type".to_string(),
            RNDCValue::Binary(command.as_bytes().to_vec()),
        );

        // message_body = {_ctrl, _data}
        let mut message_body = IndexMap::new();
        message_body.insert("_ctrl".to_string(), RNDCValue::Table(ctrl_map));
        message_body.insert("_data".to_string(), RNDCValue::Table(data_map));

        encoder::encode(&mut message_body, algorithm, secret)
    }

    fn get_nonce(&self, packet: &[u8]) -> Result<String, RndcError> {
        let resp = decoder::decode(packet, &self.algorithm, &self.secret_key)?;
        if let Some(RNDCPayload::Table(ctrl_map)) = resp.get("_ctrl")
            && let Some(RNDCPayload::String(new_nonce)) = ctrl_map.get("_nonce")
        {
            return Ok(new_nonce.to_string());
        }
        Err(RndcError::DecodingError(
            "RNDC nonce not received".to_string(),
        ))
    }

    fn read_packet(stream: &mut Connection) -> Result<Vec<u8>, RndcError> {
        let mut length_bytes = [0u8; 4];
        stream
            .read_exact(&mut length_bytes)
            .map_err(|e| map_io_error("Failed to read message length", e))?;

        let length = decoder::validate_message_length(u32::from_be_bytes(length_bytes))?;
        let mut packet = vec![0u8; 4 + length];
        packet[..4].copy_from_slice(&length_bytes);
        stream
            .read_exact(&mut packet[4..])
            .map_err(|e| map_io_error("Failed to read message", e))?;

        Ok(packet)
    }
}
