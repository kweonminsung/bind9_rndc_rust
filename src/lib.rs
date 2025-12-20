mod error;
mod internal;

use base64::Engine;
use base64::engine::general_purpose;
use indexmap::IndexMap;
use std::io::{Read, Write};
use std::net::TcpStream;

pub use crate::error::RndcError;
use crate::internal::constants::RndcAlg;
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
}
impl RndcClient {
    pub fn new(server_url: &str, algorithm: &str, secret_key_b64: &str) -> Result<Self, RndcError> {
        let secret_key = general_purpose::STANDARD
            .decode(secret_key_b64.as_bytes())
            .map_err(|e| RndcError::Base64DecodeError(e.to_string()))?;

        Ok(RndcClient {
            server_url: server_url.to_string(),
            algorithm: RndcAlg::from_string(algorithm)?,
            secret_key,
        })
    }

    fn get_stream(&self) -> Result<TcpStream, RndcError> {
        TcpStream::connect(&self.server_url)
            .map_err(|e| RndcError::NetworkError(format!("Failed to connect to server: {}", e)))
    }

    fn close_stream(&self, stream: &TcpStream) -> Result<(), RndcError> {
        stream
            .shutdown(std::net::Shutdown::Both)
            .map_err(|e| RndcError::NetworkError(format!("Failed to shutdown stream: {}", e)))?;

        Ok(())
    }

    fn rndc_handshake(&self) -> Result<(TcpStream, String), RndcError> {
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
            .map_err(|e| RndcError::NetworkError(format!("Failed to write to stream: {}", e)))?;

        let res = RndcClient::read_packet(&mut stream)?;

        let nonce = self.get_nonce(&res)?;

        Ok((stream, nonce))
    }

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
            .map_err(|e| RndcError::NetworkError(format!("Failed to write to stream: {}", e)))?;

        let res = RndcClient::read_packet(&mut stream)?;

        self.close_stream(&stream)?;

        let resp = decoder::decode(&res)?;

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
        let resp = decoder::decode(packet)?;
        if let Some(RNDCPayload::Table(ctrl_map)) = resp.get("_ctrl").and_then(|ctrl| {
            if let RNDCPayload::Table(map) = ctrl {
                Some(RNDCPayload::Table(map.clone()))
            } else {
                None
            }
        }) {
            if let Some(RNDCPayload::String(new_nonce)) = ctrl_map.get("_nonce") {
                // println!("Received nonce: {:?}", new_nonce);
                return Ok(new_nonce.to_string());
            }
        }
        Err(RndcError::DecodingError(
            "RNDC nonce not received".to_string(),
        ))
    }

    fn read_packet(stream: &mut TcpStream) -> Result<Vec<u8>, RndcError> {
        let mut header = [0u8; 8];
        stream.read_exact(&mut header).map_err(|e| {
            RndcError::NetworkError(format!(
                "Failed to read header: {} (expected length: {})",
                e,
                header.len()
            ))
        })?;

        let length_field = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) - 4;
        // let version = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);

        let mut payload = vec![0u8; length_field as usize];
        stream.read_exact(&mut payload).map_err(|e| {
            RndcError::NetworkError(format!(
                "Failed to read payload: {} (expected length: {})",
                e, length_field
            ))
        })?;

        let mut full_packet = Vec::with_capacity(8 + payload.len());
        full_packet.extend_from_slice(&header);
        full_packet.extend_from_slice(&payload);

        Ok(full_packet)
    }
}
