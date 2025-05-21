mod internal;

use base64::Engine;
use base64::engine::general_purpose;
use indexmap::IndexMap;
use internal::constants::RNDCALG;
use internal::{decoder, decoder::RNDCPayload, encoder, encoder::RNDCValue, utils};
use std::io::{Read, Write};
use std::net::TcpStream;

#[derive(Debug, Clone)]
pub struct RndcClient {
    server_url: String,
    algorithm: RNDCALG,
    secret_key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RndcResult {
    pub result: bool,
    pub text: Option<String>,
    pub err: Option<String>,
}

impl RndcClient {
    pub fn new(server_url: &str, algorithm: &str, secret_key_b64: &str) -> Self {
        let secret_key = general_purpose::STANDARD
            .decode(secret_key_b64.as_bytes())
            .expect("Invalid base64 RNDC_SECRET_KEY");

        RndcClient {
            server_url: server_url.to_string(),
            algorithm: RNDCALG::from_string(algorithm).expect("Invalid RNDC algorithm"),
            secret_key,
        }
    }

    fn get_stream(&self) -> TcpStream {
        let stream =
            TcpStream::connect(&self.server_url).expect("Failed to connect to RNDC server");
        stream
    }

    fn close_stream(&self, stream: &TcpStream) -> Result<(), String> {
        stream
            .shutdown(std::net::Shutdown::Both)
            .map_err(|e| format!("Failed to shutdown stream: {}", e))?;

        Ok(())
    }

    fn rndc_handshake(&self) -> Result<(TcpStream, String), String> {
        let msg = Self::build_message(
            "null",
            &self.algorithm,
            &self.secret_key,
            None,
            rand::random(),
        )?;

        let mut stream = self.get_stream();
        stream
            .write_all(&msg)
            .map_err(|e| format!("Failed to write to stream: {}", e))?;

        let res = RndcClient::read_packet(&mut stream)
            .map_err(|e| format!("Failed to read packet: {}", e))?;

        let nonce = self.get_nonce(&res)?;

        Ok((stream, nonce))
    }

    pub fn rndc_command(&self, command: &str) -> Result<RndcResult, String> {
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
            .map_err(|e| format!("Failed to write to stream: {}", e))?;

        let res = RndcClient::read_packet(&mut stream)
            .map_err(|e| format!("Failed to read packet: {}", e))?;

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
        Err("Failed to parse status response".to_string())
    }

    fn build_message(
        command: &str,
        algorithm: &RNDCALG,
        secret: &[u8],
        nonce: Option<&str>,
        ser: u32,
    ) -> Result<Vec<u8>, String> {
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

        match encoder::encode(&mut message_body, algorithm, secret) {
            Ok(buf) => Ok(buf),
            Err(e) => Err(format!("Failed to encode message: {}", e)),
        }
    }

    fn get_nonce(&self, packet: &[u8]) -> Result<String, String> {
        let resp = decoder::decode(packet)?;
        if let Some(ctrl) = resp.get("_ctrl") {
            if let RNDCPayload::Table(ctrl_map) = ctrl {
                if let Some(RNDCPayload::String(new_nonce)) = ctrl_map.get("_nonce") {
                    // println!("Received nonce: {:?}", new_nonce);
                    return Ok(new_nonce.to_string());
                }
            }
        }
        Err("RNDC nonce not received".to_string())
    }

    fn read_packet(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
        let mut header = [0u8; 8];
        stream.read_exact(&mut header).map_err(|e| {
            format!(
                "Failed to read header: {} (expected length: {})",
                e,
                header.len()
            )
        })?;

        let length_field = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) - 4;
        // let version = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);

        let mut payload = vec![0u8; length_field as usize];
        stream.read_exact(&mut payload).map_err(|e| {
            format!(
                "Failed to read payload: {} (expected length: {})",
                e, length_field
            )
        })?;

        let mut full_packet = Vec::with_capacity(8 + payload.len());
        full_packet.extend_from_slice(&header);
        full_packet.extend_from_slice(&payload);

        Ok(full_packet)
    }
}
