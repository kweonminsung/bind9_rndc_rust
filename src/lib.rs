mod internal;

use base64::Engine;
use base64::engine::general_purpose;
use indexmap::IndexMap;
use internal::constants::RNDCALG;
use internal::{decoder, decoder::RNDCPayload, encoder, encoder::RNDCValue, utils};
use std::io::{Read, Write};
use std::net::TcpStream;

pub struct RndcClient {
    server_url: String,
    algorithm: RNDCALG,
    secret_key: Vec<u8>,
    stream: Option<TcpStream>,
    nonce: Option<String>,
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
            stream: None,
            nonce: None,
        }
    }

    fn get_stream(&mut self) -> &mut TcpStream {
        if self.stream.is_none() {
            let stream =
                TcpStream::connect(&self.server_url).expect("Failed to connect to RNDC server");
            self.stream = Some(stream);
        }
        self.stream.as_mut().unwrap()
    }

    fn close_stream(&mut self) {
        if let Some(stream) = self.stream.take() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }

    fn rndc_handshake(&mut self) -> Result<(), String> {
        let msg = RndcClient::build_message(
            "null",
            &self.algorithm,
            &self.secret_key,
            None,
            rand::random(),
        )?;

        let stream = self.get_stream();
        match stream.write_all(&msg) {
            Ok(_) => {}
            Err(e) => return Err(format!("Failed to write to stream: {}", e)),
        }

        let res = match RndcClient::read_packet(&mut self.stream.as_mut().unwrap()) {
            Ok(res) => res,
            Err(e) => return Err(format!("Failed to read packet: {}", e)),
        };

        self.handle_packet(&res)?;

        Ok(())
    }

    pub fn rndc_command(&mut self, command: &str) -> Result<(), String> {
        self.rndc_handshake()?;

        let msg = RndcClient::build_message(
            command,
            &self.algorithm,
            &self.secret_key,
            self.nonce.as_deref(),
            rand::random(),
        )?;

        let stream = self.get_stream();
        match stream.write_all(&msg) {
            Ok(_) => {}
            Err(e) => return Err(format!("Failed to write to stream: {}", e)),
        }

        let res = Self::read_packet(&mut self.stream.as_mut().unwrap())
            .map_err(|e| format!("Failed to read packet: {}", e))
            .unwrap();

        self.handle_packet(&res)?;

        self.close_stream();

        Ok(())
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

    fn handle_packet(&mut self, packet: &[u8]) -> Result<(), String> {
        let resp = decoder::decode(packet)?;
        if let Some(ctrl) = resp.get("_ctrl") {
            if let RNDCPayload::Table(ctrl_map) = ctrl {
                if let Some(RNDCPayload::String(new_nonce)) = ctrl_map.get("_nonce") {
                    println!("Received nonce: {:?}", new_nonce);
                    self.nonce = Some(new_nonce.to_string());
                }
            }
        }

        if self.nonce.is_none() {
            return Err("RNDC nonce not received".to_string());
        }

        if let Some(data) = resp.get("_data") {
            dbg!("Received data: {:?}", data);
        }

        Ok(())
    }

    fn read_packet(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
        let mut header = [0u8; 8];
        stream.read_exact(&mut header).unwrap();

        let length_field = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) - 4;
        // let version = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);

        let mut payload = vec![0u8; length_field as usize];
        stream.read_exact(&mut payload).unwrap();

        let mut full_packet = Vec::with_capacity(8 + payload.len());
        full_packet.extend_from_slice(&header);
        full_packet.extend_from_slice(&payload);

        Ok(full_packet)
    }
}
