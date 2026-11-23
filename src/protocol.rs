use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use snow::{Builder, TransportState, params::NoiseParams};

use crate::{AppResult, pairing::PairingSecret};

const NOISE_PATTERN: &str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";
const MAX_WIRE_FRAME: usize = 64 * 1024;
const MAX_HANDSHAKE_FRAME: usize = 4 * 1024;

const CLIENT_AUTH: &[u8] = b"LANT/1 CLIENT AUTH";
const SERVER_READY: &[u8] = b"LANT/1 SERVER READY";

pub struct SecureChannel {
    stream: TcpStream,
    state: TransportState,
}

impl SecureChannel {
    pub fn send(&mut self, plaintext: &[u8]) -> AppResult<()> {
        if plaintext.len() > MAX_WIRE_FRAME - 64 {
            return Err("outgoing protocol message exceeds the size limit".into());
        }

        let mut encrypted = vec![0_u8; plaintext.len() + 64];
        let encrypted_len = self.state.write_message(plaintext, &mut encrypted)?;
        write_frame(&mut self.stream, &encrypted[..encrypted_len])?;
        Ok(())
    }

    pub fn receive(&mut self) -> AppResult<Vec<u8>> {
        let encrypted = read_frame(&mut self.stream, MAX_WIRE_FRAME)?;
        let mut plaintext = vec![0_u8; encrypted.len()];
        let plaintext_len = self.state.read_message(&encrypted, &mut plaintext)?;
        plaintext.truncate(plaintext_len);
        Ok(plaintext)
    }

    pub fn use_transfer_timeouts(&self) -> AppResult<()> {
        set_transfer_timeouts(&self.stream)
    }
}

pub fn connect_secure(mut stream: TcpStream, secret: &PairingSecret) -> AppResult<SecureChannel> {
    let params: NoiseParams = NOISE_PATTERN.parse()?;
    let builder = Builder::new(params)
        .psk(0, secret.as_bytes())?
        .prologue(b"LAN-Transfer-Core/1")?;
    let mut handshake = builder.build_initiator()?;

    let mut first_message = [0_u8; 256];
    let first_len = handshake.write_message(&[], &mut first_message)?;
    write_frame(&mut stream, &first_message[..first_len])?;

    let second_message = read_frame(&mut stream, MAX_HANDSHAKE_FRAME)?;
    let mut scratch = [0_u8; 256];
    handshake.read_message(&second_message, &mut scratch)?;

    if !handshake.is_handshake_finished() {
        return Err("Noise handshake did not finish".into());
    }

    let state = handshake.into_transport_mode()?;
    let mut channel = SecureChannel { stream, state };

    // NNpsk0 confirms possession of the pre-shared code on the first encrypted
    // transport message. This matters because an empty Noise handshake payload
    // alone is not sufficient to prove that both sides entered the same PSK.
    channel.send(CLIENT_AUTH)?;
    let response = channel.receive()?;
    if response != SERVER_READY {
        return Err("receiver did not authenticate the pairing session".into());
    }

    Ok(channel)
}

pub fn accept_secure(mut stream: TcpStream, secret: &PairingSecret) -> AppResult<SecureChannel> {
    let params: NoiseParams = NOISE_PATTERN.parse()?;
    let builder = Builder::new(params)
        .psk(0, secret.as_bytes())?
        .prologue(b"LAN-Transfer-Core/1")?;
    let mut handshake = builder.build_responder()?;

    let first_message = read_frame(&mut stream, MAX_HANDSHAKE_FRAME)?;
    let mut scratch = [0_u8; 256];
    handshake.read_message(&first_message, &mut scratch)?;

    let mut second_message = [0_u8; 256];
    let second_len = handshake.write_message(&[], &mut second_message)?;
    write_frame(&mut stream, &second_message[..second_len])?;

    if !handshake.is_handshake_finished() {
        return Err("Noise handshake did not finish".into());
    }

    let state = handshake.into_transport_mode()?;
    let mut channel = SecureChannel { stream, state };
    let authentication = channel.receive()?;
    if authentication != CLIENT_AUTH {
        return Err("invalid pairing authentication message".into());
    }
    channel.send(SERVER_READY)?;

    Ok(channel)
}

pub fn set_handshake_timeouts(stream: &TcpStream) -> AppResult<()> {
    stream.set_read_timeout(Some(Duration::from_secs(12)))?;
    stream.set_write_timeout(Some(Duration::from_secs(12)))?;
    stream.set_nodelay(true)?;
    Ok(())
}

pub fn set_transfer_timeouts(stream: &TcpStream) -> AppResult<()> {
    // A long idle timeout avoids indefinite hangs while tolerating slow disks.
    stream.set_read_timeout(Some(Duration::from_secs(180)))?;
    stream.set_write_timeout(Some(Duration::from_secs(180)))?;
    Ok(())
}

fn write_frame<W: Write>(writer: &mut W, bytes: &[u8]) -> AppResult<()> {
    if bytes.is_empty() || bytes.len() > MAX_WIRE_FRAME {
        return Err("invalid outgoing frame length".into());
    }
    let length = u32::try_from(bytes.len())?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(bytes)?;
    writer.flush()?;
    Ok(())
}

fn read_frame<R: Read>(reader: &mut R, maximum: usize) -> AppResult<Vec<u8>> {
    let mut header = [0_u8; 4];
    reader.read_exact(&mut header)?;
    let length = usize::try_from(u32::from_be_bytes(header))?;
    if length == 0 || length > maximum {
        return Err("incoming frame length is invalid or exceeds the limit".into());
    }
    let mut bytes = vec![0_u8; length];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    use crate::pairing::PairingSecret;

    use super::{accept_secure, connect_secure, set_handshake_timeouts};

    #[test]
    fn wrong_pairing_secret_is_rejected() {
        let server_secret = PairingSecret::generate().expect("secure random source available");
        let client_secret = PairingSecret::generate().expect("secure random source available");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let address = listener.local_addr().expect("local address");

        let server_secret_copy = server_secret.clone();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            set_handshake_timeouts(&stream).expect("timeouts");
            assert!(accept_secure(stream, &server_secret_copy).is_err());
        });

        let stream = TcpStream::connect(address).expect("connect loopback");
        set_handshake_timeouts(&stream).expect("timeouts");
        assert!(connect_secure(stream, &client_secret).is_err());
        server.join().expect("server thread");
    }

    #[test]
    fn noise_psk_channel_authenticates_and_encrypts() {
        let secret = PairingSecret::generate().expect("secure random source available");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let address = listener.local_addr().expect("local address");
        let server_secret = secret.clone();

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            set_handshake_timeouts(&stream).expect("timeouts");
            let mut channel = accept_secure(stream, &server_secret).expect("authenticated client");
            let message = channel.receive().expect("encrypted message");
            assert_eq!(message, b"test payload");
            channel.send(b"ack").expect("encrypted response");
        });

        let stream = TcpStream::connect(address).expect("connect loopback");
        set_handshake_timeouts(&stream).expect("timeouts");
        let mut channel = connect_secure(stream, &secret).expect("authenticated server");
        channel.send(b"test payload").expect("send payload");
        assert_eq!(channel.receive().expect("receive ack"), b"ack");
        server.join().expect("server thread");
    }
}
