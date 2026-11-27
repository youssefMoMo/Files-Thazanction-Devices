use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use snow::{Builder, TransportState, params::NoiseParams};

use crate::{AppResult, pairing::PairingSecret};

const NOISE_PATTERN: &str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";
const MAX_WIRE_FRAME: usize = 64 * 1024;
const MAX_HANDSHAKE_FRAME: usize = 4 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(12);

const CLIENT_AUTH: &[u8] = b"LANT/1 CLIENT AUTH";
const SERVER_READY: &[u8] = b"LANT/1 SERVER READY";

pub struct SecureChannel {
    stream: TcpStream,
    state: TransportState,
}

impl SecureChannel {
    pub fn send(&mut self, plaintext: &[u8]) -> AppResult<()> {
        self.send_inner(plaintext, None)
    }

    fn send_until(&mut self, plaintext: &[u8], deadline: Instant) -> AppResult<()> {
        self.send_inner(plaintext, Some(deadline))
    }

    fn send_inner(&mut self, plaintext: &[u8], deadline: Option<Instant>) -> AppResult<()> {
        if plaintext.len() > MAX_WIRE_FRAME - 64 {
            return Err("outgoing protocol message exceeds the size limit".into());
        }

        let mut encrypted = vec![0_u8; plaintext.len() + 64];
        let encrypted_len = self.state.write_message(plaintext, &mut encrypted)?;
        match deadline {
            Some(deadline) => write_frame_until(
                &mut self.stream,
                &encrypted[..encrypted_len],
                deadline,
            )?,
            None => write_frame(&mut self.stream, &encrypted[..encrypted_len])?,
        }
        Ok(())
    }

    pub fn receive(&mut self) -> AppResult<Vec<u8>> {
        self.receive_inner(None)
    }

    fn receive_until(&mut self, deadline: Instant) -> AppResult<Vec<u8>> {
        self.receive_inner(Some(deadline))
    }

    fn receive_inner(&mut self, deadline: Option<Instant>) -> AppResult<Vec<u8>> {
        let encrypted = match deadline {
            Some(deadline) => read_frame_until(&mut self.stream, MAX_WIRE_FRAME, deadline)?,
            None => read_frame(&mut self.stream, MAX_WIRE_FRAME)?,
        };
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
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let params: NoiseParams = NOISE_PATTERN.parse()?;
    let builder = Builder::new(params)
        .psk(0, secret.as_bytes())?
        .prologue(b"LAN-Transfer-Core/1")?;
    let mut handshake = builder.build_initiator()?;

    let mut first_message = [0_u8; 256];
    let first_len = handshake.write_message(&[], &mut first_message)?;
    write_frame_until(&mut stream, &first_message[..first_len], deadline)?;

    let second_message = read_frame_until(&mut stream, MAX_HANDSHAKE_FRAME, deadline)?;
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
    channel.send_until(CLIENT_AUTH, deadline)?;
    let response = channel.receive_until(deadline)?;
    if response != SERVER_READY {
        return Err("receiver did not authenticate the pairing session".into());
    }

    Ok(channel)
}

pub fn accept_secure(mut stream: TcpStream, secret: &PairingSecret) -> AppResult<SecureChannel> {
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let params: NoiseParams = NOISE_PATTERN.parse()?;
    let builder = Builder::new(params)
        .psk(0, secret.as_bytes())?
        .prologue(b"LAN-Transfer-Core/1")?;
    let mut handshake = builder.build_responder()?;

    let first_message = read_frame_until(&mut stream, MAX_HANDSHAKE_FRAME, deadline)?;
    let mut scratch = [0_u8; 256];
    handshake.read_message(&first_message, &mut scratch)?;

    let mut second_message = [0_u8; 256];
    let second_len = handshake.write_message(&[], &mut second_message)?;
    write_frame_until(&mut stream, &second_message[..second_len], deadline)?;

    if !handshake.is_handshake_finished() {
        return Err("Noise handshake did not finish".into());
    }

    let state = handshake.into_transport_mode()?;
    let mut channel = SecureChannel { stream, state };
    let authentication = channel.receive_until(deadline)?;
    if authentication != CLIENT_AUTH {
        return Err("invalid pairing authentication message".into());
    }
    channel.send_until(SERVER_READY, deadline)?;

    Ok(channel)
}

pub fn set_handshake_timeouts(stream: &TcpStream) -> AppResult<()> {
    // The receiver polls a nonblocking TcpListener. On Windows, an accepted
    // socket can retain nonblocking mode, causing handshake reads to fail with
    // WSAEWOULDBLOCK before the peer has sent its frame. Normalize every
    // accepted/connected stream before relying on blocking I/O timeouts.
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
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

fn read_frame_until(
    stream: &mut TcpStream,
    maximum: usize,
    deadline: Instant,
) -> AppResult<Vec<u8>> {
    let mut header = [0_u8; 4];
    read_exact_until(stream, &mut header, deadline)?;
    let length = usize::try_from(u32::from_be_bytes(header))?;
    if length == 0 || length > maximum {
        return Err("incoming frame length is invalid or exceeds the limit".into());
    }

    let mut bytes = vec![0_u8; length];
    read_exact_until(stream, &mut bytes, deadline)?;
    Ok(bytes)
}

fn remaining_until(deadline: Instant) -> io::Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "protocol handshake deadline exceeded",
        ));
    }
    Ok(remaining)
}

fn read_exact_until(stream: &mut TcpStream, buffer: &mut [u8], deadline: Instant) -> io::Result<()> {
    let mut offset = 0;

    while offset < buffer.len() {
        let remaining = remaining_until(deadline)?.max(Duration::from_millis(1));
        stream.set_read_timeout(Some(remaining))?;

        match stream.read(&mut buffer[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed the connection during a protocol frame",
                ));
            }
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }

    remaining_until(deadline)?;
    Ok(())
}

fn write_frame_until(stream: &mut TcpStream, bytes: &[u8], deadline: Instant) -> AppResult<()> {
    if bytes.is_empty() || bytes.len() > MAX_WIRE_FRAME {
        return Err("invalid outgoing frame length".into());
    }

    let length = u32::try_from(bytes.len())?;
    write_all_until(stream, &length.to_be_bytes(), deadline)?;
    write_all_until(stream, bytes, deadline)?;
    Ok(())
}

fn write_all_until(stream: &mut TcpStream, buffer: &[u8], deadline: Instant) -> io::Result<()> {
    let mut offset = 0;

    while offset < buffer.len() {
        let remaining = remaining_until(deadline)?.max(Duration::from_millis(1));
        stream.set_write_timeout(Some(remaining))?;

        match stream.write(&buffer[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "could not write the complete protocol frame",
                ));
            }
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }

    remaining_until(deadline)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::{Duration, Instant};

    use crate::pairing::PairingSecret;

    use super::{
        MAX_HANDSHAKE_FRAME, accept_secure, connect_secure, read_frame_until,
        set_handshake_timeouts,
    };

    #[test]
    fn handshake_frame_reader_enforces_an_absolute_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let address = listener.local_addr().expect("local address");

        let sender = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            stream.write_all(&[0]).expect("write first header byte");
            thread::sleep(Duration::from_millis(80));
            stream
                .write_all(&[0, 0, 1])
                .expect("write remainder of frame header");
            thread::sleep(Duration::from_millis(80));
            let _ = stream.write_all(&[0xAA]);
        });

        let mut stream = TcpStream::connect(address).expect("connect loopback");
        let deadline = Instant::now() + Duration::from_millis(120);
        let result = read_frame_until(&mut stream, MAX_HANDSHAKE_FRAME, deadline);

        let error = result.expect_err("trickled frame must exceed the total deadline");
        let error_kind = error.downcast_ref::<io::Error>().map(io::Error::kind);
        // std documents either TimedOut or WouldBlock for socket timeouts,
        // depending on the operating system.
        assert!(matches!(
            error_kind,
            Some(io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)
        ));
        sender.join().expect("sender thread");
    }

    #[test]
    fn accepted_socket_from_nonblocking_listener_completes_handshake() {
        let secret = PairingSecret::generate().expect("secure random source available");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        listener
            .set_nonblocking(true)
            .expect("set listener nonblocking");
        let address = listener.local_addr().expect("local address");
        let server_secret = secret.clone();

        let server = thread::spawn(move || {
            let (stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("accept failed: {error}"),
                }
            };

            // This is the same configuration path used by run_receive after
            // polling a nonblocking listener and accepting a connection.
            set_handshake_timeouts(&stream).expect("normalize accepted socket");
            let mut channel =
                accept_secure(stream, &server_secret).expect("authenticated client");
            assert_eq!(channel.receive().expect("receive payload"), b"loopback");
        });

        let stream = TcpStream::connect(address).expect("connect loopback");
        set_handshake_timeouts(&stream).expect("configure client socket");
        let mut channel = connect_secure(stream, &secret).expect("authenticated server");
        channel.send(b"loopback").expect("send payload");
        server.join().expect("server thread");
    }

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
