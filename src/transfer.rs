use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::pairing::PairingSecret;
use crate::protocol::{accept_secure, connect_secure, set_handshake_timeouts, SecureChannel};
use crate::AppResult;

const PAIRING_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_BAD_CONNECTIONS: u32 = 8;
const MAX_FILE_SIZE: u64 = 512 * 1024 * 1024 * 1024;
const CHUNK_SIZE: usize = 32 * 1024;
const MAX_NAME_BYTES: usize = 240;

const MSG_FILE_METADATA: u8 = 0x10;
const MSG_ACCEPT: u8 = 0x11;
const MSG_DECLINE: u8 = 0x12;
const MSG_FILE_CHUNK: u8 = 0x20;
const MSG_FILE_FINISH: u8 = 0x21;
const MSG_TRANSFER_COMPLETE: u8 = 0x22;

#[derive(Debug, Clone)]
struct FileMetadata {
    name: String,
    size: u64,
}

pub fn run_receive(bind: &str, output_directory: &Path) -> AppResult<()> {
    let output_directory = output_directory.canonicalize()?;
    if !output_directory.is_dir() {
        return Err("output path is not a directory".into());
    }

    let listener = TcpListener::bind(bind)?;
    listener.set_nonblocking(true)?;

    let secret = PairingSecret::generate()?;
    let local = listener.local_addr()?;
    let deadline = Instant::now() + PAIRING_TTL;

    println!("{}", crate::APP_NAME);
    println!("Listening for one paired transfer on {local}");
    println!("Enter this one-time pairing code on the sending computer:");
    println!("\n  {}\n", secret.to_code());
    println!("The code expires in 5 minutes and is consumed by the first authenticated sender.");
    println!("No router/Internet relay is used. Use a LAN IP address and allow the port only on your private network.");

    let mut rejected_connections = 0_u32;
    let mut accepted_channel: Option<SecureChannel> = None;

    while Instant::now() < deadline && rejected_connections < MAX_BAD_CONNECTIONS {
        match listener.accept() {
            Ok((stream, peer)) => {
                println!("Connection attempt from {peer}");
                if !is_lan_ip(peer.ip()) {
                    eprintln!("Rejected a connection from a non-local IP address.");
                    rejected_connections += 1;
                    continue;
                }
                if let Err(error) = set_handshake_timeouts(&stream) {
                    eprintln!("Could not configure connection: {error}");
                    rejected_connections += 1;
                    continue;
                }

                match accept_secure(stream, &secret) {
                    Ok(channel) => {
                        println!("Pairing authenticated successfully.");
                        accepted_channel = Some(channel);
                        break;
                    }
                    Err(error) => {
                        eprintln!("Rejected unauthenticated connection: {error}");
                        rejected_connections += 1;
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => return Err(error.into()),
        }
    }

    let Some(mut channel) = accepted_channel else {
        return Err("pairing window expired or too many invalid connection attempts".into());
    };

    // Do not retain the pairing secret after successful authentication.
    drop(secret);
    channel.use_transfer_timeouts()?;

    let metadata = receive_metadata(&mut channel)?;
    if let Err(error) = validate_filename(&metadata.name).and_then(|()| validate_extension(&metadata.name)) {
        send_decline(&mut channel)?;
        return Err(error);
    }
    if metadata.size > MAX_FILE_SIZE {
        send_decline(&mut channel)?;
        return Err("the incoming file exceeds the configured 512 GiB limit".into());
    }

    println!("\nIncoming file: {:?}", metadata.name);
    println!("Size: {} bytes", metadata.size);
    println!("Destination: {}", output_directory.display());
    print!("Accept this file? [y/N]: ");
    io::stdout().flush()?;

    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        send_decline(&mut channel)?;
        println!("Transfer declined.");
        return Ok(());
    }

    channel.send(&[MSG_ACCEPT])?;
    let saved_path = receive_file(&mut channel, &output_directory, &metadata)?;
    println!("\nTransfer completed and verified: {}", saved_path.display());
    Ok(())
}


pub fn run_send(receiver: &str, file_path: &Path) -> AppResult<()> {
    print!("Enter the one-time pairing code: ");
    io::stdout().flush()?;
    let mut code = String::new();
    io::stdin().read_line(&mut code)?;
    let secret = PairingSecret::from_code(code.trim())?;
    code.clear();
    let file_path = file_path.canonicalize()?;
    let mut source_file = File::open(&file_path)?;
    let metadata = source_file.metadata()?;
    if !metadata.is_file() {
        return Err("the selected source is not a regular file".into());
    }
    if metadata.len() > MAX_FILE_SIZE {
        return Err("the selected file exceeds the configured 512 GiB limit".into());
    }

    let name = file_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or("file name is not valid UTF-8")?
        .to_owned();
    validate_filename(&name)?;
    validate_extension(&name)?;

    let address = resolve_first(receiver)?;
    println!("Connecting to {address}...");
    let stream = TcpStream::connect_timeout(&address, Duration::from_secs(10))?;
    set_handshake_timeouts(&stream)?;
    let mut channel = connect_secure(stream, &secret)?;
    drop(secret);
    channel.use_transfer_timeouts()?;
    println!("Encrypted pairing authenticated.");

    send_metadata(&mut channel, &FileMetadata { name, size: metadata.len() })?;
    match channel.receive()?.as_slice() {
        [MSG_ACCEPT] => {}
        [MSG_DECLINE] => return Err("the receiver declined the file".into()),
        _ => return Err("unexpected response from receiver".into()),
    }

    let digest = send_file(&mut channel, &mut source_file, metadata.len())?;
    println!("Sent {} bytes; SHA-256 {}", metadata.len(), hex_digest(&digest));
    match channel.receive()?.as_slice() {
        [MSG_TRANSFER_COMPLETE] => {
            println!("Receiver verified the file successfully.");
            Ok(())
        }
        _ => Err("receiver did not confirm the completed transfer".into()),
    }
}

fn receive_metadata(channel: &mut SecureChannel) -> AppResult<FileMetadata> {
    let message = channel.receive()?;
    if message.len() < 11 || message[0] != MSG_FILE_METADATA {
        return Err("invalid file metadata message".into());
    }
    let name_length = usize::from(u16::from_be_bytes([message[1], message[2]]));
    if name_length == 0 || name_length > MAX_NAME_BYTES || message.len() != 11 + name_length {
        return Err("invalid file metadata length".into());
    }
    let size = u64::from_be_bytes(message[3..11].try_into()?);
    let name = std::str::from_utf8(&message[11..])?.to_owned();
    Ok(FileMetadata { name, size })
}

fn send_metadata(channel: &mut SecureChannel, metadata: &FileMetadata) -> AppResult<()> {
    let name = metadata.name.as_bytes();
    if name.is_empty() || name.len() > MAX_NAME_BYTES {
        return Err("file name is too long".into());
    }
    let name_length = u16::try_from(name.len())?;
    let mut message = Vec::with_capacity(11 + name.len());
    message.push(MSG_FILE_METADATA);
    message.extend_from_slice(&name_length.to_be_bytes());
    message.extend_from_slice(&metadata.size.to_be_bytes());
    message.extend_from_slice(name);
    channel.send(&message)
}

fn send_decline(channel: &mut SecureChannel) -> AppResult<()> {
    channel.send(&[MSG_DECLINE])
}

fn send_file(channel: &mut SecureChannel, file: &mut File, expected_size: u64) -> AppResult<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; CHUNK_SIZE];
    let mut sent = 0_u64;

    while sent < expected_size {
        let requested = usize::try_from((expected_size - sent).min(CHUNK_SIZE as u64))?;
        let count = file.read(&mut buffer[..requested])?;
        if count == 0 {
            return Err("source file changed or ended during transfer".into());
        }

        hasher.update(&buffer[..count]);
        let mut message = Vec::with_capacity(count + 1);
        message.push(MSG_FILE_CHUNK);
        message.extend_from_slice(&buffer[..count]);
        channel.send(&message)?;
        sent = sent.checked_add(u64::try_from(count)?)
            .ok_or("file size counter overflow")?;
    }

    // Detect a file that grew while it was being sent.
    let mut extra = [0_u8; 1];
    if file.read(&mut extra)? != 0 {
        return Err("source file changed during transfer".into());
    }

    let digest: [u8; 32] = hasher.finalize().into();
    let mut finish = Vec::with_capacity(41);
    finish.push(MSG_FILE_FINISH);
    finish.extend_from_slice(&sent.to_be_bytes());
    finish.extend_from_slice(&digest);
    channel.send(&finish)?;
    Ok(digest)
}

fn receive_file(
    channel: &mut SecureChannel,
    output_directory: &Path,
    metadata: &FileMetadata,
) -> AppResult<PathBuf> {
    let (temporary_path, mut temporary_file) = create_temporary_file(output_directory)?;
    let mut cleanup = TemporaryFileGuard { path: temporary_path.clone(), keep: false };
    let mut hasher = Sha256::new();
    let mut received = 0_u64;

    while received < metadata.size {
        let message = channel.receive()?;
        if message.len() < 2 || message[0] != MSG_FILE_CHUNK {
            return Err("unexpected message while receiving file data".into());
        }
        let chunk = &message[1..];
        if chunk.is_empty() || chunk.len() > CHUNK_SIZE {
            return Err("invalid file chunk size".into());
        }
        let chunk_size = u64::try_from(chunk.len())?;
        if chunk_size > metadata.size - received {
            return Err("received more data than the declared file size".into());
        }

        hasher.update(chunk);
        temporary_file.write_all(chunk)?;
        received = received.checked_add(chunk_size).ok_or("file size counter overflow")?;
    }

    let finish = channel.receive()?;
    if finish.len() != 41 || finish[0] != MSG_FILE_FINISH {
        return Err("missing or invalid transfer-finalization message".into());
    }
    let declared_size = u64::from_be_bytes(finish[1..9].try_into()?);
    let expected_hash: [u8; 32] = finish[9..41].try_into()?;
    let actual_hash: [u8; 32] = hasher.finalize().into();

    if declared_size != metadata.size || received != metadata.size || actual_hash != expected_hash {
        return Err("file size or SHA-256 verification failed".into());
    }

    temporary_file.flush()?;
    temporary_file.sync_all()?;
    drop(temporary_file);

    let final_path = commit_without_overwrite(&temporary_path, output_directory, &metadata.name)?;
    cleanup.keep = true;
    channel.send(&[MSG_TRANSFER_COMPLETE])?;
    Ok(final_path)
}

fn create_temporary_file(directory: &Path) -> AppResult<(PathBuf, File)> {
    for _ in 0..32 {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random)?;
        let name = format!(".lant-{}.part", hex_digest(&random));
        let path = directory.join(name);
        match OpenOptions::new().write(true).read(true).create_new(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err("could not allocate a unique temporary file".into())
}

struct TemporaryFileGuard {
    path: PathBuf,
    keep: bool,
}

impl Drop for TemporaryFileGuard {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn commit_without_overwrite(temporary: &Path, directory: &Path, original_name: &str) -> AppResult<PathBuf> {
    let original = Path::new(original_name);
    let stem = original.file_stem().and_then(|value| value.to_str()).ok_or("invalid file name")?;
    let extension = original.extension().and_then(|value| value.to_str());

    for index in 0_u32..10_000 {
        let candidate_name = if index == 0 {
            original_name.to_owned()
        } else if let Some(extension) = extension {
            format!("{stem} ({index}).{extension}")
        } else {
            format!("{stem} ({index})")
        };
        let candidate = directory.join(candidate_name);

        // A hard-link commit is atomic and fails if the target already exists;
        // both names are in the same destination directory/volume.
        match fs::hard_link(temporary, &candidate) {
            Ok(()) => {
                fs::remove_file(temporary)?;
                return Ok(candidate);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }

    Err("too many files with the same name already exist".into())
}

fn validate_extension(name: &str) -> AppResult<()> {
    let extension = Path::new(name)
        .extension()
        .and_then(|value| value.to_str())
        .ok_or("file type is not supported")?
        .to_ascii_lowercase();

    const ALLOWED: &[&str] = &[
        "zip", "jpg", "jpeg", "png", "gif", "bmp", "webp",
        "mp4", "mkv", "mov", "avi", "webm",
    ];

    if !ALLOWED.contains(&extension.as_str()) {
        return Err("only ZIP archives, images, and videos are supported".into());
    }
    Ok(())
}

fn validate_filename(name: &str) -> AppResult<()> {
    if name.is_empty() || name.len() > MAX_NAME_BYTES || name == "." || name == ".." {
        return Err("file name is empty or too long".into());
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return Err("file name cannot end with a dot or space".into());
    }
    if name.chars().any(|character| {
        character.is_control() || matches!(character, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*')
    }) {
        return Err("file name contains a character that is not allowed on Windows".into());
    }

    let base = name
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end_matches(|character| character == ' ' || character == '.')
        .to_ascii_uppercase();
    let reserved = matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (base.len() == 4
            && (base.starts_with("COM") || base.starts_with("LPT"))
            && matches!(base.as_bytes()[3], b'1'..=b'9'));
    if reserved {
        return Err("file name is reserved by Windows".into());
    }

    // The sender must provide a basename, never a path.
    if Path::new(name).file_name().and_then(|value| value.to_str()) != Some(name) {
        return Err("directory paths are not accepted in file metadata".into());
    }
    Ok(())
}

fn resolve_first(input: &str) -> AppResult<SocketAddr> {
    input
        .to_socket_addrs()?
        .find(|address| is_lan_ip(address.ip()))
        .ok_or_else(|| "receiver must resolve to a private, loopback, or link-local LAN address".into())
}

fn is_lan_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            address.is_private()
                || address.is_loopback()
                || (octets[0] == 169 && octets[1] == 254)
        }
        IpAddr::V6(address) => {
            let octets = address.octets();
            address.is_loopback()
                || (octets[0] & 0xfe) == 0xfc // Unique-local fc00::/7
                || (octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80) // Link-local fe80::/10
        }
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{is_lan_ip, validate_extension, validate_filename};

    #[test]
    fn accepts_supported_file_names() {
        assert!(validate_filename("holiday photo 01.jpg").is_ok());
        assert!(validate_extension("holiday photo 01.jpg").is_ok());
        assert!(validate_filename("video.final.mp4").is_ok());
        assert!(validate_extension("backup.zip").is_ok());
    }

    #[test]
    fn rejects_paths_and_windows_reserved_names() {
        assert!(validate_filename("..\\secret.jpg").is_err());
        assert!(validate_filename("folder/file.jpg").is_err());
        assert!(validate_filename("CON.jpg").is_err());
        assert!(validate_filename("name. ").is_err());
    }

    #[test]
    fn accepts_private_and_loopback_addresses_but_rejects_public_addresses() {
        assert!(is_lan_ip("192.168.1.10".parse::<IpAddr>().expect("valid IP")));
        assert!(is_lan_ip("10.0.0.4".parse::<IpAddr>().expect("valid IP")));
        assert!(is_lan_ip("127.0.0.1".parse::<IpAddr>().expect("valid IP")));
        assert!(!is_lan_ip("8.8.8.8".parse::<IpAddr>().expect("valid IP")));
    }

    #[test]
    fn rejects_unsupported_extensions() {
        assert!(validate_extension("setup.exe").is_err());
        assert!(validate_extension("document.pdf").is_err());
    }
}
