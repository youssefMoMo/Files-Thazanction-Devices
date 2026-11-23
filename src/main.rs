#![forbid(unsafe_code)]

use std::path::Path;

use lan_transfer_core::{DEFAULT_PORT, transfer};

fn print_usage() {
    eprintln!(
        "Usage:\n  lan-transfer-core receive <bind-ip:port> <output-folder>\n  lan-transfer-core send <receiver-ip:port> <file>\n\nExamples:\n  lan-transfer-core receive 0.0.0.0:{DEFAULT_PORT} C:\\Users\\You\\Downloads\\LAN-Received\n  lan-transfer-core send 192.168.1.20:{DEFAULT_PORT} C:\\Users\\You\\Pictures\\photo.jpg\n\nThe sender asks for the pairing code interactively (it is not placed in command-line arguments).\nOnly ZIP, image, and video extensions are accepted."
    );
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
}

fn run() -> lan_transfer_core::AppResult<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.as_slice() {
        [command, bind, output] if command == "receive" => {
            transfer::run_receive(bind, Path::new(output))
        }
        [command, address, file] if command == "send" => {
            transfer::run_send(address, Path::new(file))
        }
        [command] if command == "--help" || command == "-h" || command == "help" => {
            print_usage();
            Ok(())
        }
        _ => {
            print_usage();
            Err("invalid command-line arguments".into())
        }
    }
}
