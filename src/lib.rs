#![forbid(unsafe_code)]

pub mod pairing;
pub mod protocol;
pub mod transfer;

pub type AppResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub const APP_NAME: &str = "LAN Transfer Core";
pub const DEFAULT_PORT: u16 = 45123;
