mod config;
mod icmp;
mod ntt;
mod socks;

use crate::ntt::NTTStream;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::env;
use tokio::io::Result;
use tokio::prelude::*;
use winapi::um::winbase::ConvertFiberToThread;
use crate::config::Config;
use std::net::Ipv4Addr;

fn main() {
    simple_logger::SimpleLogger::new().init().unwrap();

    let config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| String::from("config.json"));
    config::load_config_from_file(config_path);
    icmp::init_and_loop();
}

/*
#[tokio::main]
pub async fn main() -> Result<()> {
    simple_logger::SimpleLogger::new().init().unwrap();

    let config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| String::from("config.json"));
    config::load_config_from_file(config_path);
    icmp::init_and_loop();
    Ok(())
}
 */
