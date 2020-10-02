mod config;
mod icmp;
mod kcp;

use log::LevelFilter;
use std::env;
use std::io::{Read, Write};

fn test_kcp() {
    use crate::config::get_config;
    use crate::kcp::KcpConnection;
    use std::fs::File;
    use std::thread;
    match get_config().remote {
        Some(ip) => thread::spawn(move || {
            let mut connection = KcpConnection::with_endpoint(get_config().conv, ip).unwrap();
            let mut file = File::open("sample-big.mp4").unwrap();
            let mut buf = [0u8; 480];
            loop {
                let len = file.read(&mut buf).unwrap();
                connection.send(&buf[..len]).unwrap();
                if len == 0 {
                    log::info!("send complete");
                    break;
                }
            }
        }),
        None => thread::spawn(|| {
            let mut connection = KcpConnection::new(get_config().conv).unwrap();
            let mut file = File::create("sample.json").unwrap();
            loop {
                let recv = connection.recv();
                if recv.is_empty() {
                    log::info!("receive complete");
                    break;
                }
                file.write_all(&recv).unwrap();
            }
        }),
    };
}

fn main() {
    env_logger::Builder::new()
        .filter_level(LevelFilter::Debug)
        .format_timestamp_millis()
        .init();

    let config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| String::from("config.toml"));

    config::load_config_from_file(config_path);
    kcp::init_kcp_scheduler();
    test_kcp();
    icmp::init_and_loop();
}
