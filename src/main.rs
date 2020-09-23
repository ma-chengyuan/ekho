mod config;
mod icmp;
mod kcp;

use log::LevelFilter;
use std::env;
use std::io::{Write, Read};

fn test_kcp() {
    use crate::config::get_config;
    use crate::kcp::KcpConnection;
    use std::convert::TryInto;
    use std::thread;
    use std::fs::File;
    match get_config().remote {
        Some(ip) => thread::spawn(move || {
            let mut connection = KcpConnection::with_endpoint(get_config().conv, ip).unwrap();
            let mut file = File::create("sample.mp4").unwrap();
            let mut buf = [0u8; 480];
            loop {
                let len = file.read(&mut buf).unwrap();
                if len == 0 {
                    break;
                }
                connection.send(&buf[..len]).unwrap();
            }
        }),
        None => thread::spawn(|| {
            let mut connection = KcpConnection::new(get_config().conv).unwrap();
            let mut file = File::create("sample.mp4").unwrap();
            loop {
                let recv = connection.recv();
                file.write_all(&recv).unwrap();
            }
        }),
    };
}

fn main() {
    env_logger::Builder::new()
        .filter_level(LevelFilter::Info)
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
