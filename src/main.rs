mod config;
mod icmp;
mod kcp;

use log::LevelFilter;
use std::env;

fn test_kcp() {
    use crate::config::get_config;
    use crate::kcp::KcpConnection;
    use std::convert::TryInto;
    use std::thread;
    use std::time::Duration;
    match get_config().remote {
        Some(ip) => thread::spawn(move || {
            let mut connection = KcpConnection::with_endpoint(get_config().conv, ip).unwrap();
            let mut buf = [0u8; 128];
            let mut packet_id = 0u32;
            loop {
                packet_id += 1;
                buf[..4].copy_from_slice(&packet_id.to_be_bytes());
                connection.send(&buf).unwrap();
                log::info!("sent packet {}", packet_id);
                thread::sleep(Duration::from_millis(200));
            }
        }),
        None => thread::spawn(|| {
            let mut connection = KcpConnection::new(get_config().conv).unwrap();
            loop {
                let recv = connection.recv();
                let id = u32::from_be_bytes(recv[..4].try_into().unwrap());
                log::info!("received packet {:?}", id);
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
