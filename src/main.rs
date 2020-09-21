mod config;
mod icmp;
mod kcp;

use log::LevelFilter;
use std::env;

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
    match config::get_config().remote_ip {
        Some(ip) => std::thread::spawn(move || {
            let mut connection =
                kcp::KcpConnection::new_with_ip(config::get_config().conv, ip).unwrap();
            loop {
                connection.send(&[1, 2, 3, 4, 5]).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }),
        None => std::thread::spawn(|| {
            let mut connection = kcp::KcpConnection::new(config::get_config().conv).unwrap();
            loop {
                let bytes = connection.recv();
                log::info!("recieived bytes: {:?}", bytes);
            }
        }),
    };
    icmp::init_and_loop();
}
