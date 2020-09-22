mod config;
mod icmp;
mod kcp;

use log::LevelFilter;
use std::env;

fn test_kcp() {
    use crate::config::get_config;
    use crate::kcp::KcpConnection;
    use std::thread;
    use std::time::Duration;
    match get_config().remote_ip {
        Some(ip) => thread::spawn(move || {
            let mut connection = KcpConnection::with_endpoint(get_config().conv, ip).unwrap();
            loop {
                connection.send(&[2, 3, 3, 3, 3]).unwrap();
                thread::sleep(Duration::from_millis(200));
            }
        }),
        None => thread::spawn(|| {
            let mut connection = KcpConnection::new(get_config().conv).unwrap();
            loop {
                let recv = connection.recv();
                log::info!("received {:?}", recv);
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
