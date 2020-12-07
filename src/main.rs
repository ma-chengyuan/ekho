mod config;
mod icmp;
mod kcp;
mod protocol;

use log::LevelFilter;
use std::env;

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
    test();
    icmp::init_and_loop();
}

fn test() {
    use crate::config::get_config;
    use crate::kcp::KcpConnection;
    use std::thread;
    if let Some(remote) = get_config().remote {
        thread::spawn(move || {
            let mut connection = KcpConnection::connect(remote, 998244353).unwrap();
            connection.send(b"hello, world!").unwrap();
        });
    } else {
        thread::spawn(move || {
            let mut connection = KcpConnection::incoming();
            let packet = connection.recv();
            log::info!("received packet: {:?}", packet);
        });
    }
}