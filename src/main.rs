mod client;
mod config;
mod icmp;
mod kcp;
mod relay;
mod server;
mod socks5;

use crate::config::get_config;
use log::LevelFilter;
use std::env;

fn main() {
    env_logger::Builder::new()
        .filter_level(LevelFilter::Debug)
        .format_timestamp_millis()
        .init();

    log::info!("Ekho 0.1.0 by Chengyuan Ma 2020");

    let config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| String::from("config.toml"));

    config::load_config_from_file(config_path);
    kcp::init_kcp_scheduler();
    icmp::init_send_recv_loop();
    if get_config().remote.is_none() {
        // server::run_server();
        server::test_file_upload();
    } else {
        // client::run_client();
        client::test_file_download();
    }
}
