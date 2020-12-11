mod client;
mod config;
mod icmp;
mod kcp;
mod relay;
mod server;
mod socks5;

use crate::config::get_config;
use log::LevelFilter;
use parking_lot::deadlock;
use std::env;
use std::thread;

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

    thread::spawn(move || loop {
        thread::sleep(std::time::Duration::from_secs(2));
        let deadlocks = deadlock::check_deadlock();
        if deadlocks.is_empty() {
            continue;
        }

        log::info!("{} deadlocks detected", deadlocks.len());
        for (i, threads) in deadlocks.iter().enumerate() {
            log::info!("Deadlock #{}", i);
            for t in threads {
                log::info!("Thread Id {:#?}", t.thread_id());
                log::info!("{:#?}", t.backtrace());
            }
        }
    });

    if get_config().remote.is_none() {
        server::run_server();
    // server::test_file_upload();
    } else {
        client::run_client();
        // client::test_file_download();
    }
}
