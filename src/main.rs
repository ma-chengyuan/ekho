mod config;
mod icmp;
mod kcp;

use log::LevelFilter;
use std::env;

fn test_kcp() {
    use kcp::KcpControlBlock;
    use parking_lot::Mutex;
    use std::sync::Arc;
    use std::time::Duration;
    let (tx1, rx1) = crossbeam_channel::bounded(10);
    let (tx2, rx2) = crossbeam_channel::bounded(10);
    let k1 = Arc::new(Mutex::new(KcpControlBlock::new_with_sender(12, tx1)));
    let k2 = Arc::new(Mutex::new(KcpControlBlock::new_with_sender(12, tx2)));
    k1.lock().set_nodelay(false, 10, 0, false);
    k2.lock().set_nodelay(false, 10, 0, false);
    kcp::init_kcp_scheduler();
    crossbeam_utils::thread::scope(|s| {
        s.spawn(|_| loop {
            k1.lock().send(&[1, 2, 3, 4, 5]);

            kcp::schedule_immediate_update(k1.clone());
            std::thread::sleep(Duration::from_millis(20));
        });
        s.spawn(|_| loop {
            {
                let mut inner = k2.lock();
                let mut buf = [0u8; 1024];
                let res = inner.recv(&mut buf);
                if res >= 0 {
                    log::info!("received {:?}", &buf[..res as usize]);
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        });
        s.spawn(|_| loop {
            if let Ok(bytes) = rx1.try_recv() {
                k2.lock().input(&bytes);
                kcp::schedule_immediate_update(k2.clone());
            }
            if let Ok(bytes) = rx2.try_recv() {
                k1.lock().input(&bytes);
                kcp::schedule_immediate_update(k1.clone());
            }
            std::thread::sleep(Duration::from_millis(1));
        });
    })
    .unwrap();
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
    icmp::init_and_loop();
}
