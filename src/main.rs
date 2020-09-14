mod config;
mod icmp;
mod kcp;

use std::env;
use std::sync::atomic::AtomicBool;

fn test_kcp() {
    use kcp::KCPControlBlock;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    let (tx1, rx1) = crossbeam_channel::bounded(10);
    let (tx2, rx2) = crossbeam_channel::bounded(10);
    let k1 = Arc::new(Mutex::new(KCPControlBlock::new_with_sender(12, tx1)));
    let k2 = Arc::new(Mutex::new(KCPControlBlock::new_with_sender(12, tx2)));
    k1.lock().unwrap().set_nodelay(false, 10, 0, false);
    k2.lock().unwrap().set_nodelay(false, 10, 0, false);
    kcp::init_kcp_update_thread();
    crossbeam_utils::thread::scope(|s| {
        s.spawn(|_| loop {
            k1.lock().unwrap().send(&[1, 2, 3, 4, 5]);
            kcp::schedule_immediate_update(k1.clone());
            std::thread::sleep(Duration::from_millis(1000));
        });
        s.spawn(|_| loop {
            {
                let mut inner = k2.lock().unwrap();
                let mut buf = [0u8; 1024];
                let res = inner.recv(&mut buf);
                if res >= 0 {
                    println!("{:?}", &buf[..res as usize]);
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        });
        s.spawn(|_| loop {
            if let Ok(bytes) = rx1.try_recv() {
                k2.lock().unwrap().input(&bytes);
                kcp::schedule_immediate_update(k2.clone());
            }
            if let Ok(bytes) = rx2.try_recv() {
                k1.lock().unwrap().input(&bytes);
                kcp::schedule_immediate_update(k1.clone());
            }
            std::thread::sleep(Duration::from_millis(1));
        });
    })
    .unwrap();
}

fn main() {
    simple_logger::SimpleLogger::new().init().unwrap();

    let config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| String::from("config.toml"));

    config::load_config_from_file(config_path);
    // kcp::init_kcp_update_thread();
    icmp::init_and_loop();
}
