mod config;
mod icmp;
mod kcp;
mod session;
mod socks5;

use crate::config::get_config;
use anyhow::Result;
use std::env;
use tracing::{info, Level};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();

    let config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| String::from("config.toml"));

    info!("Ekho (experimental asynchronous implementation) by Chengyuan Ma");

    config::load_config_from_file(config_path).await?;
    icmp::init_send_recv_loop().await?;
    session::init_recv_loop().await;

    if get_config().remote.is_none() {
        let mut session = session::Session::incoming().await;
        info!("received session: {}", session);
        session.sender.send(vec![1, 1, 4, 5, 1, 4]).await.unwrap();
        info!("data sent");
        session.close().await;
        info!("closed");
    // server::test_file_upload();
    } else {
        let mut session = session::Session::new(get_config().remote.unwrap(), 998244353);
        session.sender.send(vec![1]).await.unwrap();
        let res = session.receiver.recv().await.unwrap();
        info!("received: {:?}", res);
        session.close().await;
        info!("closed");
        // client::test_file_download();
    }
    Ok(())
}

/*
async fn test_kcp() {
    use kcp::ControlBlock;
    use tokio::time::{Instant, interval, Duration};
    use tokio::select;
    let mut kcp1 = ControlBlock::new(12345, get_config().kcp.clone());
    let mut kcp2 = ControlBlock::new(12345, get_config().kcp.clone());
    let start = Instant::now();
    let mut update = interval(Duration::from_millis(get_config().kcp.interval as u64));
    let mut message = interval(Duration::from_millis(100));
    loop {
        let now = start.elapsed().as_millis() as u32;
        select! {
            _ = message.tick() => {
                kcp1.send(b"hello, kcp2!").unwrap();
                kcp2.send(b"hello, kcp1!").unwrap();
            }
            _ = update.tick() => {}
        }
        while let Some(output) = kcp1.output() {
            kcp2.input(&output).unwrap();
        }
        while let Some(output) = kcp2.output() {
            kcp1.input(&output).unwrap();
        }
        kcp1.update(now);
        kcp2.update(now);
        while let Ok(msg) = kcp2.recv() {
            info!("kcp2 recv message: {:?}", msg);
        }
        while let Ok(msg) = kcp1.recv() {
            info!("kcp1 recv message: {:?}", msg);
        }
    }
}
 */
