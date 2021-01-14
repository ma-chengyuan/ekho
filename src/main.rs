mod config;
mod icmp;
mod kcp;
mod session;
mod socks5;

use crate::config::get_config;
use anyhow::Result;
use std::env;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, Level};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tokio::time::{sleep, Duration};

fn setup_subscriber() -> Result<()> {
    let fmt_layer = tracing_subscriber::fmt::Layer::default();
    let (flame_layer, _guard) = tracing_flame::FlameLayer::with_file("./tracing.folded")?;
    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(flame_layer)
        .init();
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_subscriber()?;

    let config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| String::from("config.toml"));

    info!("Ekho (experimental asynchronous implementation) by Chengyuan Ma");

    config::load_config_from_file(config_path).await?;
    icmp::init_send_recv_loop().await?;
    session::init_recv_loop().await;
    // test_kcp().await;

    if get_config().remote.is_none() {
        let session = session::Session::incoming().await;
        let _greeting = session.recv().await;
        info!("received session: {}", session);
        for _ in 0..1000 {
            session.send(b"hello world").await;
            sleep(Duration::from_millis(100)).await;
        }
        session.close().await;
        info!("closed");
    } else {
        let session = session::Session::new(get_config().remote.unwrap(), 998244353);
        session.send(b"\0").await;
        loop {
            let data = session.recv().await;
            info!("message received: {:?}", data);
            if data.is_empty() {
                break;
            }
        }
        session.close().await;
        info!("closed");
    }

    Ok(())
}

async fn test_kcp() {
    use kcp::ControlBlock;
    use tokio::select;
    use tokio::time::{interval, Duration, Instant};
    let mut kcp1 = ControlBlock::new(12345, get_config().kcp.clone());
    let mut kcp2 = ControlBlock::new(12345, get_config().kcp.clone());
    let mut update = interval(Duration::from_millis(get_config().kcp.interval as u64));
    let mut message = interval(Duration::from_millis(100));
    loop {
        select! {
            _ = message.tick() => {
                kcp1.send(b"hello, kcp2!").unwrap();
                kcp2.send(b"hello, kcp1!").unwrap();
            }
            _ = update.tick() => {
                kcp1.flush();
                kcp2.flush();
            }
        }
        while let Some(output) = kcp1.output() {
            kcp2.input(&output).unwrap();
        }
        while let Some(output) = kcp2.output() {
            kcp1.input(&output).unwrap();
        }
        while let Ok(msg) = kcp2.recv() {
            info!("kcp2 recv message: {:?}", msg);
        }
        while let Ok(msg) = kcp1.recv() {
            info!("kcp1 recv message: {:?}", msg);
        }
    }
}
