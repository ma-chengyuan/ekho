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

    if get_config().remote.is_none() {
        let mut session = session::Session::incoming().await;
        session.receiver.recv().await.unwrap();
        info!("received session: {}", session);
        let mut file = tokio::fs::File::open("sample").await?;
        let mut buf = vec![0u8; get_config().kcp.mss()];
        loop {
            let len = file.read(&mut buf).await?;
            if len == 0 {
                break;
            }
            session.sender.send(Vec::from(&buf[..len])).await?;
        }
        session.close().await;
        info!("closed");
    } else {
        let mut session = session::Session::new(get_config().remote.unwrap(), 998244353);
        session.sender.send(vec![0]).await?;
        let mut file = tokio::fs::File::create("sample").await?;
        loop {
            let data = session.receiver.recv().await.unwrap();
            if data.is_empty() {
                break;
            }
            file.write_all(&data).await?;
        }
        session.close().await;
        info!("closed");
    }
    Ok(())
}
