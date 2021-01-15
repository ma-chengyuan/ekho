mod config;
mod icmp;
mod kcp;
mod session;
mod socks5;

use crate::config::get_config;
use anyhow::Result;
use std::env;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use tracing::info;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[tokio::main]
async fn main() -> Result<()> {
    let (flame_layer, _guard) = tracing_flame::FlameLayer::with_file("./tracing.folded")?;
    // let (tracer, _uninstall) = opentelemetry_jaeger::new_pipeline()
    //     .with_service_name("ekho")
    //     .install()?;
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::Layer::default())
        .with(flame_layer)
        // .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .init();

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
        info!("received session: {:?}", session);
        let mut file = tokio::fs::File::open("sample").await?;
        let mut buf = vec![0u8; get_config().kcp.mss()];
        loop {
            let len = file.read(&mut buf).await?;
            if len == 0 {
                break;
            }
            session.send(&buf[..len]).await;
        }
        session.close().await;
        info!("closed");
    } else {
        let session = session::Session::new(get_config().remote.unwrap(), 998244353);
        session.send(b"\0").await;
        let mut file = tokio::fs::File::create("sample").await?;
        loop {
            let data = session.recv().await;
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
