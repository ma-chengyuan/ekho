/*
Copyright 2021 Chengyuan Ma

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute, sub-
-license, and/or sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-
-INFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

mod client;
mod config;
mod icmp;
mod kcp;
mod relay;
mod server;
mod session;
mod socks5;

use crate::config::config;
use anyhow::Result;
use std::env;

use tracing::info;
use tracing::Level;
use tracing_subscriber::util::SubscriberInitExt;
use tokio::io::{AsyncWriteExt, AsyncReadExt};

fn setep_subscriber() {
    // let (flame_layer, _guard) = tracing_flame::FlameLayer::with_file("./tracing.folded")?;
    // let (tracer, _uninstall) = opentelemetry_jaeger::new_pipeline()
    //     .with_service_name("ekho")
    //     .install()?;
    let fmt_subscriber = tracing_subscriber::fmt::fmt()
        .with_max_level(Level::DEBUG)
        .compact()
        .finish();
    fmt_subscriber.init();
    // Ok(_guard)
}

#[tokio::main]
async fn main() -> Result<()> {
    let _guard = setep_subscriber();
    let config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| String::from("config.toml"));

    info!("Ekho (experimental asynchronous implementation) by Chengyuan Ma");

    config::load_config_from_file(config_path).await?;
    icmp::init_send_recv_loop().await?;
    session::init_dispatch_loop().await;

    if config().remote.is_some() {
        let session = session::Session::new(config().remote.unwrap(), 998244353);
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
    } else {
        let session = session::Session::incoming().await;
        let _greeting = session.recv().await;
        info!("received session: {:?}", session);
        let mut file = tokio::fs::File::open("sample").await?;
        let mut buf = vec![0u8; config().kcp.mss()];
        loop {
            let len = file.read(&mut buf).await?;
            if len == 0 {
                break;
            }
            session.send(&buf[..len]).await;
        }
        session.close().await;
        info!("closed");
    }
    Ok(())
}
