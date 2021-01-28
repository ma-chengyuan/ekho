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
        client::run().await;
    } else {
        server::run().await;
    }
    Ok(())
}

#[allow(dead_code)]
mod file_test {
    use crate::config::config;
    use crate::session;
    use anyhow::Result;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tracing::info;

    pub async fn test() -> Result<()> {
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
}

#[allow(dead_code)]
mod kcp_test {
    use crate::config::config;
    use crate::kcp::{ControlBlock, Error};
    use derivative::Derivative;
    use lazy_static::lazy_static;
    use parking_lot::Mutex;
    use rand::distributions::Bernoulli;
    use rand::thread_rng;
    use rand_distr::{Binomial, Distribution};
    use std::cmp::Reverse;
    use std::collections::BinaryHeap;
    use std::sync::Arc;
    use tokio::io::AsyncReadExt;
    use tokio::sync::Notify;
    use tokio::task;
    use tokio::time::{interval, Duration, Instant};
    use tracing::info;

    #[derive(Derivative)]
    #[derivative(PartialEq, Eq, PartialOrd, Ord)]
    struct Packet(
        Instant,
        #[derivative(PartialOrd = "ignore")]
        #[derivative(Ord = "ignore")]
        Vec<u8>,
    );

    struct Network {
        queue: BinaryHeap<Reverse<Packet>>,
        delay: Binomial,
        drop: Bernoulli,
    }

    impl Network {
        fn new(delay: u64, delay_var: f64, drop: f64) -> Self {
            let p = 1f64 - delay_var / delay as f64;
            Self {
                queue: Default::default(),
                delay: Binomial::new((delay as f64 / p).round() as u64, p).unwrap(),
                drop: Bernoulli::new(drop).unwrap(),
            }
        }

        fn recv(&mut self) -> Option<Vec<u8>> {
            if self.queue.peek()?.0 .0 <= Instant::now() {
                Some(self.queue.pop()?.0 .1)
            } else {
                None
            }
        }

        fn send(&mut self, packet: Vec<u8>) {
            if !self.drop.sample(&mut thread_rng()) {
                let var = self.delay.sample(&mut thread_rng());
                self.queue.push(Reverse(Packet(
                    Instant::now() + Duration::from_millis(var),
                    packet,
                )));
            }
        }
    }

    lazy_static! {
        static ref A_B: Mutex<Network> = Mutex::new(Network::new(100, 5.0, 0.05));
        static ref B_A: Mutex<Network> = Mutex::new(Network::new(100, 5.0, 0.05));
        static ref A: Mutex<ControlBlock> =
            Mutex::new(ControlBlock::new(12345, config().kcp.clone()));
        static ref B: Mutex<ControlBlock> =
            Mutex::new(ControlBlock::new(12345, config().kcp.clone()));
        static ref A_N: Notify = Notify::new();
    }

    pub async fn test() {
        let size = Arc::new(Mutex::new(0));
        let size_cloned = size.clone();
        let sent = Arc::new(Mutex::new(0));
        let sent_cloned = sent.clone();
        let _ = task::spawn(async move {
            let mut interval = interval(Duration::from_millis(config().kcp.interval as u64));
            loop {
                interval.tick().await;
                {
                    let mut kcp = A.lock();
                    kcp.flush();
                    while let Some(packet) = kcp.output() {
                        *size_cloned.lock() += packet.len();
                        A_B.lock().send(packet)
                    }
                    A_N.notify_waiters();
                }
                {
                    let mut kcp = B.lock();
                    kcp.flush();
                    while let Some(packet) = kcp.output() {
                        B_A.lock().send(packet)
                    }
                }
            }
        });
        let _ = task::spawn(async move {
            let mut interval = interval(Duration::from_millis(10));
            let mut first = true;
            loop {
                interval.tick().await;
                {
                    let mut kcp = B.lock();
                    while let Some(packet) = A_B.lock().recv() {
                        kcp.input(&packet).unwrap();
                    }
                    loop {
                        match kcp.recv() {
                            Err(Error::NotAvailable) => break,
                            Ok(packet) => {
                                if first {
                                    first = false;
                                    info!("received!");
                                }
                                *sent_cloned.lock() += packet.len();
                            }
                            Err(err) => panic!("{:?}", err),
                        }
                    }
                }
                {
                    let mut kcp = A.lock();
                    while let Some(packet) = B_A.lock().recv() {
                        kcp.input(&packet).unwrap();
                    }
                    loop {
                        match kcp.recv() {
                            Err(Error::NotAvailable) => break,
                            Ok(_) => continue,
                            Err(err) => panic!("{:?}", err),
                        }
                    }
                }
            }
        });
        let mut file = tokio::fs::File::open("sample").await.unwrap();
        let mut buf = vec![0u8; config().kcp.mss()];
        info!("Read file!");
        let total = file.metadata().await.unwrap().len();
        let _ = task::spawn(async move {
            let mut interval = interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                let sent = sent.lock();
                info!(
                    "sent {:.2}MB ({:2}%) ({:.2}MB)",
                    *sent as f64 / 1048576.0,
                    *sent as f64 / total as f64 * 100.0,
                    *size.lock() as f64 / 1048576.0
                );
                A.lock().debug();
            }
        });
        loop {
            let len = file.read(&mut buf).await.unwrap();
            if len == 0 {
                info!("done!");
                break;
            }
            while A.lock().wait_send() >= config().kcp.send_wnd as usize {
                A_N.notified().await;
            }
            A.lock().send(&buf[..len]).unwrap();
        }
    }
}
