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

use crate::config::config;
use crate::relay::{relay_kcp, relay_tcp};
use crate::session::Session;
use crate::socks5::{
    Socks5Command, Socks5Error, Socks5Reply, Socks5Request, Socks5SocketAddr, SOCKS5_VERSION,
};
use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task;
use tracing::{debug, error, instrument};

#[instrument(skip(local), fields(local = "local.peer_addr().unwrap()"))]
async fn handle_socks(mut local: TcpStream) -> Result<()> {
    let mut buf = [0; 1024];
    let len = local
        .read(&mut buf)
        .await
        .context("failed to read SOCKS5 handshake")?;
    if len < 2 || len != buf[1] as usize + 2 || buf[0] != SOCKS5_VERSION {
        bail!("invalid SOCKS5 greeting message from {:?}", local);
    }
    if !buf[2..len].contains(&0) {
        bail!(
            "SOCKS5 client from {:?} does not support NO AUTH method",
            local
        );
    }
    local
        .write_all(&[SOCKS5_VERSION, 0])
        .await
        .context("sending back SOCKS5 method selection")?;
    let len = local
        .read(&mut buf)
        .await
        .context("reading SOCKS5 request")?;
    let request = Socks5Request::parse(&buf[..len])?;
    debug!("{:?}", request);
    match request.cmd {
        Socks5Command::Connect => {
            if connect_directly(&request.dst) {
                match request.dst.connect().await {
                    Ok(remote) => {
                        local
                            .write_all(
                                &Socks5Reply::Success {
                                    bnd: remote.local_addr()?.into(),
                                }
                                .marshal(),
                            )
                            .await
                            .context("replying SOCKS5 client (success)")?;
                        relay_tcp(local, remote)
                            .await
                            .context("relaying TCP traffic")?;
                    }
                    Err(err) => {
                        error!(
                            "error while connecting to remote host {}: {}",
                            request.dst, err
                        );
                        local
                            .write_all(&Socks5Reply::Error(err.into()).marshal())
                            .await
                            .context("replying SOCKS5 client (error)")?;
                    }
                }
            } else {
                let session = Session::connect(config().remote.unwrap());
                session.send(&request.marshal()).await;
                let reply = Socks5Reply::parse(&session.recv().await)?;
                local
                    .write_all(&reply.marshal())
                    .await
                    .context("forwarding reply from server")?;
                if let Socks5Reply::Success { .. } = reply {
                    relay_kcp(local, session).await?;
                } else {
                    session.close().await;
                }
            }
        }
        _ => {
            local
                .write_all(&Socks5Reply::Error(Socks5Error::CommandNotSupported).marshal())
                .await
                .context("replying SOCKS5 client (command not supported)")?;
        }
    }
    Ok(())
}

pub fn connect_directly(_addr: &Socks5SocketAddr) -> bool {
    false
}

#[instrument]
pub async fn run() {
    let listener = TcpListener::bind("127.0.0.1:23336").await.unwrap();
    loop {
        if let Ok((stream, _)) = listener.accept().await {
            task::spawn(async move {
                if let Err(err) = handle_socks(stream).await {
                    error!("{}", err);
                }
            });
        }
    }
}
