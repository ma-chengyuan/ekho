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

#![allow(clippy::needless_lifetimes)]

use crate::config::config;
use crate::session::Session;
use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::io::{Error, ErrorKind};
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::select;
use tracing::info;

fn handle_io_error(err: Error) -> Result<()> {
    if matches!(
        err.kind(),
        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
    ) || (cfg!(windows) && matches!(err.raw_os_error(), Some(10054 /* WSACONNRESET */)))
    {
        Ok(())
    } else {
        Err(err.into())
    }
}

async fn forward_tcp<'a>(mut from: ReadHalf<'a>, mut to: WriteHalf<'a>) -> Result<()> {
    let mut buf = [0; 1024];
    loop {
        match from.read(&mut buf).await {
            Ok(0) => break,
            Ok(len) => to.write_all(&buf[..len]).await?,
            Err(err) => handle_io_error(err)?,
        }
    }
    Ok(())
}

pub async fn relay_tcp(mut a: TcpStream, mut b: TcpStream) -> Result<()> {
    info!(
        "relaying between {:?} and {:?}",
        a.peer_addr()?,
        b.peer_addr()?
    );
    let (a_read, a_write) = a.split();
    let (b_read, b_write) = b.split();
    select! {
        res = forward_tcp(a_read, b_write) => res,
        res = forward_tcp(b_read, a_write) => res
    }
}

async fn forward_tcp_to_kcp<'a>(mut from: ReadHalf<'a>, to: &Session) -> Result<()> {
    let mut buf = vec![0; config().kcp.mss()];
    loop {
        match from.read(&mut buf).await {
            Ok(0) => break,
            Ok(len) => to.send(&buf[..len]).await,
            Err(err) if err.kind() == ErrorKind::ConnectionAborted => break,
            Err(err) => handle_io_error(err)?,
        }
    }
    Ok(())
}

async fn forward_kcp_to_tcp<'a>(from: &Session, mut to: WriteHalf<'a>) -> Result<()> {
    loop {
        let buf = from.recv().await;
        if buf.is_empty() {
            break;
        }
        match to.write_all(&buf).await {
            Ok(()) => continue,
            Err(err) if err.kind() == ErrorKind::ConnectionAborted => break,
            Err(err) => handle_io_error(err)?,
        }
    }
    Ok(())
}

pub async fn relay_kcp(mut tcp: TcpStream, session: Session) -> Result<()> {
    let (read, write) = tcp.split();
    let res = select! {
        res = forward_tcp_to_kcp(read, &session) => res,
        res = forward_kcp_to_tcp(&session, write) => res
    };
    session.close().await;
    res
}
