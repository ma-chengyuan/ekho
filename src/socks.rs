use tokio::io::{Result, Error, ErrorKind};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, TcpListener};
use crate::ntt::*;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::convert::TryInto;
use bytes::{BytesMut, Buf};
use std::cmp::min;

const SOCKS_VER: u8 = 5;
const METHOD_NO_AUTH: u8 = 0;
const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;

pub async fn copy_from_ntt<T: ?Sized, U: ?Sized>(from: &mut T, to: &mut U) -> Result<()>
    where T: AsyncRead + Unpin, U: AsyncWrite + Unpin {
    let mut buf = [0u8; 4 * (BLOCK_SIZE + 3)];
    let mut ptr = 0usize;
    loop {
        let read = from.read(&mut buf[ptr..]).await?;
        ptr += read;
        let mut head = 0;
        while head < ptr {
            let size = 1 + (buf[head] as usize) + BLOCK_SIZE;
            if ptr < head + size { break; }
            to.write_all(&intt(&buf[head..head + size])).await?;
            head += size;
        }
        if read == 0 { break; }
        buf.copy_within(head..ptr, 0);
        ptr -= head;
    }
    Ok(())
}

pub async fn copy_to_ntt<T: ?Sized, U: ?Sized>(from: &mut T, to: &mut U) -> Result<()>
    where T: AsyncRead + Unpin, U: AsyncWrite + Unpin {
    let mut buf = [0u8; 8 * (BLOCK_SIZE - 1)];
    loop {
        let read = from.read(&mut buf).await?;
        if read == 0 { break; }
        let mut head = 0;
        while head < read {
            let len = min(read - head, BLOCK_SIZE - 1);
            to.write_all(&ntt(&buf[head..head + len])).await?;
            head += len;
        }
    }
    Ok(())
}

fn parse_port(data: &[u8]) -> u16 {
    let bytes: [u8; 2] = data.try_into().unwrap();
    u16::from_be_bytes(bytes)
}

fn parse_address(data: &[u8]) -> Result<String> {
    if data.len() < 2 {
        return Err(Error::new(ErrorKind::Other, "failed to parse address"));
    }
    match data[0] {
        ATYP_IPV4 if data.len() == 1 + 4 + 2 => {
            let octets: [u8; 4] = data[1..1 + 4].try_into().unwrap();
            Ok(format!("{}:{}", Ipv4Addr::from(octets), parse_port(&data[1 + 4..])))
        }
        ATYP_IPV6 if data.len() == 1 + 16 + 2 => {
            let octets: [u8; 16] = data[1..1 + 16].try_into().unwrap();
            Ok(format!("{}:{}", Ipv6Addr::from(octets), parse_port(&data[1 + 16..])))
        }
        ATYP_DOMAIN if data.len() == 1 + 1 + data[1] as usize + 2 => {
            let len = data[1] as usize;
            let domain = String::from_utf8_lossy(&data[2..2 + len]);
            Ok(format!("{}:{}", domain, parse_port(&data[2 + len..])))
        }
        _ => Err(Error::new(ErrorKind::Other, "failed to parse address"))
    }
}

async fn handle_socks_greeting(conn: &mut TcpStream) -> Result<()> {
    let mut buf = [0; 256];
    let len = conn.read(&mut buf).await?;
    if len < 2 || buf[0] != SOCKS_VER || len != 1 + 1 + buf[1] as usize {
        return Err(Error::new(ErrorKind::Other, "invalid SOCKS5 greeting"));
    }
    if !buf[2..len].contains(&METHOD_NO_AUTH) {
        return Err(Error::new(ErrorKind::Other, "method no-auth not supported"));
    }
    conn.write_all(&[SOCKS_VER, METHOD_NO_AUTH]).await?;
    Ok(())
}

async fn handle_socks_request(conn: &mut TcpStream) -> Result<(u8, String)> {
    let mut buf = [0; 256];
    let len = conn.read(&mut buf).await?;
    if len <= 3 || buf[0] != SOCKS_VER {
        return Err(Error::new(ErrorKind::InvalidData, "invalid SOCKS request"));
    }
    Ok((buf[1], parse_address(&buf[3..len])?))
}

async fn handle_socks(conn: &mut TcpStream) -> Result<()> {
    handle_socks_greeting(conn).await?;
    let (cmd, addr) = handle_socks_request(conn).await?;
    println!("Received socks request {} - {}", cmd, addr);

    Ok(())
}

/*
async fn test_relay() {
    let mut listener = TcpListener::bind("127.0.0.1:23333").await.unwrap();
    loop {
        let (src, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            let dst = TcpStream::connect("localhost:35809").await.unwrap();
            let (mut src_r, mut src_w) = tokio::io::split(src);
            let (mut dst_r, mut dst_w) = tokio::io::split(dst);
            tokio::join!(copy_to_ntt(&mut src_r, &mut dst_w), copy_from_ntt(&mut dst_r, &mut src_w))
        });
    }
}

async fn test_handle() {
    let mut listener = TcpListener::bind("127.0.0.1:35809").await.unwrap();
    loop {
        let (mut conn, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            handle_socks_ntt(&mut conn).await.unwrap();
        });
    }
}
*/

pub async fn test_socks() {
    let mut listener = TcpListener::bind("127.0.0.1:23333").await.unwrap();
    loop {
        let (mut conn, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            handle_socks(&mut conn).await.unwrap();
        });
    }
}