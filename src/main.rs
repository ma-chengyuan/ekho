mod ntt;
mod socks;

use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, TcpListener};
use tokio::io::Result;
use std::marker::Unpin;

async fn relay_from_ntt<T: ?Sized, U: ?Sized>(from: &mut T, to: &mut U) -> Result<()>
    where T: AsyncRead + Unpin, U: AsyncWrite + Unpin {
    const BUF_SIZE: usize = 2048;
    let mut buf = [0u8; BUF_SIZE];
    let mut ptr = 0usize;
    loop {
        let read = from.read(&mut buf[ptr..]).await?;
        ptr += read;
        let mut head = 0;
        while head < ptr {
            let size = 1 + (buf[head] as usize) + ntt::BLOCK_SIZE;
            if ptr < head + size { break; }
            to.write_all(&ntt::intt(&buf[head..head + size])).await?;
            head += size;
        }
        if read == 0 {
            break;
        }
        for i in head..ptr {
            buf[i - head] = buf[i];
        }
        ptr -= head;
    }
    Ok(())
}

async fn relay_to_ntt<T: ?Sized, U: ?Sized>(from: &mut T, to: &mut U) -> Result<()>
    where T: AsyncRead + Unpin, U: AsyncWrite + Unpin {
    let mut buf = [0u8; ntt::BLOCK_SIZE - 1];
    loop {
        let read = from.read(&mut buf).await?;
        println!("Read {} bytes", read);
        if read == 0 {
            break;
        }
        to.write_all(&ntt::ntt(&buf[..read])).await?;
    }
    Ok(())
}

#[tokio::main]
pub async fn main() -> Result<()> {
    let input = vec![1u8, 1, 4, 5, 1, 4, 1, 9, 1, 9, 8, 1, 0];
    let mut listener = TcpListener::bind("127.0.0.1:35809").await?;

    tokio::spawn(async move {
        let mut conn = TcpStream::connect("127.0.0.1:35809").await.unwrap();
        conn.write(&input).await.unwrap();
    });

    loop {
        let (mut conn, _) = listener.accept().await?;

        tokio::spawn(async move {
            let mut buf = [0; 255];
            let read = conn.read(&mut buf).await.unwrap();
            if read == 0 {
                return;
            }
            println!("Received {} bytes", read);
        });
    }
}
