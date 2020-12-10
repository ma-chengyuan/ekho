use crate::config::get_config;
use crate::kcp::KcpConnection;
use crate::relay::*;
use crate::socks5::*;
use anyhow::{bail, Context, Result};
use std::convert::TryFrom;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

fn handle_socks(mut local: TcpStream) -> Result<()> {
    let mut buf = [0; 1024];
    let len = local.read(&mut buf).context("reading SOCKS5 handshake")?;
    let local_addr = local.peer_addr()?;
    if len < 2 || len != buf[1] as usize + 2 || buf[0] != SOCKS5_VERSION {
        bail!("invalid SOCKS5 greeting message from {}", local_addr);
    }
    if !buf[2..len].contains(&0) {
        bail!(
            "SOCKS5 client from {} does not support NO AUTH method",
            local_addr
        );
    }
    local
        .write_all(&[SOCKS5_VERSION, 0])
        .context("sending back SOCKS5 method selection")?;
    let len = local.read(&mut buf).context("reading SOCKS5 request")?;
    let request = Socks5Request::try_from(&buf[..len])?;
    match request.cmd {
        Socks5Command::Connect => {
            if connect_directly(&request.dst) {
                match TcpStream::connect(&request.dst) {
                    Ok(remote) => {
                        local
                            .write_all(&Vec::<u8>::from(&Socks5Reply::Success {
                                bnd: remote.local_addr()?.into(),
                            }))
                            .context("replying SOCKS5 client (success)")?;
                        relay_tcp(local, remote).context("relaying TCP traffic")?;
                    }
                    Err(err) => {
                        log::error!(
                            "error while connecting to remote host {}: {}",
                            request.dst,
                            err
                        );
                        local
                            .write_all(&Vec::<u8>::from(&Socks5Reply::Error(err.into())))
                            .context("replying SOCKS5 client (error)")?;
                    }
                }
            } else {
                let mut kcp = KcpConnection::connect_random_conv(get_config().remote.unwrap());
                kcp.send(&Vec::<u8>::from(&request));
                let reply = Socks5Reply::try_from(&kcp.recv()[..])?;
                local
                    .write_all(&Vec::<u8>::from(&reply))
                    .context("forwarding reply from server")?;
                if let Socks5Reply::Success { .. } = reply {
                    relay_kcp(local, kcp)?;
                }
            }
        }
        _ => {
            local
                .write_all(&Vec::<u8>::from(&Socks5Reply::Error(
                    Socks5Error::CommandNotSupported,
                )))
                .context("replying SOCKS5 client (command not supported)")?;
        }
    }
    Ok(())
}

pub fn connect_directly(_addr: &Socks5SocketAddr) -> bool {
    false
}

fn test_file_download() {
    use std::fs::File;
    let mut kcp = KcpConnection::connect_random_conv(get_config().remote.unwrap());
    kcp.send(b"");
    let mut file = File::create("sample.mp4").unwrap();
    loop {
        let packet = kcp.recv();
        if packet.is_empty() {
            log::info!("recv complete");
            break;
        }
        file.write_all(&packet).unwrap();
    }
}

pub fn run_client() {
    // test_file_download();
    // return;
    let listener = TcpListener::bind("127.0.0.1:23333").unwrap();
    for stream in listener.incoming() {
        thread::spawn(|| {
            if let Err(err) = handle_socks(stream.unwrap()) {
                log::error!("{}", err);
            }
        });
    }
}
