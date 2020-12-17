use crate::config::get_config;
use crate::kcp::KcpConnection;
use crate::relay::*;
use crate::socks5::*;
use anyhow::{bail, Context, Result};
use std::convert::TryFrom;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
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
                let mut kcp = KcpConnection::connect(get_config().remote.unwrap());
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
        Socks5Command::UdpAssociate => {
            let _udp = UdpSocket::bind("127.0.0.1:0")?;
            crossbeam_utils::thread::scope(|s| {
                s.spawn(move |_| {
                    let mut buf = [0u8; 1024];
                    loop {
                        let len = local.read(&mut buf).unwrap();
                        if len == 0 {
                            break;
                        }
                    }
                });
            })
            .unwrap();
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

#[allow(dead_code)]
pub fn test_file_download() {
    use std::fs::File;
    use std::time::Duration;
    crossbeam_utils::thread::scope(|s| {
        for i in 0..1 {
            s.spawn(move |_| {
                let mut kcp = KcpConnection::connect(get_config().remote.unwrap());
                kcp.send(b"");
                log::info!("request download from {}", kcp);
                let mut file = File::create(format!("sample{}", i)).unwrap();
                loop {
                    if let Some(packet) = kcp.recv_with_timeout(Duration::from_millis(100)) {
                        if packet.is_empty() {
                            log::info!("recv complete");
                            break;
                        }
                        file.write_all(&packet).unwrap();
                    }
                }
                log::info!("download complete from {}", kcp);
            });
            thread::sleep(Duration::from_secs(3));
        }
    })
    .unwrap();
}

pub fn run_client() {
    let listener = TcpListener::bind("127.0.0.1:23336").unwrap();
    for stream in listener.incoming() {
        thread::spawn(|| {
            if let Err(err) = handle_socks(stream.unwrap()) {
                log::error!("{}", err);
            }
        });
    }
}
