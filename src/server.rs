use crate::kcp::KcpConnection;
use crate::relay::relay_kcp;
use crate::socks5::*;
use anyhow::Result;
use std::convert::TryFrom;
use std::io::Read;
use std::net::TcpStream;
use std::thread;

fn handle_request(mut kcp: KcpConnection) -> Result<()> {
    let request = Socks5Request::try_from(&kcp.recv()[..])?;
    // log::info!("received request to {}", request.dst);
    match request.cmd {
        Socks5Command::Connect => match TcpStream::connect(&request.dst) {
            Ok(remote) => {
                kcp.send(&Vec::<u8>::from(&Socks5Reply::Success {
                    bnd: remote.local_addr()?.into(),
                }));
                relay_kcp(remote, kcp)?;
            }
            Err(err) => {
                log::error!(
                    "error while connecting to remote host {}: {}",
                    request.dst,
                    err
                );
                kcp.send(&Vec::<u8>::from(&Socks5Reply::Error(err.into())))
            }
        },
        _ => kcp.send(&Vec::<u8>::from(&Socks5Reply::Error(
            Socks5Error::CommandNotSupported,
        ))),
    }
    Ok(())
}

pub fn test_file_upload() {
    use std::fs::File;
    loop {
        let mut kcp = KcpConnection::incoming();
        thread::spawn(move || {
            log::info!("start file transmission to {}", kcp);
            let mut file = File::open("sample").unwrap();
            let mut buf = vec![0; kcp.mss()];
            loop {
                let len = file.read(&mut buf).unwrap();
                kcp.send(&buf[..len]);
                if len == 0 {
                    log::info!("completed transmission to {}", kcp);
                    break;
                }
            }
        });
    }
}

pub fn run_server() {
    loop {
        let kcp = KcpConnection::incoming();
        thread::spawn(|| {
            if let Err(err) = handle_request(kcp) {
                log::error!("{}", err);
            }
        });
    }
}
