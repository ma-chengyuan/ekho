use crate::kcp::KcpConnection;
use crate::relay::relay_kcp;
use crate::socks5::*;
use anyhow::Result;
use std::convert::TryFrom;
use std::net::TcpStream;
use std::thread;
use std::io::Read;

fn handle_request(mut kcp: KcpConnection) -> Result<()> {
    let request = Socks5Request::try_from(&kcp.recv()[..])?;
    log::info!("received request to {}", request.dst);
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

pub fn run_server() {
    loop {
        let mut kcp = KcpConnection::incoming();
        thread::spawn(|| {
            use std::fs::File;
            log::info!("start transmission...");
            let mut file = File::open("sample-big.mp4").unwrap();
            let mut buf = [0u8; 480];
            loop {
                let len = file.read(&mut buf).unwrap();
                kcp.send(&buf[..len]);
                if len == 0 {
                    log::info!("transmission completed!");
                    break;
                }
            }
            return;
            if let Err(err) = handle_request(kcp) {
                log::error!("{}", err);
            }
        });
    }
}
