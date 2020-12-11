use crate::kcp::KcpConnection;
use anyhow::Result;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_millis(100);

fn handle_io_error(err: Error) -> Result<()> {
    if let ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted = err.kind() {
        return Ok(());
    }
    if cfg!(windows) {
        if let Some(10054 /* WSAECONNRESET */) = err.raw_os_error() {
            return Ok(());
        }
    }
    Err(err.into())
}

pub fn relay_tcp(a: TcpStream, b: TcpStream) -> Result<()> {
    log::info!(
        "relaying TCP traffic between {} and {}",
        a.peer_addr()?,
        b.peer_addr()?
    );
    let should_stop = AtomicBool::new(false);
    let (a_read, b_read) = (a, b);
    let a_write = a_read.try_clone()?;
    let b_write = b_read.try_clone()?;
    crossbeam_utils::thread::scope(|s| {
        s.spawn(|_| forward(a_read, b_write, &should_stop));
        s.spawn(|_| forward(b_read, a_write, &should_stop));
    })
    .unwrap();
    return Ok(());

    fn forward(mut from: TcpStream, mut to: TcpStream, should_stop: &AtomicBool) {
        if let Err(err) = forward_inner(&mut from, &mut to, should_stop) {
            log::error!(
                "error forwarding TCP traffic from {} to {}: {}",
                from.peer_addr().unwrap(),
                to.peer_addr().unwrap(),
                err
            );
        }
        should_stop.store(true, Ordering::Relaxed);

        fn forward_inner(
            from: &mut TcpStream,
            to: &mut TcpStream,
            should_stop: &AtomicBool,
        ) -> Result<()> {
            let mut buf = [0; 1024];
            if let Ok(None) = from.read_timeout() {
                // Set a timeout for the read operation to ensure the should_stop flag is regularly
                // checked. The write time is usually negligible here so not setting a write timeout
                // here to avoid complicating things.
                from.set_read_timeout(Some(TIMEOUT))?;
            }
            while !should_stop.load(Ordering::Relaxed) {
                let result = from.read(&mut buf);
                match result {
                    Ok(0) => break,
                    Ok(len) => to.write_all(&buf[..len])?,
                    Err(err) => handle_io_error(err)?,
                }
            }
            Ok(())
        }
    }
}

pub fn relay_kcp(tcp: TcpStream, kcp: KcpConnection) -> Result<()> {
    log::info!(
        "relaying traffic between {} (TCP) and {} (KCP)",
        tcp.peer_addr()?,
        kcp
    );
    let stop_message = format!(
        "relay stopped between {} (TCP) and {} (KCP)",
        tcp.peer_addr()?,
        kcp
    );
    let mut tcp_read = tcp;
    let mut tcp_write = tcp_read.try_clone()?;
    let mut kcp_read = kcp;
    let mut kcp_write = kcp_read.clone();
    let should_stop = AtomicBool::new(false);
    crossbeam_utils::thread::scope(|s| {
        s.spawn(|_| {
            if let Err(err) = forward_tcp_to_kcp(&mut tcp_read, &mut kcp_write, &should_stop) {
                log::error!("{}", err);
            }
            should_stop.store(true, Ordering::Relaxed);
        });
        s.spawn(|_| {
            if let Err(err) = forward_kcp_to_tcp(&mut kcp_read, &mut tcp_write, &should_stop) {
                log::error!("{}", err);
            }
            should_stop.store(true, Ordering::Relaxed);
        });
    })
    .unwrap();
    log::info!("{}", stop_message);
    return Ok(());

    fn forward_tcp_to_kcp(
        from: &mut TcpStream,
        to: &mut KcpConnection,
        should_stop: &AtomicBool,
    ) -> Result<()> {
        let mut buf = [0; 1024];
        if let Ok(None) = from.read_timeout() {
            from.set_read_timeout(Some(TIMEOUT))?;
        }
        while !should_stop.load(Ordering::Relaxed) {
            let result = from.read(&mut buf);
            match result {
                Ok(0) => break,
                Ok(len) => to.send(&buf[..len]),
                Err(err) => handle_io_error(err)?,
            }
        }
        to.send(b"");
        Ok(())
    }

    fn forward_kcp_to_tcp(
        from: &mut KcpConnection,
        to: &mut TcpStream,
        should_stop: &AtomicBool,
    ) -> Result<()> {
        while !should_stop.load(Ordering::Relaxed) {
            if let Some(buf) = from.recv_with_timeout(TIMEOUT) {
                if buf.is_empty() {
                    break;
                }
                to.write_all(&buf)?;
            }
        }
        Ok(())
    }
}
