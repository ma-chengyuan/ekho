use crate::kcp::KcpConnection;
use anyhow::Result;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const READ_TIMEOUT: Duration = Duration::from_millis(100);
const INACTIVITY_TIMEOUT: Duration = Duration::from_secs(3600);

fn handle_io_error(err: Error) -> Result<()> {
    if let ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted = err.kind() {
        return Ok(());
    }
    if cfg!(windows) {
        if let Some(10054 /* WSAECONNRESET */) = err.raw_os_error() {
            return Ok(());
        }
    }
    log::error!("{:?}", err.kind());
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
                from.set_read_timeout(Some(READ_TIMEOUT))?;
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
    let tcp_addr = tcp.peer_addr()?;
    log::info!("relaying traffic between {} and {}", tcp_addr, kcp);
    let mut tcp_read = tcp;
    let mut tcp_write = tcp_read.try_clone()?;
    let mut kcp_read = kcp;
    let mut kcp_write = kcp_read.clone();
    let should_stop = AtomicBool::new(false);
    crossbeam_utils::thread::scope(|s| {
        s.spawn(|_| {
            if let Err(err) = forward_tcp_to_kcp(&mut tcp_read, &mut kcp_write, &should_stop) {
                #[rustfmt::skip]
                log::error!("error forwarding from {} to {}: {}", tcp_addr, kcp_write, err);
            }
            should_stop.store(true, Ordering::SeqCst);
        });
        s.spawn(|_| {
            if let Err(err) = forward_kcp_to_tcp(&mut kcp_read, &mut tcp_write, &should_stop) {
                #[rustfmt::skip]
                log::error!("error forwarding from {} to {}: {}", kcp_read, tcp_addr, err);
            }
            should_stop.store(true, Ordering::SeqCst);
        });
    })
    .unwrap();
    return Ok(());

    fn forward_tcp_to_kcp(
        from: &mut TcpStream,
        to: &mut KcpConnection,
        should_stop: &AtomicBool,
    ) -> Result<()> {
        let mut buf = vec![0; to.mss()];
        if let Ok(None) = from.read_timeout() {
            from.set_read_timeout(Some(READ_TIMEOUT))?;
        }
        while !should_stop.load(Ordering::SeqCst) {
            let result = from.read(&mut buf);
            match result {
                Ok(0) => break,
                Ok(len) => to.send(&buf[..len]),
                Err(err) if err.kind() == ErrorKind::ConnectionAborted => break,
                Err(err) if err.kind() == ErrorKind::ConnectionReset => break,
                Err(err) => handle_io_error(err)?,
            }
        }
        if !should_stop.load(Ordering::SeqCst) {
            log::debug!("TCP side closes relay to {}", to);
        }
        Ok(())
    }

    fn forward_kcp_to_tcp(
        from: &mut KcpConnection,
        to: &mut TcpStream,
        should_stop: &AtomicBool,
    ) -> Result<()> {
        let mut last_active = Instant::now();
        while !should_stop.load(Ordering::SeqCst) {
            if let Some(buf) = from.recv_with_timeout(READ_TIMEOUT) {
                if buf.is_empty() {
                    break;
                }
                last_active = Instant::now();
                match to.write_all(&buf) {
                    Ok(()) => continue,
                    Err(err) if err.kind() == ErrorKind::ConnectionAborted => break,
                    Err(err) if err.kind() == ErrorKind::ConnectionReset => break,
                    Err(err) => handle_io_error(err)?,
                }
            } else if last_active.elapsed() >= INACTIVITY_TIMEOUT {
                log::warn!("KCP relay {} inactive for too long", from);
                break;
            }
        }
        if !should_stop.load(Ordering::SeqCst) {
            log::debug!("KCP side closes relay from {}", from);
        }
        Ok(())
    }
}
