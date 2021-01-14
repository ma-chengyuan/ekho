/*
Copyright 2020 Chengyuan Ma

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

//! Build sessions above the raw KCP algorithm

#![allow(dead_code)]
use crate::config::get_config;
use crate::icmp::IcmpEndpoint;

use crate::kcp::{dissect_headers_from_raw, ControlBlock, Error};
use chacha20poly1305::aead::{AeadInPlace, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use dashmap::DashMap;
use lazy_static::lazy_static;
use parking_lot::Mutex;
use rustc_hash::FxHasher;
use std::fmt;
use std::hash::BuildHasherDefault;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use tokio::select;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::Notify;
use tokio::task;
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};
use tracing::{debug_span, error, info, Instrument};

type Control = (Mutex<ControlBlock>, Notify);

lazy_static! {
    static ref CONTROLS: DashMap<(IcmpEndpoint, u32), Weak<Control>, BuildHasherDefault<FxHasher>> =
        Default::default();
    static ref CIPHER: ChaCha20Poly1305 = ChaCha20Poly1305::new(&get_config().key);
    static ref NONCE: Nonce = Nonce::default();
    static ref INCOMING: (
        UnboundedSender<Session>,
        AsyncMutex<UnboundedReceiver<Session>>
    ) = {
        let (tx, rx) = unbounded_channel();
        (tx, AsyncMutex::new(rx))
    };
}

const CLOSE_TIMEOUT: Duration = Duration::from_secs(60);

/// A session, built on top of KCP
pub struct Session {
    conv: u32,
    peer: IcmpEndpoint,
    updater: JoinHandle<()>,
    control: Arc<Control>,
    peer_closing: Arc<AtomicBool>,
    local_closing: Arc<AtomicBool>,
}

impl Session {
    /// Creates a new session given a peer endpoint and a conv.
    pub fn new(peer: IcmpEndpoint, conv: u32) -> Self {
        assert!(!CONTROLS.contains_key(&(peer, conv)));
        // The naming here is very nasty!
        let control = Arc::new((
            Mutex::new(ControlBlock::new(conv, get_config().kcp.clone())),
            Notify::new(),
        ));
        let control_cloned = control.clone();
        CONTROLS.insert((peer, conv), Arc::downgrade(&control_cloned));
        let peer_closing = Arc::new(AtomicBool::new(false));
        let local_closing = Arc::new(AtomicBool::new(false));
        let peer_closing_cloned = peer_closing.clone();
        let local_closing_cloned = local_closing.clone();
        let updater = task::spawn(
            async move {
                let icmp_tx = crate::icmp::clone_sender().await;
                let interval = Duration::from_millis(get_config().kcp.interval as u64);
                'update_loop: loop {
                    {
                        let mut kcp = control_cloned.0.lock();
                        kcp.flush();
                        control_cloned.1.notify_waiters();
                        while let Some(mut raw) = kcp.output() {
                            // dissect_headers_from_raw(&raw, "send");
                            if CIPHER.encrypt_in_place(&NONCE, b"", &mut raw).is_ok() {
                                icmp_tx.send((peer, raw)).unwrap();
                            } else {
                                error!("error encrypting block");
                                break 'update_loop;
                            }
                        }
                        let peer_closing = peer_closing_cloned.load(Ordering::SeqCst);
                        let local_closing = local_closing_cloned.load(Ordering::SeqCst);
                        if kcp.dead_link() || peer_closing && local_closing && kcp.all_flushed() {
                            break;
                        }
                    }
                    sleep(interval).await;
                }
            }
            .instrument(debug_span!("update_loop")),
        );
        Session {
            conv,
            peer,
            control,
            updater,
            peer_closing,
            local_closing,
        }
    }

    pub async fn incoming() -> Self {
        INCOMING.1.lock().await.recv().await.unwrap()
    }

    pub async fn send(&self, buf: &[u8]) {
        loop {
            {
                let mut kcp = self.control.0.lock();
                if kcp.wait_send() < kcp.config().send_wnd as usize {
                    if buf.is_empty() {
                        self.local_closing.store(true, Ordering::SeqCst);
                    }
                    kcp.send(buf).unwrap();
                    break;
                }
            }
            self.control.1.notified().await;
        }
    }

    pub async fn recv(&self) -> Vec<u8> {
        loop {
            {
                let mut kcp = self.control.0.lock();
                match kcp.recv() {
                    Ok(data) => {
                        if data.is_empty() {
                            self.peer_closing.store(true, Ordering::SeqCst);
                        }
                        return data;
                    }
                    Err(Error::NotAvailable) => {}
                    Err(err) => Err(err).unwrap(),
                }
            }
            self.control.1.notified().await;
        }
    }

    pub async fn close(self) {
        select! {
            _ = sleep(CLOSE_TIMEOUT) => {}
            _ = async {
                self.send(b"").await;
                while !self.peer_closing.load(Ordering::SeqCst) {
                    let _discarded = self.recv().await;
                }
                self.updater.await.unwrap();
            } => {}
        }
    }
}

impl fmt::Display for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.peer, self.conv)
    }
}

async fn recv_loop() {
    loop {
        let (from, mut raw) = crate::icmp::receive_packet().await;
        if CIPHER.decrypt_in_place(&NONCE, b"", &mut raw).is_err() {
            // TODO: mimic normal ping behavior
            continue;
        }
        let conv = crate::kcp::conv_from_raw(&raw);
        let key = &(from, conv);
        let mut control = CONTROLS.get(key).and_then(|weak| weak.upgrade());
        if control.is_none() && crate::kcp::first_push_packet(&raw) {
            let new_session = Session::new(from, conv);
            INCOMING.0.send(new_session).unwrap_or_default();
            control = CONTROLS.get(key).and_then(|weak| weak.upgrade());
        }
        if let Some(control) = control {
            // dissect_headers_from_raw(&raw, "recv");
            let mut kcp = control.0.lock();
            kcp.input(&raw).unwrap();
            control.1.notify_waiters();
        }
    }
}

pub async fn init_recv_loop() {
    task::spawn(recv_loop());
}
