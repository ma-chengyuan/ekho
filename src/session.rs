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

use crate::config::get_config;
use crate::icmp::IcmpEndpoint;

use crate::kcp::ControlBlock;
use chacha20poly1305::aead::{Aead, AeadInPlace, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use dashmap::DashMap;
use lazy_static::lazy_static;
use rustc_hash::FxHasher;
use std::fmt;
use std::hash::BuildHasherDefault;
use tokio::select;
use tokio::sync::mpsc::{
    channel, unbounded_channel, Receiver, Sender, UnboundedReceiver, UnboundedSender,
};
use tokio::sync::Mutex;
use tokio::task;
use tokio::task::JoinHandle;
use tokio::time::{sleep, sleep_until, Duration, Instant};

lazy_static! {
    static ref RAW_TX: DashMap<(IcmpEndpoint, u32), Sender<Vec<u8>>, BuildHasherDefault<FxHasher>> =
        Default::default();
    static ref CIPHER: ChaCha20Poly1305 = ChaCha20Poly1305::new(&get_config().key);
    static ref NONCE: Nonce = Nonce::default();
    static ref INCOMING: (UnboundedSender<Session>, Mutex<UnboundedReceiver<Session>>) = {
        let (tx, rx) = unbounded_channel();
        (tx, Mutex::new(rx))
    };
}

const RAW_CHANNEL_SIZE: usize = 1024;
const CLOSE_TIMEOUT: Duration = Duration::from_secs(60);

/// A session, built on top of KCP
pub struct Session {
    updater: JoinHandle<()>,
    // Expose sender and receiver, so they may be used separately
    pub sender: Sender<Vec<u8>>,
    pub receiver: Receiver<Vec<u8>>,
    conv: u32,
    peer: IcmpEndpoint,
}

impl Session {
    /// Creates a new session given a peer endpoint and a conv.
    pub fn new(peer: IcmpEndpoint, conv: u32) -> Self {
        assert!(!RAW_TX.contains_key(&(peer, conv)));
        // The naming here is very nasty!
        let (sender, mut send_rx) = channel::<Vec<u8>>(1);
        let (recv_tx, receiver) = channel(1);
        let (raw_tx, mut raw_rx) = channel(RAW_CHANNEL_SIZE);
        RAW_TX.insert((peer, conv), raw_tx);
        let updater = task::spawn(async move {
            let start = Instant::now();
            let mut next_update = start;
            let mut kcp = ControlBlock::new(conv, get_config().kcp.clone());
            let send_wnd = get_config().kcp.send_wnd as usize;
            let icmp_tx = crate::icmp::clone_sender().await;
            let mut local_closing = false;
            let mut peer_closing = false;
            'u: while !(kcp.dead_link() || local_closing && peer_closing && kcp.all_flushed()) {
                select! {
                    _ = sleep_until(next_update) => { /* time for a regular update */ }
                    // Interrupted by datagrams sent bu the upper level
                    res = send_rx.recv(), if kcp.wait_send() < send_wnd => {
                        match res {
                            None => break,
                            Some(data) => {
                                local_closing |= data.is_empty();
                                kcp.send(&data).unwrap()
                            }
                        }
                    }
                    // Interrupted by raw packets received from the lower ICMP level
                    res = raw_rx.recv() => {
                        match res {
                            None => break,
                            Some(raw) => { kcp.input(&raw).unwrap(); }
                        }
                    }
                }
                let current = start.elapsed().as_millis() as u32;
                kcp.update(current);
                next_update = start + Duration::from_millis(kcp.check(current) as u64);
                while let Some(mut raw) = kcp.output() {
                    if CIPHER.encrypt_in_place(&NONCE, b"", &mut raw).is_ok() {
                        // ICMP receiver (CHANNEL.1 in crate::icmp) never closes, so unwrapping is
                        // safe here.
                        icmp_tx.send((peer, raw)).unwrap();
                    } else {
                        tracing::error!("error encrypting block");
                        break 'u;
                    }
                }
                while let Ok(data) = kcp.recv() {
                    peer_closing |= data.is_empty();
                    // Break immediately regardless of unsent segments because the peer intends
                    // to close the session
                    if recv_tx.send(data).await.is_err() {
                        break 'u;
                    }
                }
            }
        });
        Session {
            sender,
            receiver,
            conv,
            peer,
            updater,
        }
    }

    pub async fn incoming() -> Self {
        INCOMING.1.lock().await.recv().await.unwrap()
    }

    pub async fn close(&mut self) {
        self.sender.send(Vec::new()).await.unwrap_or_default();
        select! {
            _ = sleep(CLOSE_TIMEOUT) => {}
            // If we take the initiative, then here we wait for an empty segment from the peer
            // If we are passive, then closing should already contain values
            _ = &mut self.updater => tracing::info!("{} ended normally", self)
        }
    }
}

impl fmt::Display for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.peer, self.conv)
    }
}

pub async fn on_recv_packet(from: IcmpEndpoint, raw: &[u8]) {
    if let Ok(raw) = CIPHER.decrypt(&NONCE, raw) {
        let conv = crate::kcp::conv_from_raw(&raw);
        let key = &(from, conv);
        if !RAW_TX.contains_key(key) && crate::kcp::first_push_packet(&raw) {
            // The receiver of INCOMING obviously never closes, so unwrapping is safe here
            INCOMING
                .0
                .send(Session::new(from, conv))
                .unwrap_or_default();
        }
        if let Some(raw_tx) = RAW_TX.get(key) {
            if let Err(_err) = raw_tx.blocking_send(raw) {
                tracing::error!(
                    "error feeding raw packets to {}:{}@{}",
                    from.ip,
                    from.id,
                    conv
                );
            }
        }
    }
}