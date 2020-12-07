use crate::config::get_config;
use crate::icmp::Endpoint;

mod protocol;

use chacha20poly1305::aead::{Aead, AeadInPlace, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use crossbeam_channel::{Receiver, Sender};
use dashmap::DashMap;
use lazy_static::lazy_static;
use parking_lot::{Condvar, Mutex, RwLock};
use priority_queue::PriorityQueue;
use protocol::KcpControlBlock;
use std::cmp::Reverse;
use std::hash::{Hash, Hasher};
use std::io::{Error, ErrorKind, Result};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

struct KcpConnectionState {
    control: Mutex<KcpControlBlock>,
    condvar: Condvar,
    endpoint: RwLock<Endpoint>,
}

pub struct KcpConnection {
    state: Arc<KcpConnectionState>,
}

struct KcpSchedulerItem(Arc<KcpConnectionState>);

impl Eq for KcpSchedulerItem {}

impl PartialEq for KcpSchedulerItem {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Hash for KcpSchedulerItem {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.0).hash(state);
    }
}

lazy_static! {
    static ref CONNECTION_STATE: DashMap<(Endpoint, u32), Arc<KcpConnectionState>> = DashMap::new();
    static ref UPDATE_SCHEDULE: Mutex<PriorityQueue<KcpSchedulerItem, Reverse<u32>>> =
        Mutex::new(PriorityQueue::new());
    static ref CIPHER: ChaCha20Poly1305 = ChaCha20Poly1305::new(&get_config().key);
    static ref NONCE: Nonce = Nonce::default();
    static ref INCOMING: (Sender<KcpConnection>, Receiver<KcpConnection>) =
        crossbeam_channel::unbounded();
}

fn schedule_immediate_update(target: Arc<KcpConnectionState>) {
    let mut guard = UPDATE_SCHEDULE.lock();
    guard.push_increase(KcpSchedulerItem(target), Reverse(0));
}

pub fn init_kcp_scheduler() {
    thread::spawn(|| {
        let start = Instant::now();
        loop {
            let now = start.elapsed().as_millis() as u32;
            {
                let mut guard = UPDATE_SCHEDULE.lock();
                while guard
                    .peek()
                    .map(|item| *item.1 >= Reverse(now))
                    .unwrap_or(false)
                {
                    let (KcpSchedulerItem(state), _) = guard.pop().unwrap();
                    let mut kcp = state.control.lock();
                    kcp.update(now);
                    {
                        let endpoint = state.endpoint.read();
                        let next_update = std::cmp::max(kcp.check(now), now + 1);
                        guard.push(KcpSchedulerItem(state.clone()), Reverse(next_update));
                        while let Some(mut packet) = kcp.output() {
                            if CIPHER.encrypt_in_place(&NONCE, b"", &mut packet).is_ok() {
                                crate::icmp::send_packet(*endpoint, packet);
                            } else {
                                log::error!("error encrypting packet");
                            }
                        }
                    }
                    state.condvar.notify_all();
                }
            }
            // This does NOT mean sleeping for 1 ms, since most OSes have very poor sleep accuracy
            thread::sleep(Duration::from_millis(1));
        }
    });
}

impl KcpConnection {
    pub fn incoming() -> Self {
        INCOMING.1.recv().unwrap()
    }

    pub fn connect(endpoint: Endpoint, conv: u32) -> Result<Self> {
        if CONNECTION_STATE.contains_key(&(endpoint, conv)) {
            return Err(Error::from(ErrorKind::AddrInUse));
        }
        let state = Arc::new(KcpConnectionState {
            control: Mutex::new(KcpControlBlock::new(conv)),
            condvar: Condvar::new(),
            endpoint: RwLock::new(endpoint),
        });
        {
            let config = &get_config().kcp;
            let mut kcp = state.control.lock();
            kcp.set_mtu(config.mtu);
            kcp.set_window_size(config.send_window_size, config.recv_window_size);
            kcp.set_nodelay(config.nodelay);
            kcp.set_interval(config.interval);
            kcp.set_fast_resend(config.resend);
            kcp.set_congestion_control(config.congestion_control);
            kcp.set_rto_min(config.rto_min);
        }
        CONNECTION_STATE.insert((endpoint, conv), state.clone());
        Ok(KcpConnection { state })
    }

    pub fn send(&mut self, data: &[u8]) -> Result<usize> {
        let sent;
        {
            let mut kcp = self.state.control.lock();
            let max_send = get_config().kcp.send_window_size as usize * 2;
            while kcp.wait_send() > max_send {
                self.state.condvar.wait(&mut kcp);
            }
            sent = kcp.send(data).map_err(Error::from)?;
        }
        schedule_immediate_update(self.state.clone());
        Ok(sent)
    }

    pub fn recv(&mut self) -> Vec<u8> {
        let mut kcp = self.state.control.lock();
        let mut result = kcp.recv();
        while result.is_err() {
            self.state.condvar.wait(&mut kcp);
            result = kcp.recv();
        }
        result.unwrap()
    }

    pub fn flush(&mut self) {
        let mut kcp = self.state.control.lock();
        while !kcp.all_flushed() {
            self.state.condvar.wait(&mut kcp);
        }
    }
}

impl Drop for KcpConnection {
    fn drop(&mut self) {
        self.flush();
        let conv = self.state.control.lock().conv();
        CONNECTION_STATE.remove(&(*self.state.endpoint.read(), conv));
    }
}

pub fn on_recv_packet(packet: &[u8], from: Endpoint) {
    if let Ok(packet) = CIPHER.decrypt(&NONCE, packet) {
        let conv = KcpControlBlock::conv_from_raw(&packet);
        if !CONNECTION_STATE.contains_key(&(from, conv)) {
            let new_connection = KcpConnection::connect(from, conv).unwrap();
            if let Err(e) = INCOMING.0.send(new_connection) {
                log::error!("error passively creating new KCP connection: {}", e);
            }
        }
        if let Some(state) = CONNECTION_STATE.get(&(from, conv)) {
            {
                let mut kcp = state.control.lock();
                if let Err(e) = kcp.input(&packet) {
                    log::error!("error processing KCP packet: {}", e);
                }
                state.condvar.notify_all();
            }
            schedule_immediate_update(state.clone());
        }
    } else {
        // TODO: Maybe simulate real ping behavior?
    }
}
