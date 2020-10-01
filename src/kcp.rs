use crate::config::get_config;
use crate::icmp::{send_packet, Endpoint};

mod protocol;

use bytes::Bytes;
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
    endpoint: RwLock<Option<Endpoint>>,
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
    static ref CONNECTION_STATE: DashMap<u32, Arc<KcpConnectionState>> = DashMap::new();
    static ref UPDATE_SCHEDULE: Mutex<PriorityQueue<KcpSchedulerItem, Reverse<u32>>> =
        Mutex::new(PriorityQueue::new());
}

fn schedule_immediate_update(target: Arc<KcpConnectionState>) {
    let mut guard = UPDATE_SCHEDULE.lock();
    guard.push_increase(KcpSchedulerItem(target), Reverse(0));
}

pub fn init_kcp_scheduler() {
    thread::spawn(|| {
        let interval = get_config().kcp.scheduler_interval;
        let start = Instant::now();
        loop {
            let now = start.elapsed().as_millis() as u32;
            let start_round = Instant::now();
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
                        if let Some(endpoint) = *endpoint {
                            let next_update = std::cmp::max(kcp.check(now), now + 1);
                            guard.push(KcpSchedulerItem(state.clone()), Reverse(next_update));
                            while let Some(packet) = kcp.output() {
                                send_packet(endpoint, packet);
                            }
                        }
                    }
                    state.condvar.notify_all();
                }
            }
            if start_round.elapsed().as_micros() >= interval as u128 {
                log::warn!("update took a long time: {}us", start_round.elapsed().as_micros());
            }
            thread::sleep(Duration::from_micros(interval as u64));
        }
    });
}

impl KcpConnection {
    pub fn new(conv: u32) -> Result<KcpConnection> {
        if CONNECTION_STATE.contains_key(&conv) {
            return Err(Error::from(ErrorKind::AddrInUse));
        }
        let state = Arc::new(KcpConnectionState {
            control: Mutex::new(KcpControlBlock::new(conv)),
            condvar: Condvar::new(),
            endpoint: RwLock::new(None),
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
        }
        CONNECTION_STATE.insert(conv, state.clone());
        Ok(KcpConnection { state })
    }

    pub fn with_endpoint(conv: u32, endpoint: Endpoint) -> Result<Self> {
        let ret = Self::new(conv)?;
        *ret.state.endpoint.write() = Some(endpoint);
        Ok(ret)
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

    pub fn recv(&mut self) -> Bytes {
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
        while kcp.wait_send() > 0 {
            self.state.condvar.wait(&mut kcp);
        }
    }
}

impl Drop for KcpConnection {
    fn drop(&mut self) {
        self.flush();
        let conv = self.state.control.lock().conv();
        CONNECTION_STATE.remove(&conv);
        *self.state.endpoint.write() = None;
        log::debug!("connection closed");
    }
}

pub fn recv_packet(packet: &[u8], from: Endpoint) {
    let conv = KcpControlBlock::conv_from_raw(packet);
    if let Some(state) = CONNECTION_STATE.get(&conv) {
        {
            let mut kcp = state.control.lock();
            if *state.endpoint.write().get_or_insert(from) == from {
                // Ignore the result for the time being
                if let Err(e) = kcp.input(packet) {
                    log::error!("error processing KCP packet: {}", e);
                }
                state.condvar.notify_all();
            }
        }
        schedule_immediate_update(state.clone());
    }
}