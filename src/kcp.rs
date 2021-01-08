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
#![allow(dead_code)]

//! The KCP protocol (pure algorithmic implementation).
//!
//! This is adapted from the original C implementation, but slightly oxidized and optimized for
//! large send / receive windows. Optimizations currently include using B Tree as the data structure
//! behind receive buffers (as opposed to a naive linked list in original implementation) and using
//! the BBR congestion control algorithm instead of the naive loss-based congestion control.
//!
//! This is 100% compatible with other KCP implementations.

use bytes::{Buf, BufMut};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use rand::{thread_rng, Rng};
use serde::Deserialize;
use std::cmp::{max, min, Ordering};
use std::collections::{BTreeMap, VecDeque};
use std::convert::TryInto;
use thiserror::Error;

/// KCP error type.
#[derive(Debug, Error)]
pub enum Error {
    #[error("packet to be sent too large to be fragmented")]
    OversizePacket,
    #[error("invalid KCP packet")]
    IncompletePacket,
    #[error("invalid KCP command: {0}")]
    InvalidCommand(u8),
    #[error("empty queue (try again later)")]
    NotAvailable,
    #[error("wrong conv. (expected {expected}, found {found})")]
    WrongConv { expected: u32, found: u32 },
}

pub type Result<T> = std::result::Result<T, Error>;

/// The overhead imposed by KCP per packet (aka. packet header length).
const OVERHEAD: u32 = 24;
/// The upper bound for fragmentation of a long payload.
const MAX_FRAGMENTS: u16 = 128;

/// Gain cycles (x4) used in ProbeBW state of the BBR control algorithm.
const BBR_GAIN_CYCLE: [usize; 8] = [5, 3, 4, 4, 4, 4, 4, 4];
/// KCP BDP gain denominator
const BDP_GAIN_DEN: usize = 1024;

#[derive(Clone, Copy, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
enum Command {
    Push = 81,
    Ack = 82,
    AskWnd = 83,
    TellWnd = 84,
}

// Dummy impl. Actually useless
impl Default for Command {
    fn default() -> Self {
        Command::Ack
    }
}

/// KCP configuration.
///
/// All time-related items are in milliseconds.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub mtu: u32,
    pub rto_default: u32,
    pub rto_min: u32,
    pub rto_max: u32,
    /// Initial & minimal probe timeout
    pub probe_min: u32,
    /// Maximum probe timeout
    pub probe_max: u32,
    pub send_wnd: u16,
    pub recv_wnd: u16,
    pub interval: u32,
    /// After failure of this many retranmission attempts, the link will be considered to be dead.
    pub dead_link_thres: u32,
    /// In nodelay mode, rto_min = 0 and rto does not exponentially grow.
    pub nodelay: bool,
    /// In stream mode, multiple datagrams may be merged into one segment to reduce overhead.
    pub stream: bool,
    /// If non-zero, then a segment after this many skip-acks will be retransmitted immediately.
    pub fast_rexmit_thres: u32,
    /// Cap the maximum # of fast retransmission attempts.
    pub fast_rexmit_limit: u32,
    pub bbr: bool,
    /// Window length (unit: ms) for RTprop (Round-trip propagation time) filters in BBR.
    pub rt_prop_wnd: u32,
    /// Window length (unit: RTT) for BtlBW (Bottleneck bandwidth) filters in BBR.
    pub btl_bw_wnd: u32,
    /// Time for one ProbeRTT phase.
    pub probe_rtt_time: u32,
}

/// Gives a decent default configuration suitable for most use cases
impl Default for Config {
    fn default() -> Self {
        Config {
            mtu: 1400,
            rto_default: 200,
            rto_min: 100,
            rto_max: 60000,
            probe_min: 7000,
            probe_max: 120000,
            send_wnd: 1024,
            recv_wnd: 1024,
            interval: 10,
            dead_link_thres: 20,
            nodelay: false,
            stream: false,
            fast_rexmit_thres: 0,
            fast_rexmit_limit: 5,
            bbr: false,
            rt_prop_wnd: 10000,
            btl_bw_wnd: 10,
            probe_rtt_time: 200,
        }
    }
}

#[derive(Default)]
#[rustfmt::skip]
struct Segment {
    // Header layout
    #[doc = "Conversation ID."]     conv: u32,  #[doc = "KCP command."]         cmd: Command,
    #[doc = "Fragmentation."]       frg: u8,    #[doc = "Remote window size."]  wnd: u16,
    #[doc = "Timestamp when sent."] ts: u32,    #[doc = "Sequence number."]     sn: u32,
    #[doc = "UNA when sent."]       una: u32,
    ts_rexmit: u32,
    rto: u32,
    /// Number of times the packet is skip-ACKed.
    skip_acks: u32,
    /// Number of transmission attempts.
    xmits: u32,
    payload: Vec<u8>,
    /// Delivered bytes when sent.
    delivered: usize,
    /// Time of receiving the last ACK packet when the packet is sent.
    ts_last_ack: u32,
    /// When this packet is sent, is the traffic limited by bandwidth or app?
    app_limited: bool,
}

/// KCP control block with BBR congestion control.
///
/// This control block is **NOT** safe for concurrent access -- to do so please wrap it in a Mutex.
pub struct ControlBlock {
    /// Conversation ID.
    conv: u32,
    /// KCP Config (should be immutable)
    config: Config,
    dead_link: bool,
    /// Oldest Unacknowledged Packet in the send window.
    send_una: u32,
    /// Sequence number of the next packet to be sent.
    send_nxt: u32,
    /// Sequence number of the next packet to be put in the receive queue.
    recv_nxt: u32,
    /// Variance of RTT.
    rtt_var: u32,
    /// Smooth RTT estimation.
    srtt: u32,
    /// Base retransmission timeout.
    rto: u32,
    /// Remote window size (packet).
    rmt_wnd: u16,
    /// Current timestamp (ms).
    current: u32,
    /// Whether the control block is updated at least once.
    updated: bool,
    /// Timestamp for next flush.
    ts_flush: u32,
    /// Timestamp for next probe.
    ts_probe: u32,
    /// Whether we should ask the other side to tell us its window size.
    probe_ask: bool,
    /// Whether we should tell the other side our window size.
    probe_tell: bool,
    /// Probing timeout.
    probe_timeout: u32,
    /// Send queue, which stores packets that are enqueued but not in the send window.
    send_queue: VecDeque<Segment>,
    /// Receive queue, which stores packets that are received but not consumed by the application.
    recv_queue: VecDeque<Segment>,
    /// Send buffer, which stores packets sent but not yet acknowledged.
    send_buf: VecDeque<Segment>,
    /// Receive buffer, which stores packets that arrive but cannot be used because a preceding
    /// packet hasn't arrived yet.
    recv_buf: BTreeMap<u32, Segment>,
    /// ACKs to be sent in the next flush.
    ack_pending: Vec<(/* sn */ u32, /* ts */ u32)>,
    /// Output queue, the outer application should actively poll from this queue.
    output: VecDeque<Vec<u8>>,
    /// Buffer used to merge small packets into a batch (thus making better use of bandwidth).
    buffer: Vec<u8>,

    /// Controls how aggressively BBR controls the send window
    bdp_gain: usize,
    /// Time of receiving the last ACK packet.
    ts_last_ack: u32,
    /// Bytes confirmed to have been delivered.
    delivered: usize,
    /// Bytes currently inflight.
    inflight: usize,
    /// Monotonic queue for Round trip propagation time.
    rt_prop_queue: VecDeque<(u32, u32)>,
    /// Monotonic queue for Bottleneck Bandwidth.
    btl_bw_queue: VecDeque<(u32, usize)>,
    /// Whether the next BBR update should clear expired RTprop analysis.
    rt_prop_expired: bool,
    /// Current BBR state.
    bbr_state: BBRState,
    /// See the original BBR paper for more info.
    app_limited_until: usize,
}

/// States for the BBR congestion control algorithm.
///
/// Adapted from the appendix section of the original BBR paper.
#[derive(Debug)]
enum BBRState {
    /// Startup phase, in which BBR quickly discovers the bottleneck bandwidth.
    Startup,
    /// Drain phase used to drain the pipe over-filled by the previous start up phase.
    Drain,
    /// The main phase of BBR, in which BBR cycles through different gains in an attempt to probe
    /// the bottleneck bandwidth.
    ProbeBW(/* since */ u32, /* phase */ usize),
    /// In this phase, BBR drastically reduces the congestion window to accurately probe RT prop.
    ProbeRTT(/* since */ u32, /* phase */ usize),
}

impl ControlBlock {
    /// Creates a new KCP control block with the given conversation ID and default parameters.
    pub fn new(conv: u32, config: Config) -> ControlBlock {
        ControlBlock {
            conv,
            dead_link: false,
            send_una: 0,
            send_nxt: 0,
            recv_nxt: 0,
            rto: config.rto_default,
            rtt_var: 0,
            srtt: 0,
            rmt_wnd: config.recv_wnd,
            current: 0,
            ts_flush: config.interval,
            ts_probe: 0,
            probe_ask: false,
            probe_tell: false,
            probe_timeout: 0,
            updated: false,
            send_queue: Default::default(),
            recv_queue: Default::default(),
            send_buf: Default::default(),
            recv_buf: Default::default(),
            ack_pending: Default::default(),
            output: Default::default(),
            buffer: Vec::with_capacity(config.mtu as usize),

            bdp_gain: 1024,
            delivered: 0,
            ts_last_ack: 0,
            inflight: 0,
            rt_prop_queue: Default::default(),
            btl_bw_queue: Default::default(),
            rt_prop_expired: false,
            bbr_state: BBRState::Startup,
            app_limited_until: 0,

            config,
        }
    }

    /// Peeks the size of the next packet.
    ///
    /// Returns error if there is currently no packets in the receive buffer.
    pub fn peek_size(&self) -> Result<usize> {
        let seg = self.recv_queue.front().ok_or(Error::NotAvailable)?;
        if seg.frg == 0 {
            return Ok(seg.payload.len());
        }
        if self.recv_queue.len() < (seg.frg + 1) as usize {
            return Err(Error::NotAvailable);
        }
        let mut len = 0;
        for seg in &self.recv_queue {
            len += seg.payload.len();
            if seg.frg == 0 {
                break;
            }
        }
        Ok(len)
    }

    /// Receives a packet of data using this KCP control block.
    ///
    /// **Note**: if [stream mode](#structfield.stream) is off (by default), then one receive
    /// corresponds to one [send](#method.send) on the other side. Otherwise, this correlation
    /// may not hold as in stream mode KCP will try to merge payloads to reduce overheads.
    pub fn recv(&mut self) -> Result<Vec<u8>> {
        let size = self.peek_size()?;
        let mut ret = Vec::with_capacity(size);
        while !self.recv_queue.is_empty() {
            let mut seg = self.recv_queue.pop_front().unwrap();
            ret.append(&mut seg.payload);
            if seg.frg == 0 {
                break;
            }
        }
        assert_eq!(size, ret.len());
        Ok(ret)
    }

    /// Sends some data using this KCP control block.
    ///
    /// **Note**: if [stream mode](#structfield.stream) is off (by default), then one send
    /// corresponds to one [receive](#method.recv) on the other side. Otherwise, this correlation
    /// may not hold as in stream mode KCP will try to merge payloads to reduce overheads.
    ///
    /// **Note**: After calling this do remember to call [check](#method.check), as
    /// an input packet may invalidate previous time estimations of the next update.
    pub fn send(&mut self, mut buf: &[u8]) -> Result<()> {
        let mss = (self.config.mtu - OVERHEAD) as usize;
        if self.config.stream {
            if let Some(old) = self.send_queue.back_mut() {
                if old.payload.len() < mss {
                    let cap = mss - old.payload.len();
                    let extend = min(cap, buf.len());
                    let (front, back) = buf.split_at(extend);
                    old.payload.extend_from_slice(front);
                    old.frg = 0;
                    buf = back;
                }
                if buf.is_empty() {
                    return Ok(());
                }
            }
        }
        let count = if buf.len() <= mss {
            1 // Since integer division may be expensive, explicitly give this branch to accelerate
        } else {
            (buf.len() + mss - 1) / mss
        };
        if count > MAX_FRAGMENTS as usize {
            return Err(Error::OversizePacket);
        }
        assert!(count > 0);
        for i in 0..count {
            let size = min(mss, buf.len());
            let (front, back) = buf.split_at(size);
            self.send_queue.push_back(Segment {
                frg: if self.config.stream {
                    0
                } else {
                    (count - i - 1) as u8
                },
                payload: front.into(),
                ..Default::default()
            });
            buf = back;
        }
        Ok(())
    }

    /// Updates the RTT filter and recalculates RTO according to RFC 6298.
    fn update_rtt_filters(&mut self, rtt: u32) {
        if self.srtt == 0 {
            self.srtt = rtt;
            self.rtt_var = rtt / 2;
        } else {
            let delta = (rtt as i32 - self.srtt as i32).abs() as u32;
            self.rtt_var = (3 * self.rtt_var + delta) / 4;
            self.srtt = max(1, (7 * self.srtt + rtt) / 8);
        }
        let rto = self.srtt + max(self.config.interval, 4 * self.rtt_var);
        self.rto = max(self.config.rto_min, min(rto, self.config.rto_max));
    }

    /// Recalculates UNA based on the current [send buffer](#structfield.send_buf).
    fn update_una(&mut self) {
        self.send_una = self.send_buf.front().map_or(self.send_nxt, |seg| seg.sn);
    }

    /// Updates BBR filters and relevant fields when a packet is acknowledged, roughly equivalent to
    /// the `onAck` function in the BBR paper.
    fn update_bbr_on_ack(&mut self, seg: &Segment) {
        self.delivered += seg.payload.len() + OVERHEAD as usize;
        self.ts_last_ack = self.current;
        self.inflight = self
            .inflight
            .saturating_sub(seg.payload.len() + OVERHEAD as usize);
        self.app_limited_until = self
            .app_limited_until
            .saturating_sub(seg.payload.len() + OVERHEAD as usize);
        // xmits == 1 is necessary. If a packet is transmitted multiple times, and we receive an
        // UNA packet prior to the ACK packet, there is no way we can possibly know which
        // (re)transmission it was that reached the other side.
        if self.current >= seg.ts && seg.xmits == 1 {
            let rtt = max(self.current - seg.ts, 1);
            self.update_rtt_filters(rtt);
            while self
                .rt_prop_queue
                .back()
                .map(|p| p.1 >= rtt)
                .unwrap_or(false)
            {
                self.rt_prop_queue.pop_back().unwrap();
            }
            self.rt_prop_queue.push_back((self.current, rtt));
            if self.rt_prop_expired {
                while self
                    .rt_prop_queue
                    .front()
                    .map(|p| p.0 + self.config.rt_prop_wnd <= self.current)
                    .unwrap_or(false)
                {
                    self.rt_prop_queue.pop_front().unwrap();
                }
                self.rt_prop_expired = false;
            }

            let btl_bw = (self.delivered - seg.delivered)
                / max(self.ts_last_ack - seg.ts_last_ack, 1) as usize;
            if !seg.app_limited || btl_bw > self.btl_bw_queue.front().map(|p| p.1).unwrap_or(0) {
                while self
                    .btl_bw_queue
                    .front()
                    .map(|p| p.0 + self.config.btl_bw_wnd * self.srtt <= self.current)
                    .unwrap_or(false)
                {
                    self.btl_bw_queue.pop_front().unwrap();
                }
                while self
                    .btl_bw_queue
                    .back()
                    .map(|p| p.1 <= btl_bw)
                    .unwrap_or(false)
                {
                    self.btl_bw_queue.pop_back().unwrap();
                }
                self.btl_bw_queue.push_back((self.current, btl_bw));
            }
        }
    }

    /// Updates the BBR state machine.
    fn update_bbr_state(&mut self) {
        if self.rt_prop_queue.is_empty() || self.srtt == 0 {
            self.bbr_state = BBRState::Startup;
            return;
        }
        if let BBRState::Startup = self.bbr_state {
            if !self.btl_bw_queue.is_empty()
                && self.btl_bw_queue.front().unwrap().0 + 3 * self.srtt <= self.current
            {
                // Bottle neck bandwidth has not been updated in 3 RTTs, indicating that the pipe
                // is filled and we have probe the bandwidth, enter drain
                self.bbr_state = BBRState::Drain;
            }
        } else if let BBRState::Drain = self.bbr_state {
            if self.inflight <= self.bdp() {
                let phase: usize = thread_rng().gen_range(0, 7);
                self.bbr_state =
                    BBRState::ProbeBW(self.current, if phase >= 1 { phase + 1 } else { phase });
            }
        } else if let BBRState::ProbeBW(since, phase) = self.bbr_state {
            let last_rt_prop_update = self.rt_prop_queue.front().unwrap().0;
            if last_rt_prop_update + self.config.rt_prop_wnd <= self.current
                && !self.rt_prop_expired
            {
                self.bbr_state = BBRState::ProbeRTT(self.current, phase);
                self.rt_prop_expired = true;
            } else if since + self.srtt <= self.current {
                // Each gain cycle phase lasts for one RTT
                self.bbr_state =
                    BBRState::ProbeBW(self.current, (phase + 1) % BBR_GAIN_CYCLE.len());
            }
        } else if let BBRState::ProbeRTT(since, phase) = self.bbr_state {
            if since + self.config.probe_rtt_time <= self.current {
                self.bbr_state = BBRState::ProbeBW(self.current, phase);
            }
        }
    }

    /// Removes the packet from the [send buffer](#structfield.send_buf) whose sequence number is `sn`
    /// marks it as acknowledged.
    fn ack_packet_with_sn(&mut self, sn: u32) {
        if sn < self.send_una || sn >= self.send_nxt {
            return;
        }
        for i in 0..self.send_buf.len() {
            match sn.cmp(&self.send_buf[i].sn) {
                Ordering::Less => break,
                Ordering::Greater => continue,
                Ordering::Equal => {
                    let seg = self.send_buf.remove(i).unwrap();
                    self.update_bbr_on_ack(&seg);
                    break;
                }
            }
        }
    }

    /// Removes packets from the [send buffer](#structfield.send_buf) whose sequence number is less
    /// than `una` and marks them as acknowledged.
    fn ack_packets_before_una(&mut self, una: u32) {
        while !self.send_buf.is_empty() && self.send_buf[0].sn < una {
            let seg = self.send_buf.pop_front().unwrap();
            self.update_bbr_on_ack(&seg);
        }
    }

    /// Increases the skip-ACK count of packets with sequence number less than `sn` (useful in KCP
    /// fast retransmission).
    fn increase_skip_acks(&mut self, sn: u32, _ts: u32) {
        if self.send_una <= sn && sn < self.send_nxt {
            // seg.sn increasing
            for seg in self.send_buf.iter_mut() {
                if seg.sn < sn {
                    seg.skip_acks += 1;
                } else {
                    break;
                }
            }
        }
    }

    /// Pushes a segment onto the [receive buffer](#structfield.recv_buf), and if possible, moves
    /// segments from the receiver buffer to the [receive queue](#structfield.recv_queue).
    fn push_segment(&mut self, seg: Segment) {
        self.recv_buf.entry(seg.sn).or_insert(seg);
        // Move packets from the buffer to the receive queue if possible
        while !self.recv_buf.is_empty()
            && self.recv_buf.iter().next().unwrap().1.sn == self.recv_nxt
            && self.recv_queue.len() < self.config.recv_wnd as usize
        {
            self.recv_queue
                .push_back(self.recv_buf.remove(&self.recv_nxt).unwrap());
            self.recv_nxt += 1;
        }
    }

    /// Feeds a raw packet from the underlying protocol stack into the control block.
    ///
    /// Returns the total number of bytes that is actually considered valid by KCP.
    ///
    /// **Note**: After calling this do remember to call [check](#method.check), as
    /// an input packet may invalidate previous time estimations of the next update.
    pub fn input(&mut self, mut data: &[u8]) -> Result<usize> {
        let prev_len = data.len();
        let mut has_ack = false;
        let mut sn_max_ack = 0;
        let mut ts_max_ack = 0;

        if data.len() < OVERHEAD as usize {
            return Err(Error::IncompletePacket);
        }

        loop {
            if data.len() < OVERHEAD as usize {
                break;
            }
            let (mut header, body) = data.split_at(OVERHEAD as usize);
            // Read header
            let conv = header.get_u32_le();
            if conv != self.conv {
                return Err(Error::WrongConv {
                    expected: self.conv,
                    found: conv,
                });
            }
            let cmd = header.get_u8();
            let frg = header.get_u8();
            let wnd = header.get_u16_le();
            let ts = header.get_u32_le();
            let sn = header.get_u32_le();
            let una = header.get_u32_le();
            let len = header.get_u32_le() as usize;
            data = body;
            if data.len() < len {
                return Err(Error::IncompletePacket);
            }
            let cmd = Command::try_from_primitive(cmd).map_err(|_| Error::InvalidCommand(cmd))?;
            self.rmt_wnd = wnd;
            self.ack_packets_before_una(una);
            self.update_una();
            match cmd {
                Command::Ack => {
                    self.ack_packet_with_sn(sn);
                    self.update_una();
                    if !has_ack || sn > sn_max_ack {
                        has_ack = true;
                        sn_max_ack = sn;
                        ts_max_ack = ts;
                    }
                }
                Command::Push => {
                    if sn < self.recv_nxt + self.config.recv_wnd as u32 {
                        self.ack_pending.push((sn, ts));
                        if sn >= self.recv_nxt {
                            self.push_segment(Segment {
                                sn,
                                frg,
                                payload: data[..len].into(),
                                ..Default::default()
                            });
                        }
                    }
                }
                Command::AskWnd => self.probe_tell = true,
                Command::TellWnd => {}
            }
            data = &data[len..];
        }
        if has_ack && self.config.fast_rexmit_thres > 0 {
            // OPTIMIZE: if we have a large receive window and a large flow of traffic, the
            //  increase_skip_acks operation here may become computationally demanding, because
            //  it has a worst-case linear time complexity. It is perhaps better to limit the
            //  frequency to call it, perhaps every self.interval or so. This would of course
            //  undermine its purpose of fast-retransmission, but would reduce CPU usage. Another
            //  solution is to maintain send_buf with a modified BST to ensure log complexity of
            //  increase_skip_acks operation, but the effect may be canceled out by the constant
            //  factor.
            self.increase_skip_acks(sn_max_ack, ts_max_ack);
        }
        self.update_bbr_state();
        Ok(prev_len - data.len())
    }

    /// Polls an output packet that can be directly sent with the underlying protocol stack.
    ///
    /// Packet size is guaranteed to be at most the configured MTU.
    pub fn output(&mut self) -> Option<Vec<u8>> {
        self.output.pop_front()
    }

    /// Updates the probing state, recalculating the probing timeout if necessary.
    fn update_probe(&mut self) {
        if self.rmt_wnd == 0 {
            if self.probe_timeout == 0 {
                // If we are not probing, start probing window size
                self.probe_timeout = self.config.probe_min;
                self.ts_probe = self.current + self.probe_timeout;
            } else if self.current >= self.ts_probe {
                // Increase probe timeout by 1.5x until we know the window size
                self.probe_timeout = max(self.probe_timeout, self.config.probe_min);
                self.probe_timeout += self.probe_timeout / 2;
                self.probe_timeout = min(self.probe_timeout, self.config.probe_max);
                self.ts_probe = self.current + self.probe_timeout;
                self.probe_ask = true;
            }
        } else {
            self.probe_timeout = 0;
            self.ts_probe = 0;
        }
    }

    fn flush_segment(&mut self) {}

    /// Flushes packets from the [send queue](#structfield.send_queue) to the
    /// [send buffer](#structfield.send_buf), and (re)transmits the packets in the send buffer
    /// if necessary.
    fn flush(&mut self) {
        if !self.updated {
            return;
        }

        let wnd = self
            .config
            .recv_wnd
            .saturating_sub(self.recv_queue.len() as u16);
        let mut seg = Segment {
            conv: self.conv,
            cmd: Command::Ack,
            una: self.recv_nxt,
            wnd,
            ..Default::default()
        };

        let mut old_ack_list = Vec::new();
        std::mem::swap(&mut self.ack_pending, &mut old_ack_list);
        for (sn, ts) in old_ack_list {
            seg.sn = sn;
            seg.ts = ts;
            flush_segment(&mut self.buffer, &mut self.output, self.config.mtu, &seg);
        }
        seg.sn = 0;
        seg.ts = 0;

        self.update_probe();

        if self.probe_ask {
            seg.cmd = Command::AskWnd;
            flush_segment(&mut self.buffer, &mut self.output, self.config.mtu, &seg);
            self.probe_ask = false;
        }
        if self.probe_tell {
            seg.cmd = Command::TellWnd;
            flush_segment(&mut self.buffer, &mut self.output, self.config.mtu, &seg);
            self.probe_tell = false;
        }

        self.update_bbr_state();
        // Because we are not really pacing the packets, the sending logic is different from what
        // is stated in the original BBR paper. The original BBR uses two parameters: cwnd_gain
        // and pacing_gain. However, the effects of the two parameters are hard to distinguish when
        // packets are flushed. Thus, it may be better to merge the two parameters into one here.
        let limit = if self.config.bbr {
            let limit = match self.bbr_state {
                BBRState::Startup => self.bdp() * 2955 / 1024, /* 2 / ln2 */
                // ln2 / 2 is the value of pacing_gain. Given the current state machine logic in
                // update_bbr_state, this value stops KCP from sending anything.
                BBRState::Drain => self.bdp() * 355 / 1024, /* ln2 / 2 */
                BBRState::ProbeBW(_, phase) => self.bdp() * BBR_GAIN_CYCLE[phase] / 4,
                BBRState::ProbeRTT(_, _) => self.bdp() / 2,
            };
            // Empirical tests have found the current limit to be a bit conservative. One solution
            // might be to multiply the current limit with a small, configurable gain.
            limit * self.bdp_gain / BDP_GAIN_DEN
        } else {
            usize::max_value()
        };

        // Move segments from the send queue to the send buffer
        let cwnd = min(self.config.send_wnd, self.rmt_wnd);
        while self.send_nxt < self.send_una + cwnd as u32
            && !self.send_queue.is_empty()
            && self.inflight <= limit
        {
            let mut seg = self.send_queue.pop_front().unwrap();
            seg.conv = self.conv;
            seg.cmd = Command::Push;
            seg.sn = self.send_nxt;
            self.send_nxt += 1;
            seg.app_limited = self.app_limited_until > 0;
            self.inflight += seg.payload.len() + OVERHEAD as usize;
            self.send_buf.push_back(seg);
            if self.inflight <= limit && self.send_queue.is_empty() {
                self.app_limited_until = self.inflight;
            }
        }

        let rto_min = if self.config.nodelay {
            0
        } else {
            self.config.rto_min
        };

        // (Re)transmit segments in the send buffer
        for i in 0..self.send_buf.len() {
            let seg = &mut self.send_buf[i];
            let mut xmit = false;
            if seg.xmits == 0 {
                xmit = true;
                seg.rto = self.rto;
                seg.ts_rexmit = self.current + seg.rto + rto_min;
            } else if self.current >= seg.ts_rexmit {
                // Regular retransmission
                xmit = true;
                seg.rto = if self.config.nodelay {
                    max(seg.rto, self.rto)
                } else {
                    // Increase RTO by 1.5x, better than 2x in TCP
                    seg.rto + seg.rto / 2
                };
                seg.ts_rexmit = self.current + seg.rto;
            } else if self.config.fast_rexmit_thres != 0
                && seg.skip_acks >= self.config.fast_rexmit_thres
                && (seg.xmits <= self.config.fast_rexmit_limit
                    || self.config.fast_rexmit_limit == 0)
            {
                // Fast retransmission
                xmit = true;
                seg.skip_acks = 0;
                seg.ts_rexmit = self.current + seg.rto;
            }

            if xmit {
                seg.xmits += 1;
                seg.ts = self.current;
                seg.wnd = wnd;
                seg.una = self.recv_nxt;

                seg.delivered = self.delivered;
                seg.ts_last_ack = self.ts_last_ack;
                flush_segment(&mut self.buffer, &mut self.output, self.config.mtu, &seg);
                self.dead_link |= seg.xmits >= self.config.dead_link_thres;
            }
        }

        if !self.buffer.is_empty() {
            let mut new_buf = Vec::with_capacity(self.config.mtu as usize);
            std::mem::swap(&mut self.buffer, &mut new_buf);
            self.output.push_back(new_buf);
        }

        fn flush_segment(
            buf: &mut Vec<u8>,
            output: &mut VecDeque<Vec<u8>>,
            mtu: u32,
            seg: &Segment,
        ) {
            if buf.len() + seg.payload.len() + OVERHEAD as usize > mtu as usize {
                let mut new_buf = Vec::with_capacity(mtu as usize);
                std::mem::swap(buf, &mut new_buf);
                output.push_back(new_buf);
            }
            buf.put_u32_le(seg.conv);
            buf.put_u8(seg.cmd.into());
            buf.put_u8(seg.frg);
            buf.put_u16_le(seg.wnd);
            buf.put_u32_le(seg.ts);
            buf.put_u32_le(seg.sn);
            buf.put_u32_le(seg.una);
            buf.put_u32_le(seg.payload.len() as u32);
            buf.extend_from_slice(&seg.payload);
        }
    }

    /// Sets the internal time to `current` and then updates the whole control block.
    pub fn update(&mut self, current: u32) {
        self.current = current;
        if !self.updated {
            self.updated = true;
            self.ts_flush = current;
        }
        if self.ts_flush <= current {
            self.ts_flush += self.config.interval;
            if self.current >= self.ts_flush {
                self.ts_flush = self.current + self.config.interval;
            }
            self.flush();
        }
    }

    /// Checks the next time you should call [update](#method.update) assuming current time is
    /// `current`.
    pub fn check(&self, current: u32) -> u32 {
        if !self.updated {
            return current;
        }
        if self.ts_flush <= current {
            return current;
        }
        let mut next_update = min(current + self.config.interval, self.ts_flush);
        for seg in &self.send_buf {
            if seg.ts_rexmit <= current {
                return current;
            }
            next_update = min(next_update, seg.ts_rexmit);
        }
        next_update
    }

    /// Gets the number of packets wait to be sent. This includes both unsent packets and packets
    /// that have been sent but not acknowledged by the other side.
    pub fn wait_send(&self) -> usize {
        self.send_buf.len() + self.send_queue.len()
    }

    /// Checks if everything is flushed, including unsent data packets and ACK packets.
    ///
    /// You may want to call this when you are about to drop this control block, to check if KCP has
    /// finished everything up.
    pub fn all_flushed(&self) -> bool {
        self.send_buf.is_empty() && self.send_queue.is_empty() && self.ack_pending.is_empty()
    }

    /// Returns the Bandwidth-Delay Product.
    ///
    /// For detailed explanation of BDP please refer to Google's BBR paper.
    pub fn bdp(&self) -> usize {
        if self.rt_prop_queue.is_empty() || self.btl_bw_queue.is_empty() {
            self.config.mtu as usize
        } else {
            self.rt_prop_queue.front().unwrap().1 as usize * self.btl_bw_queue.front().unwrap().1
        }
    }

    pub fn dead_link(&self) -> bool {
        self.dead_link
    }

    pub fn conv(&self) -> u32 {
        self.conv
    }
}

/// Gets the conversation id from a raw buffer.
///
/// Panics if `buf` has a length less than 4.
pub fn conv_from_raw(buf: &[u8]) -> u32 {
    u32::from_le_bytes(buf[..4].try_into().unwrap())
}

/// Check if the given raw buffer `buf` contains the first PUSH packet, which marks the start
/// of a new connection.
pub fn first_push_packet(mut buf: &[u8]) -> bool {
    while buf.len() >= OVERHEAD as usize {
        let _conv = buf.get_u32_le();
        let cmd = buf.get_u8();
        let _frg = buf.get_u8();
        let _wnd = buf.get_u16_le();
        let _ts = buf.get_u32_le();
        let sn = buf.get_u32_le();
        let _una = buf.get_u32_le();
        let len = buf.get_u32_le() as usize;
        if cmd == Command::Push as u8 {
            return sn == 0;
        }
        buf = &buf[len..];
    }
    true
}

/// Print the headers of the packets in the given raw buffer `buf` using `log::debug!(...)`
pub fn dissect_headers_from_raw(mut buf: &[u8]) {
    while buf.len() >= OVERHEAD as usize {
        let _conv = buf.get_u32_le();
        let cmd = buf.get_u8();
        let frg = buf.get_u8();
        let wnd = buf.get_u16_le();
        let ts = buf.get_u32_le();
        let sn = buf.get_u32_le();
        let una = buf.get_u32_le();
        let len = buf.get_u32_le() as usize;
        #[rustfmt::skip]
        tracing::debug!(
            "{:?}\tfrg\t{}\twnd\t{}\tts\t{}\tsn\t{}\tuna\t{}\tlen\t{}",
            cmd, frg, wnd, ts, sn, una, len
        );
        buf = &buf[len..];
    }
}
