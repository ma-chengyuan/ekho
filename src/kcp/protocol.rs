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
use rand::{thread_rng, Rng};
use std::cmp::{max, min, Ordering};
use std::collections::{BTreeMap, VecDeque};
use std::convert::TryInto;
use thiserror::Error;

/// KCP error type.
#[derive(Debug, Error)]
pub enum KcpError {
    #[error("the packet to be sent is too large to be fragmented")]
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

/// The result type for KCP operations.
pub(crate) type Result<T> = std::result::Result<T, KcpError>;

/// The overhead imposed by KCP per packet (aka. packet header length).
const KCP_OVERHEAD: u32 = 24;

/// The default retransmission time out for KCP. This is used until an ACK packet is received, after
/// which RTO will be calculated based on RTT.
const KCP_RTO_DEFAULT: u32 = 200;
/// Minimum RTO, which is the time needed after first transmission attempt for KCP to first consider
/// retransmission.
const KCP_RTO_MIN: u32 = 100;
/// The upper bound for RTO.
const KCP_RTO_MAX: u32 = 60000;

/// KCP command that pushes a data segment onto the receive buffer.
const KCP_CMD_PUSH: u8 = 81;
/// KCP command that represents an ACK packet.
const KCP_CMD_ACK: u8 = 82;
/// KCP command that asks the receiver to send back a packet telling the sender its window size.
const KCP_CMD_WND_ASK: u8 = 83;
/// KCP command that tells the receiver the sender's window size.
const KCP_CMD_WND_TELL: u8 = 84;

/// Default send window size.
const KCP_WND_SND_DEFAULT: u16 = 32;
/// Default receive window size.
const KCP_WND_RCV_DEFAULT: u16 = 128;
/// The upper bound for fragmentation of a long payload.
const KCP_MAX_FRAGMENTS: u16 = 128;

/// MTU for a default KCP control block.
const KCP_MTU_DEFAULT: u32 = 1400;
/// Update interval for a default KCP control block.
const KCP_INTERVAL_DEFAULT: u32 = 100;
/// Dead link threshold for a default KCP control block.
const KCP_DEAD_LINK_DEFAULT: u32 = 20;

/// Initial window probing timeout.
const KCP_PROBE_INIT: u32 = 7000;
/// The upper bound for window probing timeout.
const KCP_PROBE_LIMIT: u32 = 120000;

/// Maximum number of fast resend attempts by default.
const KCP_FAST_RESEND_LIMIT: u32 = 5;
/// If the difference between the current time and the time of last flush is greater than this
/// value, KCP considers the clock to have been changed.
const KCP_CLOCK_CHANGED: i32 = 10000;

/// Window length (unit: ms) for RTprop (Round-trip propagation time) filters in BBR.
const KCP_RT_PROP_WINDOW: u32 = 10000;
/// Window length (unit: RTT) for BtlBW (Bottleneck bandwidth) filters in BBR.
const KCP_BTL_BW_WINDOW: u32 = 10;
/// Time (unit: ms) for one ProbeRTT phase.
const KCP_PROBE_RTT_TIME: u32 = 200;
/// Gain cycles (x4) used in ProbeBW state of the BBR control algorithm.
const KCP_GAIN_CYCLE: [usize; 8] = [5, 3, 4, 4, 4, 4, 4, 4];
/// KCP BDP gain denominator
const KCP_BDP_GAIN_DEN: usize = 1024;

/// KCP segment representing a KCP packet.
#[derive(Default)]
#[rustfmt::skip]
struct KcpSegment {
    // Header
    #[doc = "Conversation ID."]     conv: u32,  #[doc = "KCP command."]         cmd: u8,
    #[doc = "Fragmentation."]       frg: u8,    #[doc = "Remote window size."]  wnd: u16,
    #[doc = "Timestamp when sent."] ts: u32,    #[doc = "Sequence number."]     sn: u32,
    #[doc = "UNA when sent."]       una: u32,
    /// Timestamp for next retransmission.
    ts_resend: u32,
    /// Retransmission timeout.
    rto: u32,
    /// Number of times the packet is skip-ACKed.
    skip_acks: u32,
    /// Number of transmission attempts.
    xmits: u32,
    /// The payload.
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
pub struct KcpControlBlock {
    /// Conversation ID.
    conv: u32,
    /// Maximum transmission unit.
    mtu: u32,
    /// Maximum segment size.
    mss: u32,
    /// Is the link dead?
    dead_link: bool,
    /// Oldest Unacknowledged Packet in the send window.
    snd_una: u32,
    /// Sequence number of the next packet to be sent.
    snd_nxt: u32,
    /// Sequence number of the next packet to be put in the receive queue.
    rcv_nxt: u32,
    /// Variance of RTT.
    rtt_var: u32,
    /// Smooth RTT estimation.
    srtt: u32,
    /// Base retransmission timeout.
    rto: u32,
    /// Minimum retransmission timeout.
    rto_min: u32,
    /// Send window size (packet).
    snd_wnd: u16,
    /// Receive window size (packet).
    rcv_wnd: u16,
    /// Remote window size (packet).
    rmt_wnd: u16,
    /// Current timestamp (ms).
    current: u32,
    /// Update interval (ms).
    interval: u32,
    /// Nodelay mode.
    nodelay: bool,
    /// Whether the control block is updated at least once.
    updated: bool,
    /// Timestamp for next flush.
    ts_flush: u32,
    /// Timestamp for next probe.
    ts_probe: u32,
    /// Whether we should ask the other side to tell us its window size.
    probe_should_ask: bool,
    /// Whether we should tell the other side our window size.
    probe_should_tell: bool,
    /// Probing timeout.
    probe_timeout: u32,
    /// If a packet does not arrive after this many resend attempts, the link is considered dead.
    dead_link_threshold: u32,
    /// Send queue, which stores packets that are enqueued but not in the send window.
    snd_queue: VecDeque<KcpSegment>,
    /// Receive queue, which stores packets that are received but not consumed by the application.
    rcv_queue: VecDeque<KcpSegment>,
    /// Send buffer, which stores packets sent but not yet acknowledged.
    snd_buf: VecDeque<KcpSegment>,
    /// Receive buffer, which stores packets that arrive but cannot be used because a preceding
    /// packet hasn't arrived yet.
    rcv_buf: BTreeMap<u32, KcpSegment>,
    /// ACKs to be sent in the next flush.
    ack_list: Vec<(/* sn */ u32, /* ts */ u32)>,
    /// Stream mode. If enabled, KCP will try to merge payloads to save bandwidth.
    stream: bool,
    /// Fast resend threshold. If set to a non-zero value, a packet will be resend immediately if
    /// it is skip-ACKed this many time, regardless of RTO.
    fast_resend_threshold: u32,
    /// Fast resend limit. If set to a non-zero value, a packet will be resent for at most this many
    /// attempts.
    fast_resend_limit: u32,
    /// Output queue, the outer application should actively poll from this queue.
    output: VecDeque<Vec<u8>>,
    /// Buffer used to merge small packets into a batch (thus making better use of bandwidth).
    buffer: Vec<u8>,

    /// Whether the BBR congestion control algorithm is enabled
    bbr_enabled: bool,
    /// Controls how aggressively BBR controls the send window
    bdp_gain: usize,
    /// Time of receiving the last ACK packet.
    ts_last_ack: u32,
    /// Bytes confirmed to have been delivered.
    delivered: usize,
    /// Bytes currently inflight.
    inflight: usize,
    /// Monotone queue for Round trip propagation time.
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

impl KcpControlBlock {
    /// Creates a new KCP control block with the given conversation ID and default parameters.
    pub fn new(conv: u32) -> KcpControlBlock {
        KcpControlBlock {
            conv,
            mtu: KCP_MTU_DEFAULT,
            mss: KCP_MTU_DEFAULT - KCP_OVERHEAD,
            dead_link: false,
            snd_una: 0,
            snd_nxt: 0,
            rcv_nxt: 0,
            rtt_var: 0,
            srtt: 0,
            rto: KCP_RTO_DEFAULT,
            rto_min: KCP_RTO_MIN,
            snd_wnd: KCP_WND_SND_DEFAULT,
            rcv_wnd: KCP_WND_RCV_DEFAULT,
            rmt_wnd: KCP_WND_RCV_DEFAULT,
            current: 0,
            interval: KCP_INTERVAL_DEFAULT,
            ts_flush: KCP_INTERVAL_DEFAULT,
            ts_probe: 0,
            probe_should_ask: false,
            probe_should_tell: false,
            probe_timeout: 0,
            nodelay: false,
            updated: false,
            dead_link_threshold: KCP_DEAD_LINK_DEFAULT,
            snd_queue: Default::default(),
            rcv_queue: Default::default(),
            snd_buf: Default::default(),
            rcv_buf: Default::default(),
            ack_list: Default::default(),
            stream: false,
            fast_resend_threshold: 0,
            fast_resend_limit: KCP_FAST_RESEND_LIMIT,
            output: Default::default(),
            buffer: Vec::with_capacity(2 * KCP_MTU_DEFAULT as usize),

            // BBR
            bbr_enabled: true,
            bdp_gain: 1024,
            delivered: 0,
            ts_last_ack: 0,
            inflight: 0,
            rt_prop_queue: Default::default(),
            btl_bw_queue: Default::default(),
            rt_prop_expired: false,
            bbr_state: BBRState::Startup,
            app_limited_until: 0,
        }
    }

    /// Peeks the size of the next packet.
    ///
    /// Returns error if there is currently no packets in the receive buffer.
    pub fn peek_size(&self) -> Result<usize> {
        let seg = self.rcv_queue.front().ok_or(KcpError::NotAvailable)?;
        if seg.frg == 0 {
            return Ok(seg.payload.len());
        }
        if self.rcv_queue.len() < (seg.frg + 1) as usize {
            return Err(KcpError::NotAvailable);
        }
        let mut len = 0;
        for seg in &self.rcv_queue {
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
        while !self.rcv_queue.is_empty() {
            let mut seg = self.rcv_queue.pop_front().unwrap();
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
        if self.stream {
            if let Some(old) = self.snd_queue.back_mut() {
                if old.payload.len() < self.mss as usize {
                    let cap = self.mss as usize - old.payload.len();
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
        let count = if buf.len() <= self.mss as usize {
            1
        } else {
            (buf.len() + self.mss as usize - 1) / self.mss as usize
        };
        if count > KCP_MAX_FRAGMENTS as usize {
            return Err(KcpError::OversizePacket);
        }
        assert!(count > 0);
        for i in 0..count {
            let size = min(self.mss as usize, buf.len());
            let (front, back) = buf.split_at(size);
            self.snd_queue.push_back(KcpSegment {
                frg: if self.stream {
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
        let rto = self.srtt + max(self.interval, 4 * self.rtt_var);
        self.rto = max(self.rto_min, min(rto, KCP_RTO_MAX));
    }

    /// Recalculates UNA based on the current [send buffer](#structfield.snd_buf).
    fn update_una(&mut self) {
        self.snd_una = self.snd_buf.front().map_or(self.snd_nxt, |seg| seg.sn);
    }

    /// Updates BBR filters and relevant fields when a packet is acknowledged, roughly equivalent to
    /// the `onAck` function in the BBR paper.
    fn update_bbr_on_ack(&mut self, seg: &KcpSegment) {
        self.delivered += seg.payload.len() + KCP_OVERHEAD as usize;
        self.ts_last_ack = self.current;
        self.inflight = self
            .inflight
            .saturating_sub(seg.payload.len() + KCP_OVERHEAD as usize);
        self.app_limited_until = self
            .app_limited_until
            .saturating_sub(seg.payload.len() + KCP_OVERHEAD as usize);
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
                    .map(|p| p.0 + KCP_RT_PROP_WINDOW <= self.current)
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
                    .map(|p| p.0 + KCP_BTL_BW_WINDOW * self.srtt <= self.current)
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
            if last_rt_prop_update + KCP_RT_PROP_WINDOW <= self.current && !self.rt_prop_expired {
                self.bbr_state = BBRState::ProbeRTT(self.current, phase);
                self.rt_prop_expired = true;
            } else if since + self.srtt <= self.current {
                // Each gain cycle phase lasts for one RTT
                self.bbr_state =
                    BBRState::ProbeBW(self.current, (phase + 1) % KCP_GAIN_CYCLE.len());
            }
        } else if let BBRState::ProbeRTT(since, phase) = self.bbr_state {
            if since + KCP_PROBE_RTT_TIME <= self.current {
                self.bbr_state = BBRState::ProbeBW(self.current, phase);
            }
        }
    }

    /// Removes the packet from the [send buffer](#structfield.snd_buf) whose sequence number is `sn`
    /// marks it as acknowledged.
    fn ack_packet_with_sn(&mut self, sn: u32) {
        if sn < self.snd_una || sn >= self.snd_nxt {
            return;
        }
        for i in 0..self.snd_buf.len() {
            match sn.cmp(&self.snd_buf[i].sn) {
                Ordering::Less => break,
                Ordering::Greater => continue,
                Ordering::Equal => {
                    let seg = self.snd_buf.remove(i).unwrap();
                    self.update_bbr_on_ack(&seg);
                    break;
                }
            }
        }
    }

    /// Removes packets from the [send buffer](#structfield.snd_buf) whose sequence number is less
    /// than `una` and marks them as acknowledged.
    fn ack_packets_before_una(&mut self, una: u32) {
        while !self.snd_buf.is_empty() && self.snd_buf[0].sn < una {
            let seg = self.snd_buf.pop_front().unwrap();
            self.update_bbr_on_ack(&seg);
        }
    }

    /// Increases the skip-ACK count of packets with sequence number less than `sn` (useful in KCP
    /// fast retransmission).
    fn increase_skip_acks(&mut self, sn: u32, _ts: u32) {
        if sn < self.snd_una || sn >= self.snd_nxt {
            return;
        }
        // seg.sn increasing
        for seg in self.snd_buf.iter_mut() {
            if seg.sn < sn {
                seg.skip_acks += 1;
            } else {
                break;
            }
        }
    }

    /// Pushes a segment onto the [receive buffer](#structfield.rcv_buf), and if possible, moves
    /// segments from the receiver buffer to the [receive queue](#structfield.rcv_queue).
    fn push_segment(&mut self, seg: KcpSegment) {
        if seg.sn >= self.rcv_nxt + self.rcv_wnd as u32 || seg.sn < self.rcv_nxt {
            // OPTIMIZE: this check is unnecessary, since this function is only called in input(),
            //  which contains this check already.
            return;
        }
        self.rcv_buf.entry(seg.sn).or_insert(seg);
        // Move packets from the buffer to the receive queue if possible
        while !self.rcv_buf.is_empty()
            && self.rcv_buf.iter().next().unwrap().1.sn == self.rcv_nxt
            && self.rcv_queue.len() < self.rcv_wnd as usize
        {
            self.rcv_queue
                .push_back(self.rcv_buf.remove(&self.rcv_nxt).unwrap());
            self.rcv_nxt += 1;
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

        if data.len() < KCP_OVERHEAD as usize {
            return Err(KcpError::IncompletePacket);
        }

        loop {
            if data.len() < KCP_OVERHEAD as usize {
                break;
            }
            let (mut header, body) = data.split_at(KCP_OVERHEAD as usize);
            // Read header
            let conv = header.get_u32_le();
            if conv != self.conv {
                return Err(KcpError::WrongConv {
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
                return Err(KcpError::IncompletePacket);
            }
            if cmd != KCP_CMD_PUSH
                && cmd != KCP_CMD_ACK
                && cmd != KCP_CMD_WND_ASK
                && cmd != KCP_CMD_WND_TELL
            {
                return Err(KcpError::InvalidCommand(cmd));
            }
            self.rmt_wnd = wnd;
            self.ack_packets_before_una(una);
            self.update_una();
            match cmd {
                KCP_CMD_ACK => {
                    self.ack_packet_with_sn(sn);
                    self.update_una();
                    if !has_ack || sn > sn_max_ack {
                        has_ack = true;
                        sn_max_ack = sn;
                        ts_max_ack = ts;
                    }
                }
                KCP_CMD_PUSH => {
                    if sn < self.rcv_nxt + self.rcv_wnd as u32 {
                        self.ack_list.push((sn, ts));
                        if sn >= self.rcv_nxt {
                            self.push_segment(KcpSegment {
                                sn,
                                frg,
                                payload: data[..len].into(),
                                ..Default::default()
                            });
                        }
                    }
                }
                KCP_CMD_WND_ASK => self.probe_should_tell = true,
                KCP_CMD_WND_TELL => {}
                _ => unreachable!(),
            }
            data = &data[len..];
        }
        if has_ack && self.fast_resend_threshold > 0 {
            // OPTIMIZE: if we have a large receive window and a large flow of traffic, the
            //  increase_skip_acks operation here may become computationally demanding, because
            //  it has a worst-case linear time complexity. It is perhaps better to limit the
            //  frequency to call it, perhaps every self.interval or so. This would of course
            //  undermine its purpose of fast-retransmission, but would reduce CPU usage. Another
            //  solution is to maintain snd_buf with a modified BST to ensure log complexity of
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
                self.probe_timeout = KCP_PROBE_INIT;
                self.ts_probe = self.current + self.probe_timeout;
            } else if self.current >= self.ts_probe {
                // Increase probe timeout by 1.5x until we know the window size
                self.probe_timeout = max(self.probe_timeout, KCP_PROBE_INIT);
                self.probe_timeout += self.probe_timeout / 2;
                self.probe_timeout = min(self.probe_timeout, KCP_PROBE_LIMIT);
                self.ts_probe = self.current + self.probe_timeout;
                self.probe_should_ask = true;
            }
        } else {
            self.probe_timeout = 0;
            self.ts_probe = 0;
        }
    }

    /// Flushes packets from the [send queue](#structfield.snd_queue) to the
    /// [send buffer](#structfield.snd_buf), and (re)transmits the packets in the send buffer
    /// if necessary.
    fn flush(&mut self) {
        if !self.updated {
            return;
        }

        let wnd = self.rcv_wnd.saturating_sub(self.rcv_queue.len() as u16);
        let mut seg = KcpSegment {
            conv: self.conv,
            cmd: KCP_CMD_ACK,
            una: self.rcv_nxt,
            wnd,
            ..Default::default()
        };

        let mut old_ack_list = Vec::new();
        std::mem::swap(&mut self.ack_list, &mut old_ack_list);
        for (sn, ts) in old_ack_list {
            seg.sn = sn;
            seg.ts = ts;
            flush_segment(&mut self.buffer, &mut self.output, self.mtu, &seg);
        }
        seg.sn = 0;
        seg.ts = 0;

        self.update_probe();

        if self.probe_should_ask {
            seg.cmd = KCP_CMD_WND_ASK;
            flush_segment(&mut self.buffer, &mut self.output, self.mtu, &seg);
            self.probe_should_ask = false;
        }
        if self.probe_should_tell {
            seg.cmd = KCP_CMD_WND_TELL;
            flush_segment(&mut self.buffer, &mut self.output, self.mtu, &seg);
            self.probe_should_tell = false;
        }

        self.update_bbr_state();
        // Because we are not really pacing the packets, the sending logic is different from what
        // is stated in the original BBR paper. The original BBR uses two parameters: cwnd_gain
        // and pacing_gain. However, the effects of the two parameters are hard to distinguish when
        // packets are flushed. Thus, it may be better to merge the two parameters into one here.
        let limit = if self.bbr_enabled {
            let limit = match self.bbr_state {
                BBRState::Startup => self.bdp() * 2955 / 1024, /* 2 / ln2 */
                // ln2 / 2 is the value of pacing_gain. Given the current state machine logic in
                // update_bbr_state, this value stops KCP from sending anything.
                BBRState::Drain => self.bdp() * 355 / 1024, /* ln2 / 2 */
                BBRState::ProbeBW(_, phase) => self.bdp() * KCP_GAIN_CYCLE[phase] / 4,
                BBRState::ProbeRTT(_, _) => self.bdp() / 2,
            };
            // Empirical tests have found the current limit to be a bit conservative. One solution
            // might be to multiply the current limit with a small, configurable gain.
            limit * self.bdp_gain / KCP_BDP_GAIN_DEN
        } else {
            usize::max_value()
        };

        if !self.rt_prop_queue.is_empty() && !self.btl_bw_queue.is_empty() {
            log::trace!(
                "{:?} rt prop {}@{} btl bw {}@{} bdp {}",
                self.bbr_state,
                self.rt_prop_queue.front().unwrap().1,
                self.rt_prop_queue.front().unwrap().0,
                self.btl_bw_queue.front().unwrap().1,
                self.btl_bw_queue.front().unwrap().0,
                self.bdp()
            );
        }

        // Move segments from the send queue to the send buffer
        let cwnd = min(self.snd_wnd, self.rmt_wnd);
        while self.snd_nxt < self.snd_una + cwnd as u32
            && !self.snd_queue.is_empty()
            && self.inflight <= limit
        {
            let mut seg = self.snd_queue.pop_front().unwrap();
            seg.conv = self.conv;
            seg.cmd = KCP_CMD_PUSH;
            seg.sn = self.snd_nxt;
            self.snd_nxt += 1;
            seg.app_limited = self.app_limited_until > 0;
            self.inflight += seg.payload.len() + KCP_OVERHEAD as usize;
            self.snd_buf.push_back(seg);
            if self.inflight <= limit && self.snd_queue.is_empty() {
                self.app_limited_until = self.inflight;
            }
        }

        let rto_min = if self.nodelay { 0 } else { self.rto_min };

        // (Re)transmit segments in the send buffer
        for i in 0..self.snd_buf.len() {
            let seg = &mut self.snd_buf[i];
            let mut xmit = false;
            if seg.xmits == 0 {
                xmit = true;
                seg.rto = self.rto;
                seg.ts_resend = self.current + seg.rto + rto_min;
            } else if self.current >= seg.ts_resend {
                // Regular retransmission
                xmit = true;
                seg.rto = if self.nodelay {
                    max(seg.rto, self.rto)
                } else {
                    // Increase RTO by 1.5x, better than 2x in TCP
                    seg.rto + seg.rto / 2
                };
                seg.ts_resend = self.current + seg.rto;
            } else if self.fast_resend_threshold != 0
                && seg.skip_acks >= self.fast_resend_threshold
                && (seg.xmits <= self.fast_resend_limit || self.fast_resend_limit == 0)
            {
                // Fast retransmission
                xmit = true;
                seg.skip_acks = 0;
                seg.ts_resend = self.current + seg.rto;
            }

            if xmit {
                seg.xmits += 1;
                seg.ts = self.current;
                seg.wnd = wnd;
                seg.una = self.rcv_nxt;

                seg.delivered = self.delivered;
                seg.ts_last_ack = self.ts_last_ack;

                flush_segment(&mut self.buffer, &mut self.output, self.mtu, &seg);
                self.dead_link |= seg.xmits >= self.dead_link_threshold;
            }
        }

        if !self.buffer.is_empty() {
            let mut new_buf = Vec::with_capacity(2 * self.mtu as usize);
            std::mem::swap(&mut self.buffer, &mut new_buf);
            self.output.push_back(new_buf);
        }

        fn flush_segment(
            buf: &mut Vec<u8>,
            output: &mut VecDeque<Vec<u8>>,
            mtu: u32,
            seg: &KcpSegment,
        ) {
            if buf.len() + seg.payload.len() + KCP_OVERHEAD as usize > mtu as usize {
                let mut new_buf = Vec::with_capacity(2 * mtu as usize);
                std::mem::swap(buf, &mut new_buf);
                output.push_back(new_buf);
            }
            buf.put_u32_le(seg.conv);
            buf.put_u8(seg.cmd);
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
        if (current as i32 - self.ts_flush as i32).abs() >= KCP_CLOCK_CHANGED {
            self.ts_flush = current;
        }
        if self.ts_flush <= current {
            self.ts_flush += self.interval;
            if self.current >= self.ts_flush {
                self.ts_flush = self.current + self.interval;
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
        let ts_flush = if (current as i32 - self.ts_flush as i32).abs() >= KCP_CLOCK_CHANGED {
            current
        } else {
            self.ts_flush
        };
        if ts_flush <= current {
            return current;
        }
        let mut next_update = min(current + self.interval, ts_flush);
        for seg in &self.snd_buf {
            if seg.ts_resend <= current {
                return current;
            }
            next_update = min(next_update, seg.ts_resend);
        }
        next_update
    }

    /// Gets the number of packets wait to be sent. This includes both unsent packets and packets
    /// that have been sent but not acknowledged by the other side.
    pub fn wait_send(&self) -> usize {
        self.snd_buf.len() + self.snd_queue.len()
    }

    /// Checks if everything is flushed, including unsent data packets and ACK packets.
    ///
    /// You may want to call this when you are about to drop this control block, to check if KCP has
    /// finished everything up.
    pub fn all_flushed(&self) -> bool {
        self.snd_buf.is_empty() && self.snd_queue.is_empty() && self.ack_list.is_empty()
    }

    /// Returns the Bandwidth-Delay Product.
    ///
    /// For detailed explanation of BDP please refer to Google's BBR paper.
    pub fn bdp(&self) -> usize {
        if self.rt_prop_queue.is_empty() || self.btl_bw_queue.is_empty() {
            self.mtu as usize
        } else {
            self.rt_prop_queue.front().unwrap().1 as usize * self.btl_bw_queue.front().unwrap().1
        }
    }

    pub fn set_mtu(&mut self, mtu: u32) {
        if mtu < KCP_OVERHEAD {
            panic!(
                "KCP MTU too low: {} (should be at least {})",
                mtu, KCP_OVERHEAD
            );
        }
        self.mtu = mtu;
        self.mss = mtu - KCP_OVERHEAD;
    }

    pub fn mtu(&mut self) -> u32 {
        self.mtu
    }

    pub fn mss(&mut self) -> u32 {
        self.mss
    }

    pub fn set_interval(&mut self, interval: u32) {
        self.interval = interval;
    }

    pub fn interval(&self) -> u32 {
        self.interval
    }

    pub fn set_nodelay(&mut self, nodelay: bool) {
        self.nodelay = nodelay;
    }

    pub fn nodelay(&self) -> bool {
        self.nodelay
    }

    pub fn set_fast_resend(&mut self, fast_resend: u32) {
        self.fast_resend_threshold = fast_resend;
    }

    pub fn fast_resend(&self) -> u32 {
        self.fast_resend_threshold
    }

    pub fn set_bbr(&mut self, enabled: bool) {
        self.bbr_enabled = enabled
    }

    pub fn bbr(&self) -> bool {
        self.bbr_enabled
    }

    pub fn set_bdp_gain(&mut self, bdp_gain: f64) {
        self.bdp_gain = (KCP_BDP_GAIN_DEN as f64 * bdp_gain).round() as usize
    }

    pub fn bdp_gain(&self) -> f64 {
        self.bdp_gain as f64 / KCP_BDP_GAIN_DEN as f64
    }

    pub fn set_rto_min(&mut self, rto_min: u32) {
        self.rto_min = rto_min;
    }

    pub fn rto_min(&self) -> u32 {
        self.rto_min
    }

    pub fn set_window_size(&mut self, send: u16, recv: u16) {
        self.snd_wnd = send;
        self.rcv_wnd = max(recv, KCP_MAX_FRAGMENTS);
    }

    pub fn dead_link(&self) -> bool {
        self.dead_link
    }

    pub fn conv(&self) -> u32 {
        self.conv
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
        while buf.len() >= KCP_OVERHEAD as usize {
            let _conv = buf.get_u32_le();
            let cmd = buf.get_u8();
            let _frg = buf.get_u8();
            let _wnd = buf.get_u16_le();
            let _ts = buf.get_u32_le();
            let sn = buf.get_u32_le();
            let _una = buf.get_u32_le();
            let len = buf.get_u32_le() as usize;
            if cmd == KCP_CMD_PUSH {
                return sn == 0;
            }
            buf = &buf[len..];
        }
        true
    }

    /// Print the headers of the packets in the given raw buffer `buf` using `log::debug!(...)`
    pub fn dissect_headers_from_raw(mut buf: &[u8]) {
        while buf.len() >= KCP_OVERHEAD as usize {
            let _conv = buf.get_u32_le();
            let cmd = buf.get_u8();
            let frg = buf.get_u8();
            let wnd = buf.get_u16_le();
            let ts = buf.get_u32_le();
            let sn = buf.get_u32_le();
            let una = buf.get_u32_le();
            let len = buf.get_u32_le() as usize;
            #[rustfmt::skip]
            log::debug!(
                "{}\tfrg\t{}\twnd\t{}\tts\t{}\tsn\t{}\tuna\t{}\tlen\t{}",
                match cmd {
                    KCP_CMD_PUSH => "PUSH ",
                    KCP_CMD_ACK => "ACK  ",
                    KCP_CMD_WND_ASK => "WASK ",
                    KCP_CMD_WND_TELL => "WTELL",
                    _ => "ERROR",
                },
                frg, wnd, ts, sn, una, len
            );
            buf = &buf[len..];
        }
    }
}
