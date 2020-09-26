#![allow(dead_code)]

use byteorder::{ByteOrder, LittleEndian};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::cmp::{max, min, Ordering};
use std::collections::VecDeque;
use std::error::Error;
use std::fmt::Display;

/// KCP error type
#[derive(Debug, Clone)]
pub enum KcpError {
    /// Input message is too big to be sent even with fragmentation.
    SendPacketTooLarge,
    /// Input data is so small that it can't be a valid KCP packet.
    InvalidKcpPacket,
    /// Command not supported.
    UnsupportedCommand(u8),
    /// No packet is available in receive queue.
    NotAvailable,
    /// Wrong conversation ID.
    WrongConv { expected: u32, found: u32 },
}

impl Error for KcpError {}

impl Display for KcpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KcpError::SendPacketTooLarge => write!(f, "send packet too large"),
            KcpError::InvalidKcpPacket => write!(f, "invalid kcp block"),
            KcpError::UnsupportedCommand(cmd) => write!(f, "unsupported command: {}", cmd),
            KcpError::NotAvailable => write!(f, "empty queue (try again later)"),
            KcpError::WrongConv { expected, found } => {
                write!(f, "wrong conv (expected {}, found {})", expected, found)
            }
        }
    }
}

impl From<KcpError> for std::io::Error {
    fn from(kcp: KcpError) -> Self {
        use std::io::ErrorKind;
        let message = format!("{}", &kcp);
        let kind = match kcp {
            KcpError::SendPacketTooLarge => ErrorKind::InvalidInput,
            KcpError::InvalidKcpPacket => ErrorKind::InvalidData,
            KcpError::NotAvailable => ErrorKind::WouldBlock,
            KcpError::UnsupportedCommand(_) => ErrorKind::InvalidData,
            KcpError::WrongConv { .. } => ErrorKind::InvalidData,
        };
        std::io::Error::new(kind, message)
    }
}

type Result<T> = std::result::Result<T, KcpError>;

const KCP_OVERHEAD: u32 = 24;

const KCP_RTO_NODELAY: u32 = 30;
const KCP_RTO_DEFAULT: u32 = 200;
const KCP_RTO_MIN: u32 = 100;
const KCP_RTO_MAX: u32 = 60000;

const KCP_CMD_PUSH: u8 = 81;
const KCP_CMD_ACK: u8 = 82;
const KCP_CMD_WND_ASK: u8 = 83;
const KCP_CMD_WND_TELL: u8 = 84;

const KCP_WND_SND_DEFAULT: u16 = 32;
const KCP_WND_RCV_DEFAULT: u16 = 128;

const KCP_MTU_DEFAULT: u32 = 1400;
const KCP_INTERVAL_DEFAULT: u32 = 100;
const KCP_DEAD_LINK_DEFAULT: u32 = 20;

const KCP_SSTHRESH_INIT: u16 = 2;
const KCP_SSTHRESH_MIN: u16 = 2;
const KCP_PROBE_INIT: u32 = 7000;
const KCP_PROBE_LIMIT: u32 = 120000;

const KCP_FAST_RESEND_LIMIT: u32 = 5;
const KCP_LONG_TIME_NO_FLUSH: i32 = 10000;

/// A KCP segment
struct KcpSegment {
    /// Conversation ID.
    conv: u32,
    /// KCP command.
    cmd: u8,
    /// Packet fragmentation.
    frg: u8,
    /// Window size.
    wnd: u16,
    /// Timestamp when sent.
    ts: u32,
    /// Packet sequence number.
    sn: u32,
    /// UNA when sent.
    una: u32,
    /// Timestamp for next resend.
    ts_resend: u32,
    /// Resent timeout.
    rto: u32,
    /// Number of times the packet is skip-ACKed.
    skip_acks: u32,
    /// Number of resend attempts.
    resend_attempts: u32,
    /// The data.
    data: BytesMut,
}

/// A KCP control block (full algorithmic implementation)
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
    /// Slow start threshold.
    ssthresh: u16,
    /// Variance of RTT.
    rtt_var: u32,
    /// Smooth RTT estimation.
    srtt: u32,
    /// Base resend timeout.
    rto: u32,
    /// Minimum resend timeout.
    rto_min: u32,
    /// Send window size (packet).
    snd_wnd: u16,
    /// Receive window size (packet).
    rcv_wnd: u16,
    /// Remote window size (packet).
    rmt_wnd: u16,
    /// Congestion window size.
    cwnd: u16,
    /// Current timestamp (ms).
    current: u32,
    /// Update interval (ms).
    interval: u32,
    /// Total resend attempts.
    total_resend_attempts: u32,
    /// Nodelay mode.
    nodelay: bool,
    /// Whether the control block is updated at least once.
    updated: bool,
    /// Timestamp for next flush.
    ts_flush: u32,
    /// Timestamp for next probe.
    ts_probe: u32,
    /// Whether we should ask the other side to tell us its window size
    probe_should_ask: bool,
    /// Whether we should tell the otherside its window size
    probe_should_tell: bool,
    /// Probing timeout.
    probe_timeout: u32,
    /// If a packet does not arrive after this many resend attempts, the link is considered dead.
    dead_link_threshold: u32,
    /// Estimated inflight data in one RTT.
    incr: u32,
    /// Send queue.
    snd_queue: VecDeque<KcpSegment>,
    /// Receive queue.
    rcv_queue: VecDeque<KcpSegment>,
    /// Send buffer, which stores packets sent / just about to be sent but not yet acknowledged.
    snd_buf: VecDeque<KcpSegment>,
    /// Receive buffer, which stores packets that arrive but are not the one we are waiting for.
    rcv_buf: VecDeque<KcpSegment>,
    /// ACKs to be sent in the next flush.
    ack_list: Vec<(/* sn */ u32, /* ts */ u32)>,
    /// Disable congestion control?
    no_cwnd: bool,
    /// Stream mode. If enabled, KCP will try to merge messages to save bandwidth.
    stream: bool,
    /// Fast resend threshold. If set to a non-zero value, a packet will be resend immediately if
    /// it is skip-ACKed this many time.
    fast_resend_threshold: u32,
    /// Fast resend limit. If set to a non-zero value, a packet will not be resent after this many
    /// attempts.
    fast_resend_limit: u32,
    /// Output queue.
    output: VecDeque<Bytes>,
    /// Buffer used in outputs
    buffer: BytesMut,
}

impl KcpSegment {
    fn with_data(data: BytesMut) -> KcpSegment {
        KcpSegment {
            conv: 0,
            cmd: 0,
            frg: 0,
            wnd: 0,
            ts: 0,
            sn: 0,
            una: 0,
            ts_resend: 0,
            rto: 0,
            skip_acks: 0,
            resend_attempts: 0,
            data,
        }
    }

    fn len(&self) -> usize {
        self.data.len()
    }

    fn encode(&self) -> Bytes {
        let mut ret = BytesMut::with_capacity(self.len() + KCP_OVERHEAD as usize);
        ret.put_u32_le(self.conv);
        ret.put_u8(self.cmd);
        ret.put_u8(self.frg);
        ret.put_u16_le(self.wnd);
        ret.put_u32_le(self.ts);
        ret.put_u32_le(self.sn);
        ret.put_u32_le(self.una);
        ret.put_u32_le(self.len() as u32);
        ret.extend_from_slice(&self.data);
        ret.to_bytes()
    }
}

impl KcpControlBlock {
    pub fn new(conv: u32) -> KcpControlBlock {
        KcpControlBlock {
            conv,
            mtu: KCP_MTU_DEFAULT,
            mss: KCP_MTU_DEFAULT - KCP_OVERHEAD,
            dead_link: false,
            snd_una: 0,
            snd_nxt: 0,
            rcv_nxt: 0,
            ssthresh: KCP_SSTHRESH_INIT,
            rtt_var: 0,
            srtt: 0,
            rto: KCP_RTO_DEFAULT,
            rto_min: KCP_RTO_MIN,
            snd_wnd: KCP_WND_SND_DEFAULT,
            rcv_wnd: KCP_WND_RCV_DEFAULT,
            rmt_wnd: KCP_WND_RCV_DEFAULT,
            cwnd: 0,
            current: 0,
            interval: KCP_INTERVAL_DEFAULT,
            ts_flush: KCP_INTERVAL_DEFAULT,
            ts_probe: 0,
            probe_should_ask: false,
            probe_should_tell: false,
            probe_timeout: 0,
            total_resend_attempts: 0,
            nodelay: false,
            updated: false,
            dead_link_threshold: KCP_DEAD_LINK_DEFAULT,
            incr: 0,
            snd_queue: Default::default(),
            rcv_queue: Default::default(),
            snd_buf: Default::default(),
            rcv_buf: Default::default(),
            ack_list: Default::default(),
            no_cwnd: false,
            stream: false,
            fast_resend_threshold: 0,
            fast_resend_limit: KCP_FAST_RESEND_LIMIT,
            output: Default::default(),
            buffer: BytesMut::with_capacity(2 * KCP_MTU_DEFAULT as usize),
        }
    }

    /// Peeks the size of the next packet in the receive queue
    pub fn peek_size(&self) -> Result<usize> {
        let seg = self.rcv_queue.front().ok_or(KcpError::NotAvailable)?;
        if seg.frg == 0 {
            return Ok(seg.len());
        }
        if self.rcv_queue.len() < (seg.frg + 1) as usize {
            return Err(KcpError::NotAvailable);
        }
        let mut len = 0;
        for seg in &self.rcv_queue {
            len += seg.len();
            if seg.frg == 0 {
                break;
            }
        }
        Ok(len)
    }

    /// Receives the next packet
    pub fn recv(&mut self) -> Result<Bytes> {
        let size = self.peek_size()?;
        let mut ret = BytesMut::with_capacity(size);
        while !self.rcv_queue.is_empty() {
            let seg = self.rcv_queue.pop_front().unwrap();
            ret.extend_from_slice(&seg.data);
            if seg.frg == 0 {
                break;
            }
        }
        assert_eq!(size, ret.len());
        log::info!("recv queue size: {}", self.rcv_queue.len());
        Ok(ret.to_bytes())
    }

    /// Send a packet
    pub fn send(&mut self, mut buf: &[u8]) -> Result<usize> {
        let mut sent = 0;
        if self.stream {
            if let Some(old) = self.snd_queue.back_mut() {
                if old.len() < self.mss as usize {
                    let cap = self.mss as usize - old.len();
                    let extend = min(cap, buf.len());
                    let (front, back) = buf.split_at(extend);
                    old.data.extend_from_slice(front);
                    old.frg = 0;
                    buf = back;
                    sent += extend;
                }
                if buf.is_empty() {
                    return Ok(sent);
                }
            }
        }
        let count = if buf.len() <= self.mss as usize {
            1
        } else {
            (buf.len() + self.mss as usize - 1) / self.mss as usize
        };
        if count > KCP_WND_RCV_DEFAULT as usize {
            return Err(KcpError::SendPacketTooLarge);
        }
        assert!(count > 0);
        for i in 0..count {
            let size = min(self.mss as usize, buf.len());
            let (front, back) = buf.split_at(size);
            let mut seg = KcpSegment::with_data(front.into());
            seg.frg = if self.stream {
                0
            } else {
                (count - i - 1) as u8
            };
            self.snd_queue.push_back(seg);
            sent += size;
            buf = back;
        }
        Ok(sent)
    }

    /// Updates the RTT filter
    fn update_rtt_filter(&mut self, rtt: u32) {
        if self.srtt == 0 {
            self.srtt = rtt;
            self.rtt_var = rtt / 2;
        } else {
            let delta = (rtt as i32 - self.srtt as i32).abs() as u32;
            self.rtt_var = (3 * self.rtt_var + delta) / 4;
            self.srtt = max(1, (7 * self.srtt + delta) / 8);
        }
        let rto = self.srtt + max(self.interval, 4 * self.rtt_var);
        self.rto = max(self.rto_min, min(rto, KCP_RTO_MAX));
    }

    /// Updates UNA
    fn update_una(&mut self) {
        self.snd_una = self.snd_buf.front().map_or(self.snd_nxt, |seg| seg.sn);
    }

    /// On ACK, remove the corresponding packet from the send buffer
    fn ack_packet_with_sn(&mut self, sn: u32) {
        if sn < self.snd_una || sn >= self.snd_nxt {
            return;
        }
        for i in 0..self.snd_buf.len() {
            match sn.cmp(&self.snd_buf[i].sn) {
                Ordering::Less => break,
                Ordering::Greater => continue,
                Ordering::Equal => {
                    self.snd_buf.remove(i);
                    break;
                }
            }
        }
    }

    /// On UNA, remove all packets before UNA value from the send buffer
    fn ack_packets_before_una(&mut self, una: u32) {
        while !self.snd_buf.is_empty() && self.snd_buf[0].sn < una {
            self.snd_buf.pop_front();
        }
    }

    /// If an packet after an unACKed packet is ACKed, we say that the latter packet is skip-ACKed
    fn increase_skip_acks(&mut self, sn: u32, _ts: u32) {
        if sn < self.snd_una || sn >= self.snd_nxt {
            return;
        }
        // seg.sn increasing
        for seg in self.snd_buf.iter_mut() {
            if seg.sn >= sn {
                break;
            } else {
                seg.skip_acks += 1;
            }
        }
    }

    /// Receives a segment
    fn recv_segment(&mut self, seg: KcpSegment) {
        if seg.sn >= self.rcv_nxt + self.rcv_wnd as u32 || seg.sn < self.rcv_nxt {
            // The segment is invalid
            return;
        }
        // Do we have this segment already?
        let mut repeat = false;
        // If we don't, what's the index after which we insert this segment?
        let mut index = self.rcv_buf.len();
        // self.rcv_buf[i].sn decreasing
        for i in (0..self.rcv_buf.len()).rev() {
            match self.rcv_buf[i].sn.cmp(&seg.sn) {
                Ordering::Greater => continue,
                Ordering::Less => {
                    index = i;
                    break;
                }
                Ordering::Equal => {
                    repeat = true;
                    break;
                }
            }
        }
        if !repeat {
            self.rcv_buf.insert(index, seg);
        }

        // Move packets from the buffer to the receive queue if possible
        while !self.rcv_buf.is_empty()
            && self.rcv_buf[0].sn == self.rcv_nxt
            && self.rcv_queue.len() < self.rcv_wnd as usize
        {
            self.rcv_queue.push_back(self.rcv_buf.pop_front().unwrap());
            self.rcv_nxt += 1;
        }
    }

    /// Call this when a packet is received from the underlying protocol stack
    /// Return the actual number of bytes inputted into the control block
    pub fn input(&mut self, mut data: &[u8]) -> Result<usize> {
        let prev_una = self.snd_una;
        let prev_len = data.len();
        let mut has_ack = false;
        let mut sn_max_ack = 0;
        let mut ts_max_ack = 0;

        if data.len() < KCP_OVERHEAD as usize {
            return Err(KcpError::InvalidKcpPacket);
        }

        loop {
            if data.len() < KCP_OVERHEAD as usize {
                break;
            }
            let (header, body) = data.split_at(KCP_OVERHEAD as usize);
            // Read header
            let conv = LittleEndian::read_u32(&header[0..4]);
            if conv != self.conv {
                return Err(KcpError::WrongConv {
                    expected: self.conv,
                    found: conv,
                });
            }
            let cmd = header[4];
            let frg = header[5];
            let wnd = LittleEndian::read_u16(&header[6..8]);
            let ts = LittleEndian::read_u32(&header[8..12]);
            let sn = LittleEndian::read_u32(&header[12..16]);
            let una = LittleEndian::read_u32(&header[16..20]);
            let len = LittleEndian::read_u32(&header[20..24]) as usize;
            data = body;
            if data.len() < len {
                return Err(KcpError::InvalidKcpPacket);
            }
            if cmd != KCP_CMD_PUSH
                && cmd != KCP_CMD_ACK
                && cmd != KCP_CMD_WND_ASK
                && cmd != KCP_CMD_WND_TELL
            {
                return Err(KcpError::UnsupportedCommand(cmd));
            }
            self.rmt_wnd = wnd;
            self.ack_packets_before_una(una);
            self.update_una();
            match cmd {
                KCP_CMD_ACK => {
                    if self.current >= ts {
                        self.update_rtt_filter(self.current - ts);
                    }
                    self.ack_packet_with_sn(sn);
                    self.update_una();
                    if !has_ack || sn > sn_max_ack {
                        has_ack = true;
                        sn_max_ack = sn;
                        ts_max_ack = ts;
                    }
                }
                KCP_CMD_PUSH => {
                    self.ack_list.push((sn, ts));
                    if sn < self.rcv_nxt + self.rcv_wnd as u32 {
                        let mut seg = KcpSegment::with_data(data[..len].into());
                        seg.conv = conv;
                        seg.cmd = cmd;
                        seg.frg = frg;
                        seg.wnd = wnd;
                        seg.ts = ts;
                        seg.sn = sn;
                        seg.una = una;
                        self.recv_segment(seg);
                    }
                }
                KCP_CMD_WND_ASK => self.probe_should_tell = true,
                KCP_CMD_WND_TELL => {}
                _ => unreachable!(),
            }
        }
        if has_ack {
            self.increase_skip_acks(sn_max_ack, ts_max_ack);
        }
        // Update congestion window
        if self.snd_una > prev_una && self.cwnd < self.rmt_wnd {
            let mss = self.mss;
            if self.cwnd < self.ssthresh {
                self.cwnd += 1;
                self.incr += mss;
            } else {
                self.incr = max(self.incr, mss);
                self.incr += (mss * mss) / self.incr + (mss / 16);
                if (self.cwnd + 1) as u32 * mss <= self.incr {
                    self.cwnd = ((self.incr + mss - 1) / max(1, mss)) as u16;
                }
            }
            if self.cwnd > self.rmt_wnd {
                self.cwnd = self.rmt_wnd;
                self.incr = self.cwnd as u32 * mss;
            }
        }
        Ok(prev_len - data.len())
    }

    /// Polls an output packet
    #[inline]
    pub fn output(&mut self) -> Option<Bytes> {
        self.output.pop_front()
    }

    #[inline]
    pub fn has_output(&self) -> bool {
        !self.output.is_empty()
    }

    /// Flush packets in the send queue and the send buffer
    pub fn flush(&mut self) {
        if !self.updated {
            return;
        }

        fn flush_segment(
            buf: &mut BytesMut,
            output: &mut VecDeque<Bytes>,
            mtu: u32,
            seg: &KcpSegment,
        ) {
            buf.extend_from_slice(&seg.encode());
            if buf.len() as u32 + KCP_OVERHEAD > mtu {
                output.push_back(Bytes::copy_from_slice(&buf));
                buf.clear();
            }
        }

        // A template segment
        let mut seg = KcpSegment::with_data(BytesMut::new());
        let wnd = self.rcv_wnd.saturating_sub(self.rcv_queue.len() as u16);
        seg.conv = self.conv;
        seg.cmd = KCP_CMD_ACK;
        seg.una = self.rcv_nxt;
        seg.wnd = wnd;
        // Send pending ACK packets
        let mut old_ack_list = Vec::new();
        std::mem::swap(&mut self.ack_list, &mut old_ack_list);
        for (sn, ts) in old_ack_list {
            seg.sn = sn;
            seg.ts = ts;
            flush_segment(&mut self.buffer, &mut self.output, self.mtu, &seg);
        }
        seg.sn = 0;
        seg.ts = 0;
        // Probe window
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
        // Send a packet to ask the other side for its window size
        if self.probe_should_ask {
            seg.cmd = KCP_CMD_WND_ASK;
            flush_segment(&mut self.buffer, &mut self.output, self.mtu, &seg);
            self.probe_should_ask = false;
        }
        // Send a packet to tell the other side our window size
        if self.probe_should_tell {
            seg.cmd = KCP_CMD_WND_TELL;
            flush_segment(&mut self.buffer, &mut self.output, self.mtu, &seg);
            self.probe_should_tell = false;
        }

        // Computer congestion window
        let mut cwnd = min(self.snd_wnd, self.rmt_wnd);
        if !self.no_cwnd {
            cwnd = min(cwnd, self.cwnd);
        }

        let current = self.current;
        let mut change = false;
        let mut lost = false;

        // Move segments from the send queue to the send buffer
        while self.snd_nxt < self.snd_una + cwnd as u32 && !self.snd_queue.is_empty() {
            let mut seg = self.snd_queue.pop_front().unwrap();
            seg.conv = self.conv;
            seg.cmd = KCP_CMD_PUSH;
            seg.wnd = wnd;
            seg.ts = current;
            seg.sn = self.snd_nxt;
            self.snd_nxt += 1;
            seg.una = self.rcv_nxt;
            seg.ts_resend = current;
            seg.rto = self.rto as u32;
            seg.skip_acks = 0;
            seg.resend_attempts = 0;
            self.snd_buf.push_back(seg);
        }

        let resent = if self.fast_resend_threshold == 0 {
            u32::max_value()
        } else {
            self.fast_resend_threshold
        };
        let rto_min = if self.nodelay { 0 } else { self.rto_min >> 3 };

        // Flush data segments
        for seg in self.snd_buf.iter_mut() {
            let mut should_send = false;
            if seg.resend_attempts == 0 {
                // The first time we try to send this packet!
                should_send = true;
                seg.resend_attempts += 1;
                seg.rto = self.rto as u32;
                seg.ts_resend = current + seg.rto + rto_min;
            } else if current >= seg.ts_resend {
                // Attempt to resend
                should_send = true;
                seg.resend_attempts += 1;
                self.total_resend_attempts += 1;
                seg.rto = if self.nodelay {
                    max(seg.rto, self.rto as u32)
                } else {
                    // Increase RTO by 1.5x, better than 2.0 in TCP
                    seg.rto + seg.rto / 2
                };
                seg.ts_resend = current + seg.rto;
                lost = true;
            } else if seg.skip_acks >= resent
                && (seg.resend_attempts <= self.fast_resend_limit || self.fast_resend_limit == 0)
            {
                // Fast resend
                should_send = true;
                seg.resend_attempts += 1;
                seg.skip_acks = 0;
                seg.ts_resend = current + seg.rto;
                change = true;
            }

            if should_send {
                seg.ts = current;
                seg.wnd = wnd;
                seg.una = self.rcv_nxt;
                flush_segment(&mut self.buffer, &mut self.output, self.mtu, &seg);
                self.dead_link |= seg.resend_attempts >= self.dead_link_threshold;
            }
        }
        if !self.buffer.is_empty() {
            self.output.push_back(Bytes::copy_from_slice(&self.buffer));
            self.buffer.clear();
        }

        // Update congestion control code
        if change {
            let inflight = self.snd_nxt - self.snd_una;
            self.ssthresh = max((inflight / 2) as u16, KCP_SSTHRESH_MIN);
            self.cwnd = self.ssthresh + resent as u16;
            self.incr = self.cwnd as u32 * self.mss;
        }

        if lost {
            self.ssthresh = max(self.cwnd / 2, KCP_SSTHRESH_MIN);
            self.cwnd = 1;
            self.incr = self.cwnd as u32 * self.mss;
        }

        if self.cwnd < 1 {
            self.cwnd = 1;
            self.incr = self.mss;
        }
    }

    /// Updates the control block
    pub fn update(&mut self, current: u32) {
        self.current = current;
        if !self.updated {
            self.updated = true;
            self.ts_flush = current;
        }
        let mut dt = current as i32 - self.ts_flush as i32;
        if dt >= KCP_LONG_TIME_NO_FLUSH || dt < -KCP_LONG_TIME_NO_FLUSH {
            self.ts_flush = current;
            dt = 0
        }
        if dt >= 0 {
            self.ts_flush += self.interval;
            if self.current >= self.ts_flush {
                self.ts_flush = self.current + self.interval;
            }
            self.flush();
        }
    }

    /// Checks when to update again
    pub fn check(&self, current: u32) -> u32 {
        if !self.updated {
            return current;
        }
        let ts_flush = {
            let dt = current as i32 - self.ts_flush as i32;
            if dt >= KCP_LONG_TIME_NO_FLUSH || dt < -KCP_LONG_TIME_NO_FLUSH {
                current
            } else {
                self.ts_flush
            }
        };
        if current >= ts_flush {
            return current;
        }
        let mut next_update = min(self.interval, ts_flush - current);
        for seg in &self.snd_buf {
            if seg.ts_resend <= current {
                return current;
            }
            next_update = min(next_update, seg.ts_resend - current);
        }
        current + next_update
    }

    #[inline]
    pub fn wait_send(&self) -> usize {
        self.snd_buf.len() + self.snd_queue.len()
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
        self.rto_min = if nodelay {
            KCP_RTO_NODELAY
        } else {
            KCP_RTO_MIN
        };
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

    pub fn set_congestion_control(&mut self, enabled: bool) {
        self.no_cwnd = !enabled
    }

    pub fn congestion_control(&self) -> bool {
        !self.no_cwnd
    }

    pub fn set_window_size(&mut self, send: u16, recv: u16) {
        self.snd_wnd = send;
        self.rcv_wnd = max(recv, KCP_WND_RCV_DEFAULT);
    }

    pub fn conv(&self) -> u32 {
        self.conv
    }

    pub fn conv_from_raw(buf: &[u8]) -> u32 {
        LittleEndian::read_u32(&buf)
    }
}
