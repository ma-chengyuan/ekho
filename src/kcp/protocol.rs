#![allow(dead_code)]

/// The KCP protocol -- pure algorithmic implementation
/// Adapted from the original C implementation
/// Oxidization is under way
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::cell::RefCell;
use std::cmp::{max, min, Ordering};
use std::collections::{BTreeMap, BinaryHeap, VecDeque};
use std::convert::TryInto;
use std::error::Error;
use std::fmt::Display;
use std::rc::{Rc, Weak};

/// KCP error type
#[derive(Debug, Clone)]
pub enum KcpError {
    /// Input message is too large to be sent even with fragmentation.
    SendPacketTooLarge,
    /// Input data is so short that it can't be a valid KCP packet.
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
const KCP_MAX_FRAGMENTS: u16 = 128;

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
    /// Retransmission timeout.
    rto: u32,
    /// Number of times the packet is skip-ACKed.
    skip_acks: u32,
    /// Number of resend attempts.
    send_attempts: u32,
    /// The data.
    data: BytesMut,

    // Experimental BBR fields
    delivered: usize,
    ts_last_ack: u32,
}

struct ResendSegment {
    ts: u32,
    seg: Weak<RefCell<KcpSegment>>,
}

impl Eq for ResendSegment {}

impl PartialEq for ResendSegment {
    fn eq(&self, other: &Self) -> bool {
        self.ts == other.ts
    }
}

impl Ord for ResendSegment {
    fn cmp(&self, other: &Self) -> Ordering {
        other.ts.cmp(&self.ts)
    }
}

impl PartialOrd for ResendSegment {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A KCP control block (pure algorithmic implementation)
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
    /// Send queue, which stores packets that are enqueued but not in the send window.
    snd_queue: VecDeque<KcpSegment>,
    /// Receive queue, which stores packets that are received but not consumed by the application.
    rcv_queue: VecDeque<KcpSegment>,
    /// Send buffer, which stores packets sent but not acknowledged
    snd_buf: VecDeque<Rc<RefCell<KcpSegment>>>,
    /// Receive buffer, which stores packets that arrive but cannot be used because a preceding
    /// packet hasn't arrived yet.
    rcv_buf: BTreeMap<u32, KcpSegment>,
    /// ACKs to be sent in the next flush.
    ack_list: VecDeque<(/* sn */ u32, /* ts */ u32)>,
    /// Disable congestion control?
    no_cwnd: bool,
    /// Stream mode. If enabled, KCP will try to merge messages to save bandwidth.
    stream: bool,
    /// Fast resend threshold. If set to a non-zero value, a packet will be resend immediately if
    /// it is skip-ACKed this many time, regardless of RTO.
    fast_resend_threshold: u32,
    /// Fast resend limit. If set to a non-zero value, a packet will be resent for at most this many
    /// attempts.
    fast_resend_limit: u32,
    /// Output queue, the outer application should actively poll from this queue.
    output: VecDeque<Bytes>,
    /// Buffer used to merge small packets into a batch (thus making better use of bandwidth).
    buffer: BytesMut,

    resends: BinaryHeap<ResendSegment>,

    // Experimental BBR fields
    ts_last_ack: u32,
    delivered: usize,
    rtt_queue: VecDeque<(u32, u32)>,
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
            send_attempts: 0,
            data,
            // BBR
            delivered: 0,
            ts_last_ack: 0,
        }
    }

    fn len(&self) -> usize {
        self.data.len()
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32_le(self.conv);
        buf.put_u8(self.cmd);
        buf.put_u8(self.frg);
        buf.put_u16_le(self.wnd);
        buf.put_u32_le(self.ts);
        buf.put_u32_le(self.sn);
        buf.put_u32_le(self.una);
        buf.put_u32_le(self.len() as u32);
        buf.extend_from_slice(&self.data);
    }
}

impl Drop for KcpSegment {
    fn drop(&mut self) {
        if self.cmd == KCP_CMD_PUSH {
            log::debug!("dropped {}", self.sn);
        }
    }
}

unsafe impl Send for KcpControlBlock {}

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
            // BBR
            delivered: 0,
            ts_last_ack: 0,
            rtt_queue: Default::default(),
            resends: Default::default(),
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
        if count > KCP_MAX_FRAGMENTS as usize {
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
        self.snd_una = self
            .snd_buf
            .front()
            .map_or(self.snd_nxt, |seg| seg.borrow().sn);
    }

    fn update_bbr(&mut self, seg: &KcpSegment) {
        if self.current >= seg.ts && seg.send_attempts == 1 {
            self.update_rtt_filter(self.current - seg.ts);
            self.delivered += seg.len() + KCP_OVERHEAD as usize;
            self.ts_last_ack = self.current;
            let rtt = self.current - seg.ts;
            let btl_bw =
                (self.delivered - seg.delivered) / (self.current - seg.ts_last_ack) as usize;
            while !self.rtt_queue.is_empty() && self.rtt_queue.back().unwrap().1 > rtt {
                self.rtt_queue.pop_back();
            }
            self.rtt_queue.push_back((self.current, rtt));
        }
    }

    /// On ACK, remove the corresponding packet from the send buffer
    fn ack_packet_with_sn(&mut self, sn: u32) {
        if sn < self.snd_una || sn >= self.snd_nxt {
            return;
        }
        for i in 0..self.snd_buf.len() {
            let tmp_sn = self.snd_buf[i].borrow().sn;
            match sn.cmp(&tmp_sn) {
                Ordering::Less => break,
                Ordering::Greater => continue,
                Ordering::Equal => {
                    let seg = self.snd_buf.remove(i).unwrap();
                    self.update_bbr(&*seg.borrow());
                    break;
                }
            }
        }
    }

    /// On UNA, remove all packets before UNA value from the send buffer
    fn ack_packets_before_una(&mut self, una: u32) {
        while !self.snd_buf.is_empty() && self.snd_buf[0].borrow().sn < una {
            let seg = self.snd_buf.pop_front().unwrap();
            self.update_bbr(&*seg.borrow());
        }
    }

    /// If an packet after an unACKed packet is ACKed, we say that the latter packet is skip-ACKed
    fn increase_skip_acks(&mut self, sn: u32, _ts: u32) {
        if self.fast_resend_threshold == 0 || sn < self.snd_una || sn >= self.snd_nxt {
            return;
        }
        // seg.sn increasing
        for seg_rc in self.snd_buf.iter_mut() {
            let mut seg = seg_rc.borrow_mut();
            if seg.sn < sn {
                seg.skip_acks += 1;
                if seg.skip_acks >= self.fast_resend_threshold
                    && (seg.send_attempts <= self.fast_resend_limit || self.fast_resend_limit == 0)
                {
                    seg.skip_acks = 0;
                    seg.ts_resend = self.current + seg.rto;
                    self.resends.push(ResendSegment {
                        ts: seg.ts_resend,
                        seg: Rc::downgrade(seg_rc),
                    })
                }
            } else {
                break;
            }
        }
    }

    /// Receives a segment
    fn push_segment(&mut self, seg: KcpSegment) {
        if seg.sn >= self.rcv_nxt + self.rcv_wnd as u32 || seg.sn < self.rcv_nxt {
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

    /// Call this when a packet is received from the underlying protocol stack
    /// Return the actual number of bytes inputted into the control block
    pub fn input(&mut self, mut data: &[u8]) -> Result<usize> {
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
            let (mut header, body) = data.split_at(KCP_OVERHEAD as usize);
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
                    log::debug!("ack packet {}", sn);
                    self.ack_packet_with_sn(sn);
                    self.update_una();
                    if !has_ack || sn > sn_max_ack {
                        has_ack = true;
                        sn_max_ack = sn;
                        ts_max_ack = ts;
                    }
                }
                KCP_CMD_PUSH => {
                    self.ack_list.push_back((sn, ts));
                    if sn < self.rcv_nxt + self.rcv_wnd as u32 {
                        let mut seg = KcpSegment::with_data(data[..len].into());
                        seg.frg = frg;
                        seg.sn = sn;
                        self.push_segment(seg);
                    }
                }
                KCP_CMD_WND_ASK => self.probe_should_tell = true,
                KCP_CMD_WND_TELL => {}
                _ => unreachable!(),
            }
            data = &data[len..];
        }
        if has_ack {
            self.increase_skip_acks(sn_max_ack, ts_max_ack);
        }
        Ok(prev_len - data.len())
    }

    fn remove_invalid_resends(&mut self) {
        while !self.resends.is_empty() {
            let resend = self.resends.peek().unwrap();
            if let Some(seg) = resend.seg.upgrade() {
                if seg.borrow().ts_resend == resend.ts {
                    break;
                }
            }
            self.resends.pop();
        }
    }

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

    fn update_snd_buf(&mut self) {
        let cwnd = min(self.snd_wnd, self.rmt_wnd);
        while self.snd_nxt < self.snd_una + cwnd as u32 && !self.snd_queue.is_empty() {
            let mut seg = self.snd_queue.pop_front().unwrap();
            seg.conv = self.conv;
            seg.cmd = KCP_CMD_PUSH;
            seg.sn = self.snd_nxt;
            self.snd_nxt += 1;
            seg.ts_resend = 0;
            seg.rto = self.rto;
            seg.skip_acks = 0;
            seg.send_attempts = 0;
            let seg = Rc::new(RefCell::new(seg));
            self.resends.push(ResendSegment {
                ts: 0,
                seg: Rc::downgrade(&seg),
            });
            self.snd_buf.push_back(seg);
        }
    }

    fn poll_segment(&mut self) -> Option<Rc<RefCell<KcpSegment>>> {
        if let Some((sn, ts)) = self.ack_list.pop_front() {
            let mut seg = KcpSegment::with_data(BytesMut::new());
            seg.conv = self.conv;
            seg.cmd = KCP_CMD_ACK;
            seg.sn = sn;
            seg.ts = ts;
            Some(Rc::new(RefCell::new(seg)))
        } else if self.probe_should_ask {
            let mut seg = KcpSegment::with_data(BytesMut::new());
            seg.conv = self.conv;
            seg.cmd = KCP_CMD_WND_ASK;
            self.probe_should_ask = false;
            Some(Rc::new(RefCell::new(seg)))
        } else if self.probe_should_tell {
            let mut seg = KcpSegment::with_data(BytesMut::new());
            seg.conv = self.conv;
            seg.cmd = KCP_CMD_WND_TELL;
            self.probe_should_tell = false;
            Some(Rc::new(RefCell::new(seg)))
        } else {
            self.remove_invalid_resends();
            if !self.resends.is_empty() {
                let seg = self.resends.peek().unwrap().seg.upgrade().unwrap();
                if seg.borrow().ts_resend <= self.current {
                    self.resends.pop();
                    return Some(seg);
                }
            }
            None
        }
    }

    pub fn output(&mut self) -> Option<Bytes> {
        self.update_probe();
        self.update_snd_buf();
        let mut seg_rc = self.poll_segment()?;
        self.buffer.clear();
        loop {
            {
                let mut seg = seg_rc.borrow_mut();
                seg.ts = self.current;
                seg.wnd = self.rcv_wnd.saturating_sub(self.rcv_queue.len() as u16);
                seg.una = self.rcv_nxt;
                seg.encode(&mut self.buffer);
                if seg.cmd == KCP_CMD_PUSH {
                    // Add next to resend
                    if seg.send_attempts == 0 {
                        seg.rto = self.rto;
                        let rto_min = if self.nodelay { 0 } else { self.rto_min >> 3 };
                        seg.ts_resend = self.current + rto_min + seg.rto;
                        log::debug!("scheduled resend time {}", seg.ts_resend);
                    } else {
                        seg.rto = if self.nodelay {
                            max(seg.rto, self.rto)
                        } else {
                            seg.rto + seg.rto / 2
                        };
                        seg.ts_resend = self.current + seg.rto;
                        log::debug!("scheduled resend time {}", seg.ts_resend);
                    }
                    seg.send_attempts += 1;
                    self.resends.push(ResendSegment {
                        ts: seg.ts_resend,
                        seg: Rc::downgrade(&seg_rc),
                    });
                }
            }
            if let Some(nxt) = self.poll_segment() {
                if self.buffer.len() + nxt.borrow().len() + KCP_OVERHEAD as usize
                    <= self.mtu as usize
                {
                    seg_rc = nxt;
                    continue;
                }
            }
            break;
        }
        Some(Bytes::copy_from_slice(&self.buffer))
    }

    pub fn update(&mut self, current: u32) {
        self.current = current;
        self.update_probe();
        self.update_snd_buf();
    }

    pub fn check(&mut self) -> u32 {
        self.remove_invalid_resends();
        self.resends
            .peek()
            .map(|r| r.ts)
            .unwrap_or(u32::max_value())
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
        self.rcv_wnd = max(recv, KCP_MAX_FRAGMENTS);
    }

    pub fn set_rto_min(&mut self, rto_min: u32) {
        self.rto_min = rto_min;
    }

    pub fn rto_min(&self) -> u32 {
        self.rto_min
    }

    pub fn set_rto(&mut self, rto: u32) {
        self.rto = rto;
    }

    pub fn rto(&self) -> u32 {
        self.rto
    }

    pub fn conv(&self) -> u32 {
        self.conv
    }

    pub fn conv_from_raw(buf: &[u8]) -> u32 {
        u32::from_le_bytes(buf[..4].try_into().unwrap())
    }
}

pub fn test() {}
