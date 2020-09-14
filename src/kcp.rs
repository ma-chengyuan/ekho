#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(clippy::type_complexity)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use bytes::{Bytes, BytesMut};
use crossbeam_channel::Sender;
use lazy_static::lazy_static;
use once_cell::sync::OnceCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::io::{Error, ErrorKind, Read, Result};
use std::os::raw::{c_char, c_int, c_long, c_void};
use std::ptr::slice_from_raw_parts;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

//==================================================================================================
//                                Wrapper around the unsafe C FFI
//==================================================================================================

unsafe extern "C" fn output_callback(
    buf: *const c_char,
    len: c_int,
    kcp: *mut ikcpcb,
    user: *mut c_void,
) -> c_int {
    let obj = user as *mut KCPControlBlock;
    assert_ne!(obj, std::ptr::null_mut());
    assert_eq!(kcp, (*obj).inner);
    let bytes = Bytes::copy_from_slice(&*slice_from_raw_parts(buf as *const u8, len as usize));
    (*obj).sender.send(bytes).unwrap();
    len
}

pub fn get_conv(block: &[u8]) -> u32 {
    unsafe { ikcp_getconv(block.as_ptr() as *const c_void) }
}

/// A thin wrapper above KCP
#[derive(Debug)]
pub struct KCPControlBlock {
    inner: *mut ikcpcb,
    sender: Sender<Bytes>,
}

unsafe impl Send for KCPControlBlock {}

unsafe impl Sync for KCPControlBlock {}

impl KCPControlBlock {
    pub fn new_with_sender(conv: u32, sender: Sender<Bytes>) -> Box<KCPControlBlock> {
        let mut ret = Box::new(KCPControlBlock {
            inner: std::ptr::null_mut(),
            sender,
        });
        ret.inner = unsafe {
            ikcp_create(
                conv as IUINT32,
                &mut *ret as *mut KCPControlBlock as *mut c_void,
            )
        };
        unsafe { ikcp_setoutput(ret.inner, Some(output_callback)) };
        ret
    }

    pub fn new(conv: u32) -> Box<KCPControlBlock> {
        Self::new_with_sender(conv, crate::icmp::get_sender())
    }

    pub fn conv(&self) -> u32 {
        unsafe { (*self.inner).conv }
    }

    pub fn check(&self, time: u32) -> u32 {
        unsafe { ikcp_check(self.inner, time as IUINT32) }
    }

    pub fn update(&mut self, time: u32) {
        unsafe {
            ikcp_update(self.inner, time as IUINT32);
        }
    }

    pub fn input(&mut self, data: &[u8]) {
        unsafe {
            ikcp_input(
                self.inner,
                data.as_ptr() as *const c_char,
                data.len() as c_long,
            );
        }
    }

    pub fn peek_size(&self) -> i32 {
        unsafe { ikcp_peeksize(self.inner) as i32 }
    }

    pub fn set_mtu(&mut self, mtu: usize) {
        unsafe {
            ikcp_setmtu(self.inner, mtu as c_int);
        }
    }

    pub fn set_window_size(&mut self, send: u32, recv: u32) {
        unsafe {
            ikcp_wndsize(self.inner, send as c_int, recv as c_int);
        }
    }

    pub fn set_nodelay(&mut self, nodelay: bool, interval: u32, resend: u32, nc: bool) {
        let _ = unsafe {
            ikcp_nodelay(
                self.inner,
                nodelay as c_int,
                interval as c_int,
                resend as c_int,
                nc as c_int,
            )
        };
    }

    pub fn send(&mut self, data: &[u8]) -> i32 {
        unsafe {
            ikcp_send(
                self.inner,
                data.as_ptr() as *const c_char,
                data.len() as c_int,
            ) as i32
        }
    }

    pub fn recv(&mut self, buf: &mut [u8]) -> i32 {
        unsafe {
            ikcp_recv(
                self.inner,
                buf.as_mut_ptr() as *mut c_char,
                buf.len() as c_int,
            ) as i32
        }
    }
}

impl Drop for KCPControlBlock {
    fn drop(&mut self) {
        unsafe { ikcp_release(self.inner) };
    }
}

//==================================================================================================
//                                     KCP Update Scheduling
//==================================================================================================

#[derive(Debug, Clone)]
struct KCPSchedulerRef(Arc<Mutex<Box<KCPControlBlock>>>);

impl Eq for KCPSchedulerRef {}

impl PartialEq for KCPSchedulerRef {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Hash for KCPSchedulerRef {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.0).hash(state);
    }
}

const UPDATE_CHECK_INTERVAL: Duration = Duration::from_millis(5);
lazy_static! {
    /// Maintain an ordered surjection from KCP control blocks to their next update time
    static ref UPDATE_SCHEDULE: Mutex<(
        BTreeMap<u32, HashSet<KCPSchedulerRef>>,
        HashMap<KCPSchedulerRef, u32>,
    )> = Default::default();
}

fn schedule_update_internal(
    target: Arc<Mutex<Box<KCPControlBlock>>>,
    time: u32,
    time_to_updates: &mut BTreeMap<u32, HashSet<KCPSchedulerRef>>,
    update_to_time: &mut HashMap<KCPSchedulerRef, u32>,
) {
    let key = KCPSchedulerRef(target);
    // If its update has already been scheduled, then remove that scheduled update
    if let Some(prev) = update_to_time.get(&key) {
        time_to_updates.get_mut(prev).unwrap().remove(&key);
        if time_to_updates.get(prev).unwrap().is_empty() {
            time_to_updates.remove(prev);
        }
    }
    time_to_updates.entry(time).or_default().insert(key.clone());
    update_to_time.insert(key, time);
}

pub fn schedule_immediate_update(target: Arc<Mutex<Box<KCPControlBlock>>>) {
    let mut guard = UPDATE_SCHEDULE.lock().unwrap();
    let (time_to_updates, update_to_time) = &mut *guard;
    schedule_update_internal(target, 0, time_to_updates, update_to_time);
}

pub fn init_kcp_update_thread() {
    thread::spawn(|| loop {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u32;
        let mut to_be_updated = vec![];
        {
            let mut guard = UPDATE_SCHEDULE.lock().unwrap();
            let (time_to_updates, update_to_time) = &mut *guard;
            for (&time, updates) in time_to_updates.iter() {
                if time > now {
                    break;
                }
                to_be_updated.extend(updates.iter().cloned());
            }
            for update in to_be_updated {
                let mut kcp = update.0.lock().unwrap();
                kcp.update(now);
                schedule_update_internal(
                    update.0.clone(),
                    kcp.check(now),
                    time_to_updates,
                    update_to_time,
                );
            }
        }
        thread::sleep(UPDATE_CHECK_INTERVAL);
    });
}

//==================================================================================================
//                                    Connection Management
//==================================================================================================

#[derive(Copy, Clone, Debug)]
struct KCPConfig {
    nodelay: bool,
    interval: u32,
    resend: u32,
    flow_control: bool,
}

lazy_static! {
    static ref CONNECTION_STATE: Mutex<HashMap<u32, Arc<Mutex<Box<KCPControlBlock>>>>> =
        Default::default();
}

struct KCPConnection {
    control: Arc<Mutex<Box<KCPControlBlock>>>,
}

impl KCPConnection {
    pub fn new(conv: u32, config: KCPConfig) -> Result<KCPConnection> {
        let mut state = CONNECTION_STATE.lock().unwrap();
        if state.contains_key(&conv) {
            return Err(Error::from(ErrorKind::AddrInUse));
        }
        let control = Arc::new(Mutex::new(KCPControlBlock::new(conv)));
        control.lock().unwrap().set_nodelay(
            config.nodelay,
            config.interval,
            config.resend,
            !config.flow_control,
        );
        state.insert(conv, control.clone());
        Ok(KCPConnection { control })
    }

    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        let ret = self.control.lock().unwrap().send(data);
        if ret < 0 {
            return Err(Error::new(
                ErrorKind::Other,
                format!("KCP internal error {}", ret),
            ));
        }
        schedule_immediate_update(self.control.clone());
        Ok(())
    }

    pub fn try_recv(&mut self) -> Option<Bytes> {
        let mut control = self.control.lock().unwrap();
        let size = control.peek_size();
        if size < 0 {
            None
        } else {
            let mut ret = BytesMut::with_capacity(size as usize);
            control.recv(ret.as_mut());
            Some(Bytes::from(ret))
        }
    }
}

impl Drop for KCPConnection {
    fn drop(&mut self) {
        let mut state = CONNECTION_STATE.lock().unwrap();
        state.remove(&self.control.lock().unwrap().conv());
    }
}

pub fn handle_kcp_packet(packet: &[u8]) {
    let state = CONNECTION_STATE.lock().unwrap();
    let conv = get_conv(packet);
    if let Some(control) = state.get(&conv) {
        control.lock().unwrap().input(packet);
        schedule_immediate_update(control.clone());
    }
}
