use tokio::io::{AsyncRead, AsyncWrite, Result, Error, ErrorKind};
use bytes::{BytesMut, BufMut};
use pin_project_lite::pin_project;
use std::task::Context;
use tokio::macros::support::{Pin, Poll};
use std::cmp::min;

const LOG_BLOCK_SIZE: usize = 8;
pub const BLOCK_SIZE: usize = 1 << LOG_BLOCK_SIZE;
const PRIME: i32 = 257;
const INV: [usize; BLOCK_SIZE] = [
    0, 128, 64, 192, 32, 160, 96, 224, 16, 144, 80, 208, 48, 176, 112, 240,
    8, 136, 72, 200, 40, 168, 104, 232, 24, 152, 88, 216, 56, 184, 120, 248,
    4, 132, 68, 196, 36, 164, 100, 228, 20, 148, 84, 212, 52, 180, 116, 244,
    12, 140, 76, 204, 44, 172, 108, 236, 28, 156, 92, 220, 60, 188, 124, 252,
    2, 130, 66, 194, 34, 162, 98, 226, 18, 146, 82, 210, 50, 178, 114, 242,
    10, 138, 74, 202, 42, 170, 106, 234, 26, 154, 90, 218, 58, 186, 122, 250,
    6, 134, 70, 198, 38, 166, 102, 230, 22, 150, 86, 214, 54, 182, 118, 246,
    14, 142, 78, 206, 46, 174, 110, 238, 30, 158, 94, 222, 62, 190, 126, 254,
    1, 129, 65, 193, 33, 161, 97, 225, 17, 145, 81, 209, 49, 177, 113, 241,
    9, 137, 73, 201, 41, 169, 105, 233, 25, 153, 89, 217, 57, 185, 121, 249,
    5, 133, 69, 197, 37, 165, 101, 229, 21, 149, 85, 213, 53, 181, 117, 245,
    13, 141, 77, 205, 45, 173, 109, 237, 29, 157, 93, 221, 61, 189, 125, 253,
    3, 131, 67, 195, 35, 163, 99, 227, 19, 147, 83, 211, 51, 179, 115, 243,
    11, 139, 75, 203, 43, 171, 107, 235, 27, 155, 91, 219, 59, 187, 123, 251,
    7, 135, 71, 199, 39, 167, 103, 231, 23, 151, 87, 215, 55, 183, 119, 247,
    15, 143, 79, 207, 47, 175, 111, 239, 31, 159, 95, 223, 63, 191, 127, 255
];
const OMEGA: [i32; LOG_BLOCK_SIZE] = [256, 241, 64, 249, 136, 81, 9, 3];
const OMEGA_INV: [i32; LOG_BLOCK_SIZE] = [256, 16, 253, 32, 240, 165, 200, 86];
const BLOCK_SIZE_INV: i32 = 256;

fn ntt_raw(x: &mut [i32; BLOCK_SIZE], omega: &[i32; LOG_BLOCK_SIZE]) {
    for (h, w_) in omega.iter().enumerate() {
        let half = 1 << h;
        let len = half << 1;
        for i in (0..BLOCK_SIZE).step_by(len) {
            let mut w = 1;
            for j in i..(i + half) {
                let t = w * x[j + half];
                x[j + half] = (x[j] - t) % PRIME;
                x[j] = (x[j] + t) % PRIME;
                w = w * w_ % PRIME;
            }
        }
    }
    for y in x.iter_mut() {
        if *y < 0 {
            *y += PRIME;
        }
    }
}

pub fn ntt(block: &[u8]) -> BytesMut {
    if block.len() >= BLOCK_SIZE {
        panic!("NTT block too long: expected less than {}, found {}", BLOCK_SIZE, block.len())
    }
    let mut x = [0; BLOCK_SIZE];
    x[0] = block.len() as i32;
    for (i, &y) in block.iter().enumerate() {
        x[INV[i + 1]] = y as i32;
    }
    ntt_raw(&mut x, &OMEGA);
    let mut ret = BytesMut::with_capacity(2 * BLOCK_SIZE);
    ret.put_u8(0);
    for (i, y) in x.iter_mut().enumerate() {
        if *y == (PRIME - 1) as i32 {
            ret[0] += 1;
            *y = 0;
            ret.put_u8(i as u8);
        }
    }
    ret.extend(x.iter().map(|&x| x as u8));
    ret
}

pub fn intt(block: &[u8]) -> BytesMut {
    let overflow = *block.first().expect("empty INTT block");
    if block.len() != 1 + overflow as usize + BLOCK_SIZE {
        panic!("wrong INTT block length: expected {}, found {}",
               1 + overflow as usize + BLOCK_SIZE, block.len())
    }
    let mut x: [i32; BLOCK_SIZE] = [0; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        x[INV[i]] = block[1 + overflow as usize + i] as i32;
    }
    for &i in block[1..1 + overflow as usize].iter() {
        x[INV[i as usize]] += 256;
    }
    ntt_raw(&mut x, &OMEGA_INV);
    for y in x.iter_mut() {
        *y = *y * BLOCK_SIZE_INV % PRIME;
    }
    let len = x[0] as usize;
    if len >= BLOCK_SIZE {
        panic!("inner block size too large, expected less than {}, found {}", BLOCK_SIZE, len)
    }
    let mut ret = BytesMut::with_capacity(len);
    ret.extend(x[1..1 + len].iter().map(|&x| x as u8));
    ret
}

fn has_full_ntt_block(buf: &BytesMut) -> bool {
    !buf.is_empty() && buf.len() >= 1 + BLOCK_SIZE + buf[0] as usize
}

pin_project! {
    /// Wrapper over some reader or writer to automatically do NTT when reading / writing.
    ///
    /// Implements `AsyncRead` if the underlying type implements `AsyncRead`.
    ///
    /// Implements `AsyncWrite` if the underlying type implements `AsyncWrite`.
    pub struct NTTStream<T> {
        #[pin]
        inner: T,
        read_raw: BytesMut,
        read_buf: BytesMut,
        write_buf: BytesMut
    }
}

const NTT_READ_RAW_CAPACITY: usize = 4 * 2 * BLOCK_SIZE;
const NTT_READ_RAW_CAPACITY_MAX: usize = 16 * 2 * BLOCK_SIZE;

impl<T> NTTStream<T> {
    /// Creates an `NTTStream` by providing a reader / writer it wraps.
    pub fn new(inner: T) -> Self {
        NTTStream {
            inner,
            read_raw: BytesMut::with_capacity(NTT_READ_RAW_CAPACITY),
            read_buf: BytesMut::with_capacity(BLOCK_SIZE),
            write_buf: BytesMut::with_capacity(2 * BLOCK_SIZE)
        }
    }
}

impl<T> AsyncRead for NTTStream<T> where T: AsyncRead {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<usize>> {
        let mut read = 0;
        let mut this = self.project();
        let buf_len = buf.len();
        if !this.read_buf.is_empty() { // If we have left some unread decoded bytes, read it first
            let len = min(buf_len, this.read_buf.len());
            buf[..len].copy_from_slice(&this.read_buf.split_to(len));
            read += len;
            if read == buf_len { // Return if the buffer is filled up
                return Poll::Ready(Ok(read));
            }
        }
        debug_assert!(this.read_buf.is_empty());
        while !has_full_ntt_block(this.read_raw) { // Try to get at least one complete NTT block
            match this.inner.as_mut().poll_read_buf(cx, &mut this.read_raw) {
                Poll::Pending => return Poll::Pending, // Forward pending
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)), // Forward error
                Poll::Ready(Ok(0)) => return Poll::Ready(if this.read_raw.is_empty() {
                    Ok(0) // If haven't read any partial INTT block, then EOF is acceptable
                } else {
                    // Otherwise we have EOF in the middle of a NTT block, which is bad
                    Err(Error::new(ErrorKind::UnexpectedEof, "incomplete NTT block"))
                }),
                _ => continue
            }
        }
        debug_assert!(has_full_ntt_block(this.read_raw));
        while has_full_ntt_block(this.read_raw) { // Time to decode the block and fill buf
            let len = 1 + BLOCK_SIZE + this.read_raw[0] as usize;
            let mut res = intt(&this.read_raw.split_to(len));
            if read + res.len() <= buf_len { // If we can append the whole res to buf, append it
                buf[read..read + res.len()].copy_from_slice(&res);
                read += res.len();
            } else {
                buf[read..].copy_from_slice(&res.split_to(buf_len - read));
                *this.read_buf = res; // Buffer the unread part of res to be read next time
                read = buf_len;
            }
        }
        // BytesMut always refers to a slice of contiguous memory, therefore, if we keep appending
        // data to it, the underlying memory slice might one day become too long. Thus, we have to
        // reallocate the memory regularly when the capacity of the BytesMut exceeds a certain
        // threshold
        if this.read_raw.capacity() > NTT_READ_RAW_CAPACITY_MAX {
            let mut new_buf = BytesMut::with_capacity(NTT_READ_RAW_CAPACITY);
            new_buf.extend_from_slice(&this.read_raw);
            *this.read_raw = new_buf
        }
        Poll::Ready(Ok(read))
    }
}

impl<T> AsyncWrite for NTTStream<T> where T: AsyncWrite {
    /// **WARNING:** You should best set the buffer size to multiples of (`BLOCK_SIZE` - 1) (which is
    /// 255 bytes), otherwise the output may bloat considerably.
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
        let mut this = self.project();
        while !this.write_buf.is_empty() { // If there are an unwritten partial NTT block, write them first
            let res = this.inner.as_mut().poll_write_buf(cx, &mut this.write_buf);
            if let Poll::Pending | Poll::Ready(Err(_)) | Poll::Ready(Ok(0)) = res {
                return res; // Forward pending, error, or EOF
            }
        }
        debug_assert!(this.write_buf.is_empty());
        let mut written = 0;
        while written < buf.len() {
            // The encapsulated data in an NTT block must have size at most BLOCK_SIZE - 1
            let len = min(buf.len() - written, BLOCK_SIZE - 1);
            let mut res = ntt(&buf[written..written + len]);
            written += len;
            match this.inner.as_mut().poll_write_buf(cx, &mut res) {
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)), // Forward error
                // Forward EOF, but only when this is the first piece of data we are trying to write
                Poll::Ready(Ok(0)) if written == len => return Poll::Ready(Ok(0)),
                _ => if !res.is_empty() { // Otherwise, leave unwritten part of res in the buffer
                    *this.write_buf = res;
                    break;
                }
            }
        }
        Poll::Ready(Ok(written))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let mut this = self.project();
        while !this.write_buf.is_empty() { // Flush internal buffer
            match this.inner.as_mut().poll_write_buf(cx, &mut this.write_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => break,
                _ => continue
            }
        }
        this.inner.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let res = self.as_mut().poll_flush(cx);
        if let Poll::Pending | Poll::Ready(Err(_)) = res {
            return res;
        }
        self.project().inner.as_mut().poll_shutdown(cx)
    }
}