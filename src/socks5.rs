/*
Copyright 2021 Chengyuan Ma

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

use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::io::{Error, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use thiserror::Error;
use tokio::net::TcpStream;

pub const SOCKS5_VERSION: u8 = 0x05;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN_NAME: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

#[derive(Debug, Error)]
pub enum Socks5ParseError {
    #[error("invalid message length")]
    InvalidLength,
    #[error("invalid protocol: {0}")]
    InvalidProtocol(u8),
    #[error("invalid request command: {0}")]
    InvalidCommand(u8),
    #[error("invalid error code: {0}")]
    InvalidErrorCode(u8),
}

type Result<T> = std::result::Result<T, Socks5ParseError>;

#[derive(Debug, Clone, Copy, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum Socks5Command {
    Connect = 1,
    Bind = 2,
    UdpAssociate = 3,
}

#[derive(Debug, Clone, Copy, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum Socks5Error {
    GeneralServerFailure = 1,
    ConnectionNotAllowed = 2,
    NetworkUnreachable = 3,
    HostUnreachable = 4,
    ConnectionRefused = 5,
    TtlExpired = 6,
    CommandNotSupported = 7,
    AddressTypeNotSupported = 8,
}

impl From<Error> for Socks5Error {
    fn from(err: Error) -> Self {
        match err.kind() {
            ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset => Socks5Error::ConnectionRefused,
            ErrorKind::AddrInUse | ErrorKind::AddrNotAvailable | ErrorKind::TimedOut => {
                Socks5Error::HostUnreachable
            }
            _ => Socks5Error::GeneralServerFailure,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Socks5Addr {
    Ip(IpAddr),
    Hostname(String),
}

impl Socks5Addr {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.is_empty() {
            return Err(Socks5ParseError::InvalidLength);
        }
        let ret: Socks5Addr;
        match buf[0] {
            ATYP_IPV4 if buf.len() == 5 => {
                let octets: [u8; 4] = buf[1..].try_into().unwrap();
                ret = Socks5Addr::Ip(IpAddr::from(octets));
            }
            ATYP_IPV6 if buf.len() == 17 => {
                let octets: [u8; 16] = buf[1..].try_into().unwrap();
                ret = Socks5Addr::Ip(IpAddr::from(octets));
            }
            ATYP_DOMAIN_NAME if buf.len() >= 2 && buf.len() == (2 + buf[1]) as usize => {
                let domain = String::from_utf8_lossy(&buf[2..(2 + buf[1]) as usize]);
                ret = Socks5Addr::Hostname(domain.parse().unwrap());
            }
            _ => return Err(Socks5ParseError::InvalidLength),
        }
        Ok(ret)
    }

    pub fn marshal(&self) -> Vec<u8> {
        let mut ret: Vec<u8>;
        match self {
            Socks5Addr::Ip(IpAddr::V4(ipv4)) => {
                ret = Vec::with_capacity(5);
                ret.push(ATYP_IPV4);
                ret.extend_from_slice(&ipv4.octets());
            }
            Socks5Addr::Ip(IpAddr::V6(ipv6)) => {
                ret = Vec::with_capacity(17);
                ret.push(ATYP_IPV6);
                ret.extend_from_slice(&ipv6.octets());
            }
            Socks5Addr::Hostname(str) => {
                let lossy = str.as_bytes();
                ret = Vec::with_capacity(2 + lossy.len());
                ret.push(ATYP_DOMAIN_NAME);
                ret.push(lossy.len() as u8);
                ret.extend_from_slice(lossy);
            }
        }
        ret
    }
}

impl fmt::Display for Socks5Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Socks5Addr::Ip(ip) => write!(f, "{}", ip),
            Socks5Addr::Hostname(hostname) => write!(f, "{}", hostname),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Socks5SocketAddr {
    pub addr: Socks5Addr,
    pub port: u16,
}

impl Socks5SocketAddr {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 2 {
            return Err(Socks5ParseError::InvalidLength);
        }
        Ok(Socks5SocketAddr {
            addr: Socks5Addr::parse(&buf[..buf.len() - 2])?,
            port: u16::from_be_bytes(buf[buf.len() - 2..].try_into().unwrap()),
        })
    }

    pub fn marshal(&self) -> Vec<u8> {
        let mut ret: Vec<u8> = self.addr.marshal();
        ret.extend(&self.port.to_be_bytes());
        ret
    }

    pub async fn connect(&self) -> tokio::io::Result<TcpStream> {
        match &self.addr {
            Socks5Addr::Ip(ip) => TcpStream::connect((*ip, self.port)).await,
            Socks5Addr::Hostname(hostname) => {
                TcpStream::connect((hostname.as_str(), self.port)).await
            }
        }
    }
}

impl From<SocketAddr> for Socks5SocketAddr {
    fn from(socket_addr: SocketAddr) -> Self {
        Socks5SocketAddr {
            addr: Socks5Addr::Ip(socket_addr.ip()),
            port: socket_addr.port(),
        }
    }
}

impl fmt::Display for Socks5SocketAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.addr, self.port)
    }
}

#[derive(Debug, Clone)]
pub struct Socks5Request {
    pub cmd: Socks5Command,
    pub dst: Socks5SocketAddr,
}

impl Socks5Request {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() <= 3 {
            return Err(Socks5ParseError::InvalidLength);
        }
        if buf[0] != SOCKS5_VERSION {
            return Err(Socks5ParseError::InvalidProtocol(buf[0]));
        }
        Ok(Socks5Request {
            cmd: Socks5Command::try_from(buf[1])
                .map_err(|_| Socks5ParseError::InvalidCommand(buf[1]))?,
            dst: Socks5SocketAddr::parse(&buf[3..])?,
        })
    }

    pub fn marshal(&self) -> Vec<u8> {
        let mut ret = vec![SOCKS5_VERSION, self.cmd.into(), 0];
        ret.extend(self.dst.marshal());
        ret
    }
}

#[derive(Debug, Clone)]
pub enum Socks5Reply {
    Error(Socks5Error),
    Success { bnd: Socks5SocketAddr },
}

impl Socks5Reply {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() <= 3 {
            return Err(Socks5ParseError::InvalidLength);
        }
        if buf[0] != SOCKS5_VERSION {
            return Err(Socks5ParseError::InvalidProtocol(buf[0]));
        }
        Ok(if buf[1] == 0 {
            Socks5Reply::Success {
                bnd: Socks5SocketAddr::parse(&buf[3..])?,
            }
        } else {
            Socks5Reply::Error(
                Socks5Error::try_from(buf[1])
                    .map_err(|_| Socks5ParseError::InvalidErrorCode(buf[1]))?,
            )
        })
    }

    pub fn marshal(&self) -> Vec<u8> {
        match self {
            Socks5Reply::Error(code) => {
                vec![SOCKS5_VERSION, (*code).into(), 0, 0x01, 0, 0, 0, 0, 0, 0]
            }
            Socks5Reply::Success { bnd } => {
                let mut ret = vec![SOCKS5_VERSION, 0, 0];
                ret.extend(bnd.marshal());
                ret
            }
        }
    }
}

pub struct Socks5UdpEncapsulation {
    pub frag: u8,
    pub dst: Socks5SocketAddr,
    pub data: Vec<u8>,
}

impl Socks5UdpEncapsulation {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() <= 4 {
            return Err(Socks5ParseError::InvalidLength);
        }
        let frag = buf[2];
        let addr_len = match buf[3] {
            ATYP_IPV4 => 5,
            ATYP_IPV6 => 17,
            ATYP_DOMAIN_NAME => buf[4] as usize + 2,
            _ => return Err(Socks5ParseError::InvalidLength),
        };
        let dst = Socks5SocketAddr::parse(&buf[3..3 + addr_len])?;
        let data = Vec::from(&buf[3 + addr_len..]);
        Ok(Socks5UdpEncapsulation { frag, dst, data })
    }

    pub fn marshal(&self) -> Vec<u8> {
        let mut ret = vec![0, 0, self.frag];
        ret.extend(self.dst.marshal());
        ret.extend(&self.data);
        ret
    }
}
