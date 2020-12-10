use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::io::{Error, ErrorKind};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use thiserror::Error;

pub const SOCKS5_VERSION: u8 = 5;

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

impl TryFrom<&[u8]> for Socks5Addr {
    type Error = Socks5ParseError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        if buf.is_empty() {
            return Err(Socks5ParseError::InvalidLength);
        }
        let ret: Socks5Addr;
        match buf[0] {
            0x01 if buf.len() == 5 => {
                let octets: [u8; 4] = buf[1..].try_into().unwrap();
                ret = Socks5Addr::Ip(IpAddr::from(octets));
            }
            0x04 if buf.len() == 17 => {
                let octets: [u8; 16] = buf[1..].try_into().unwrap();
                ret = Socks5Addr::Ip(IpAddr::from(octets));
            }
            0x03 if buf.len() >= 2 && buf.len() == (2 + buf[1]) as usize => {
                let domain = String::from_utf8_lossy(&buf[2..(2 + buf[1]) as usize]);
                ret = Socks5Addr::Hostname(domain.parse().unwrap());
            }
            _ => return Err(Socks5ParseError::InvalidLength),
        }
        Ok(ret)
    }
}

impl From<&Socks5Addr> for Vec<u8> {
    fn from(addr: &Socks5Addr) -> Self {
        let mut ret: Vec<u8>;
        match addr {
            Socks5Addr::Ip(IpAddr::V4(ipv4)) => {
                ret = Vec::with_capacity(5);
                ret.push(0x01);
                ret.extend_from_slice(&ipv4.octets());
            }
            Socks5Addr::Ip(IpAddr::V6(ipv6)) => {
                ret = Vec::with_capacity(17);
                ret.push(0x04);
                ret.extend_from_slice(&ipv6.octets());
            }
            Socks5Addr::Hostname(str) => {
                let lossy = str.as_bytes();
                ret = Vec::with_capacity(2 + lossy.len());
                ret.push(0x03);
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

impl TryFrom<&[u8]> for Socks5SocketAddr {
    type Error = Socks5ParseError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        if buf.len() < 2 {
            return Err(Socks5ParseError::InvalidLength);
        }
        Ok(Socks5SocketAddr {
            addr: Socks5Addr::try_from(&buf[..buf.len() - 2])?,
            port: u16::from_be_bytes(buf[buf.len() - 2..].try_into().unwrap()),
        })
    }
}

impl From<&Socks5SocketAddr> for Vec<u8> {
    fn from(socket_addr: &Socks5SocketAddr) -> Self {
        let mut ret: Vec<u8> = (&socket_addr.addr).into();
        ret.extend(&socket_addr.port.to_be_bytes());
        ret
    }
}

impl ToSocketAddrs for Socks5SocketAddr {
    type Iter = std::vec::IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
        (self.addr.to_string(), self.port).to_socket_addrs()
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

impl TryFrom<&[u8]> for Socks5Request {
    type Error = Socks5ParseError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        if buf.len() <= 3 {
            return Err(Socks5ParseError::InvalidLength);
        }
        if buf[0] != SOCKS5_VERSION {
            return Err(Socks5ParseError::InvalidProtocol(buf[0]));
        }
        Ok(Socks5Request {
            cmd: Socks5Command::try_from(buf[1])
                .map_err(|_| Socks5ParseError::InvalidCommand(buf[1]))?,
            dst: Socks5SocketAddr::try_from(&buf[3..])?,
        })
    }
}

impl From<&Socks5Request> for Vec<u8> {
    fn from(request: &Socks5Request) -> Self {
        let mut ret = vec![SOCKS5_VERSION, request.cmd.into(), 0];
        ret.extend(Vec::<u8>::from(&request.dst));
        ret
    }
}

#[derive(Debug, Clone)]
pub enum Socks5Reply {
    Error(Socks5Error),
    Success { bnd: Socks5SocketAddr },
}

impl TryFrom<&[u8]> for Socks5Reply {
    type Error = Socks5ParseError;

    fn try_from(buf: &[u8]) -> Result<Self, Socks5ParseError> {
        if buf.len() <= 3 {
            return Err(Socks5ParseError::InvalidLength);
        }
        if buf[0] != SOCKS5_VERSION {
            return Err(Socks5ParseError::InvalidProtocol(buf[0]));
        }
        Ok(if buf[1] == 0 {
            Socks5Reply::Success {
                bnd: Socks5SocketAddr::try_from(&buf[3..])?,
            }
        } else {
            Socks5Reply::Error(
                Socks5Error::try_from(buf[1])
                    .map_err(|_| Socks5ParseError::InvalidErrorCode(buf[1]))?,
            )
        })
    }
}

impl From<&Socks5Reply> for Vec<u8> {
    fn from(reply: &Socks5Reply) -> Self {
        match reply {
            Socks5Reply::Error(code) => {
                vec![SOCKS5_VERSION, (*code).into(), 0, 0x01, 0, 0, 0, 0, 0, 0]
            }
            Socks5Reply::Success { bnd } => {
                let mut ret = vec![SOCKS5_VERSION, 0, 0];
                ret.append(&mut Vec::<u8>::from(bnd));
                ret
            }
        }
    }
}
