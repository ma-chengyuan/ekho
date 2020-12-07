use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::net::IpAddr;

const SOCKS5_VERSION: u8 = 5;
const EKHO_VERSION: u8 = 39; // ('E' + 'K' + 'H' + 'O') % 256

#[derive(Debug, Clone)]
enum ParseError {
    WrongLength,
    WrongProtocolVersion(u8, u8),
    UnknownCommand(u8),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::WrongLength => write!(f, "wrong buffer length"),
            ParseError::WrongProtocolVersion(expected, found) => {
                write!(
                    f,
                    "wrong protocol version: {} (expected {})",
                    found, expected
                )
            }
            ParseError::UnknownCommand(found) => write!(f, "unknown request command: {}", found),
        }
    }
}

#[derive(Debug, Clone, Copy, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
enum RequestCommand {
    Connect = 1,
    Bind = 2,
    UdpAssociate = 3,
}

#[derive(Debug, Clone, Copy, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
enum ErrorCode {
    GeneralServerFailure = 1,
    ConnectionNotAllowed = 2,
    NetworkUnreachable = 3,
    HostUnreachable = 4,
    ConnectionRefused = 5,
    TtlExpired = 6,
    CommandNotSupported = 7,
    AddressTypeNotSupported = 8,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
enum Address {
    Ip(IpAddr),
    DomainName(String),
}

impl TryFrom<&[u8]> for Address {
    type Error = ParseError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        if buf.is_empty() {
            return Err(ParseError::WrongLength);
        }
        let ret: Address;
        match buf[0] {
            0x01 if buf.len() == 5 => {
                let octets: [u8; 4] = buf[1..].try_into().unwrap();
                ret = Address::Ip(IpAddr::from(octets));
            }
            0x04 if buf.len() == 17 => {
                let octets: [u8; 16] = buf[1..].try_into().unwrap();
                ret = Address::Ip(IpAddr::from(octets));
            }
            0x03 if buf.len() >= 2 && buf.len() == (2 + buf[1]) as usize => {
                let domain = String::from_utf8_lossy(&buf[2..(2 + buf[1]) as usize]);
                ret = Address::DomainName(domain.parse().unwrap());
            }
            _ => return Err(ParseError::WrongLength),
        }
        Ok(ret)
    }
}

impl From<&Address> for Vec<u8> {
    fn from(addr: &Address) -> Self {
        let mut ret: Vec<u8>;
        match addr {
            Address::Ip(IpAddr::V4(ipv4)) => {
                ret = Vec::with_capacity(5);
                ret.push(0x01);
                ret.extend_from_slice(&ipv4.octets());
            }
            Address::Ip(IpAddr::V6(ipv6)) => {
                ret = Vec::with_capacity(17);
                ret.push(0x04);
                ret.extend_from_slice(&ipv6.octets());
            }
            Address::DomainName(str) => {
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

#[derive(Debug, Clone)]
struct Request {
    cmd: RequestCommand,
    dst_addr: Address,
    dst_port: u16,
}

impl TryFrom<&[u8]> for Request {
    type Error = ParseError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        if buf.len() <= 3 {
            return Err(ParseError::WrongLength);
        }
        if buf[0] != SOCKS5_VERSION {
            return Err(ParseError::WrongProtocolVersion(SOCKS5_VERSION, buf[0]));
        }
        Ok(Request {
            cmd: RequestCommand::try_from(buf[1])
                .map_err(|_| ParseError::UnknownCommand(buf[1]))?,
            dst_addr: Address::try_from(&buf[3..buf.len() - 2])?,
            dst_port: u16::from_be_bytes(buf[buf.len() - 2..].try_into().unwrap()),
        })
    }
}

#[derive(Debug, Clone)]
enum Reply {
    Error(ErrorCode),
    Success { bnd_addr: Address, bnd_port: u16 },
}

impl From<&Reply> for Vec<u8> {
    fn from(reply: &Reply) -> Self {
        match reply {
            Reply::Error(code) => {
                vec![SOCKS5_VERSION, (*code).into(), 0, 0x01, 0, 0, 0, 0, 0, 0]
            }
            Reply::Success { bnd_addr, bnd_port } => {
                let mut ret = vec![SOCKS5_VERSION, 0, 0];
                ret.append(&mut Vec::<u8>::from(bnd_addr));
                ret.extend_from_slice(&bnd_port.to_be_bytes());
                ret
            }
        }
    }
}
