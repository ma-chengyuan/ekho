use crate::icmp::IcmpEndpoint;
use chacha20poly1305::Key;
use once_cell::sync::OnceCell;
use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt;
use std::path::Path;

#[derive(Deserialize, Debug)]
pub struct Config {
    #[serde(default)]
    pub remote: Option<IcmpEndpoint>,
    pub kcp: KcpConfig,
    #[serde(deserialize_with = "deserialize_key")]
    pub key: Key,
}

#[derive(Deserialize, Debug)]
pub struct KcpConfig {
    pub mtu: u32,
    pub nodelay: bool,
    pub interval: u32,
    pub resend: u32,
    pub bbr: bool,
    pub rto_min: u32,
    #[serde(default = "default_bdp_gain")]
    pub bdp_gain: f64,
    #[serde(default = "default_kcp_send_window_size")]
    pub send_window_size: u16,
    #[serde(default = "default_kcp_recv_window_size")]
    pub recv_window_size: u16,
}

static CONFIG: OnceCell<Config> = OnceCell::new();

const fn default_kcp_send_window_size() -> u16 {
    2048
}

const fn default_kcp_recv_window_size() -> u16 {
    2048
}

const fn default_bdp_gain() -> f64 {
    1.25
}

fn deserialize_key<'de, D: Deserializer<'de>>(d: D) -> Result<Key, D::Error> {
    struct HexKeyVisitor;
    impl<'de> Visitor<'de> for HexKeyVisitor {
        type Value = Key;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "a length-64 hex string describing the key")
        }

        fn visit_str<E: Error>(self, v: &str) -> Result<Self::Value, E> {
            let bytes = hex::decode(v).map_err(E::custom)?;
            Ok(Key::from_exact_iter(bytes).ok_or_else(|| E::custom("wrong key length"))?)
        }
    }
    d.deserialize_any(HexKeyVisitor)
}

pub fn get_config() -> &'static Config {
    CONFIG.get().expect("config not initialized")
}

pub fn load_config_from_file(path: impl AsRef<Path>) {
    let content = std::fs::read_to_string(path).expect("cannot find specified config file");
    let config = toml::from_str(&content).expect("error parsing config file");
    CONFIG
        .set(config)
        .expect("error setting OnceCell for Config");
}
