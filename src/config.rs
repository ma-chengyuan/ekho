use crate::icmp::Endpoint;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    #[serde(default)]
    pub remote: Option<Endpoint>,
    pub conv: u32,

    pub kcp: KcpConfig,
    pub icmp: IcmpConfig,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KcpConfig {
    #[serde(default = "default_kcp_update_interval")]
    pub scheduler_interval: u32,
    pub mtu: usize,
    pub nodelay: bool,
    pub interval: u32,
    pub resend: u32,
    pub flow_control: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IcmpConfig {
    #[serde(default = "default_icmp_recv_buffer_size")]
    pub recv_buffer_size: usize,
    #[serde(default = "default_icmp_send_buffer_size")]
    pub send_buffer_size: usize,
}

static CONFIG: OnceCell<Config> = OnceCell::new();

const fn default_icmp_recv_buffer_size() -> usize {
    4096
}

const fn default_icmp_send_buffer_size() -> usize {
    10
}

const fn default_kcp_update_interval() -> u32 {
    5
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
