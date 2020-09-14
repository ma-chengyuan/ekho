use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::Path;

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub dest_ip: Ipv4Addr,

    #[serde(default = "default_layer4_buffer")]
    pub layer4_buffer: usize,
}

static CONFIG: OnceCell<Config> = OnceCell::new();

const fn default_layer4_buffer() -> usize {
    4096
}

pub fn get_config() -> &'static Config {
    CONFIG.get().expect("config not initialized")
}

pub fn load_config_from_file(path: impl AsRef<Path>) {
    let content = std::fs::read_to_string(path).expect("cannot find specified config file");
    let config = toml::from_str(&content).expect("error parsing config json");
    CONFIG
        .set(config)
        .expect("error setting OnceCell for Config");
}
