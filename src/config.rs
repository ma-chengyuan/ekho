use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::BufReader;
use std::net::Ipv4Addr;
use std::path::Path;

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub iface_name: String,
    pub dest_ip: Ipv4Addr,
}

static CONFIG: OnceCell<Config> = OnceCell::new();

pub fn get_config() -> &'static Config {
    CONFIG.get().expect("config not initialized")
}

pub fn load_config_from_file(path: impl AsRef<Path>) {
    let file = File::open(path).expect("cannot find specified config file");
    let buf = BufReader::new(file);
    let config = serde_json::from_reader(buf).expect("error parsing config json");
    CONFIG
        .set(config)
        .expect("error setting OnceCell for Config");
}
