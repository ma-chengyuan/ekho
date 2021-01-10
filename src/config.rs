use crate::icmp::IcmpEndpoint;
use anyhow::{Context, Result};
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
    pub kcp: crate::kcp::Config,
    #[serde(deserialize_with = "deserialize_key")]
    pub key: Key,
}

static CONFIG: OnceCell<Config> = OnceCell::new();

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

pub async fn load_config_from_file(path: impl AsRef<Path>) -> Result<()> {
    let content = tokio::fs::read_to_string(path)
        .await
        .context("loading config")?;
    let config = toml::from_str(&content).context("parsing config file")?;
    CONFIG
        .set(config)
        .ok()
        .context("error setting OnceCell for Config")?;
    Ok(())
}
