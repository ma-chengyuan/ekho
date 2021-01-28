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

use crate::icmp::Endpoint;
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
    pub remote: Option<Endpoint>,
    pub kcp: crate::kcp::Config,
    pub icmp: crate::icmp::Config,
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

pub fn config() -> &'static Config {
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
