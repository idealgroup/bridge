pub mod actor;
pub mod engine;
pub mod network;
pub mod params;
pub mod regtest;
pub mod scripts;
pub mod transactions;

use std::fmt;

#[derive(Debug)]
pub enum BridgeError {
    IndexOutOfRange {
        name: &'static str,
        index: usize,
        max: usize,
    },
    TaprootBuilder(String),
    Sighash(bitcoin::sighash::TaprootError),
    Signing(String),
    MissingData(&'static str),
    Regtest(String),
}

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IndexOutOfRange { name, index, max } => {
                write!(f, "{name} index {index} out of range (max {max})")
            }
            Self::TaprootBuilder(msg) => write!(f, "taproot builder: {msg}"),
            Self::Sighash(e) => write!(f, "sighash: {e}"),
            Self::Signing(msg) => write!(f, "signing: {msg}"),
            Self::MissingData(name) => write!(f, "missing data: {name}"),
            Self::Regtest(msg) => write!(f, "regtest: {msg}"),
        }
    }
}

impl std::error::Error for BridgeError {}
