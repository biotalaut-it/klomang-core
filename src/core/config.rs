use crate::core::errors::CoreError;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub network: String,
    pub data_dir: String,
    pub max_block_weight: u64,
    pub mempool_max_size: usize,
    pub block_reward: u64,
    pub k: usize,
    pub target_block_time: u64,
    pub finality_depth: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: "mainnet".to_string(),
            data_dir: "./data".to_string(),
            max_block_weight: 4_000_000,
            mempool_max_size: 10000,
            block_reward: 50,
            k: 18,
            target_block_time: 1,
            finality_depth: 100,
        }
    }
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load_config(_path: &str) -> Result<Config, CoreError> {
        // In pure library mode, config is deterministic and defaulted.
        // Path-based configuration is not needed in this stateless core.
        Ok(Config::default())
    }
}
