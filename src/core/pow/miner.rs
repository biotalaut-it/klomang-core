use crate::core::crypto::Hash;
use super::hash::is_valid_pow;

pub const TARGET_BLOCK_TIME: u64 = 1; // target 1 second per block

pub struct Pow {
    pub difficulty: u64,
}

impl Pow {
    pub fn new(difficulty: u64) -> Self {
        Self { difficulty: difficulty.max(1) }
    }

    /// Calculate target for given difficulty
    pub fn target(&self) -> u64 {
        u64::MAX / self.difficulty.max(1)
    }

    /// Verify behaviour of squared difficulty adjustment; this is protocol-level DAA helper
    pub fn calculate_next_difficulty(&self, block_timestamps: &[u64]) -> u64 {
        if block_timestamps.len() < 2 {
            return self.difficulty.max(1).min(u64::MAX / 2);
        }

        let diffs: Vec<u64> = block_timestamps
            .windows(2)
            .map(|w| w[1].saturating_sub(w[0]).max(1))
            .collect();

        let sma = diffs.iter().copied().map(u64::from).sum::<u64>() as f64 / diffs.len() as f64;
        let adjustment = TARGET_BLOCK_TIME as f64 / sma;
        let mut next = (self.difficulty as f64 * adjustment).round() as u64;

        let max_step = (self.difficulty / 2).max(1);
        if next > self.difficulty.saturating_add(max_step) {
            next = self.difficulty.saturating_add(max_step);
        } else if next + max_step < self.difficulty {
            next = self.difficulty.saturating_sub(max_step);
        }

        next = next.max(1).min(u64::MAX / 2);
        next
    }

    pub fn validate_pow(&self, hash: &Hash) -> bool {
        let target = self.target();
        is_valid_pow(hash, target)
    }
}

/// Validate proof-of-work for a header-derived hash and explicit target.
pub fn verify_pow(hash: &Hash, target: u64) -> bool {
    is_valid_pow(hash, target)
}
