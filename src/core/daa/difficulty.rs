use crate::core::dag::Dag;
use crate::core::crypto::Hash;

pub struct Daa {
    pub target_time: u64,
    pub window_size: usize,
}

impl Daa {
    pub fn new(target_time: u64, window_size: usize) -> Self {
        Self {
            target_time,
            window_size,
        }
    }

    /// Calculate next difficulty using SMA over the last N block intervals.
    /// Transition target in this protocol is 1 second per block.
    pub fn calculate_next_difficulty(&self, dag: &Dag, _current_timestamp: u64) -> u64 {
        let all_hashes: Vec<Hash> = dag.get_all_hashes().into_iter().collect();
        if all_hashes.is_empty() {
            return 1000; // initial difficulty
        }

        let mut blocks: Vec<_> = all_hashes
            .into_iter()
            .filter_map(|h| dag.get_block(&h).map(|b| (h, b.timestamp, b.difficulty)))
            .collect();

        // Sort oldest->newest and keep only recent window
        blocks.sort_by_key(|(_, ts, _)| *ts);
        if blocks.len() < 2 {
            return blocks.last().map(|(_, _, diff)| *diff).unwrap_or(1000);
        }

        let start = blocks.len().saturating_sub(self.window_size);
        let window = &blocks[start..];
        if window.len() < 2 {
            return window.last().map(|(_, _, diff)| *diff).unwrap_or(1000);
        }

        let mut total_interval = 0u128;
        for i in 1..window.len() {
            let prev_ts = window[i - 1].1;
            let cur_ts = window[i].1;
            let diff = cur_ts.saturating_sub(prev_ts).max(1);
            total_interval += diff as u128;
        }

        let sma = total_interval as f64 / (window.len() - 1) as f64;
        let current_difficulty = window.last().map(|(_, _, diff)| *diff).unwrap_or(1000) as f64;

        // Target 1 second per block, so adjustment ratio = target / observed
        let target_time = self.target_time as f64;
        let adjustment = (target_time / sma).clamp(0.5, 2.0); // smooth 50%-200% step

        let mut next = (current_difficulty * adjustment).round() as u64;

        // Keep difficulty in safe bounds.
        next = next.max(1).min(u64::MAX / 2);
        next
    }
}

