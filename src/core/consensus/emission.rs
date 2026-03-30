/// DAG-based emission system with hard cap (8 decimal unit)
///
/// Calculates block rewards based on DAA score (blue score)
/// Ensures total supply never exceeds MAX_SUPPLY
pub const COIN_UNIT: u64 = 100_000_000; // 1 SLUG = 10^8 smallest units
pub const UNIT: u128 = COIN_UNIT as u128; // 8 decimal places
pub const MAX_GLOBAL_SUPPLY: u128 = 600_000_000_000_000_000; // 600M in Nano-SLUG (smallest unit)
pub const MAX_SUPPLY: u128 = MAX_GLOBAL_SUPPLY;
pub const BASE_REWARD: u128 = 100u128 * UNIT; // initial block reward (100 coins)
pub const HALVING_INTERVAL: u64 = 100_000;
pub const MIN_REWARD: u128 = 1; // 1 smallest unit (sat equivalent)

/// Raw block reward in smallest units (u128), no split
pub fn raw_block_reward(daa_score: u64) -> u128 {
    if daa_score == 0 {
        return BASE_REWARD;
    }

    let halvings = (daa_score / HALVING_INTERVAL) as u32;
    let halving_steps = halvings.min(128); // safety cap

    let mut reward = BASE_REWARD;
    for _ in 0..halving_steps {
        reward = (reward / 2).max(MIN_REWARD);
        if reward == MIN_REWARD {
            break;
        }
    }

    reward.max(MIN_REWARD)
}

/// Calculate block reward share for miner and infrastructure nodes.
/// Returns (miner_reward, infra_reward, infra_per_active_node), all in smallest units.
///
/// - If active_node_count == 0: miner receives full reward (no infra reward distribution).
/// - Otherwise: 80/20 split and per-node share is calculated.
pub fn block_reward(daa_score: u64, active_node_count: u32) -> (u64, u64, u64) {
    let total = capped_reward(daa_score);
    let miner = (total * 80) / 100;
    let infra = if active_node_count == 0 {
        0
    } else {
        total.saturating_sub(miner)
    };

    let miner = if active_node_count == 0 {
        total
    } else {
        miner
    };

    let per_node = if active_node_count == 0 {
        0
    } else {
        infra / (active_node_count as u128)
    };

    (miner as u64, infra as u64, per_node as u64)
}

/// Calculate total coins emitted up to a given DAA score
/// This is an approximation since DAG structure is complex
pub fn total_emitted(daa_score: u64) -> u128 {
    if daa_score == 0 {
        return 0;
    }

    // Parameterized halving series up to the floor-1 reward point.
    const HALVING_REWARDS: [u128; 34] = [
        10000000000, 5000000000, 2500000000, 1250000000, 625000000, 312500000,
        156250000, 78125000, 39062500, 19531250, 9765625, 4882812, 2441406,
        1220703, 610351, 305175, 152587, 76293, 38146, 19073, 9536, 4768,
        2384, 1192, 596, 298, 149, 74, 37, 18, 9, 4, 2, 1,
    ];

    const CUMULATIVE_REWARDS: [u128; 34] = [
        10000000000, 15000000000, 17500000000, 18750000000, 19375000000,
        19687500000, 19843750000, 19921875000, 19960937500, 19980468750,
        19990234375, 19995117187, 19997558593, 19998779296, 19999389647,
        19999694822, 19999847409, 19999923702, 19999961848, 19999980921,
        19999990457, 19999995225, 19999997609, 19999998801, 19999999397,
        19999999695, 19999999844, 19999999918, 19999999955, 19999999973,
        19999999982, 19999999986, 19999999988, 19999999989,
    ];

    let full_intervals = (daa_score / HALVING_INTERVAL) as usize;
    let remainder_blocks = daa_score % HALVING_INTERVAL;

    let full_emitted = if full_intervals == 0 {
        0
    } else if full_intervals <= HALVING_REWARDS.len() {
        CUMULATIVE_REWARDS[full_intervals - 1] * HALVING_INTERVAL as u128
    } else {
        // After rewards reach 1 unit, they remain constant.
        let capped_base = CUMULATIVE_REWARDS.last().copied().unwrap_or(0);
        capped_base * HALVING_INTERVAL as u128
            + (full_intervals as u128 - HALVING_REWARDS.len() as u128) * MIN_REWARD * HALVING_INTERVAL as u128
    };

    let next_reward = if full_intervals < HALVING_REWARDS.len() {
        HALVING_REWARDS[full_intervals]
    } else {
        MIN_REWARD
    };

    let remainder_emitted = (remainder_blocks as u128).saturating_mul(next_reward);

    full_emitted
        .saturating_add(remainder_emitted)
        .min(MAX_SUPPLY)
}

/// Calculate capped reward that won't exceed total supply
/// Returns the actual reward amount that can be issued
pub fn capped_reward(daa_score: u64) -> u128 {
    let current_total = total_emitted(daa_score);
    let base_reward = raw_block_reward(daa_score);

    if current_total >= MAX_SUPPLY {
        return 0;
    }

    if current_total + base_reward > MAX_SUPPLY {
        MAX_SUPPLY.saturating_sub(current_total)
    } else {
        base_reward
    }
}

/// Validate reward split does not exceed capped reward
pub fn validate_reward_split(daa_score: u64, active_node_count: u32) -> bool {
    let (miner, infra, _) = block_reward(daa_score, active_node_count);
    let split_total = miner as u128 + infra as u128;
    split_total <= capped_reward(daa_score)
}

/// Get maximum supply constant
pub fn max_supply() -> u128 {
    MAX_GLOBAL_SUPPLY
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_reward() {
        let (miner, infra, per_node) = block_reward(0, 1);
        assert_eq!(miner + infra, (100u128 * UNIT) as u64);
        assert_eq!(per_node, (20u128 * UNIT) as u64);
        assert!(validate_reward_split(0, 1));
    }

    #[test]
    fn test_reward_halving() {
        let (m1, i1, p1) = block_reward(100_000, 10);
        assert_eq!(m1 + i1, (50 * UNIT) as u64);
        assert_eq!(p1, (1 * UNIT) as u64);

        let (m2, i2, p2) = block_reward(200_000, 10);
        assert_eq!(m2 + i2, (25 * UNIT) as u64);
        assert_eq!(p2, (UNIT / 2) as u64);

        let (m3, i3, _p3) = block_reward(300_000, 10);
        assert_eq!(m3 + i3, (1_250_000_000u128) as u64);
    }

    #[test]
    fn test_minimum_reward() {
        let (m, i, _p) = block_reward(5_000_000, 10);
        assert_eq!(m + i, MIN_REWARD as u64); // After many halvings
    }

    #[test]
    fn test_total_emitted_increases() {
        assert!(total_emitted(100) > total_emitted(50));
    }

    #[test]
    fn test_max_supply_cap() {
        assert!(total_emitted(1_000_000) <= MAX_SUPPLY);
    }

    #[test]
    fn test_capped_reward() {
        // For very high DAA scores, reward should be capped
        let high_score = 10_000_000;
        let reward = capped_reward(high_score);
        assert!(reward <= MAX_SUPPLY);
        assert!(validate_reward_split(high_score, 100));
    }

    #[test]
    fn test_max_supply_constant() {
        assert_eq!(max_supply(), MAX_GLOBAL_SUPPLY);
        assert_eq!(max_supply(), 600_000_000_000_000_000u128);
    }
}