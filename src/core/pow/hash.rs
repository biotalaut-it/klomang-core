use crate::core::crypto::Hash;

/// Calculate hash of block header using Blake3
pub fn calculate_hash(header: &[u8]) -> Hash {
    Hash::new(header)
}

/// Check if hash meets the target difficulty
pub fn is_valid_pow(hash: &Hash, target: u64) -> bool {
    // Convert first 8 bytes of hash to u64 (little endian)
    let hash_bytes = hash.as_bytes();
    if hash_bytes.len() < 8 {
        return false;
    }
    let hash_val = u64::from_le_bytes(hash_bytes[0..8].try_into().unwrap_or([0u8; 8]));
    hash_val < target
}

/// Mine a block by finding a valid nonce with miner and node reward addresses
/// Includes address fields in hashed input to ensure explicit minting destination.
/// This guards coinbase issuance by making reward addresses part of PoW input.
pub fn mine_block(
    header: &[u8],
    target: u64,
    miner_address: &[u8],
    node_reward_address: &[u8],
) -> Option<u64> {
    if miner_address.is_empty() || node_reward_address.is_empty() {
        return None;
    }

    for nonce in 0..=u64::MAX {
        let mut header_with_nonce = header.to_vec();
        header_with_nonce.extend_from_slice(&nonce.to_le_bytes());
        header_with_nonce.extend_from_slice(miner_address);
        header_with_nonce.extend_from_slice(node_reward_address);

        let hash = calculate_hash(&header_with_nonce);
        if is_valid_pow(&hash, target) {
            return Some(nonce);
        }
    }
    None
}