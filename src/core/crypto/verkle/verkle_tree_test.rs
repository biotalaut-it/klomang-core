use crate::core::state::MemoryStorage;
use crate::core::crypto::verkle::verkle_tree::{ProofType, VerkleTree};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

#[test]
fn test_verkle_tree_stress_inserts_root_consistency() {
    let storage = MemoryStorage::new();
    let mut tree = VerkleTree::new(storage);

    let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
    let mut kv_pairs = Vec::with_capacity(1200);

    for i in 0..1200u32 {
        let mut key = [0u8; 32];
        key[0..4].copy_from_slice(&i.to_le_bytes());
        for b in 4..32 {
            key[b] = rng.gen();
        }

        let value_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        tree.insert(key, value_bytes.clone());
        kv_pairs.push((key, value_bytes));
    }

    let root_first = tree.get_root();

    for (key, value) in &kv_pairs {
        assert_eq!(tree.get(*key).unwrap(), Some(value.clone()));
    }

    // Rebuild tree with same data and compare root to ensure deterministic consistency
    let storage2 = MemoryStorage::new();
    let mut tree2 = VerkleTree::new(storage2);
    for (key, value) in &kv_pairs {
        tree2.insert(*key, value.clone());
    }
    let root_second = tree2.get_root();

    assert_eq!(root_first, root_second);
}

#[test]
fn test_verkle_tree_proof_verification_and_tampering() {
    let storage = MemoryStorage::new();
    let mut tree = VerkleTree::new(storage);

    let key = [42u8; 32];
    let value = b"verkle_proof_value".to_vec();

    tree.insert(key, value.clone());
    let proof = tree.generate_proof(key);

    assert_eq!(proof.proof_type, ProofType::Membership);
    assert_eq!(proof.leaf_value, Some(value.clone()));
    assert!(tree.verify_proof(&proof));

    // Tampered root
    let mut tampered = proof.clone();
    tampered.root[0] ^= 0xFF;
    assert!(!tree.verify_proof(&tampered));

    // Tampered leaf value (should invalidate membership proof)
    let mut tampered2 = proof.clone();
    if let Some(leaf_bytes) = tampered2.leaf_value.as_mut() {
        leaf_bytes[0] ^= 0xFF;
    }
    assert!(!tree.verify_proof(&tampered2));

    // Tampered path index
    let mut tampered3 = proof.clone();
    tampered3.path[0] = tampered3.path[0].wrapping_add(1);
    assert!(!tree.verify_proof(&tampered3));
}

#[test]
fn test_verkle_tree_non_membership_proof_fails_when_data_tampered() {
    let storage = MemoryStorage::new();
    let mut tree = VerkleTree::new(storage);

    let in_key = [1u8; 32];
    tree.insert(in_key, b"exists".to_vec());

    let absent_key = [2u8; 32];
    let proof = tree.generate_proof(absent_key);

    assert_eq!(proof.proof_type, ProofType::NonMembership);
    assert!(tree.verify_proof(&proof));

    // Tampering leaf value on a non-membership proof should fail
    let mut tampered = proof.clone();
    tampered.leaf_value = Some(b"fake".to_vec());
    assert!(!tree.verify_proof(&tampered));
}

#[test]
fn test_verkle_tree_cryptography_stress_1000_plus_pairs() {
    let storage = MemoryStorage::new();
    let mut tree = VerkleTree::new(storage);

    let mut rng = StdRng::seed_from_u64(0xCAFEBABE);
    let mut kv_pairs = Vec::with_capacity(1500);

    // Insert 1500 random key-value pairs
    for i in 0..1500u32 {
        let mut key = [0u8; 32];
        key[0..4].copy_from_slice(&i.to_le_bytes());
        for b in 4..32 {
            key[b] = rng.gen();
        }

        let value_len = rng.gen_range(1..=64);
        let value: Vec<u8> = (0..value_len).map(|_| rng.gen()).collect();
        tree.insert(key, value.clone());
        kv_pairs.push((key, value));
    }

    // Verify root consistency after all inserts
    let root_after_inserts = tree.get_root();

    // Verify all values can be retrieved correctly
    for (key, expected_value) in &kv_pairs {
        let retrieved = tree.get(*key).unwrap();
        assert_eq!(retrieved, Some(expected_value.clone()), "Failed to retrieve value for key {:?}", key);
    }

    // Rebuild tree and verify root matches
    let storage2 = MemoryStorage::new();
    let mut tree2 = VerkleTree::new(storage2);
    for (key, value) in &kv_pairs {
        tree2.insert(*key, value.clone());
    }
    let root_rebuilt = tree2.get_root();
    assert_eq!(root_after_inserts, root_rebuilt, "Root hash inconsistent after rebuild");

    // Additional random updates to test incremental updates
    for _ in 0..500 {
        let idx = rng.gen_range(0..kv_pairs.len());
        let (key, _) = kv_pairs[idx].clone();
        let new_value_len = rng.gen_range(1..=64);
        let new_value: Vec<u8> = (0..new_value_len).map(|_| rng.gen()).collect();
        tree.insert(key, new_value.clone());
        kv_pairs[idx].1 = new_value;
    }

    // Final root check
    let final_root = tree.get_root();
    let storage3 = MemoryStorage::new();
    let mut tree3 = VerkleTree::new(storage3);
    for (key, value) in &kv_pairs {
        tree3.insert(*key, value.clone());
    }
    let final_root_rebuilt = tree3.get_root();
    assert_eq!(final_root, final_root_rebuilt, "Final root hash inconsistent");
}

#[test]
fn test_verkle_tree_proof_verification_ipa_comprehensive() {
    let storage = MemoryStorage::new();
    let mut tree = VerkleTree::new(storage);

    let mut rng = StdRng::seed_from_u64(0xBEEFCAFE);
    let mut keys_values = Vec::new();

    // Insert multiple entries
    for i in 0..100u32 {
        let mut key = [0u8; 32];
        key[0..4].copy_from_slice(&i.to_le_bytes());
        for b in 4..32 {
            key[b] = rng.gen();
        }
        let value = format!("value_{}", i).into_bytes();
        tree.insert(key, value.clone());
        keys_values.push((key, value));
    }

    // Test membership proofs
    for (key, value) in &keys_values {
        let proof = tree.generate_proof(*key);
        assert_eq!(proof.proof_type, ProofType::Membership);
        assert_eq!(proof.leaf_value, Some(value.clone()));
        assert!(tree.verify_proof(&proof), "Membership proof failed for key {:?}", key);

        // Test tampering with various parts
        let mut tampered_root = proof.clone();
        tampered_root.root[0] ^= 0x01;
        assert!(!tree.verify_proof(&tampered_root), "Tampered root should fail");

        let mut tampered_value = proof.clone();
        if let Some(ref mut val) = tampered_value.leaf_value {
            if !val.is_empty() {
                val[0] ^= 0x01;
            }
        }
        assert!(!tree.verify_proof(&tampered_value), "Tampered value should fail");

        let mut tampered_path = proof.clone();
        if !tampered_path.path.is_empty() {
            tampered_path.path[0] ^= 0x01;
        }
        assert!(!tree.verify_proof(&tampered_path), "Tampered path should fail");

        let mut tampered_siblings = proof.clone();
        if !tampered_siblings.siblings.is_empty() {
            // Tamper on an entry guaranteed to be used in the recomputation path
            let depth = 0;
            let tamper_index = ((proof.path[depth] as usize) + 1) % 256;
            tampered_siblings.siblings[depth * 256 + tamper_index][0] ^= 0x01;
        }
        assert!(!tree.verify_proof(&tampered_siblings), "Tampered siblings should fail");
    }

    // Test non-membership proofs
    for i in 100..150u32 {
        let mut absent_key = [0u8; 32];
        absent_key[0..4].copy_from_slice(&i.to_le_bytes());
        for b in 4..32 {
            absent_key[b] = rng.gen();
        }

        let proof = tree.generate_proof(absent_key);
        assert_eq!(proof.proof_type, ProofType::NonMembership);
        assert_eq!(proof.leaf_value, None);
        assert!(tree.verify_proof(&proof), "Non-membership proof failed for key {:?}", absent_key);

        // Tamper non-membership proof
        let mut tampered_non_mem = proof.clone();
        tampered_non_mem.leaf_value = Some(b"should_not_exist".to_vec());
        assert!(!tree.verify_proof(&tampered_non_mem), "Tampered non-membership should fail");
    }
}
