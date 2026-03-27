use k256::schnorr::{SigningKey, VerifyingKey, Signature};
use k256::ecdsa::signature::{Signer, Verifier};
use rand::rngs::OsRng;
use crate::core::crypto::hash::Hash;
use crate::core::errors::CoreError;
use crate::core::state::transaction::{Transaction, SigHashType};
use blake3;

const TAG_TX_SIGN: &str = "KLOMANG_TX_V1";

pub struct KeyPairWrapper {
    signing_key: SigningKey,
}

impl KeyPairWrapper {
    pub fn new() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        Self { signing_key }
    }

    pub fn public_key(&self) -> VerifyingKey {
        *self.signing_key.verifying_key()
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        let msg_hash = Hash::new(msg);
        self.signing_key.sign(&msg_hash.as_bytes()[..])
    }
}

pub fn verify(pubkey: &VerifyingKey, msg: &[u8], signature: &Signature) -> bool {
    let msg_hash = Hash::new(msg);
    pubkey.verify(&msg_hash.as_bytes()[..], signature).is_ok()
}

/// BIP340-style tagged hash for domain separation
pub fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = blake3::hash(tag.as_bytes());
    let mut hasher = blake3::Hasher::new();
    hasher.update(tag_hash.as_bytes());
    hasher.update(tag_hash.as_bytes());
    hasher.update(data);
    let hash_result = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash_result.as_bytes()[..32]);
    result
}

/// Serialize transaction for sighash computation
pub fn serialize_tx_for_sighash(
    tx: &Transaction,
    input_index: usize,
    sighash: SigHashType,
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&tx.chain_id.to_be_bytes());
    
    match sighash {
        SigHashType::All => {
            for (idx, input) in tx.inputs.iter().enumerate() {
                if idx == input_index {
                    data.extend_from_slice(&input.pubkey);
                } else {
                    data.extend_from_slice(input.prev_tx.as_bytes());
                    data.extend_from_slice(&input.index.to_be_bytes());
                }
            }
            for output in &tx.outputs {
                data.extend_from_slice(&output.value.to_be_bytes());
                data.extend_from_slice(output.pubkey_hash.as_bytes());
            }
        },
        SigHashType::None => {
            for (idx, input) in tx.inputs.iter().enumerate() {
                if idx == input_index {
                    data.extend_from_slice(&input.pubkey);
                } else {
                    data.extend_from_slice(input.prev_tx.as_bytes());
                    data.extend_from_slice(&input.index.to_be_bytes());
                }
            }
        },
        SigHashType::Single => {
            for (idx, input) in tx.inputs.iter().enumerate() {
                if idx == input_index {
                    data.extend_from_slice(&input.pubkey);
                } else {
                    data.extend_from_slice(input.prev_tx.as_bytes());
                    data.extend_from_slice(&input.index.to_be_bytes());
                }
            }
            if input_index < tx.outputs.len() {
                let output = &tx.outputs[input_index];
                data.extend_from_slice(&output.value.to_be_bytes());
                data.extend_from_slice(output.pubkey_hash.as_bytes());
            }
        },
    }
    
    data.extend_from_slice(&tx.locktime.to_be_bytes());
    data
}

/// Compute sighash for transaction input
pub fn compute_sighash(
    tx: &Transaction,
    input_index: usize,
    sighash: SigHashType,
) -> Result<[u8; 32], CoreError> {
    let serialized = serialize_tx_for_sighash(tx, input_index, sighash);
    Ok(tagged_hash(TAG_TX_SIGN, &serialized))
}

/// Legacy compatibility - compute message hash for transaction
pub fn tx_message(tx: &Transaction) -> [u8; 32] {
    let mut data = Vec::new();
    for input in &tx.inputs {
        data.extend_from_slice(input.prev_tx.as_bytes());
        data.extend_from_slice(&input.index.to_be_bytes());
    }
    for output in &tx.outputs {
        data.extend_from_slice(&output.value.to_be_bytes());
        data.extend_from_slice(output.pubkey_hash.as_bytes());
    }
    tagged_hash(TAG_TX_SIGN, &data)
}

/// Verify Schnorr signature with BIP340-compliance
pub fn verify_schnorr(
    pubkey_bytes: &[u8; 32],
    sig_bytes: &[u8; 64],
    msg: &[u8],
) -> Result<bool, CoreError> {
    let pubkey = VerifyingKey::from_bytes(pubkey_bytes)
        .map_err(|_| CoreError::InvalidPublicKey)?;
    
    if sig_bytes.len() != 64 {
        return Err(CoreError::InvalidSignature);
    }
    
    let sig = Signature::try_from(&sig_bytes[..])
        .map_err(|_| CoreError::InvalidSignature)?;
    
    let msg_hash = tagged_hash(TAG_TX_SIGN, msg);
    Ok(pubkey.verify(&msg_hash, &sig).is_ok())
}

/// Batch verify multiple Schnorr signatures
pub fn batch_verify(
    items: &[(VerifyingKey, [u8; 32], Signature)],
) -> Result<bool, CoreError> {
    if items.is_empty() {
        return Ok(true);
    }
    
    for (pubkey, msg, sig) in items {
        if pubkey.verify(msg, sig).is_err() {
            return Ok(false);
        }
    }
    
    Ok(true)
}
