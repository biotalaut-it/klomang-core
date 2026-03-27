use crate::core::crypto::Hash;

/// Signature hash type for transaction signing (BIP340-compatible)
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SigHashType {
    /// All inputs and outputs must not change
    All = 0x01,
    /// No outputs must change
    None = 0x02,
    /// Only corresponding output ne change
    Single = 0x03,
}

impl SigHashType {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(SigHashType::All),
            0x02 => Some(SigHashType::None),
            0x03 => Some(SigHashType::Single),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TxInput {
    pub prev_tx: Hash,
    pub index: u32,
    pub signature: Vec<u8>,
    pub pubkey: Vec<u8>,
    pub sighash_type: SigHashType,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TxOutput {
    pub value: u64,
    pub pubkey_hash: Hash,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Transaction {
    pub id: Hash,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub chain_id: u32,
    pub locktime: u32,
}

impl Transaction {
    pub fn new(inputs: Vec<TxInput>, outputs: Vec<TxOutput>) -> Self {
        let mut tx = Self {
            id: Hash::new(&[]),
            inputs,
            outputs,
            chain_id: 1,
            locktime: 0,
        };
        tx.id = tx.calculate_id();
        tx
    }

    pub fn calculate_id(&self) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(&self.chain_id.to_be_bytes());
        for input in &self.inputs {
            data.extend_from_slice(input.prev_tx.as_bytes());
            data.extend_from_slice(&input.index.to_be_bytes());
            data.extend_from_slice(&input.pubkey);
            data.push(input.sighash_type.as_u8());
        }
        for output in &self.outputs {
            data.extend_from_slice(&output.value.to_be_bytes());
            data.extend_from_slice(output.pubkey_hash.as_bytes());
        }
        data.extend_from_slice(&self.locktime.to_be_bytes());
        Hash::new(&data)
    }

    pub fn is_coinbase(&self) -> bool {
        self.inputs.is_empty()
    }
}

impl Default for Transaction {
    fn default() -> Self {
        Self {
            id: Hash::new(&[]),
            inputs: Vec::new(),
            outputs: Vec::new(),
            chain_id: 1,
            locktime: 0,
        }
    }
}