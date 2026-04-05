use blake3;
use hex;
use std::fmt;

#[derive(Clone, Eq, PartialEq, Hash, PartialOrd, Ord, Debug, serde::Serialize, serde::Deserialize)]
pub struct Hash([u8; 32]);

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Hash {
    #[inline]
    pub fn new(data: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(data);
        let hash = hasher.finalize();
        let bytes = hash.as_bytes();
        let mut array = [0u8; 32];
        array.copy_from_slice(bytes);
        Self(array)
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(*bytes)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
