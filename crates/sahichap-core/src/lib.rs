use serde::Serialize;
use sha2::{Digest, Sha256};

pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    serde_jcs::to_vec(value)
}

pub fn canonical_hash<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let bytes = canonical_bytes(value)?;
    let digest = Sha256::digest(&bytes);
    Ok(format!("sha256:{}", hex::encode(digest)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_matches_ts_vector() {
        let v = serde_json::json!({"b": 2, "a": 1});
        assert_eq!(
            canonical_hash(&v).unwrap(),
            "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
        )
    }
}
