use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    #[serde(rename = "type")]
    pub kind: String,
    pub request_id: String,
    pub doc_id: String,
    pub doc_hash: String,
    pub doc_size: u64,
    pub signer_id: String,
    pub signer_pk: String,
    pub role: String,
    pub intent: String,
    pub stage_index: u32,
    pub prev_stage_hash: Option<String>,
    pub sign_nonce: String,
}
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

    #[test]
    fn manifest_hash_matches_ts() {
        let m = Manifest {
            kind: "sahichap/manifest/v1".into(),
            request_id: "req-1".into(),
            doc_id: "doc-1".into(),
            doc_hash: format!("sha256:{}", "00".repeat(32)),
            doc_size: 12345,
            signer_id: "alice".into(),
            signer_pk: "ed25519:ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
                .into(),
            role: "approver".into(),
            intent: "approve".into(),
            stage_index: 0,
            prev_stage_hash: None,
            sign_nonce: "nonce-1".into(),
        };
        assert_eq!(
            canonical_hash(&m).unwrap(),
            "sha256:602a57bdeb5a3edd4333b0572a7910787e004e2900270001352155b1266968e0"
        );
    }
}
