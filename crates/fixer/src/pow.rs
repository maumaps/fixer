use crate::models::ProofOfWork;
use crate::util::{hash_text, now_rfc3339};
use chrono::{DateTime, Duration, Utc};

const POW_ALGORITHM: &str = "sha256-leading-hex-zeroes";

pub fn mine_pow(install_id: &str, payload_hash: &str, difficulty: u32) -> ProofOfWork {
    let issued_at = now_rfc3339();
    let mut nonce = 0_u64;
    loop {
        if proof_hash(install_id, &issued_at, payload_hash, nonce)
            .chars()
            .take(difficulty as usize)
            .all(|ch| ch == '0')
        {
            return ProofOfWork {
                algorithm: POW_ALGORITHM.to_string(),
                difficulty,
                issued_at,
                nonce,
                payload_hash: payload_hash.to_string(),
            };
        }
        nonce = nonce.saturating_add(1);
    }
}

pub fn verify_pow(
    install_id: &str,
    proof: &ProofOfWork,
    expected_payload_hash: &str,
    required_difficulty: u32,
    max_age_minutes: i64,
) -> bool {
    if proof.algorithm != POW_ALGORITHM {
        return false;
    }
    if proof.payload_hash != expected_payload_hash {
        return false;
    }
    if proof.difficulty < required_difficulty {
        return false;
    }
    if !proof_hash(
        install_id,
        &proof.issued_at,
        &proof.payload_hash,
        proof.nonce,
    )
    .chars()
    .take(required_difficulty as usize)
    .all(|ch| ch == '0')
    {
        return false;
    }
    let issued_at = DateTime::parse_from_rfc3339(&proof.issued_at)
        .map(|value| value.with_timezone(&Utc))
        .ok();
    let Some(issued_at) = issued_at else {
        return false;
    };
    let now = Utc::now();
    let min_time = now - Duration::minutes(max_age_minutes);
    let max_time = now + Duration::minutes(5);
    issued_at >= min_time && issued_at <= max_time
}

fn proof_hash(install_id: &str, issued_at: &str, payload_hash: &str, nonce: u64) -> String {
    hash_text(format!("{install_id}:{issued_at}:{payload_hash}:{nonce}"))
}

#[cfg(test)]
mod tests {
    use super::{mine_pow, verify_pow};

    #[test]
    fn mines_and_verifies_pow() {
        let proof = mine_pow("install-1", "payload", 2);
        assert!(verify_pow("install-1", &proof, "payload", 2, 10));
        assert!(!verify_pow("install-1", &proof, "other", 2, 10));
    }
}
