use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use canonical_json::to_string as canonical_to_string;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("serialization error: {0}")]
    Ser(String),
    #[error("signature error: {0}")]
    Sig(String),
}

pub fn canonical_json_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, CryptoError> {
    let v: Value = serde_json::to_value(value).map_err(|e| CryptoError::Ser(e.to_string()))?;
    let s = canonical_to_string(&v).map_err(|e| CryptoError::Ser(e.to_string()))?;
    Ok(s.into_bytes())
}

pub fn sign_canonical<T: Serialize>(
    signing_key: &SigningKey,
    value: &T,
) -> Result<String, CryptoError> {
    let msg = canonical_json_vec(value)?;
    let sig: Signature = signing_key
        .try_sign(&msg)
        .map_err(|e| CryptoError::Sig(e.to_string()))?;
    Ok(B64.encode(sig.to_bytes()))
}

pub fn verify_canonical<T: Serialize>(
    verifying_key: &VerifyingKey,
    value: &T,
    b64sig: &str,
) -> Result<bool, CryptoError> {
    let msg = canonical_json_vec(value)?;
    let sig_bytes = B64
        .decode(b64sig)
        .map_err(|e| CryptoError::Sig(e.to_string()))?;
    let arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| CryptoError::Sig("sig size".into()))?;
    let sig = Signature::from_bytes(&arr);
    Ok(verifying_key.verify_strict(&msg, &sig).is_ok())
}
