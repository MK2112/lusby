use sha2::{Digest, Sha256};

pub struct FingerprintInput<'a> {
    pub vendor_id: &'a str,
    pub product_id: &'a str,
    pub serial: Option<&'a str>,
    pub manufacturer: Option<&'a str>,
    pub product: Option<&'a str>,
    pub raw_descriptors: Option<&'a [u8]>,
}

fn hash_field(hasher: &mut Sha256, tag: &str, data: &[u8]) {
    // Length-prefixed, tagged fields: a `|` inside a serial can no longer
    // shift bytes into a neighbouring field and forge a collision.
    hasher.update(tag.as_bytes());
    hasher.update([0u8]);
    hasher.update((data.len() as u64).to_le_bytes());
    hasher.update(data);
}

pub fn compute_fingerprint(input: &FingerprintInput) -> String {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, "vid", input.vendor_id.as_bytes());
    hash_field(&mut hasher, "pid", input.product_id.as_bytes());
    // Encode optionality explicitly so None != Some("").
    match input.serial {
        Some(s) => {
            hash_field(&mut hasher, "serial?", &[1]);
            hash_field(&mut hasher, "serial", s.as_bytes());
        }
        None => hash_field(&mut hasher, "serial?", &[0]),
    }
    match input.manufacturer {
        Some(s) => {
            hash_field(&mut hasher, "manufacturer?", &[1]);
            hash_field(&mut hasher, "manufacturer", s.as_bytes());
        }
        None => hash_field(&mut hasher, "manufacturer?", &[0]),
    }
    match input.product {
        Some(s) => {
            hash_field(&mut hasher, "product?", &[1]);
            hash_field(&mut hasher, "product", s.as_bytes());
        }
        None => hash_field(&mut hasher, "product?", &[0]),
    }
    // Distinguish "no descriptors" from "empty descriptors".
    match input.raw_descriptors {
        Some(desc) => hash_field(&mut hasher, "desc", desc),
        None => hash_field(&mut hasher, "nodesc", &[]),
    }
    let digest = hasher.finalize();
    format!("sha256:{}", hex::encode(digest))
}

pub fn short_fingerprint(full: &str) -> String {
    // Expect format sha256:<hex>
    if let Some(hexpart) = full.split(':').nth(1) {
        hexpart[0..8.min(hexpart.len())].to_string()
    } else {
        full.chars().take(8).collect()
    }
}
