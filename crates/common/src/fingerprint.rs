use sha2::{Digest, Sha256};

pub struct FingerprintInput<'a> {
    pub vendor_id: &'a str,
    pub product_id: &'a str,
    pub serial: Option<&'a str>,
    pub manufacturer: Option<&'a str>,
    pub product: Option<&'a str>,
    pub raw_descriptors: Option<&'a [u8]>,
}

pub fn compute_fingerprint(input: &FingerprintInput) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.vendor_id.as_bytes());
    hasher.update(b"|");
    hasher.update(input.product_id.as_bytes());
    hasher.update(b"|");
    if let Some(s) = input.serial { hasher.update(s.as_bytes()); }
    hasher.update(b"|");
    if let Some(m) = input.manufacturer { hasher.update(m.as_bytes()); }
    hasher.update(b"|");
    if let Some(p) = input.product { hasher.update(p.as_bytes()); }
    hasher.update(b"|");
    if let Some(desc) = input.raw_descriptors { hasher.update(desc); }
    let digest = hasher.finalize();
    format!("sha256:{}", hex::encode(digest))
}

pub fn short_fingerprint(full: &str) -> String {
    // Expect format sha256:<hex>
    if let Some(hexpart) = full.split(':').nth(1) { hexpart[0..8.min(hexpart.len())].to_string() } else { full.chars().take(8).collect() }
}
