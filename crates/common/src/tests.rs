#[cfg(test)]
use crate::audit::{verify_chain, AuditEntry, AuditEntryPayload};
#[cfg(test)]
use crate::baseline::is_usbguard_hash;
#[cfg(test)]
use crate::baseline::{Baseline, DeviceEntry};
#[cfg(test)]
use crate::fingerprint::{compute_fingerprint, short_fingerprint, FingerprintInput};
#[cfg(test)]
use chrono::Utc;
#[cfg(test)]
use ed25519_dalek::{SigningKey, VerifyingKey};
#[cfg(test)]
use rand::rngs::OsRng;

#[test]
fn fingerprint_deterministic() {
    let input = FingerprintInput {
        vendor_id: "0x046d",
        product_id: "0xc534",
        serial: Some("123456"),
        manufacturer: Some("Logitech"),
        product: Some("Keyboard"),
        raw_descriptors: Some(&[0x01, 0x02, 0x03, 0x04]),
    };
    let fp1 = compute_fingerprint(&input);
    let fp2 = compute_fingerprint(&input);
    assert_eq!(fp1, fp2);
    assert_eq!(short_fingerprint(&fp1).len(), 8);
}

#[test]
fn fingerprint_separates_fields() {
    // A `|` inside one field must not be able to masquerade as a field boundary.
    let a = FingerprintInput {
        vendor_id: "ab",
        product_id: "cd",
        serial: Some("x|y"),
        manufacturer: None,
        product: None,
        raw_descriptors: None,
    };
    let b = FingerprintInput {
        vendor_id: "ab",
        product_id: "cd|x",
        serial: Some("y"),
        manufacturer: None,
        product: None,
        raw_descriptors: None,
    };
    assert_ne!(compute_fingerprint(&a), compute_fingerprint(&b));
    // Present vs absent optional fields must differ.
    let c = FingerprintInput {
        vendor_id: "ab",
        product_id: "cd",
        serial: None,
        manufacturer: None,
        product: None,
        raw_descriptors: None,
    };
    let d = FingerprintInput {
        vendor_id: "ab",
        product_id: "cd",
        serial: Some(""),
        manufacturer: None,
        product: None,
        raw_descriptors: None,
    };
    assert_ne!(compute_fingerprint(&c), compute_fingerprint(&d));
}

#[test]
fn canonical_sign_verify_baseline() {
    let mut rng = OsRng;
    let sk = SigningKey::generate(&mut rng);
    let vk: VerifyingKey = sk.verifying_key();

    let mut b = Baseline {
        version: 1,
        created_by: "admin@example.com".into(),
        created_at: Utc::now(),
        expires_at: None,
        devices: vec![DeviceEntry {
            vendor_id: "0x046d".into(),
            product_id: "0xc534".into(),
            serial: Some("ABC".into()),
            bus_path: None,
            descriptors_hash: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into(),
            device_type: "hid".into(),
            interfaces: vec!["03:01:01".into()],
            comment: Some("test".into()),
        }],
        signature: None,
    };

    b.sign_attach(&sk).expect("sign");
    let ok = b.verify_signature(&vk).expect("verify");
    assert!(ok);

    // Tamper payload
    let mut tampered = b.clone();
    tampered.devices[0].product_id = "0x9999".into();
    let ok = tampered.verify_signature(&vk).expect("verify");
    assert!(!ok);
}

#[test]
fn audit_chain_integrity() {
    let p1 = AuditEntryPayload {
        timestamp: Utc::now(),
        event_type: "start".into(),
        device_fingerprint: None,
        action: "daemon_start".into(),
        requester_uid: None,
    };
    let e1 = AuditEntry::new(None, p1);
    let p2 = AuditEntryPayload {
        timestamp: Utc::now(),
        event_type: "approve".into(),
        device_fingerprint: Some("sha256:abc".into()),
        action: "allow_ephemeral".into(),
        requester_uid: Some(1000),
    };
    let e2 = AuditEntry::new(Some(e1.entry_hash.clone()), p2);
    let chain = vec![e1.clone(), e2.clone()];
    assert!(verify_chain(&chain));

    let mut bad = chain.clone();
    bad[1].payload.action = "tamper".into();
    assert!(!verify_chain(&bad));
}

#[test]
fn audit_chain_rejects_empty() {
    // An empty or fully truncated log must never verify as valid.
    assert!(!verify_chain(&[]));
}

#[test]
fn short_fingerprint_never_panics() {
    // Multibyte input must not be sliced by byte index.
    assert_eq!(short_fingerprint("sha256:äöüßäöüßx"), "äöüßäöüß");
    assert_eq!(short_fingerprint("no-colon"), "no-colon");
    assert_eq!(short_fingerprint(""), "");
}

#[test]
fn baseline_validation_requires_identity() {
    let mk = |serial: Option<&str>, hash: &str, ifaces: Vec<&str>| Baseline {
        version: 1,
        created_by: "test".into(),
        created_at: Utc::now(),
        expires_at: None,
        devices: vec![DeviceEntry {
            vendor_id: "046d".into(),
            product_id: "c534".into(),
            serial: serial.map(String::from),
            bus_path: None,
            descriptors_hash: hash.into(),
            device_type: "hid".into(),
            interfaces: ifaces.into_iter().map(String::from).collect(),
            comment: None,
        }],
        signature: None,
    };
    // VID/PID only: rejected.
    assert!(mk(None, "", vec![]).validate().is_err());
    // Non-hex placeholder hash alone is not identity.
    assert!(mk(None, "none", vec![]).validate().is_err());
    // Serial, usbguard hash, or interfaces each suffice.
    assert!(mk(Some("ABC"), "", vec![]).validate().is_ok());
    assert!(mk(None, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", vec![])
        .validate()
        .is_ok());
    assert!(mk(None, "", vec!["03:01:01"]).validate().is_ok());
    // Malformed interface specs are rejected.
    assert!(mk(None, "", vec!["rm -rf"]).validate().is_err());
}

#[test]
fn baseline_expiry_is_enforced() {
    let now = Utc::now();
    let mut b = Baseline {
        version: 1,
        created_by: "test".into(),
        created_at: now - chrono::Duration::days(30),
        expires_at: Some(now - chrono::Duration::days(1)),
        devices: vec![DeviceEntry {
            vendor_id: "046d".into(),
            product_id: "c534".into(),
            serial: Some("ABC".into()),
            bus_path: None,
            descriptors_hash: String::new(),
            device_type: "hid".into(),
            interfaces: vec![],
            comment: None,
        }],
        signature: None,
    };
    // Already expired.
    assert!(b.validate_at(now).is_err());
    // Valid window.
    b.expires_at = Some(now + chrono::Duration::days(1));
    assert!(b.validate_at(now).is_ok());
    // Expiry before creation is nonsense.
    b.expires_at = Some(b.created_at - chrono::Duration::days(1));
    assert!(b.validate_at(now).is_err());
    // Created in the future.
    b.expires_at = None;
    b.created_at = now + chrono::Duration::hours(1);
    assert!(b.validate_at(now).is_err());
}

#[test]
fn baseline_hash_is_stable_and_signature_independent() {
    let mut b = Baseline {
        version: 1,
        created_by: "test".into(),
        created_at: Utc::now(),
        expires_at: None,
        devices: vec![DeviceEntry {
            vendor_id: "046d".into(),
            product_id: "c534".into(),
            serial: Some("ABC".into()),
            bus_path: None,
            descriptors_hash: String::new(),
            device_type: "hid".into(),
            interfaces: vec![],
            comment: None,
        }],
        signature: None,
    };
    let h1 = b.baseline_hash().expect("hash");
    let sk = SigningKey::generate(&mut OsRng);
    b.sign_attach(&sk).expect("sign");
    let h2 = b.baseline_hash().expect("hash");
    assert_eq!(h1, h2, "hash must cover signed content only");
    assert!(is_usbguard_hash("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"));
    assert!(!is_usbguard_hash("sha256:deadbeef"));
}
#[cfg(test)]
mod proptests {
    use super::*;
    use crate::crypto::canonical_json_vec;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn canonical_json_does_not_crash(s in "\\PC*") {
            // Generating random strings to serialize
            let _ = canonical_json_vec(&s);
        }

        #[test]
        fn fingerprint_stability(
            vid in "[0-9a-f]{4}",
            pid in "[0-9a-f]{4}",
            serial in proptest::option::of("[a-zA-Z0-9]{1,20}")
        ) {
            let input = FingerprintInput {
                vendor_id: &vid,
                product_id: &pid,
                serial: serial.as_deref(),
                manufacturer: None,
                product: None,
                raw_descriptors: None,
            };
            let fp1 = compute_fingerprint(&input);
            let fp2 = compute_fingerprint(&input);
            prop_assert!(fp1.starts_with("sha256:"));
            prop_assert_eq!(fp1, fp2);
        }
    }
}
