#[cfg(test)]
use crate::audit::{verify_chain, AuditEntry, AuditEntryPayload};
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
fn canonical_sign_verify_baseline() {
    let mut rng = OsRng;
    let sk = SigningKey::generate(&mut rng);
    let vk: VerifyingKey = sk.verifying_key();

    let mut b = Baseline {
        version: 1,
        created_by: "admin@example.com".into(),
        created_at: Utc::now(),
        devices: vec![DeviceEntry {
            vendor_id: "0x046d".into(),
            product_id: "0xc534".into(),
            serial: Some("ABC".into()),
            bus_path: None,
            descriptors_hash: "sha256:deadbeef".into(),
            device_type: "hid".into(),
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
