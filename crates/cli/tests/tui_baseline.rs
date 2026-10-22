use chrono::Utc;
use lusby_common::baseline::{Baseline, DeviceEntry};
use lusby_common::types::DeviceInfo;

fn make_device(vendor_id: &str, product_id: &str, serial: &str, device_type: &str) -> DeviceInfo {
    DeviceInfo {
        id: format!("{}:{}", vendor_id, product_id),
        vendor_id: vendor_id.to_string(),
        product_id: product_id.to_string(),
        serial: serial.to_string(),
        fingerprint: String::new(),
        device_type: device_type.to_string(),
        allowed: false,
        persistent: false,
        usbguard_hash: String::new(),
        interfaces: vec![],
    }
}

fn make_entry(info: &DeviceInfo) -> DeviceEntry {
    DeviceEntry {
        vendor_id: info.vendor_id.clone(),
        product_id: info.product_id.clone(),
        serial: if info.serial.is_empty() {
            None
        } else {
            Some(info.serial.clone())
        },
        bus_path: None,
        descriptors_hash: info.usbguard_hash.clone(),
        device_type: info.device_type.clone(),
        interfaces: info.interfaces.clone(),
        comment: None,
    }
}

#[test]
fn test_add_remove_device_to_baseline() {
    let info = make_device("abcd", "1234", "SERIAL1", "usb");
    let mut baseline_devices: Vec<DeviceEntry> = Vec::new();
    // Add device
    baseline_devices.push(make_entry(&info));
    assert_eq!(baseline_devices.len(), 1);
    // Remove device
    let idx = baseline_devices
        .iter()
        .position(|d| {
            d.vendor_id == info.vendor_id
                && d.product_id == info.product_id
                && d.serial.as_deref() == Some(&info.serial)
        })
        .unwrap();
    baseline_devices.remove(idx);
    assert!(baseline_devices.is_empty());
}

#[test]
fn test_comment_assignment() {
    let info = make_device("abcd", "1234", "SERIAL1", "usb");
    let mut entry = make_entry(&info);
    let comment = "Testgerät".to_string();
    entry.comment = Some(comment.clone());
    assert_eq!(entry.comment, Some(comment));
}

#[test]
fn test_baseline_serialization_roundtrip() {
    let info = make_device("abcd", "1234", "SERIAL1", "usb");
    let mut entry = make_entry(&info);
    entry.comment = Some("Kommentar".to_string());
    let baseline = Baseline {
        version: 1,
        created_by: "tester".to_string(),
        created_at: Utc::now(),
        expires_at: None,
        devices: vec![entry],
        signature: None,
    };
    let json = serde_json::to_string_pretty(&baseline).unwrap();
    let baseline2: Baseline = serde_json::from_str(&json).unwrap();
    assert_eq!(baseline2.devices.len(), 1);
    assert_eq!(baseline2.devices[0].comment, Some("Kommentar".to_string()));
}

#[test]
fn test_add_multiple_devices_and_comments() {
    let info1 = make_device("abcd", "1234", "SERIAL1", "usb");
    let info2 = make_device("efgh", "5678", "SERIAL2", "usb");
    let mut e1 = make_entry(&info1);
    e1.comment = Some("Erstes Gerät".to_string());
    let mut e2 = make_entry(&info2);
    e2.comment = Some("Zweites Gerät".to_string());
    let baseline_devices: Vec<DeviceEntry> = vec![e1, e2];
    assert_eq!(baseline_devices.len(), 2);
    assert_eq!(
        baseline_devices[0].comment,
        Some("Erstes Gerät".to_string())
    );
    assert_eq!(
        baseline_devices[1].comment,
        Some("Zweites Gerät".to_string())
    );
}

#[test]
fn test_empty_serial_and_comment() {
    let info = make_device("abcd", "1234", "", "usb");
    let entry = make_entry(&info);
    assert!(entry.serial.is_none());
    assert!(entry.comment.is_none());
}

#[test]
fn test_tui_entries_carry_identity_binding() {
    // A device with usbguard hash + interfaces must produce an entry that
    // passes the daemon's identity requirements.
    let mut info = make_device("abcd", "1234", "", "usb");
    info.usbguard_hash = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string();
    info.interfaces = vec!["03:01:01".to_string()];
    let entry = make_entry(&info);
    assert_eq!(
        entry.descriptors_hash,
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    );
    assert_eq!(entry.interfaces, vec!["03:01:01".to_string()]);
    let baseline = Baseline {
        version: 1,
        created_by: "tester".to_string(),
        created_at: Utc::now(),
        expires_at: None,
        devices: vec![entry],
        signature: None,
    };
    assert!(baseline.validate().is_ok());
}

#[test]
fn test_empty_baseline_is_rejected() {
    // The daemon (and therefore the TUI's save path) must refuse an empty
    // baseline instead of writing an unusable draft.
    let baseline = Baseline {
        version: 1,
        created_by: "tester".to_string(),
        created_at: Utc::now(),
        expires_at: None,
        devices: vec![],
        signature: None,
    };
    assert!(baseline.validate().is_err());
}
