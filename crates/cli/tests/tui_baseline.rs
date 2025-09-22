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
    }
}

#[test]
fn test_add_remove_device_to_baseline() {
    let info = make_device("abcd", "1234", "SERIAL1", "usb");
    let mut baseline_devices: Vec<DeviceEntry> = Vec::new();
    // Add device
    baseline_devices.push(DeviceEntry {
        vendor_id: info.vendor_id.clone(),
        product_id: info.product_id.clone(),
        serial: Some(info.serial.clone()),
        bus_path: None,
        descriptors_hash: String::new(),
        device_type: info.device_type.clone(),
        comment: None,
    });
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
    let mut entry = DeviceEntry {
        vendor_id: info.vendor_id.clone(),
        product_id: info.product_id.clone(),
        serial: Some(info.serial.clone()),
        bus_path: None,
        descriptors_hash: String::new(),
        device_type: info.device_type.clone(),
        comment: None,
    };
    let comment = "Testgerät".to_string();
    entry.comment = Some(comment.clone());
    assert_eq!(entry.comment, Some(comment));
}

#[test]
fn test_baseline_serialization_roundtrip() {
    let info = make_device("abcd", "1234", "SERIAL1", "usb");
    let entry = DeviceEntry {
        vendor_id: info.vendor_id.clone(),
        product_id: info.product_id.clone(),
        serial: Some(info.serial.clone()),
        bus_path: None,
        descriptors_hash: String::new(),
        device_type: info.device_type.clone(),
        comment: Some("Kommentar".to_string()),
    };
    let baseline = Baseline {
        version: 1,
        created_by: "tester".to_string(),
        created_at: Utc::now(),
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
    let baseline_devices: Vec<DeviceEntry> = vec![
        DeviceEntry {
            vendor_id: info1.vendor_id.clone(),
            product_id: info1.product_id.clone(),
            serial: Some(info1.serial.clone()),
            bus_path: None,
            descriptors_hash: String::new(),
            device_type: info1.device_type.clone(),
            comment: Some("Erstes Gerät".to_string()),
        },
        DeviceEntry {
            vendor_id: info2.vendor_id.clone(),
            product_id: info2.product_id.clone(),
            serial: Some(info2.serial.clone()),
            bus_path: None,
            descriptors_hash: String::new(),
            device_type: info2.device_type.clone(),
            comment: Some("Zweites Gerät".to_string()),
        },
    ];
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
    let entry = DeviceEntry {
        vendor_id: info.vendor_id.clone(),
        product_id: info.product_id.clone(),
        serial: None,
        bus_path: None,
        descriptors_hash: String::new(),
        device_type: info.device_type.clone(),
        comment: None,
    };
    assert!(entry.serial.is_none());
    assert!(entry.comment.is_none());
}
