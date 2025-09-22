use std::collections::HashMap;
use zbus::message::Header;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};
use zbus::Connection;

// Return true if the sender (from header) is authorized by polkit for org.lusby.manage
pub async fn check_manage_authorization(
    conn: &Connection,
    header: &Header<'_>,
) -> zbus::Result<bool> {
    let sender = match header.sender() {
        Some(s) => s,
        None => return Ok(false),
    };
    // Query DBus daemon for the sender's Unix UID
    let dbus_proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .await?;
    let uid: u32 = dbus_proxy
        .call("GetConnectionUnixUser", &(sender.clone()))
        .await
        .unwrap_or(0);

    // Build polkit subject: ("unix-user", {"uid": <u32>}) with signature (sa{sv})
    let mut subject_details: HashMap<String, OwnedValue> = HashMap::new();
    subject_details.insert("uid".to_string(), OwnedValue::from(uid));
    let subject = ("unix-user", subject_details);

    let action_id = "org.lusby.manage";
    // details a{sv}
    let details: HashMap<String, OwnedValue> = HashMap::new();
    let flags: u32 = 1; // AllowUserInteraction
    let cancel: OwnedObjectPath = OwnedObjectPath::try_from("/org/lusby/Cancel").unwrap();

    // Call polkit
    let polkit = zbus::Proxy::new(
        conn,
        "org.freedesktop.PolicyKit1",
        "/org/freedesktop/PolicyKit1/Authority",
        "org.freedesktop.PolicyKit1.Authority",
    )
    .await?;
    // Returns (IsAuthorized: bool, IsChallenge: bool, Details: a{sv})
    let (is_auth, _is_challenge, _ret_details): (bool, bool, HashMap<String, OwnedValue>) = polkit
        .call(
            "CheckAuthorization",
            &(subject, action_id, details, flags, cancel),
        )
        .await?;
    Ok(is_auth)
}
