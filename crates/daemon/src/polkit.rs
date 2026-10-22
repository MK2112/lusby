use std::collections::HashMap;
use zbus::message::Header;
use zbus::zvariant::OwnedValue;
use zbus::Connection;

// Return the sender's Unix UID as recorded by the bus, or None when the
// lookup fails (e.g. the caller disconnected). Never substitute a default.
pub async fn sender_uid(conn: &Connection, header: &Header<'_>) -> Option<u32> {
    let sender = header.sender()?;
    let dbus_proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .await
    .ok()?;
    let uid: u32 = dbus_proxy
        .call("GetConnectionUnixUser", &(sender.clone()))
        .await
        .ok()?;
    Some(uid)
}

// Return true if the sender (from header) is authorized by polkit for org.lusby.manage
pub async fn check_manage_authorization(
    conn: &Connection,
    header: &Header<'_>,
) -> zbus::Result<bool> {
    let sender = match header.sender() {
        Some(s) => s,
        None => return Ok(false),
    };
    // Query DBus daemon for the sender's Unix UID.
    // Fail closed: polkit always authorizes UID 0, so falling back to 0 on a
    // lookup failure would turn a transient error into an authentication
    // bypass (same class as CVE-2021-3560).
    let dbus_proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .await?;
    let uid: u32 = match dbus_proxy
        .call("GetConnectionUnixUser", &(sender.clone()))
        .await
    {
        Ok(u) => u,
        Err(_) => return Ok(false),
    };

    // Build polkit subject: ("unix-user", {"uid": <u32>}) with signature (sa{sv})
    let mut subject_details: HashMap<String, OwnedValue> = HashMap::new();
    subject_details.insert("uid".to_string(), OwnedValue::from(uid));
    let subject = ("unix-user", subject_details);

    let action_id = "org.lusby.manage";
    // polkit expects `details` as a{ss} (string->string), not a{sv}.
    let details: HashMap<String, String> = HashMap::new();
    let flags: u32 = 1; // AllowUserInteraction
                        // polkit expects the cancellation id as a plain string ('s'). An empty
                        // string means "no cancellation"; a fixed non-empty id would collide
                        // between concurrent checks.
    let cancel = "";

    // Call polkit: CheckAuthorization (sa{sv})sa{ss}us -> (bba{ss})
    let polkit = zbus::Proxy::new(
        conn,
        "org.freedesktop.PolicyKit1",
        "/org/freedesktop/PolicyKit1/Authority",
        "org.freedesktop.PolicyKit1.Authority",
    )
    .await?;
    let (is_auth, _is_challenge, _ret_details): (bool, bool, HashMap<String, String>) = polkit
        .call(
            "CheckAuthorization",
            &(subject, action_id, details, flags, cancel),
        )
        .await?;
    Ok(is_auth)
}
