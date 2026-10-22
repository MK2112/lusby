use std::os::unix::net::UnixDatagram;
use std::thread;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use zbus::Connection;

use lusby_common::fingerprint::{compute_fingerprint, FingerprintInput};
use lusby_common::types::DeviceInfo;

const DBUS_PATH: &str = "/org/lusby/Daemon";

/// Minimal serialisable struct sent from the blocking thread to the async task.
#[derive(Serialize, Deserialize, Debug)]
struct RawUdevEvent {
    action: String,
    devnode: String,
    vendor_id: String,
    product_id: String,
    serial: String,
    device_type: String,
    vendor: Option<String>,
    product: Option<String>,
}

/// Message the udev thread sends over the datagram bridge.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "kind")]
enum ThreadMsg {
    Event(RawUdevEvent),
    /// Setup failed on the udev thread; the async side turns this into an
    /// error so the supervisor logs and restarts instead of running blind.
    Fatal(String),
}

pub async fn run_udev_listener(
    connection: Connection,
    state: crate::dbus::DaemonState,
) -> Result<()> {
    // Create a Unix datagram pair for thread -> async notifications
    let (sock1, sock2) = UnixDatagram::pair().context("creating unix datagram pair")?;
    sock1
        .set_nonblocking(true)
        .context("setting nonblocking on bridge socket")?;
    let sock = tokio::net::UnixDatagram::from_std(sock1).context("async datagram socket")?;

    // Spawn an OS thread that creates the udev monitor (so udev's non-Send
    // types never cross the thread boundary).
    thread::spawn(move || udev_thread(sock2));

    // Async loop: wait for datagrams, parse them and process the event.
    let mut buf = vec![0u8; 16 * 1024]; // large enough buffer for the JSON payload
    loop {
        let len = sock.recv(&mut buf).await?;
        // A closed bridge (thread died) must stop this task; spinning on a
        // permanently readable closed socket would burn a CPU core.
        if len == 0 {
            bail!("udev bridge closed");
        }
        match serde_json::from_slice::<ThreadMsg>(&buf[..len]) {
            Ok(ThreadMsg::Fatal(e)) => bail!("udev monitor setup failed: {}", e),
            Ok(ThreadMsg::Event(raw)) => {
                handle_event(&connection, &state, raw).await;
            }
            Err(e) => tracing::warn!(error = %e, "dropping unparsable udev payload"),
        }
    }
}

async fn handle_event(
    connection: &Connection,
    state: &crate::dbus::DaemonState,
    raw: RawUdevEvent,
) {
    let action = raw.action.as_str();
    if action != "add" && action != "remove" {
        return;
    }
    let fp = compute_fingerprint(&FingerprintInput {
        vendor_id: &raw.vendor_id,
        product_id: &raw.product_id,
        serial: if raw.serial.is_empty() {
            None
        } else {
            Some(&raw.serial)
        },
        manufacturer: raw.vendor.as_deref(),
        product: raw.product.as_deref(),
        raw_descriptors: None,
    });
    // Stable composite id the daemon can resolve to a backend (usbguard
    // numeric) id. Falls back to the devnode only when vid/pid are missing.
    let id = if raw.vendor_id.is_empty() && raw.product_id.is_empty() {
        if raw.devnode.is_empty() {
            format!("unknown:unknown:{}", raw.serial)
        } else {
            raw.devnode.clone()
        }
    } else if raw.serial.is_empty() {
        format!("{}:{}", raw.vendor_id, raw.product_id)
    } else {
        format!("{}:{}:{}", raw.vendor_id, raw.product_id, raw.serial)
    };
    let info = DeviceInfo {
        id,
        vendor_id: raw.vendor_id.clone(),
        product_id: raw.product_id.clone(),
        serial: raw.serial.clone(),
        fingerprint: fp,
        device_type: raw.device_type.clone(),
        allowed: false,
        persistent: false,
        usbguard_hash: String::new(),
        interfaces: vec![],
    };

    if action == "add" {
        // Only notify for devices that are actually not allowed; already
        // approved devices, hubs and interfaces must not spam the tray.
        let allowed = state
            .is_device_allowed(&info.vendor_id, &info.product_id, &info.serial)
            .await;
        if allowed == Some(true) {
            return;
        }
        if let Err(e) = connection
            .emit_signal(
                Option::<&str>::None,
                DBUS_PATH,
                "org.lusby.Daemon",
                "UnknownDeviceInserted",
                &(&info,),
            )
            .await
        {
            tracing::warn!(error = %e, "failed to emit UnknownDeviceInserted signal");
        }
    } else if let Err(e) = connection
        .emit_signal(
            Option::<&str>::None,
            DBUS_PATH,
            "org.lusby.Daemon",
            "DeviceRemoved",
            &(&info.id,),
        )
        .await
    {
        tracing::warn!(error = %e, "failed to emit DeviceRemoved signal");
    }
}

fn udev_thread(sock2: UnixDatagram) {
    let send = |msg: &ThreadMsg| -> bool {
        match serde_json::to_vec(msg) {
            Ok(j) => sock2.send(&j).is_ok(),
            Err(_) => false,
        }
    };

    // Create monitor inside this thread. This keeps the non-Send udev types
    // on this thread only.
    let socket = match udev::MonitorBuilder::new()
        .and_then(|b| b.match_subsystem("usb"))
        .and_then(|b| b.listen())
    {
        Ok(s) => {
            // Make socket blocking for iterator
            use std::os::unix::io::AsRawFd;
            let fd = s.as_raw_fd();
            // Remove non-blocking flag to allow blocking iteration
            unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFL, 0);
                libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
            }
            s
        }
        Err(e) => {
            // Surface setup failure to the async side so the daemon logs it
            // and restarts instead of running without USB events.
            send(&ThreadMsg::Fatal(format!("udev monitor setup: {e}")));
            return;
        }
    };

    // Iterate blocking for udev events, serialise some fields and send them on.
    for event in socket.iter() {
        // Only physical USB devices: `match_subsystem("usb")` also delivers
        // interface events, which would produce several signals per device.
        let is_device =
            event.property_value("DEVTYPE").and_then(|s| s.to_str()) == Some("usb_device");
        if !is_device {
            continue;
        }
        let action = event
            .action()
            .and_then(|a| a.to_str())
            .unwrap_or("unknown")
            .to_string();
        if action != "add" && action != "remove" {
            continue;
        }
        let devnode = event
            .devnode()
            .and_then(|p| p.to_str())
            .unwrap_or("")
            .to_string();

        let vendor_id = event
            .property_value("ID_VENDOR_ID")
            .and_then(|s| s.to_str())
            .map(|s| format!("0x{}", s))
            .unwrap_or_default();
        let product_id = event
            .property_value("ID_MODEL_ID")
            .and_then(|s| s.to_str())
            .map(|s| format!("0x{}", s))
            .unwrap_or_default();
        let serial = event
            .property_value("ID_SERIAL_SHORT")
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        let device_type = event
            .property_value("ID_USB_DRIVER")
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();

        let vendor = event
            .property_value("ID_VENDOR")
            .and_then(|s| s.to_str())
            .map(|s| s.to_string());
        let product = event
            .property_value("ID_MODEL")
            .and_then(|s| s.to_str())
            .map(|s| s.to_string());

        let raw = RawUdevEvent {
            action,
            devnode,
            vendor_id,
            product_id,
            serial,
            device_type,
            vendor,
            product,
        };
        // A failed send means the async side is gone; stop the thread.
        if !send(&ThreadMsg::Event(raw)) {
            return;
        }
    }
}
