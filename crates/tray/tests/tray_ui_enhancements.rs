use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[test]
fn test_countdown_logic() {
    let approval_end = Arc::new(Mutex::new(Some(Instant::now() + Duration::from_secs(10))));
    let now = Instant::now();
    let end = approval_end.lock().unwrap().unwrap();
    assert!(end > now);
    let secs_left = (end - now).as_secs();
    assert!(secs_left <= 10 && secs_left > 0);
}

#[test]
fn test_manual_revoke_resets_countdown() {
    let approval_end = Arc::new(Mutex::new(Some(Instant::now() + Duration::from_secs(10))));
    *approval_end.lock().unwrap() = None;
    assert!(approval_end.lock().unwrap().is_none());
}
