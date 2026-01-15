use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

#[derive(Debug, Default)]
pub struct Telemetry {
    decisions: AtomicU64,
    matches: AtomicU64,
    xray_start: AtomicU64,
    xray_stop: AtomicU64,
    xray_restart: AtomicU64,
    errors: AtomicU64,
    last_error: Mutex<Option<String>>,
}

impl Telemetry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_decision(&self, matched: bool) {
        self.decisions.fetch_add(1, Ordering::Relaxed);
        if matched {
            self.matches.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_xray_start(&self) {
        self.xray_start.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_xray_stop(&self) {
        self.xray_stop.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_xray_restart(&self) {
        self.xray_restart.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_error(&self, message: String) {
        self.errors.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut guard) = self.last_error.lock() {
            *guard = Some(message);
        }
    }

    pub fn snapshot(&self) -> TelemetrySnapshot {
        let last_error = self
            .last_error
            .lock()
            .ok()
            .and_then(|guard| guard.clone());
        TelemetrySnapshot {
            decisions: self.decisions.load(Ordering::Relaxed),
            matches: self.matches.load(Ordering::Relaxed),
            xray_start: self.xray_start.load(Ordering::Relaxed),
            xray_stop: self.xray_stop.load(Ordering::Relaxed),
            xray_restart: self.xray_restart.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            last_error,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct TelemetrySnapshot {
    pub decisions: u64,
    pub matches: u64,
    pub xray_start: u64,
    pub xray_stop: u64,
    pub xray_restart: u64,
    pub errors: u64,
    pub last_error: Option<String>,
}
