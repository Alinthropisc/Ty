//! Real-time packet statistics — lock-free atomics, printed by the sender loop.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

#[derive(Debug)]
pub struct Stats {
    pub sent: AtomicU64,
    pub errors: AtomicU64,
    pub start: Instant,
}

impl Stats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            sent: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            start: Instant::now(),
        })
    }

    pub fn inc_sent(&self) {
        self.sent.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_errors(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> (u64, u64, f64) {
        let sent = self.sent.load(Ordering::Relaxed);
        let errors = self.errors.load(Ordering::Relaxed);
        let secs = self.start.elapsed().as_secs_f64();
        (sent, errors, secs)
    }

    pub fn pps(&self) -> f64 {
        let (sent, _, secs) = self.snapshot();
        if secs > 0.0 { sent as f64 / secs } else { 0.0 }
    }
}
