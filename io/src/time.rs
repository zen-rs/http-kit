//! Timers.

use std::{
    future::Future,
    time::{Duration, Instant},
};

/// Waits for deadlines on the implementation's own timer wheel.
///
/// Deadlines are absolute, which is what protocol timers (an idle timeout, a
/// QUIC loss-detection alarm) are expressed in; re-arming one is dropping the
/// old future and creating a new one.
pub trait Timer {
    /// Completes at `deadline`, or at once if it has passed.
    fn sleep_until(&self, deadline: Instant) -> impl Future<Output = ()>;

    /// Completes after `duration`.
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> {
        self.sleep_until(Instant::now() + duration)
    }
}
