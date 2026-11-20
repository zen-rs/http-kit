//! Timers.

use core::{future::Future, time::Duration};

#[cfg(feature = "std")]
use std::time::Instant;

/// Waits for deadlines on the implementation's own timer wheel.
///
/// Deadlines are relative — `core` has no monotonic clock, so the required
/// primitive is [`sleep`](Self::sleep); an absolute deadline on `std`
/// ([`sleep_until`](Self::sleep_until)) resolves to a relative wait at call
/// time. Re-arming one is dropping the old future and creating a new one.
pub trait Timer {
    /// Completes after `duration`.
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()>;

    /// Completes at `deadline`, or at once if it has passed.
    #[cfg(feature = "std")]
    fn sleep_until(&self, deadline: Instant) -> impl Future<Output = ()> {
        self.sleep(deadline.saturating_duration_since(Instant::now()))
    }
}
