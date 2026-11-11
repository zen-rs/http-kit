use core::time::Duration;

/// Receive-side deadlines for one client exchange, read by the protocol crate
/// from the request's extensions when the connection takes the request.
///
/// Absent, the exchange has none. `Duration::MAX` means no bound, as does any
/// duration too long to represent as an `Instant`.
///
/// # Examples
///
/// ```rust
/// use core::time::Duration;
/// use http_kit::Deadlines;
///
/// let mut request = http_kit::Request::new(http_kit::Body::empty());
/// request.extensions_mut().insert(
///     Deadlines::default()
///         .with_response_head(Duration::from_secs(10))
///         .with_body_idle(Duration::from_secs(30)),
/// );
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Deadlines {
    /// How long the final response head may take to arrive in full, counted
    /// from when the connection takes the request: the request's own
    /// transmission, interim `1xx` responses and the server's think time
    /// included. Expiry fails the exchange and closes the connection.
    pub response_head: Option<Duration>,
    /// How long each wait for more of the response body may take; every read
    /// that yields bytes starts the next wait. It bounds the socket, not a
    /// consumer slow to ask for more. Expiry fails the body with
    /// [`ReceiveError::Stalled`](crate::ReceiveError::Stalled) and closes the
    /// connection.
    pub body_idle: Option<Duration>,
}

impl Deadlines {
    /// `self` with the response-head deadline set. The struct is
    /// `#[non_exhaustive]`, so other crates build it from
    /// [`Default`] through these setters.
    #[must_use]
    pub const fn with_response_head(mut self, timeout: Duration) -> Self {
        self.response_head = Some(timeout);
        self
    }

    /// `self` with the body-idle deadline set.
    #[must_use]
    pub const fn with_body_idle(mut self, timeout: Duration) -> Self {
        self.body_idle = Some(timeout);
        self
    }
}
