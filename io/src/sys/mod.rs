//! Platform calls shared by the implementations.

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(feature = "compio", feature = "tokio", feature = "async-io")
))]
pub(crate) mod linux;

#[cfg(all(
    target_vendor = "apple",
    any(feature = "compio", feature = "tokio", feature = "async-io")
))]
pub(crate) mod apple;

#[cfg(all(
    any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        windows
    ),
    any(feature = "compio", feature = "tokio", feature = "async-io")
))]
pub(crate) mod control;

#[cfg(all(windows, any(feature = "tokio", feature = "async-io")))]
pub(crate) mod winsock;
