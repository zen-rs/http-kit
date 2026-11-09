//! Apple platform calls.

use std::{io, os::fd::RawFd, ptr};

/// One non-blocking `sendfile(2)` of up to `len` bytes of `file` at `offset`
/// to the stream socket `socket`. The socket must be non-blocking; a call
/// that would block having sent nothing is [`io::ErrorKind::WouldBlock`].
pub(crate) fn sendfile(socket: RawFd, file: RawFd, offset: u64, len: usize) -> io::Result<usize> {
    if len == 0 {
        // A length of zero asks Darwin to send until the end of the file.
        return Ok(0);
    }
    let offset = libc::off_t::try_from(offset)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "file offset exceeds off_t"))?;
    let mut sent = libc::off_t::try_from(len).unwrap_or(libc::off_t::MAX);
    // SAFETY: both descriptors are open for the duration of the call, `sent`
    // is a valid in/out pointer, and no header/trailer vector is passed.
    let ret = unsafe { libc::sendfile(file, socket, offset, &raw mut sent, ptr::null_mut(), 0) };
    // Darwin reports a partial transfer that then blocked or was interrupted
    // as an error with `sent` set to the bytes that went out.
    let sent = usize::try_from(sent).expect("sendfile reports a non-negative count");
    if ret == -1 {
        let err = io::Error::last_os_error();
        let partial = matches!(
            err.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
        );
        return if partial && sent > 0 {
            Ok(sent)
        } else {
            Err(err)
        };
    }
    Ok(sent)
}
