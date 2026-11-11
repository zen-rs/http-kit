//! The frames a [`Body`](super::Body) is made of.

use bytes::Bytes;
use http::HeaderMap;

/// One frame of a [`Body`](super::Body).
///
/// A body is a stream of these: data, trailers, and — with the `fs` feature —
/// a region of a file, and bytes in a pipe. A consumer that can hand a file to
/// the kernel (sendfile, splice) sends a [`FileRegion`] as it is; one that
/// needs bytes reads it through [`FileRegion::into_stream`]. Nothing turns a
/// region or a pipe into bytes implicitly, except the `http_body::Body`
/// boundary and [`into_data_stream`](super::GenericBody::into_data_stream),
/// which have no frame for them and read them out there.
///
/// The enum is `#[non_exhaustive]` because the `File` and `Pipe` variants exist
/// only with the `fs` and `pipe` features: a match in another crate must not
/// stop compiling when a different crate in the build enables one.
#[derive(Debug)]
#[non_exhaustive]
pub enum BodyFrame {
    /// A chunk of body data.
    Data(Bytes),
    /// Trailing header fields, sent after the last data.
    Trailers(HeaderMap),
    /// A region of a file, sent as the file's bytes.
    #[cfg(feature = "fs")]
    File(FileRegion),
    /// Body bytes still in the kernel, in a pipe.
    ///
    /// A source produces one only for a consumer that offered a
    /// [`PipeOffer`](super::PipeOffer); the consumer sends it on with
    /// `splice(2)` or reads it out with `FilledPipe::read_out`. Linux and
    /// Android only, with the `pipe` feature.
    #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
    Pipe(http_kit_io::splice::FilledPipe),
}

impl BodyFrame {
    /// Returns the data of a data frame, or `None` for any other frame.
    #[must_use]
    pub const fn as_data(&self) -> Option<&Bytes> {
        match self {
            Self::Data(data) => Some(data),
            _ => None,
        }
    }

    /// Returns the trailers of a trailers frame, or `None` for any other frame.
    #[must_use]
    pub const fn as_trailers(&self) -> Option<&HeaderMap> {
        match self {
            Self::Trailers(trailers) => Some(trailers),
            _ => None,
        }
    }

    /// Returns the region of a file frame, or `None` for any other frame.
    #[cfg(feature = "fs")]
    #[must_use]
    pub const fn as_file(&self) -> Option<&FileRegion> {
        match self {
            Self::File(region) => Some(region),
            _ => None,
        }
    }

    /// Returns the pipe of a pipe frame, or `None` for any other frame.
    #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
    #[must_use]
    pub const fn as_pipe(&self) -> Option<&http_kit_io::splice::FilledPipe> {
        match self {
            Self::Pipe(pipe) => Some(pipe),
            _ => None,
        }
    }
}

impl From<Bytes> for BodyFrame {
    fn from(data: Bytes) -> Self {
        Self::Data(data)
    }
}

impl From<HeaderMap> for BodyFrame {
    fn from(trailers: HeaderMap) -> Self {
        Self::Trailers(trailers)
    }
}

#[cfg(feature = "fs")]
pub use file::{FileRegion, FileRegionStream};

#[cfg(feature = "fs")]
mod file {
    extern crate std;

    use bytes::Bytes;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{ready, Context, Poll};
    use futures_lite::Stream;
    use std::fs::File;
    use std::io;
    use std::sync::Arc;

    /// The largest chunk [`FileRegionStream`] reads in one blocking call.
    ///
    /// Each chunk costs one hop to the blocking pool, so it is large enough to
    /// amortise that hop and small enough not to hold a big buffer per stream.
    const READ_CHUNK: u64 = 64 * 1024;

    /// `length` bytes of a shared file, starting at `offset`.
    ///
    /// The file is an [`Arc<File>`], so any number of regions, and a cache that
    /// keeps the file open, share one descriptor. The file's cursor is not
    /// part of the region and is never moved: a sender uses the offset
    /// (sendfile, splice, `pread`), and [`into_stream`](Self::into_stream)
    /// reads by offset.
    #[derive(Debug, Clone)]
    pub struct FileRegion {
        file: Arc<File>,
        offset: u64,
        len: u64,
    }

    impl FileRegion {
        /// Creates a region of `len` bytes of `file`, starting at `offset`.
        ///
        /// `file` is a [`File`], which the region then owns, or an existing
        /// [`Arc<File>`], which it shares without duplicating the descriptor.
        ///
        /// The region is not checked against the file's size; a reader that
        /// reaches the end of the file before `len` bytes fails with
        /// [`io::ErrorKind::UnexpectedEof`].
        #[must_use]
        pub fn new(file: impl Into<Arc<File>>, offset: u64, len: u64) -> Self {
            Self {
                file: file.into(),
                offset,
                len,
            }
        }

        /// Returns the file the region belongs to.
        #[must_use]
        pub fn file(&self) -> &File {
            &self.file
        }

        /// Returns the offset of the region's first byte in the file.
        #[must_use]
        pub const fn offset(&self) -> u64 {
            self.offset
        }

        /// Returns the number of bytes in the region.
        #[must_use]
        pub const fn len(&self) -> u64 {
            self.len
        }

        /// Returns `true` if the region holds no bytes.
        #[must_use]
        pub const fn is_empty(&self) -> bool {
            self.len == 0
        }

        /// Splits the region into its file, offset and length.
        #[must_use]
        pub fn into_parts(self) -> (Arc<File>, u64, u64) {
            (self.file, self.offset, self.len)
        }

        /// Reads the region as a stream of byte chunks.
        ///
        /// This is the helper for a consumer that needs the bytes — a
        /// compressor, a hash, a backend that cannot send files. The reads run
        /// on the [`blocking`] thread pool, which belongs to no async runtime,
        /// so the stream can be polled from any executor.
        #[must_use]
        pub fn into_stream(self) -> FileRegionStream {
            FileRegionStream {
                state: State::Idle { file: self.file },
                position: self.offset,
                remaining: self.len,
            }
        }
    }

    /// The bytes of a [`FileRegion`], read chunk by chunk off the async thread.
    ///
    /// Created by [`FileRegion::into_stream`]. It yields exactly the region's
    /// length and then ends; a file shorter than the region is an
    /// [`io::ErrorKind::UnexpectedEof`] error, never a short body.
    #[derive(Debug)]
    pub struct FileRegionStream {
        state: State,
        /// The file offset of the next byte to read; the stream's own cursor.
        position: u64,
        remaining: u64,
    }

    #[derive(Debug)]
    enum State {
        Idle { file: Arc<File> },
        Reading(blocking::Task<(Arc<File>, io::Result<Bytes>)>),
        Done,
    }

    impl FileRegionStream {
        /// Returns the number of bytes the stream has yet to yield.
        #[must_use]
        pub const fn remaining(&self) -> u64 {
            self.remaining
        }
    }

    /// Reads into `buf` from `offset` without touching the file's cursor.
    #[cfg(unix)]
    fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        std::os::unix::fs::FileExt::read_at(file, buf, offset)
    }

    /// Reads into `buf` from `offset`. Windows moves the cursor here, which
    /// nothing reads: every access to a region's file is by offset.
    #[cfg(windows)]
    fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        std::os::windows::fs::FileExt::seek_read(file, buf, offset)
    }

    #[cfg(target_os = "wasi")]
    fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        std::os::wasi::fs::FileExt::read_at(file, buf, offset)
    }

    #[cfg(not(any(unix, windows, target_os = "wasi")))]
    compile_error!("the `fs` feature needs positioned file reads, which this target lacks");

    fn read_chunk(file: &File, offset: u64, len: u64) -> io::Result<Bytes> {
        // A chunk is at most `READ_CHUNK`, so it fits in `usize` everywhere.
        let mut buf = alloc::vec![0; len as usize];
        let mut filled = 0;
        while filled < buf.len() {
            match read_at(file, &mut buf[filled..], offset + filled as u64) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "file ended before the end of its region",
                    ));
                }
                Ok(read) => filled += read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(Bytes::from(buf))
    }

    impl Stream for FileRegionStream {
        type Item = io::Result<Bytes>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let this = &mut *self;
            loop {
                match &mut this.state {
                    State::Done => return Poll::Ready(None),
                    State::Idle { .. } if this.remaining == 0 => {
                        // Close the file as soon as the region is read.
                        this.state = State::Done;
                        return Poll::Ready(None);
                    }
                    State::Idle { .. } => {
                        let State::Idle { file } = core::mem::replace(&mut this.state, State::Done)
                        else {
                            unreachable!("matched the idle state above")
                        };
                        let len = this.remaining.min(READ_CHUNK);
                        let offset = this.position;
                        this.state = State::Reading(blocking::unblock(move || {
                            let chunk = read_chunk(&file, offset, len);
                            (file, chunk)
                        }));
                    }
                    State::Reading(task) => {
                        let (file, chunk) = ready!(Pin::new(task).poll(cx));
                        return Poll::Ready(Some(match chunk {
                            Ok(chunk) => {
                                this.remaining -= chunk.len() as u64;
                                this.position += chunk.len() as u64;
                                this.state = State::Idle { file };
                                Ok(chunk)
                            }
                            Err(error) => {
                                this.state = State::Done;
                                Err(error)
                            }
                        }));
                    }
                }
            }
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            let chunks = self.remaining.div_ceil(READ_CHUNK);
            let chunks = usize::try_from(chunks).unwrap_or(usize::MAX);
            (chunks, Some(chunks))
        }
    }
}
