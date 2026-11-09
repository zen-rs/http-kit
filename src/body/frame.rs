//! The frames a [`Body`](super::Body) is made of.

use bytes::Bytes;
use http::HeaderMap;

/// One frame of a [`Body`](super::Body).
///
/// A body is a stream of these: data, trailers, and — with the `fs` feature —
/// a region of a file. A consumer that can hand a file to the kernel
/// (sendfile, splice) sends a [`FileRegion`] as it is; one that needs bytes
/// reads it through [`FileRegion::into_stream`]. Nothing turns a region into
/// bytes implicitly, except the `http_body::Body` boundary, which has no frame
/// for it and reads it out there.
///
/// The enum is `#[non_exhaustive]` because the `File` variant exists only with
/// the `fs` feature: a match in another crate must not stop compiling when a
/// different crate in the build enables it.
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

    use alloc::vec::Vec;
    use bytes::Bytes;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{ready, Context, Poll};
    use futures_lite::Stream;
    use std::fs::File;
    use std::io::{self, Read, Seek, SeekFrom};

    /// The largest chunk [`FileRegionStream`] reads in one blocking call.
    ///
    /// Each chunk costs one hop to the blocking pool, so it is large enough to
    /// amortise that hop and small enough not to hold a big buffer per stream.
    const READ_CHUNK: u64 = 64 * 1024;

    /// `length` bytes of an owned file, starting at `offset`.
    ///
    /// The file's cursor is not part of the region: a sender uses the offset
    /// (sendfile, splice, `pread`), and [`into_stream`](Self::into_stream)
    /// seeks to it before reading.
    #[derive(Debug)]
    pub struct FileRegion {
        file: File,
        offset: u64,
        len: u64,
    }

    impl FileRegion {
        /// Creates a region of `len` bytes of `file`, starting at `offset`.
        ///
        /// The region is not checked against the file's size; a reader that
        /// reaches the end of the file before `len` bytes fails with
        /// [`io::ErrorKind::UnexpectedEof`].
        #[must_use]
        pub const fn new(file: File, offset: u64, len: u64) -> Self {
            Self { file, offset, len }
        }

        /// Returns the file the region belongs to.
        #[must_use]
        pub const fn file(&self) -> &File {
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
        pub fn into_parts(self) -> (File, u64, u64) {
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
                state: State::Idle {
                    file: self.file,
                    seek_to: Some(self.offset),
                },
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
        remaining: u64,
    }

    #[derive(Debug)]
    enum State {
        Idle { file: File, seek_to: Option<u64> },
        Reading(blocking::Task<(File, io::Result<Bytes>)>),
        Done,
    }

    impl FileRegionStream {
        /// Returns the number of bytes the stream has yet to yield.
        #[must_use]
        pub const fn remaining(&self) -> u64 {
            self.remaining
        }
    }

    fn read_chunk(mut file: &File, seek_to: Option<u64>, len: u64) -> io::Result<Bytes> {
        if let Some(offset) = seek_to {
            file.seek(SeekFrom::Start(offset))?;
        }
        // A chunk is at most `READ_CHUNK`, so it fits in `usize` everywhere.
        let mut buf = Vec::with_capacity(len as usize);
        file.take(len).read_to_end(&mut buf)?;
        if buf.len() as u64 != len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "file ended before the end of its region",
            ));
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
                        let State::Idle { file, seek_to } =
                            core::mem::replace(&mut this.state, State::Done)
                        else {
                            unreachable!("matched the idle state above")
                        };
                        let len = this.remaining.min(READ_CHUNK);
                        this.state = State::Reading(blocking::unblock(move || {
                            let chunk = read_chunk(&file, seek_to, len);
                            (file, chunk)
                        }));
                    }
                    State::Reading(task) => {
                        let (file, chunk) = ready!(Pin::new(task).poll(cx));
                        return Poll::Ready(Some(match chunk {
                            Ok(chunk) => {
                                this.remaining -= chunk.len() as u64;
                                this.state = State::Idle {
                                    file,
                                    seek_to: None,
                                };
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
