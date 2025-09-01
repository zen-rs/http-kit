#[cfg(feature = "std")]
extern crate std;

use bytes::buf::Reader;
use bytes::{Buf, Bytes};
use core::ops::DerefMut;
use core::pin::Pin;
use core::task::{Context, Poll};
use futures_lite::ready;
use std::io::{self, BufRead, Read};

use futures_lite::{AsyncBufRead, AsyncRead};

use crate::body::BoxHttpBody;

use super::{Body, BodyInner, BoxBufReader};

pub(crate) enum IntoAsyncRead {
    Once(Reader<Bytes>),
    Reader(BoxBufReader),
    Stream {
        stream: Option<BoxHttpBody>,
        buf: Reader<Bytes>,
    },
    Freeze,
}

impl IntoAsyncRead {
    pub fn new(body: Body) -> Self {
        match body.inner {
            BodyInner::Once(data) => Self::Once(data.reader()),
            BodyInner::Reader { reader, .. } => Self::Reader(reader),
            BodyInner::HttpBody(stream) => Self::Stream {
                stream: Some(stream),
                buf: Bytes::new().reader(),
            },
            BodyInner::Freeze => Self::Freeze,
        }
    }
}

fn poll_data(
    optional_stream: &mut Option<BoxHttpBody>,
    buf: &mut Reader<Bytes>,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    let stream;
    if let Some(s) = optional_stream {
        stream = s;
    } else {
        return Poll::Ready(Ok(()));
    }

    if !buf.get_ref().is_empty() {
        return Poll::Ready(Ok(()));
    }

    if let Some(frame) = ready!(stream.as_mut().poll_frame(cx))
        .transpose()
        .map_err(io::Error::other)?
    {
        let data = match frame.into_data() {
            Ok(data) => data,
            Err(_) => return Poll::Ready(Ok(())),
        };
        if data.is_empty() {
            return poll_data(optional_stream, buf, cx);
        }
        *buf = data.reader();
    } else {
        // Calling `poll_next` after the stream finished may cause problem,
        // so that we drop the stream after it finished.
        *optional_stream = None;
    }

    Poll::Ready(Ok(()))
}
impl AsyncRead for IntoAsyncRead {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        read_buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match self.deref_mut() {
            Self::Once(bytes) => Poll::Ready(bytes.read(read_buf)),
            Self::Reader(reader) => reader.as_mut().poll_read(cx, read_buf),
            Self::Stream { stream, buf } => {
                ready!(poll_data(stream, buf, cx))?;
                Poll::Ready(buf.read(read_buf))
            }
            Self::Freeze => Poll::Ready(Err(io::Error::other(super::Error::BodyFrozen))),
        }
    }
}

impl AsyncBufRead for IntoAsyncRead {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        match self.get_mut() {
            Self::Once(data) => Poll::Ready(data.fill_buf()),
            Self::Reader(reader) => reader.as_mut().poll_fill_buf(cx),
            Self::Stream { stream, buf } => {
                ready!(poll_data(stream, buf, cx))?;
                Poll::Ready(buf.fill_buf())
            }
            Self::Freeze => Poll::Ready(Err(io::Error::other(super::Error::BodyFrozen))),
        }
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        match self.get_mut() {
            Self::Once(data) => data.consume(amt),
            Self::Reader(reader) => reader.as_mut().consume(amt),
            Self::Stream { buf, .. } => buf.consume(amt),
            Self::Freeze => {}
        }
    }
}
// TODO: test them.
