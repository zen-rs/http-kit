use bytes::Bytes;
use core::pin::Pin;
use core::task::{Context, Poll};
use http_body::{Frame, SizeHint};
use pin_project_lite::pin_project;

use super::Error;

pin_project! {
    /// Converts an `http_body::Body`'s data into `Bytes` and its errors into
    /// [`Error`]. Unlike `BodyExt::map_frame`, it keeps the inner size hint:
    /// the conversion never changes a frame's length.
    pub(super) struct IntoBytes<B> {
        #[pin]
        inner: B,
    }
}

impl<B> IntoBytes<B> {
    pub(super) const fn new(inner: B) -> Self {
        Self { inner }
    }
}

impl<B> http_body::Body for IntoBytes<B>
where
    B: http_body::Body,
    B::Data: Into<Bytes>,
    B::Error: Into<Error>,
{
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        self.project().inner.poll_frame(cx).map(|frame| {
            frame.map(|result| {
                result
                    .map(|frame| frame.map_data(Into::into))
                    .map_err(Into::into)
            })
        })
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
