//! Sources of frames that can be asked for a pipe.

use core::pin::Pin;
use core::task::{Context, Poll};

use futures_lite::Stream;
use pin_project_lite::pin_project;

use super::{BodyFrame, Error};

#[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
use http_kit_io::splice::Pipe;

/// What a consumer tells a body it would take instead of bytes.
///
/// A consumer that can move bytes without reading them (a forwarder that
/// writes to another socket with `splice(2)`) passes an offer when it polls
/// with [`GenericBody::poll_frame_offering`](super::GenericBody::poll_frame_offering).
/// A source whose bytes are still in the kernel, an HTTP/1.1 connection with a
/// run of raw body bytes, may then answer with a `BodyFrame::Pipe` of no more
/// than [`max`](Self::max) bytes. A source that cannot, or a consumer that
/// offers nothing, gets and gives plain data frames: an offer is a permission,
/// never a promise.
///
/// The offer can carry an empty `Pipe`, so a consumer reuses one pipe for a
/// whole body; a source that takes it with `PipeOffer::take_pipe`
/// fills it, and the consumer gets it back from the frame. Offers exist on
/// every platform, so code that passes them needs no `cfg`; only a platform
/// with pipes has sources that accept them.
#[derive(Debug)]
pub struct PipeOffer {
    max: usize,
    #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
    pipe: Option<Pipe>,
}

impl PipeOffer {
    /// An offer to take pipe frames of up to `max` bytes. `max` must not be
    /// zero.
    #[must_use]
    pub const fn new(max: usize) -> Self {
        debug_assert!(max > 0, "an offer of no bytes");
        Self {
            max,
            #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
            pipe: None,
        }
    }

    /// An offer that supplies the empty `pipe` a source fills.
    #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
    #[must_use]
    pub const fn with_pipe(max: usize, pipe: Pipe) -> Self {
        Self {
            max,
            pipe: Some(pipe),
        }
    }

    /// The most bytes one pipe frame may hold.
    #[must_use]
    pub const fn max(&self) -> usize {
        self.max
    }

    /// Takes the empty pipe the consumer supplied, if it supplied one and no
    /// source has taken it. A source that takes it answers with a pipe frame;
    /// one without a supplied pipe makes its own.
    #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
    pub const fn take_pipe(&mut self) -> Option<Pipe> {
        self.pipe.take()
    }

    /// Moves the offer out of this one, leaving an offer of the same
    /// [`max`](Self::max) that supplies no pipe.
    ///
    /// A source whose bytes are read by another task (a connection's driver
    /// behind a channel) forwards the consumer's offer this way, and hands it
    /// back with [`reattach`](Self::reattach) when it answers without using
    /// the pipe.
    #[must_use]
    pub const fn detach(&mut self) -> Self {
        Self {
            max: self.max,
            #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
            pipe: self.pipe.take(),
        }
    }

    /// Takes back the pipe of an offer [`detach`](Self::detach)ed from this
    /// one, unless this offer has been given another pipe meanwhile, in which
    /// case the returned one is dropped.
    pub fn reattach(&mut self, detached: Self) {
        #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
        if self.pipe.is_none() {
            self.pipe = detached.pipe;
        }
        #[cfg(not(all(feature = "pipe", any(target_os = "linux", target_os = "android"))))]
        let _ = detached;
    }
}

/// An async source of [`BodyFrame`]s that can answer a [`PipeOffer`].
///
/// Implement it for a source that can hand over bytes still in the kernel; a
/// plain `Stream` of frames is already a source that ignores offers, through
/// [`Body::from_frames`](super::GenericBody::from_frames).
pub trait FrameSource {
    /// Polls the next frame. `offer` is `Some` when the consumer would take a
    /// pipe frame of up to [`PipeOffer::max`] bytes, and `None` when it takes
    /// only data. A source that does not use the offer leaves it as it is.
    fn poll_next_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        offer: Option<&mut PipeOffer>,
    ) -> Poll<Option<Result<BodyFrame, Error>>>;

    /// The bounds on the number of frames left, as [`Stream::size_hint`].
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, None)
    }
}

pin_project! {
    /// A frame stream as a source that ignores every offer.
    #[derive(Debug)]
    pub(crate) struct StreamSource<S> {
        #[pin]
        stream: S,
    }
}

impl<S> StreamSource<S> {
    pub(crate) const fn new(stream: S) -> Self {
        Self { stream }
    }
}

impl<S: Stream<Item = Result<BodyFrame, Error>>> FrameSource for StreamSource<S> {
    fn poll_next_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        _offer: Option<&mut PipeOffer>,
    ) -> Poll<Option<Result<BodyFrame, Error>>> {
        self.project().stream.poll_next(cx)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.stream.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Body, LocalBody};
    use alloc::{rc::Rc, vec, vec::Vec};
    use bytes::Bytes;
    use core::cell::RefCell;
    use futures_lite::{future::poll_fn, stream, StreamExt};
    use http_body_util::BodyExt;

    // Real multi-byte text: Chinese, Japanese and Korean.
    const CJK_TEXT: &str =
        "管道里的字节不进用户态。パイプの中身はユーザー空間を通らない。파이프 안의 바이트는 사용자 공간을 거치지 않는다.";

    /// A source of one data frame that records what each poll offered.
    struct Recording {
        offers: Rc<RefCell<Vec<Option<usize>>>>,
        left: usize,
    }

    impl FrameSource for Recording {
        fn poll_next_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            offer: Option<&mut PipeOffer>,
        ) -> Poll<Option<Result<BodyFrame, Error>>> {
            self.offers
                .borrow_mut()
                .push(offer.map(|offer| offer.max()));
            if self.left == 0 {
                return Poll::Ready(None);
            }
            self.left -= 1;
            Poll::Ready(Some(Ok(BodyFrame::Data(Bytes::from(CJK_TEXT)))))
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            (self.left, Some(self.left))
        }
    }

    fn recording(frames: usize) -> (LocalBody, Rc<RefCell<Vec<Option<usize>>>>) {
        let offers = Rc::default();
        let source = Recording {
            offers: Rc::clone(&offers),
            left: frames,
        };
        (LocalBody::from_source(source), offers)
    }

    #[tokio::test]
    async fn a_source_sees_the_offer_only_when_one_is_made() {
        let (mut body, offers) = recording(4);
        assert_eq!(body.size_hint(), (4, Some(4)));

        let plain = body.next().await.unwrap().unwrap();
        assert_eq!(plain.as_data().unwrap(), CJK_TEXT);

        let mut offer = PipeOffer::new(64 * 1024);
        let offered = poll_fn(|cx| Pin::new(&mut body).poll_frame_offering(cx, &mut offer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(offered.as_data().unwrap(), CJK_TEXT);

        // The `http_body` and data-stream views make no offer.
        let frame = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(frame, CJK_TEXT);
        let mut data = body.into_data_stream();
        assert_eq!(data.next().await.unwrap().unwrap(), CJK_TEXT);
        assert!(data.next().await.is_none());

        assert_eq!(
            *offers.borrow(),
            [None, Some(64 * 1024), None, None, None],
            "one offer per poll that made one"
        );
    }

    #[tokio::test]
    async fn from_frames_ignores_offers() {
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-checksum", http::HeaderValue::from_static("abc123"));
        let mut body = Body::from_frames(stream::iter([
            Ok::<_, Error>(BodyFrame::Data(Bytes::from(CJK_TEXT))),
            Ok(BodyFrame::Trailers(trailers.clone())),
        ]));
        let mut offer = PipeOffer::new(4096);

        let mut frames = Vec::new();
        while let Some(frame) =
            poll_fn(|cx| Pin::new(&mut body).poll_frame_offering(cx, &mut offer)).await
        {
            frames.push(frame.unwrap());
        }
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].as_data().unwrap(), CJK_TEXT);
        assert_eq!(frames[1].as_trailers(), Some(&trailers));
        assert_eq!(offer.max(), 4096);
        #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
        assert!(offer.take_pipe().is_none());
    }

    #[tokio::test]
    async fn bodies_that_are_not_sources_ignore_offers() {
        let mut offer = PipeOffer::new(4096);
        for mut body in [
            Body::from_bytes(CJK_TEXT),
            Body::from_stream(stream::iter(vec![Ok::<_, Error>(Bytes::from(CJK_TEXT))])),
        ] {
            let frame = poll_fn(|cx| Pin::new(&mut body).poll_frame_offering(cx, &mut offer))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(frame.as_data().unwrap(), CJK_TEXT);
        }
    }

    #[test]
    fn a_detached_offer_keeps_its_max() {
        let mut offer = PipeOffer::new(4096);
        let detached = offer.detach();
        assert_eq!(detached.max(), 4096);
        assert_eq!(offer.max(), 4096);
        offer.reattach(detached);
        assert_eq!(offer.max(), 4096);
    }

    #[test]
    fn a_shared_body_is_still_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Body>();
    }
}

/// The pipe frames themselves, which exist only where pipes do.
#[cfg(all(
    test,
    feature = "pipe",
    any(target_os = "linux", target_os = "android")
))]
mod pipe_tests {
    extern crate std;

    use super::*;
    use crate::Body;
    use alloc::vec::Vec;
    use bytes::Bytes;
    use futures_lite::{future::poll_fn, stream, StreamExt};
    use http_body_util::BodyExt;
    use http_kit_io::{
        splice::{FilledPipe, Pipe, Spliced},
        tokio::Tokio,
        Listen, Listener, SpliceRead,
    };
    use std::io::Write as _;

    // Real multi-byte text: Chinese, Japanese and Korean.
    const CJK_TEXT: &str =
        "管道里的字节不进用户态。パイプの中身はユーザー空間を通らない。파이프 안의 바이트는 사용자 공간을 거치지 않는다.";

    /// A pipe holding `payload`, spliced out of a loopback socket.
    async fn filled_pipe(payload: &'static str) -> FilledPipe {
        let io = Tokio;
        let listener = io.bind_tcp(([127, 0, 0, 1], 0).into()).expect("bind");
        let addr = listener.local_addr().expect("local address");
        let (done, finished) = std::sync::mpsc::channel::<()>();
        let sender = std::thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(addr).expect("connect");
            stream.write_all(payload.as_bytes()).expect("send");
            // Keep the connection open until the pipe is filled.
            finished.recv().ok();
        });
        let (mut stream, _) = listener.accept().await.expect("accept");
        let filled = match stream
            .splice_to_pipe(Pipe::new().expect("pipe"), usize::MAX)
            .await
        {
            Ok(Spliced::Filled(filled)) => filled,
            Ok(Spliced::End(_)) => panic!("the peer ended without sending"),
            Err((error, _)) => panic!("splice: {error}"),
        };
        drop(done);
        sender.join().expect("sender thread");
        assert_eq!(filled.len(), payload.len(), "the payload arrived whole");
        filled
    }

    fn mixed_body(pipe: FilledPipe) -> (Body, http::HeaderMap, Vec<u8>) {
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-checksum", http::HeaderValue::from_static("abc123"));
        let body = Body::from_frames(stream::iter([
            Ok::<_, Error>(BodyFrame::Data(Bytes::from_static(b"head:"))),
            Ok(BodyFrame::Pipe(pipe)),
            Ok(BodyFrame::Data(Bytes::from_static(b":tail"))),
            Ok(BodyFrame::Trailers(trailers.clone())),
        ]));
        let mut expected = b"head:".to_vec();
        expected.extend_from_slice(CJK_TEXT.as_bytes());
        expected.extend_from_slice(b":tail");
        (body, trailers, expected)
    }

    #[tokio::test]
    async fn a_pipe_frame_survives_the_stream() {
        let (body, trailers, _) = mixed_body(filled_pipe(CJK_TEXT).await);
        let frames: Vec<BodyFrame> = body.try_collect().await.unwrap();
        assert_eq!(frames.len(), 4);
        assert_eq!(frames[0].as_data().unwrap().as_ref(), b"head:");
        let pipe = frames[1].as_pipe().expect("the pipe stays a pipe");
        assert_eq!(pipe.len(), CJK_TEXT.len());
        assert_eq!(frames[2].as_data().unwrap().as_ref(), b":tail");
        assert_eq!(frames[3].as_trailers(), Some(&trailers));

        let BodyFrame::Pipe(pipe) = frames.into_iter().nth(1).unwrap() else {
            unreachable!()
        };
        let (bytes, _pipe) = pipe.read_out().unwrap();
        assert_eq!(bytes, CJK_TEXT.as_bytes());
    }

    #[tokio::test]
    async fn a_pipe_frame_is_read_out_by_into_data_stream() {
        let (body, _, expected) = mixed_body(filled_pipe(CJK_TEXT).await);
        let chunks: Vec<Bytes> = body.into_data_stream().try_collect().await.unwrap();
        assert_eq!(
            chunks.len(),
            3,
            "trailers are dropped, the pipe is one chunk"
        );
        assert_eq!(chunks.concat(), expected);
    }

    #[tokio::test]
    async fn a_pipe_frame_is_read_out_by_http_body() {
        let (mut body, trailers, expected) = mixed_body(filled_pipe(CJK_TEXT).await);
        let mut data = Vec::new();
        let mut received_trailers = None;
        while let Some(frame) = body.frame().await {
            let frame = frame.unwrap();
            assert!(received_trailers.is_none(), "trailers come last");
            match frame.into_data() {
                Ok(chunk) => data.extend_from_slice(&chunk),
                Err(frame) => received_trailers = Some(frame.into_trailers().unwrap()),
            }
        }
        assert_eq!(data, expected);
        assert_eq!(received_trailers, Some(trailers));

        let (body, _, expected) = mixed_body(filled_pipe(CJK_TEXT).await);
        assert_eq!(body.into_bytes().await.unwrap(), expected);
    }

    /// Answers an offer that carries a pipe with a pipe frame, and any other
    /// poll with data.
    struct Taking(Option<FilledPipe>);

    impl FrameSource for Taking {
        fn poll_next_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            offer: Option<&mut PipeOffer>,
        ) -> Poll<Option<Result<BodyFrame, Error>>> {
            let taken = offer.is_some_and(|offer| offer.take_pipe().is_some());
            match (taken, self.0.take()) {
                (true, Some(pipe)) => Poll::Ready(Some(Ok(BodyFrame::Pipe(pipe)))),
                (false, Some(pipe)) => {
                    let (bytes, _pipe) = pipe.read_out().unwrap();
                    Poll::Ready(Some(Ok(BodyFrame::Data(bytes))))
                }
                (_, None) => Poll::Ready(None),
            }
        }
    }

    #[tokio::test]
    async fn an_offered_pipe_is_answered_with_a_pipe_frame() {
        let mut body = Body::from_source(Taking(Some(filled_pipe(CJK_TEXT).await)));
        let mut offer = PipeOffer::with_pipe(64 * 1024, Pipe::new().unwrap());
        let frame = poll_fn(|cx| Pin::new(&mut body).poll_frame_offering(cx, &mut offer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(frame.as_pipe().unwrap().len(), CJK_TEXT.len());
        assert!(offer.take_pipe().is_none(), "the source took the pipe");

        // Without an offer the same source yields data.
        let mut body = Body::from_source(Taking(Some(filled_pipe(CJK_TEXT).await)));
        let frame = body.next().await.unwrap().unwrap();
        assert_eq!(frame.as_data().unwrap(), CJK_TEXT);
    }

    #[test]
    fn a_detached_offer_carries_the_pipe_and_gives_it_back() {
        let mut offer = PipeOffer::with_pipe(4096, Pipe::new().unwrap());
        let mut detached = offer.detach();
        assert!(offer.take_pipe().is_none(), "the pipe left with the offer");
        offer.reattach(PipeOffer::new(1));
        assert!(
            offer.take_pipe().is_none(),
            "an offer without a pipe gives none back"
        );

        let pipe = detached
            .take_pipe()
            .expect("the detached offer holds the pipe");
        offer.reattach(PipeOffer::with_pipe(4096, pipe));
        assert!(offer.take_pipe().is_some(), "the pipe came back");

        // An offer that has a pipe again keeps it; the returned one is dropped.
        let mut offer = PipeOffer::with_pipe(4096, Pipe::new().unwrap());
        offer.reattach(PipeOffer::with_pipe(4096, Pipe::new().unwrap()));
        assert!(offer.take_pipe().is_some());
        assert!(offer.take_pipe().is_none());
    }

    #[tokio::test]
    async fn a_frame_stream_leaves_the_offered_pipe_with_the_consumer() {
        let mut body = Body::from_frames(stream::iter([Ok::<_, Error>(BodyFrame::Data(
            Bytes::from(CJK_TEXT),
        ))]));
        let mut offer = PipeOffer::with_pipe(4096, Pipe::new().unwrap());
        let frame = poll_fn(|cx| Pin::new(&mut body).poll_frame_offering(cx, &mut offer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(frame.as_data().unwrap(), CJK_TEXT);
        assert!(offer.take_pipe().is_some());
    }
}
