//! Endpoints, bodies and middleware need `Send` only where their parts are.

use std::{cell::Cell, convert::Infallible, future::Future, rc::Rc};

use bytes::Bytes;
use futures_lite::{stream, StreamExt};
use http_kit::{
    endpoint::{AnyEndpoint, AnySendEndpoint, SendNext, WithMiddleware},
    flavor::{Flavor, Local},
    middleware::{AnySendMiddleware, MiddlewareError},
    Body, Endpoint, GenericBody, LocalBody, LocalRequest, LocalResponse, Middleware, Request,
    Response, SendEndpoint, SendMiddleware,
};

/// Counts requests in per-thread state and echoes the request body.
struct Counter {
    served: Rc<Cell<u32>>,
}

impl Endpoint<Local> for Counter {
    type Error = Infallible;
    async fn respond(&mut self, request: &mut LocalRequest) -> Result<LocalResponse, Infallible> {
        self.served.set(self.served.get() + 1);
        let body = request.body_mut().take().expect("body taken once");
        Ok(LocalResponse::new(body))
    }
}

/// Tags every response, for any body flavour.
struct Tag(&'static str);

impl<F: Flavor> Middleware<F> for Tag {
    type Error = Infallible;
    async fn handle<E: Endpoint<F>>(
        &mut self,
        request: &mut Request<F>,
        mut next: E,
    ) -> Result<Response<F>, MiddlewareError<E::Error, Infallible>> {
        let mut response = next
            .respond(request)
            .await
            .map_err(MiddlewareError::Endpoint)?;
        response
            .headers_mut()
            .insert("x-tag", http::HeaderValue::from_static(self.0));
        Ok(response)
    }
}

impl SendMiddleware for Tag {
    fn handle_send<E: SendEndpoint>(
        &mut self,
        request: &mut Request,
        next: E,
    ) -> impl Future<Output = Result<Response, MiddlewareError<E::Error, Infallible>>> + Send {
        self.handle(request, SendNext::new(next))
    }
}

/// A body whose stream holds an `Rc`, so it can only be a `LocalBody`.
fn local_body(owner: Rc<str>) -> LocalBody {
    LocalBody::from_stream(stream::iter(["thread", "-", "local"]).map(move |chunk| {
        let _ = &owner;
        Ok::<_, Infallible>(Bytes::from_static(chunk.as_bytes()))
    }))
}

#[test]
fn local_endpoint_and_body_serve_on_a_single_threaded_executor() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    let served = Rc::new(Cell::new(0));

    let mut endpoint = AnyEndpoint::<Local>::new(WithMiddleware::new(
        Counter {
            served: served.clone(),
        },
        Tag("local"),
    ));

    let task = local.spawn_local(async move {
        let mut bodies = Vec::new();
        for _ in 0..2 {
            let mut request = LocalRequest::new(local_body(Rc::from("owner")));
            let response = endpoint.respond(&mut request).await.unwrap();
            assert_eq!(response.headers()["x-tag"], "local");
            bodies.push(response.into_body().into_bytes().await.unwrap());
        }
        bodies
    });
    let bodies = local.block_on(&runtime, task).unwrap();

    assert_eq!(bodies, ["thread-local", "thread-local"]);
    assert_eq!(served.get(), 2);
}

/// Echoes the request body; every part is `Send`.
struct Echo;

impl Endpoint for Echo {
    type Error = Infallible;
    async fn respond(&mut self, request: &mut Request) -> Result<Response, Infallible> {
        let body = request.body_mut().take().expect("body taken once");
        Ok(Response::new(body))
    }
}

impl SendEndpoint for Echo {
    fn respond_send(
        &mut self,
        request: &mut Request,
    ) -> impl Future<Output = Result<Response, Infallible>> + Send {
        self.respond(request)
    }
}

fn send_body() -> Body {
    Body::from_stream(
        stream::iter(["work", "-", "stealing"])
            .map(|chunk| Ok::<_, Infallible>(Bytes::from_static(chunk.as_bytes()))),
    )
}

/// Moves any `SendEndpoint` to another thread without knowing its type.
async fn spawn_generic<E: SendEndpoint + 'static>(mut endpoint: E) -> (String, Bytes) {
    tokio::spawn(async move {
        let mut request = Request::new(send_body());
        let response = endpoint.respond_send(&mut request).await.unwrap();
        let tag = response.headers()["x-tag"].to_str().unwrap().to_owned();
        (tag, response.into_body().into_bytes().await.unwrap())
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_endpoint_and_body_pass_through_tokio_spawn() {
    // A concrete endpoint built from `Send` parts, called through the plain
    // `Endpoint` trait: its future is `Send` without any bound saying so.
    let mut endpoint = WithMiddleware::new(Echo, Tag("concrete"));
    let mut request = Request::new(send_body());
    let response = tokio::spawn(async move { endpoint.respond(&mut request).await })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.headers()["x-tag"], "concrete");
    assert_eq!(
        response.into_body().into_bytes().await.unwrap(),
        "work-stealing"
    );

    // The same through generic code, and through the `Send` erased forms.
    let (tag, body) = spawn_generic(WithMiddleware::new(Echo, Tag("generic"))).await;
    assert_eq!(
        (tag.as_str(), body.as_ref()),
        ("generic", &b"work-stealing"[..])
    );

    let erased = AnySendEndpoint::new(WithMiddleware::new(
        AnySendEndpoint::new(Echo),
        AnySendMiddleware::new(Tag("erased")),
    ));
    let (tag, body) = spawn_generic(erased).await;
    assert_eq!(
        (tag.as_str(), body.as_ref()),
        ("erased", &b"work-stealing"[..])
    );
}

#[tokio::test]
async fn send_body_becomes_local() {
    let body: GenericBody<Local> = send_body().into();
    assert_eq!(body.into_bytes().await.unwrap(), "work-stealing");
}
