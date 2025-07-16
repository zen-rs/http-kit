use core::any::Any;

use alloc::boxed::Box;
use bytes::{Buf, Bytes};
use http_body_util::BodyExt;

use crate::endpoint::AnyError;
pub trait Body:
    http_body::Body<Error: core::error::Error + Send + Sync> + Send + Sync + Any
{
}

pub(crate) fn erased(body: impl Body) -> AnyBody {
    let body = body
        .map_frame(|frame| frame.map_data(|mut data| data.copy_to_bytes(data.remaining())))
        .map_err(AnyError::new);

    AnyBody::new(body)
}

impl<T> Body for T where
    T: http_body::Body<Error: core::error::Error + Send + Sync> + Send + Sync + 'static
{
}

pub struct AnyBody(Box<dyn Body<Data = Bytes, Error = AnyError>>);

impl AnyBody {
    pub fn new(body: impl Body<Data = Bytes, Error = AnyError> + Send + Sync + 'static) -> Self {
        Self(Box::new(body))
    }

    pub fn downcast<T: Body>(self) -> Result<Box<T>, Box<dyn Any + Send + Sync>> {
        let this: Box<dyn Any + Send + Sync> = self.0;
        this.downcast::<T>()
    }
}

impl http_body::Body for AnyBody {
    type Data = Bytes;
    type Error = AnyError;

    fn poll_frame(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        // Delegate to the inner boxed body
        let this = self.get_mut();
        // Safety: AnyBody is a newtype over Box<dyn Body<Data=Bytes, Error=AnyError>>
        let inner = unsafe { core::pin::Pin::new_unchecked(&mut *this.0) };
        http_body::Body::poll_frame(inner, cx)
    }
}
