use alloc::{borrow::Cow, boxed::Box, string::String, vec::Vec};
use bytes::Bytes;
use bytestr::ByteStr;
use core::pin::Pin;
use futures_lite::AsyncBufRead;

use super::{Body, BodyInner};

macro_rules! from_bytes {
    ($($ty:ty),*) => {
        $(
            impl From<$ty> for Body {
                fn from(data: $ty) -> Self {
                    Body::from_bytes(data)
                }
            }
        )*
    };
}
from_bytes!(Bytes, Vec<u8>, Box<[u8]>, ByteStr, String);

impl<'a> From<Cow<'a, [u8]>> for Body {
    fn from(data: Cow<[u8]>) -> Self {
        Body::from_bytes(data.into_owned())
    }
}

impl From<&[u8]> for Body {
    fn from(data: &[u8]) -> Self {
        Body::from_bytes(data.to_vec())
    }
}

impl From<Box<str>> for Body {
    fn from(data: Box<str>) -> Self {
        Body::from_bytes(ByteStr::from(data))
    }
}

impl<'a> From<Cow<'a, str>> for Body {
    fn from(data: Cow<str>) -> Self {
        data.as_bytes().into()
    }
}

impl From<&str> for Body {
    fn from(data: &str) -> Self {
        data.as_bytes().into()
    }
}

impl From<Box<dyn AsyncBufRead + Send + 'static>> for Body {
    fn from(reader: Box<dyn AsyncBufRead + Send + 'static>) -> Self {
        Pin::from(reader).into()
    }
}

impl From<Pin<Box<dyn AsyncBufRead + Send + 'static>>> for Body {
    fn from(reader: Pin<Box<dyn AsyncBufRead + Send + 'static>>) -> Self {
        Self {
            inner: BodyInner::Reader {
                reader,
                length: None,
            },
        }
    }
}
