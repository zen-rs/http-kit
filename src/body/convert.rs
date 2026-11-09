use alloc::{borrow::Cow, boxed::Box, string::String, vec::Vec};
use bytes::Bytes;
use bytestr::ByteStr;

use super::Body;

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

macro_rules! from_str {
    ($($ty:ty),*) => {
        $(
            impl From<$ty> for Body {
                fn from(data: $ty) -> Self {
                    Body::from_text(data)
                }
            }
        )*
    };
}

from_str!(ByteStr, String, Box<str>, &str, Cow<'_, str>);

from_bytes!(Bytes, Vec<u8>, Box<[u8]>);

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

#[cfg(feature = "fs")]
impl From<super::FileRegion> for Body {
    fn from(region: super::FileRegion) -> Self {
        Body::from_file_region(region)
    }
}
