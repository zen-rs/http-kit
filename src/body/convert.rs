use alloc::{borrow::Cow, boxed::Box, string::String, vec::Vec};
use bytes::Bytes;
use bytestr::ByteStr;

use super::GenericBody;
use crate::flavor::Flavor;

macro_rules! from_bytes {
    ($($ty:ty),*) => {
        $(
            impl<F: Flavor> From<$ty> for GenericBody<F> {
                fn from(data: $ty) -> Self {
                    Self::from_bytes(data)
                }
            }
        )*
    };
}

macro_rules! from_str {
    ($($ty:ty),*) => {
        $(
            impl<F: Flavor> From<$ty> for GenericBody<F> {
                fn from(data: $ty) -> Self {
                    Self::from_text(data)
                }
            }
        )*
    };
}

from_str!(ByteStr, String, Box<str>, &str, Cow<'_, str>);

from_bytes!(Bytes, Vec<u8>, Box<[u8]>);

impl<F: Flavor> From<Cow<'_, [u8]>> for GenericBody<F> {
    fn from(data: Cow<[u8]>) -> Self {
        Self::from_bytes(data.into_owned())
    }
}

impl<F: Flavor> From<&[u8]> for GenericBody<F> {
    fn from(data: &[u8]) -> Self {
        Self::from_bytes(data.to_vec())
    }
}

#[cfg(feature = "fs")]
impl<F: Flavor> From<super::FileRegion> for GenericBody<F> {
    fn from(region: super::FileRegion) -> Self {
        Self::from_file_region(region)
    }
}
