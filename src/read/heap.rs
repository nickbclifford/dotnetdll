use super::{metadata::index, signature::compressed};
use scroll::{ctx::StrCtx, Endian, Error, Pread};

pub trait Heap<'a> {
    type Index;
    type Value;

    fn new(bytes: &'a [u8]) -> Self;

    fn at_index(&self, idx: Self::Index) -> Result<Self::Value, Error>;
}

macro_rules! heap_struct {
    ($name:ident, { $($i:item)* }) => {
        pub struct $name<'a> {
            bytes: &'a [u8],
        }

        impl<'a> Heap<'a> for $name<'a> {
            fn new(bytes: &'a [u8]) -> $name<'a> {
                $name {
                    bytes: &bytes,
                }
            }

            $($i)*
        }
    };
}

heap_struct!(Strings, {
    type Index = index::String;
    type Value = &'a str;

    fn at_index(&self, index::String(idx): Self::Index) -> Result<Self::Value, Error> {
        self.bytes.pread_with(idx, StrCtx::Delimiter(0))
    }
});
heap_struct!(Blob, {
    type Index = index::Blob;
    type Value = &'a [u8];

    fn at_index(&self, index::Blob(idx): Self::Index) -> Result<Self::Value, Error> {
        let mut offset = idx;

        let compressed::Unsigned(size) = self.bytes.gread_with(&mut offset, scroll::LE)?;

        let bytes = self.bytes.pread_with(offset, size as usize)?;

        Ok(bytes)
    }
});
heap_struct!(GUID, {
    type Index = index::GUID;
    type Value = u128;

    fn at_index(&self, index::GUID(idx): Self::Index) -> Result<Self::Value, Error> {
        Ok(self.bytes.pread_with(idx, Endian::Little)?)
    }
});
