use super::metadata::index;
use scroll::{Endian, Error, Pread};

pub trait Heap {
    type Index;
    type Value;

    fn at_index(&self, idx: Self::Index) -> Result<Self::Value, Error>;
}

macro_rules! heap_struct {
    ($name:ident) => {
        pub struct $name<'a> {
            bytes: &'a [u8],
        }

        impl $name<'_> {
            pub fn new(bytes: &[u8], offset: usize) -> $name {
                $name {
                    bytes: &bytes[offset..],
                }
            }
        }
    };
}

heap_struct!(Strings);
heap_struct!(Blob);
heap_struct!(GUID);

impl Heap for Strings<'_> {
    type Index = index::String;
    type Value = String;

    fn at_index(&self, index::String(idx): Self::Index) -> Result<Self::Value, Error> {
        let mut buf = vec![];
        let mut offset = idx as usize;
        loop {
            let c: u8 = self.bytes.gread_with(&mut offset, Endian::Little)?;
            if c == 0 {
                break;
            } else {
                buf.push(c);
            }
        }
        // This should never happen, but might as well be careful
        Ok(String::from_utf8(buf).map_err(|e| Error::Custom(e.to_string()))?)
    }
}

impl<'a> Heap for Blob<'a> {
    type Index = index::Blob;
    type Value = &'a [u8];

    fn at_index(&self, index::Blob(idx): Self::Index) -> Result<Self::Value, Error> {
        let mut offset = idx as usize;
        let mut size = 0usize;

        let indicator: u8 = self.bytes.gread_with(&mut offset, Endian::Little)?;
        if (indicator >> 7) == 0 {
            size = indicator as usize;
        } else if (indicator >> 6) == 0b10 {
            let b2: u8 = self.bytes.gread_with(&mut offset, Endian::Little)?;
            size = (((indicator & 0b111111) << 8) + b2) as usize;
        } else if (indicator >> 5) == 0b110 {
            let b2: u8 = self.bytes.gread_with(&mut offset, Endian::Little)?;
            let b3: u8 = self.bytes.gread_with(&mut offset, Endian::Little)?;
            let b4: u8 = self.bytes.gread_with(&mut offset, Endian::Little)?;
            size = (((indicator & 0b11111) << 24) + (b2 << 16) + (b3 << 8) + b4) as usize;
        }

        Ok(self.bytes.pread_with(offset, size)?)
    }
}

impl Heap for GUID<'_> {
    type Index = index::GUID;
    type Value = u128;

    fn at_index(&self, index::GUID(idx): Self::Index) -> Result<Self::Value, Error> {
        Ok(self.bytes.pread_with(idx as usize, Endian::Little)?)
    }
}
