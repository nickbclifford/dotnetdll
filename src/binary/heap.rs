use super::{metadata::index, signature::compressed};
use crate::utils::hash;
use scroll::{ctx::StrCtx, Pread, Pwrite, Result};
use std::collections::HashMap;

// TODO: seal these traits

/// Read-side abstraction over one metadata heap stream.
///
/// Implementations decode values from one of the standard heap streams (`#Strings`, `#Blob`,
/// `#GUID`, or `#US`) using that heap's index type and binary format.
///
/// See ECMA-335, II.24.2.3, II.24.2.4, and II.24.2.5.
pub trait Reader<'a> {
    /// Heap index type used by this reader.
    type Index;
    /// Value returned for an index lookup.
    type Value;

    /// Metadata stream name for this heap (for example, `"#Blob"`).
    const NAME: &'static str;

    /// Creates a heap reader over the raw stream bytes.
    fn new(bytes: &'a [u8]) -> Self;

    /// Reads and decodes the value stored at `idx`.
    fn at_index(&self, idx: Self::Index) -> Result<Self::Value>;
}

macro_rules! heap_reader {
    ($(#[$meta:meta])* $name:ident, $heap:literal, $index:ty, $value:ty, |$s:ident, $val:ident| $e:expr) => {
        $(#[$meta])*
        #[derive(Copy, Clone)]
        pub struct $name<'a> {
            bytes: &'a [u8],
        }

        impl<'a> Reader<'a> for $name<'a> {
            type Index = $index;
            type Value = $value;

            const NAME: &'static str = $heap;

            fn new(bytes: &'a [u8]) -> $name<'a> {
                $name {
                    bytes: &bytes,
                }
            }

            fn at_index(&$s, $val: Self::Index) -> Result<Self::Value> {
                $e
            }
        }

        impl std::fmt::Debug for $name<'_> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(stringify!($name))
            }
        }
    };
}

fn read_bytes(bytes: &[u8], idx: usize) -> Result<&[u8]> {
    let mut offset = idx;

    let compressed::Unsigned(size) = bytes.gread(&mut offset)?;

    bytes.pread_with(offset, size as usize)
}

heap_reader!(
    /// Reader for the `#Strings` heap.
    ///
    /// Entries are null-terminated UTF-8 strings. Index `0` resolves to the empty string.
    ///
    /// See ECMA-335, II.24.2.3.
    StringsReader,
    "#Strings",
    index::String,
    &'a str,
    |self, idx| self.bytes.pread_with(idx.0, StrCtx::Delimiter(0))
);
heap_reader!(
    /// Reader for the `#Blob` heap.
    ///
    /// Entries are compressed-length-prefixed byte arrays.
    ///
    /// See ECMA-335, II.24.2.4.
    BlobReader,
    "#Blob",
    index::Blob,
    &'a [u8],
    |self, idx| read_bytes(self.bytes, idx.0)
);
heap_reader!(
    /// Reader for the `#GUID` heap.
    ///
    /// Entries are 16-byte GUID values addressed by 1-based indices (`0` is the null index).
    ///
    /// See ECMA-335, II.24.2.5.
    GUIDReader,
    "#GUID",
    index::GUID,
    [u8; 16],
    |self, idx| {
        let mut buf = [0_u8; 16];
        self.bytes
            .gread_inout_with(&mut ((idx.0 - 1) * 16), &mut buf, scroll::LE)?;
        Ok(buf)
    }
);
heap_reader!(
    /// Reader for the `#US` heap.
    ///
    /// Entries are compressed-length-prefixed UTF-16 data with a trailing special-byte flag.
    /// This reader returns the UTF-16 code units and discards the trailing flag byte.
    ///
    /// See ECMA-335, II.24.2.4.
    UserStringReader,
    "#US",
    usize,
    Vec<u16>,
    |self, idx| {
        let bytes = read_bytes(self.bytes, idx)?;

        let num_utf16 = (bytes.len() - 1) / 2;
        let offset = &mut 0;
        let chars = (0..num_utf16)
            .map(|_| bytes.gread_with::<u16>(offset, scroll::LE))
            .collect::<Result<_>>()?;

        Ok(chars)
    }
);

fn write_bytes(bytes: &[u8]) -> Result<Vec<u8>> {
    let len = bytes.len();

    let mut buf = vec![0_u8; len];

    let len_size = buf.pwrite(compressed::Unsigned(len as u32), 0)?;

    buf.extend(vec![0_u8; len_size]);

    buf.pwrite(bytes, len_size)?;

    Ok(buf)
}

/// Write-side abstraction for one metadata heap stream.
///
/// Implementations build heap bytes and return the corresponding heap index for each inserted
/// value. Concrete writers in this module use a hash-based cache to intern repeated inputs so the
/// same value maps to the same index during one write session.
///
/// In this crate, these writers are constructed by [`crate::resolution::write`] while emitting a
/// [`crate::resolution::Resolution`].
pub trait Writer {
    /// Heap index type produced by this writer.
    type Index;
    /// Value type accepted by this writer.
    type Value: ?Sized;

    /// Creates an empty writer, including any required heap sentinel bytes.
    fn new() -> Self;

    /// Writes `value` into the heap (or reuses an interned entry) and returns its index.
    fn write(&mut self, value: &Self::Value) -> Result<Self::Index>;

    /// Returns the finalized heap stream bytes.
    fn into_vec(self) -> Vec<u8>;
}

macro_rules! heap_writer {
    ($(#[$meta:meta])* $name:ident, ($buf:expr, $map:expr), $index:ty, $value:ty, |$s:ident, $n:ident| $e:expr) => {
        $(#[$meta])*
        pub struct $name {
            buffer: Vec<u8>,
            index_cache: HashMap<u64, <Self as Writer>::Index>,
        }

        impl Writer for $name {
            type Index = $index;
            type Value = $value;

            fn new() -> Self {
                $name {
                    buffer: $buf,
                    index_cache: $map,
                }
            }

            fn into_vec(self) -> Vec<u8> {
                self.buffer
            }

            fn write(&mut $s, $n: &Self::Value) -> Result<Self::Index> {
                let h = hash($n);

                Ok(match $s.index_cache.get(&h) {
                    Some(&i) => i,
                    None => {
                        let idx = $e;
                        $s.index_cache.insert(h, idx);
                        idx
                    }
                })
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(stringify!($name))
            }
        }
    };
}

heap_writer!(
    /// Writer for the `#Strings` heap.
    ///
    /// Emits null-terminated UTF-8 strings and interns repeated strings by hash.
    ///
    /// See ECMA-335, II.24.2.3.
    StringsWriter,
    (vec![0], HashMap::from([(hash(""), 0.into())])),
    index::String,
    str,
    |self, value| {
        let start = self.buffer.len();
        self.buffer.extend(value.as_bytes());
        self.buffer.push(0_u8);
        index::String(start)
    }
);
heap_writer!(
    /// Writer for the `#Blob` heap.
    ///
    /// Emits compressed-length-prefixed blob payloads and interns repeated byte arrays by hash.
    ///
    /// See ECMA-335, II.24.2.4.
    BlobWriter,
    (vec![0], HashMap::from([(hash(&[] as &Self::Value), 0.into())])),
    index::Blob,
    [u8],
    |self, value| {
        let start = self.buffer.len();
        self.buffer.extend(write_bytes(value)?);
        index::Blob(start)
    }
);
heap_writer!(
    /// Writer for the `#GUID` heap.
    ///
    /// Emits 16-byte GUID entries and returns 1-based heap indices.
    ///
    /// See ECMA-335, II.24.2.5.
    GUIDWriter,
    (vec![], HashMap::new()),
    index::GUID,
    [u8; 16],
    |self, value| {
        let start = self.buffer.len();
        self.buffer.extend(value);
        index::GUID(((start + 1) / 16) + 1)
    }
);
heap_writer!(
    /// Writer for the `#US` heap.
    ///
    /// Emits compressed-length-prefixed UTF-16 strings with the trailing special-byte flag and
    /// interns repeated inputs by hash.
    ///
    /// See ECMA-335, II.24.2.4.
    UserStringWriter,
    (vec![0], HashMap::from([(hash(&[] as &Self::Value), 0)])),
    usize,
    [u16],
    |self, value| {
        let final_byte = value.iter().any(|u| {
            let [high, low] = u.to_be_bytes();
            high != 0 || matches!(low, 0x01..=0x08 | 0x0E..=0x1F | 0x27 | 0x2D | 0x7F)
        }) as u8;

        let start = self.buffer.len();
        self.buffer.extend(write_bytes(
            &value
                .iter()
                .flat_map(|&u| u.to_le_bytes())
                .chain(std::iter::once(final_byte))
                .collect::<Vec<_>>(),
        )?);
        start
    }
);
