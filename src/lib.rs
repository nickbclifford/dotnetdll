#![warn(clippy::pedantic)]
#![allow(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::enum_glob_use,
    clippy::items_after_statements,
    clippy::match_wildcard_for_single_variants,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::struct_excessive_bools,
    clippy::uninlined_format_args,
    clippy::wildcard_imports
)]

#[macro_use]
mod utils {
    macro_rules! check_bitmask {
        ($mask:expr, $val:literal) => {
            $mask & $val == $val
        };
    }

    macro_rules! build_bitmask {
        ($target:expr, $($field:ident => $val:literal),+) => {{
            let mut mask = 0;
            $(
                if $target.$field {
                    mask |= $val;
                }
            )+
            mask
        }}
    }

    macro_rules! try_into_ctx {
        ($t:ty, |$s:ident, $buf:ident| $e:expr) => {
            try_into_ctx!(() => $t, |$s, $buf, _ctx| $e);
        };
        ($ctx:ty => $t:ty, |$s:ident, $buf:ident, $ctx_i:ident| $e:expr) => {
            impl TryIntoCtx<$ctx> for $t {
                type Error = scroll::Error;

                fn try_into_ctx(
                    $s,
                    $buf: &mut [u8],
                    $ctx_i: $ctx,
                ) -> std::result::Result<usize, Self::Error> {
                    $e
                }
            }

            impl TryIntoCtx<$ctx, scroll_buffer::DynamicBuffer> for $t {
                type Error = scroll::Error;

                fn try_into_ctx(
                    $s,
                    $buf: &mut scroll_buffer::DynamicBuffer,
                    $ctx_i: $ctx,
                ) -> std::result::Result<usize, Self::Error> {
                    $e
                }
            }
        };
    }

    use std::hash::*;

    pub fn hash(val: impl Hash) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        val.hash(&mut hasher);
        hasher.finish()
    }

    pub fn round_up_to_4(mut val: usize) -> (usize, usize) {
        let rem = val % 4;
        if rem != 0 {
            val += 4 - rem;
        }
        (val, rem)
    }
}

pub mod binary;
mod convert;
pub mod dll;
pub mod resolution;
pub mod resolved;

pub mod prelude {
    pub use crate::{
        access, asm,
        dll::{DLLError, DLL},
        resolution::{read::Options as ReadOptions, utils::*, write::Options as WriteOptions, *},
        resolved::{
            assembly::*,
            attribute::*,
            body, generic,
            il::*,
            members::{Accessibility as MemberAccessibility, *},
            module::*,
            resource,
            signature::*,
            types::{Accessibility as TypeAccessibility, *},
            Accessibility, ResolvedDebug,
        },
    };
}

#[cfg(test)]
mod tests {
    #[test]
    pub fn constructor_macros() {
        use super::resolved::{signature::*, types::*};

        let m: MethodType = ctype! { string[] };
        println!("{:?}", m);
        let m: MethodType = ctype! { bool };
        println!("{:?}", m);
        let m: MethodType = ctype! { char[]* };
        println!("{:?}", m);
        let m: MethodType = ctype! { void*[] };
        println!("{:?}", m);

        let m: ManagedMethod<_> = msig! { string (int, ref #m) };
        println!("{:?}", m);
        let m: ManagedMethod<MethodType> = msig! { static void (string[]) };
        println!("{:?}", m);
    }
}
