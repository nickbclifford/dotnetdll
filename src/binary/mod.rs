#[macro_use]
mod utils {
    macro_rules! throw {
        ($($arg:tt)*) => {
            return Err(scroll::Error::Custom(format!($($arg)*)))
        }
    }
}

pub mod cli;
pub mod heap;
pub mod il;
pub mod metadata;
pub mod method;
pub mod signature;
pub mod stream;
