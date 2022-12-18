use once_cell::sync::Lazy;
use std::path::{Path, PathBuf};

macro_rules! lazy_paths {
    ($($name:ident = $value:expr;)*) => {
        $(
            #[allow(dead_code)]
            pub static $name: Lazy<PathBuf> = Lazy::new(|| $value);
        )*
    }
}

fn first_child_dir(path: impl AsRef<Path>) -> PathBuf {
    let mut read_dir = path.as_ref().read_dir().unwrap();
    let entry = read_dir.next().unwrap()  // Option
        .unwrap(); // io::Result
    entry.path()
}

lazy_paths! {
    DOTNET_SDK = PathBuf::from(required("DOTNET_SDK"));
    RUNTIME_ARTIFACTS = PathBuf::from(required("RUNTIME_ARTIFACTS"));
    CORECLR = first_child_dir(RUNTIME_ARTIFACTS.join("bin/coreclr"));
    ILASM = CORECLR.join("ilasm");
    ILDASM = CORECLR.join("ildasm");
    TESTHOST = first_child_dir(RUNTIME_ARTIFACTS.join("bin/testhost"));
    LIBRARIES = first_child_dir(TESTHOST.join("shared/Microsoft.NETCore.App"));
}

pub fn optional(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

pub fn required(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| {
        panic!(
            "Missing required environment variable {}! Please set this variable before running tests.",
            key
        )
    })
}
