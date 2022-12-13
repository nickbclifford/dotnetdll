use once_cell::sync::Lazy;
use std::path::PathBuf;

macro_rules! lazy_paths {
    ($($name:ident = $value:expr;)*) => {
        $(
            pub static $name: Lazy<PathBuf> = Lazy::new(|| $value);
        )*
    }
}

lazy_paths! {
    RUNTIME_ARTIFACTS = PathBuf::from(required("RUNTIME_ARTIFACTS"));
    // TODO: determine framework version and build triple
    ILASM = panic!("bin/coreclr/[framework]/ilasm");
    ILDASM = panic!("bin/coreclr/[framework]/ildasm");
    DOTNET = panic!("bin/testhost/[framework]-[triple]/dotnet");
    LIBRARIES = panic!("bin/testhost/[framework]-[triple]/shared/Microsoft.NETCore.App/[version]");
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
