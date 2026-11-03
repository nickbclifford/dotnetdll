use dotnetdll::prelude::*;
fn main() {
    let bytes = std::fs::read(std::env::args().nth(1).expect("DLL path")).unwrap();
    let own = std::env::args().nth(2).as_deref() == Some("owned");
    let options = ReadOptions::default()
        .with_lazy_method_bodies(true)
        .with_lazy_attributes(true)
        .with_own_heap_values(own);
    let start = std::time::Instant::now();
    let resolution = Resolution::parse(&bytes, options).unwrap();
    println!(
        "parse {:?}; own={own}; types={}",
        start.elapsed(),
        resolution.type_definitions.len()
    );
    assert_eq!(matches!(resolution.module.name, std::borrow::Cow::Owned(_)), own);
    std::hint::black_box(resolution);
}
