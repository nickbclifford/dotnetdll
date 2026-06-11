use criterion::{Criterion, black_box, criterion_group, criterion_main};
use dotnetdll::prelude::*;

#[path = "../tests/common/env.rs"]
mod env;

fn parse_system_private_corelib(c: &mut Criterion) {
    let bytes = std::fs::read(env::LIBRARIES.join("System.Private.CoreLib.dll"))
        .expect("failed to read System.Private.CoreLib.dll");

    c.bench_function("parse/System.Private.CoreLib", |b| {
        b.iter(|| {
            let parsed = Resolution::parse(black_box(&bytes), ReadOptions::default())
                .expect("failed to parse System.Private.CoreLib.dll");
            black_box(parsed);
        })
    });
}

criterion_group!(parse_benches, parse_system_private_corelib);
criterion_main!(parse_benches);
