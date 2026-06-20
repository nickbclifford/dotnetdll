use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use dotnetdll::prelude::*;

#[path = "../tests/common/env.rs"]
mod env;

fn parse_system_private_corelib(c: &mut Criterion) {
    let bytes = std::fs::read(env::LIBRARIES.join("System.Private.CoreLib.dll"))
        .expect("failed to read System.Private.CoreLib.dll");

    let mut group = c.benchmark_group("parse");
    group.throughput(Throughput::Bytes(bytes.len() as u64));
    group.sample_size(30);

    group.bench_function("System.Private.CoreLib/eager", |b| {
        b.iter(|| {
            let parsed = Resolution::parse(black_box(&bytes), ReadOptions::default())
                .expect("failed to parse System.Private.CoreLib.dll");
            black_box(parsed);
        })
    });

    group.bench_function("System.Private.CoreLib/lazy_bodies", |b| {
        b.iter(|| {
            let parsed = Resolution::parse(
                black_box(&bytes),
                ReadOptions {
                    lazy_method_bodies: true,
                    ..ReadOptions::default()
                },
            )
            .expect("failed to parse System.Private.CoreLib.dll");
            black_box(parsed);
        })
    });

    group.bench_function("System.Private.CoreLib/lazy_signatures", |b| {
        b.iter(|| {
            let parsed = Resolution::parse(
                black_box(&bytes),
                ReadOptions {
                    lazy_method_signatures: true,
                    ..ReadOptions::default()
                },
            )
            .expect("failed to parse System.Private.CoreLib.dll");
            black_box(parsed);
        })
    });

    group.bench_function("System.Private.CoreLib/lazy_all", |b| {
        b.iter(|| {
            let parsed = Resolution::parse(
                black_box(&bytes),
                ReadOptions {
                    lazy_method_bodies: true,
                    lazy_method_signatures: true,
                    ..ReadOptions::default()
                },
            )
            .expect("failed to parse System.Private.CoreLib.dll");
            black_box(parsed);
        })
    });

    group.bench_function("System.Private.CoreLib/lazy_production", |b| {
        b.iter(|| {
            let parsed = Resolution::parse(
                black_box(&bytes),
                ReadOptions {
                    lazy_method_bodies: true,
                    lazy_method_signatures: true,
                    lazy_attributes: true,
                    ..ReadOptions::default()
                },
            )
            .expect("failed to parse System.Private.CoreLib.dll");
            black_box(parsed);
        })
    });

    group.finish();
}

criterion_group!(parse_benches, parse_system_private_corelib);
criterion_main!(parse_benches);
