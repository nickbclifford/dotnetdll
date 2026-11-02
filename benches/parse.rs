use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use dotnetdll::prelude::*;
use std::hint::black_box;

#[path = "../tests/common/env.rs"]
mod env;

fn parse_dll(c: &mut Criterion) {
    let input = std::env::var_os("DOTNETDLL_BENCH_DLL")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| env::LIBRARIES.join("System.Private.CoreLib.dll"));
    let bytes = std::fs::read(&input).expect("failed to read benchmark DLL");
    let name = input.file_stem().unwrap().to_string_lossy();
    let mut group = c.benchmark_group("parse");
    group.throughput(Throughput::Bytes(bytes.len() as u64));
    group.sample_size(30);
    for (mode, options) in [
        ("eager", ReadOptions::default()),
        ("lazy_bodies", ReadOptions::default().with_lazy_method_bodies(true)),
        (
            "lazy_signatures",
            ReadOptions::default().with_lazy_method_signatures(true),
        ),
        (
            "lazy_all",
            ReadOptions::default()
                .with_lazy_method_bodies(true)
                .with_lazy_method_signatures(true),
        ),
        (
            "lazy_production",
            ReadOptions::default()
                .with_lazy_method_bodies(true)
                .with_lazy_method_signatures(true)
                .with_lazy_attributes(true),
        ),
        (
            "consumer",
            ReadOptions::default()
                .with_lazy_method_bodies(true)
                .with_lazy_attributes(true),
        ),
    ] {
        for own in [false, true] {
            let suffix = if own { "/owned_heaps" } else { "" };
            group.bench_function(format!("{name}/{mode}{suffix}"), |b| {
                b.iter(|| {
                    black_box(
                        Resolution::parse(black_box(&bytes), options.with_own_heap_values(own))
                            .expect("failed to parse benchmark DLL"),
                    )
                })
            });
        }
    }
    group.finish();
}

criterion_group!(parse_benches, parse_dll);
criterion_main!(parse_benches);
