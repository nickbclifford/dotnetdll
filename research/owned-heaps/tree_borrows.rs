use std::{hint::black_box, time::Instant};

#[inline(never)]
fn read(bytes: &[u8]) -> u64 {
    bytes[..16].iter().map(|&b| u64::from(b)).sum()
}

fn main() {
    let n: usize = std::env::args().nth(1).unwrap_or("600".into()).parse().unwrap();
    let bytes = vec![1u8; (n + 1) * 16];
    let borrows: Vec<&[u8]> = (0..n).map(|i| &bytes[i * 16..i * 16 + 1]).collect();
    let start = Instant::now();
    for _ in 0..100 {
        black_box(read(black_box(&bytes)));
    }
    println!("n={n} reads={:?}", start.elapsed());
    black_box(borrows);
}
