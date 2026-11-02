use dotnetdll::prelude::*;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicUsize, Ordering::Relaxed},
    time::Instant,
};
struct Meter;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
// SAFETY: all operations forward the original pointers/layouts to System.
// Accounting touches only atomics and never dereferences allocation pointers.
unsafe impl GlobalAlloc for Meter {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            let n = LIVE.fetch_add(l.size(), Relaxed) + l.size();
            PEAK.fetch_max(n, Relaxed);
            ALLOCS.fetch_add(1, Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Relaxed);
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        let q = unsafe { System.realloc(p, l, n) };
        if !q.is_null() {
            let live = LIVE.fetch_add(n, Relaxed) + n - l.size();
            LIVE.fetch_sub(l.size(), Relaxed);
            PEAK.fetch_max(live, Relaxed);
            ALLOCS.fetch_add(1, Relaxed);
        }
        q
    }
}
#[global_allocator]
static ALLOC: Meter = Meter;
#[inline(never)]
fn parse_once(bytes: &[u8], opts: ReadOptions) {
    std::hint::black_box(Resolution::parse(std::hint::black_box(bytes), opts).unwrap());
}
fn main() {
    let bytes = std::fs::read(std::env::args().nth(1).unwrap()).unwrap();
    let mode = std::env::args().nth(4).unwrap_or("consumer".into());
    let mut opts = ReadOptions::default().with_own_heap_values(std::env::args().nth(3).as_deref() == Some("owned"));
    if mode != "eager" {
        opts = opts.with_lazy_method_bodies(true);
    }
    if mode == "consumer" || mode == "production" {
        opts = opts.with_lazy_attributes(true);
    }
    if mode == "production" {
        opts = opts.with_lazy_method_signatures(true);
    }

    parse_once(&bytes, opts);
    let live = LIVE.load(Relaxed);
    PEAK.store(live, Relaxed);
    ALLOCS.store(0, Relaxed);
    let now = Instant::now();
    let r = Resolution::parse(&bytes, opts).unwrap();
    println!(
        "parse_us={} retained_bytes={} peak_extra_bytes={} allocations={}",
        now.elapsed().as_micros(),
        LIVE.load(Relaxed) - live,
        PEAK.load(Relaxed) - live,
        ALLOCS.load(Relaxed)
    );
    drop(r);
    let n = std::env::args()
        .nth(2)
        .map(|s| s.parse::<u32>().unwrap())
        .unwrap_or(100);
    let now = Instant::now();
    for _ in 0..n {
        parse_once(&bytes, opts)
    }
    println!("n={n} mean_us={}", now.elapsed().as_micros() as f64 / n as f64);
}
