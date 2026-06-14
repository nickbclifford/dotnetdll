use dotnetdll::prelude::*;
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tracing::{Event, Subscriber};
use tracing_subscriber::{
    layer::{Context, Layer},
    prelude::*,
    Registry,
};

#[path = "../tests/common/env.rs"]
mod env;

#[derive(Debug, Clone)]
struct StageSample {
    stage: String,
    elapsed_ns: u64,
}

#[derive(Clone, Default)]
struct StageTimingRecorder {
    entries: Arc<Mutex<Vec<StageSample>>>,
}

impl StageTimingRecorder {
    fn take(&self) -> Vec<StageSample> {
        let mut lock = self.entries.lock().expect("stage recorder mutex poisoned");
        std::mem::take(&mut *lock)
    }
}

impl<S> Layer<S> for StageTimingRecorder
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = StageEventVisitor::default();
        event.record(&mut visitor);

        if let (Some(stage), Some(elapsed_ns)) = (visitor.stage, visitor.elapsed_ns) {
            self.entries
                .lock()
                .expect("stage recorder mutex poisoned")
                .push(StageSample { stage, elapsed_ns });
        }
    }
}

#[derive(Default)]
struct StageEventVisitor {
    stage: Option<String>,
    elapsed_ns: Option<u64>,
}

impl tracing::field::Visit for StageEventVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "stage" {
            self.stage = Some(value.to_owned());
        }
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        if field.name() == "elapsed_ns" {
            self.elapsed_ns = Some(value);
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "stage" {
            self.stage = Some(format!("{value:?}").trim_matches('"').to_owned());
            return;
        }

        if field.name() == "elapsed_ns" {
            self.elapsed_ns = format!("{value:?}").parse().ok();
        }
    }
}

#[derive(Debug)]
struct Config {
    mode: String,
    runs: usize,
    input: PathBuf,
}

fn parse_config() -> Config {
    let mut mode = String::from("all");
    let mut runs = 1usize;
    let mut input: Option<PathBuf> = None;

    let mut args = std::env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--mode" => {
                mode = args.next().unwrap_or_else(|| {
                    panic!("missing value for --mode (expected eager|lazy_bodies|lazy_signatures|lazy_all|all)")
                });
            }
            "--runs" => {
                runs = args
                    .next()
                    .unwrap_or_else(|| panic!("missing value for --runs"))
                    .parse::<usize>()
                    .expect("--runs value must be a positive integer");
            }
            "--input" => {
                input = Some(PathBuf::from(
                    args.next().unwrap_or_else(|| panic!("missing value for --input")),
                ));
            }
            "--help" | "-h" => {
                println!(
                    "Usage: cargo bench --features stage-timing --bench stage_timing -- [--mode <mode>] [--runs <n>] [--input <path>]\n\
                     Modes: eager | lazy_bodies | lazy_signatures | lazy_all | all (default)\n\
                     Default input: $RUNTIME_ARTIFACTS/.../System.Private.CoreLib.dll"
                );
                std::process::exit(0);
            }
            _ => {
                // `cargo bench` may forward harness arguments (for example `--bench stage_timing`).
                // Ignore unknown flags and a following non-flag value so this one-shot harness can
                // run under both Cargo and direct invocation without treating forwarded values as
                // positional arguments.
                if arg.starts_with('-') {
                    if args.peek().is_some_and(|next| !next.starts_with('-')) {
                        args.next();
                    }
                    continue;
                }
                panic!("unknown argument: {arg}");
            }
        }
    }

    assert!(runs > 0, "--runs must be >= 1");

    Config {
        mode,
        runs,
        input: input.unwrap_or_else(|| env::LIBRARIES.join("System.Private.CoreLib.dll")),
    }
}

fn modes(mode: &str) -> Vec<(&'static str, ReadOptions)> {
    match mode {
        "eager" => vec![("eager", ReadOptions::default())],
        "lazy_bodies" => vec![(
            "lazy_bodies",
            ReadOptions {
                lazy_method_bodies: true,
                ..ReadOptions::default()
            },
        )],
        "lazy_signatures" => vec![(
            "lazy_signatures",
            ReadOptions {
                lazy_method_signatures: true,
                ..ReadOptions::default()
            },
        )],
        "lazy_all" => vec![(
            "lazy_all",
            ReadOptions {
                lazy_method_bodies: true,
                lazy_method_signatures: true,
                ..ReadOptions::default()
            },
        )],
        "all" => vec![
            ("eager", ReadOptions::default()),
            (
                "lazy_bodies",
                ReadOptions {
                    lazy_method_bodies: true,
                    ..ReadOptions::default()
                },
            ),
            (
                "lazy_signatures",
                ReadOptions {
                    lazy_method_signatures: true,
                    ..ReadOptions::default()
                },
            ),
            (
                "lazy_all",
                ReadOptions {
                    lazy_method_bodies: true,
                    lazy_method_signatures: true,
                    ..ReadOptions::default()
                },
            ),
        ],
        _ => panic!("invalid mode '{mode}' (expected eager|lazy_bodies|lazy_signatures|lazy_all|all)"),
    }
}

fn print_stage_table(mode_name: &str, run_samples: &[Vec<StageSample>]) {
    let run_count = run_samples.len();

    let mut order = Vec::<String>::new();
    let mut index = HashMap::<String, usize>::new();
    let mut values = Vec::<Vec<f64>>::new();

    for (run_idx, samples) in run_samples.iter().enumerate() {
        for sample in samples {
            let stage_idx = if let Some(idx) = index.get(&sample.stage).copied() {
                idx
            } else {
                let idx = order.len();
                index.insert(sample.stage.clone(), idx);
                order.push(sample.stage.clone());
                values.push(vec![0.0; run_count]);
                idx
            };

            values[stage_idx][run_idx] += sample.elapsed_ns as f64 / 1_000_000.0;
        }
    }

    println!("\n=== Stage timings: {mode_name} ({run_count} run(s)) ===");

    print!("| stage |");
    for run_idx in 0..run_count {
        print!(" run {} (ms) |", run_idx + 1);
    }
    println!(" avg (ms) |");

    print!("|---|");
    for _ in 0..run_count {
        print!("---:|");
    }
    println!("---:|");

    let mut totals = vec![0.0f64; run_count];

    for (stage_idx, stage_name) in order.iter().enumerate() {
        let row = &values[stage_idx];
        print!("| {stage_name} |");
        for (run_idx, value) in row.iter().enumerate() {
            totals[run_idx] += *value;
            print!(" {value:.3} |");
        }
        let avg = row.iter().sum::<f64>() / run_count as f64;
        println!(" {avg:.3} |");
    }

    print!("| **total** |");
    for total in &totals {
        print!(" **{total:.3}** |");
    }
    let avg_total = totals.iter().sum::<f64>() / run_count as f64;
    println!(" **{avg_total:.3}** |");
}

fn main() {
    if !cfg!(feature = "stage-timing") {
        panic!("stage_timing bench requires `--features stage-timing`");
    }

    let config = parse_config();
    let bytes =
        std::fs::read(&config.input).unwrap_or_else(|e| panic!("failed to read {}: {e}", config.input.display()));

    let recorder = StageTimingRecorder::default();
    let subscriber = Registry::default().with(recorder.clone());
    tracing::subscriber::set_global_default(subscriber).expect("failed to install stage timing subscriber");

    println!("Input: {}", config.input.display());

    for (mode_name, options) in modes(&config.mode) {
        let mut run_samples = Vec::with_capacity(config.runs);

        for _ in 0..config.runs {
            recorder.take(); // clear straggler events from previous work
            Resolution::parse(&bytes, options)
                .unwrap_or_else(|e| panic!("failed to parse {} in mode {mode_name}: {e}", config.input.display()));
            let samples = recorder.take();
            assert!(
                !samples.is_empty(),
                "captured zero stage timing events; make sure `stage-timing` is enabled"
            );
            run_samples.push(samples);
        }

        print_stage_table(mode_name, &run_samples);
    }
}
