use criterion::{criterion_group, criterion_main, Criterion};
use netpolicy::engine::{evaluate_ruleset, MatchContext};
use netpolicy::rules::parse_ruleset;
use netpolicy::state::EngineState;

fn build_ruleset_yaml(count: usize) -> String {
    let mut out = String::from("rules:\n");
    for i in 0..count {
        out.push_str(&format!(
            "  - name: rule_{i}\n    priority: {p}\n    match:\n      port: \"{port}\"\n    action:\n      route: direct\n",
            i = i,
            p = 1000 - (i as i32),
            port = 1000 + (i % 1000)
        ));
    }
    out
}

fn bench_engine(c: &mut Criterion) {
    let yaml = build_ruleset_yaml(1000);
    let ruleset = parse_ruleset(&yaml).expect("ruleset");
    let ctx = MatchContext {
        port: Some(1500),
        ..MatchContext::default()
    };

    c.bench_function("engine_evaluate_1000_rules", |b| {
        b.iter(|| {
            let _ = evaluate_ruleset(&ruleset, &ctx, EngineState::Normal).unwrap();
        })
    });
}

criterion_group!(benches, bench_engine);
criterion_main!(benches);
