# NetPolicy Engine Roadmap (Rust)

Target: build a programmable network policy engine focused on decision logic
first, with a clear path to traffic inspection and OS integration later.

## Phase 0 - Scope and Foundations (Week 1)
- ✓ Define v1 rule schema (YAML) and matching model.
- ✓ Decide rule priority, conflict resolution, and default actions.
- ✓ Create repo structure and minimal CLI skeleton.
- ✓ Draft core data types (Match, Action, Rule, EngineState).
- ✓ Add unit tests for rule parsing and evaluation.

Deliverables:
- ✓ `rules/` module with parser + validator.
- ✓ `engine/` module with evaluation engine.
- ✓ `examples/` with 2-3 rulesets.

## Phase 1 - Core Engine v1 (Week 2)
- ✓ Implement deterministic rule evaluation (priority + specificity).
- ✓ Add state machine (NORMAL -> DEGRADED -> FAILOVER -> RECOVERY).
- ✓ Add action executor (log + route choice as abstract enum).
- ✓ Implement config loading and hot-reload (signal or file watch).

Deliverables:
- ✓ `state/` module with state transitions.
- ✓ `actions/` module with log/route actions.
- ✓ `netpolicyd` CLI with `--config` and `--dry-run`.

## Phase 2 - Inspector v1 (Week 3)
- ✓ Build a user-space inspector based on connection metadata.
- ✓ Collect SNI, IP, port, protocol, RTT (best effort).
- ✓ Feed inspector output into the policy engine.
- ✓ Add integration tests using synthetic connection events.

Deliverables:
- ✓ `inspector/` module with mockable interface.
- ✓ Test harness for engine + inspector.

## Phase 3 - Policies in the Real World (Week 4)
- ✓ Add rule runtime context (latency thresholds, error rate).
- ✓ Add "fallback" and "failover" actions.
- ✓ Create example scenarios (zoom priority, latency failover).
- ✓ Write docs for rules, state machine, and actions.
- ✓ Add Xray URL generator (vmess/vless/trojan) + examples.
- ✓ Extend Xray URL generator (ss/socks/http, plugins, grpc/h2/reality) + validation tests.
- ✓ Add Xray generator UI (web/Android/OpenWrt web assets).
- ✓ Add Xray process manager (start/stop/restart/log) in netpolicyd.

Deliverables:
- ✓ `docs/` with rule reference + examples.
- ✓ `examples/` runnable scenarios.

## Phase 4 - Hardening (Week 5-6)
- ✓ Benchmark evaluation performance (1000+ rules).
- ✓ Improve parser error messages and diagnostics.
- ✓ Add policy linting and validation CLI.
- ✓ Add telemetry hooks (structured logs, metrics).

Deliverables:
- ✓ `netpolicy lint` command.
- ✓ Benchmarks and performance notes.

## Future Options
- ✓ eBPF inspector backend (Linux).
- ✓ Termux support (limited inspector, full engine).
- ✓ DSL upgrade from YAML to custom syntax.
- ✓ Action backends for iptables/nftables/route marks.
- ✓ Android VPN gateway (full tunnel, hotspot best-effort).

## Definition of Done for v1
- ✓ Stable rule schema.
- ✓ Deterministic evaluation with state awareness.
- ✓ CLI with load, dry-run, and validate (via `netpolicyd` + `netpolicy lint`).
- ✓ Example rules and docs.
- ✓ Tests covering parser + engine + state transitions.
