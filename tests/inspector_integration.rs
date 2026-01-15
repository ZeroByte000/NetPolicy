use netpolicy::engine::evaluate_ruleset;
use netpolicy::inspector::{to_match_context, ConnectionMeta, MockInspector, Inspector};
use netpolicy::rules::parse_ruleset;
use netpolicy::state::EngineState;

#[test]
fn inspector_to_engine_flow() {
    let yaml = r#"
rules:
  - name: tcp_rule
    priority: 10
    match:
      protocol: tcp
      port: "443"
    action:
      route: direct
"#;
    let ruleset = parse_ruleset(yaml).expect("ruleset");

    let inspector = MockInspector {
        meta: ConnectionMeta {
            protocol: Some("tcp".to_string()),
            port: Some(443),
            ..ConnectionMeta::default()
        },
    };

    let ctx = to_match_context(&inspector.inspect());
    let decision = evaluate_ruleset(&ruleset, &ctx, EngineState::Normal)
        .expect("decision");
    assert_eq!(decision.rule.unwrap().name, "tcp_rule");
}
