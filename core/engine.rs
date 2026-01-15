use crate::rules::{Action, Match, Rule, RuleError, RuleSet, StateSelector};
use crate::state::EngineState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineDecisionKind {
    Action,
    NoMatch,
}

#[derive(Debug)]
pub struct EngineDecision<'a> {
    pub kind: EngineDecisionKind,
    pub rule: Option<&'a Rule>,
    pub action: Option<&'a Action>,
}

#[derive(Debug, Default)]
pub struct MatchContext {
    pub sni: Option<String>,
    pub protocol: Option<String>,
    pub port: Option<u16>,
    pub latency_ms: Option<u32>,
    pub rtt_ms: Option<u32>,
}

pub fn evaluate_ruleset<'a>(
    ruleset: &'a RuleSet,
    ctx: &MatchContext,
    state: EngineState,
) -> Result<EngineDecision<'a>, RuleError> {
    if ruleset.rules.is_empty() {
        return Err(RuleError::Invalid("rules must not be empty".to_string()));
    }

    let mut best: Option<&Rule> = None;
    for rule in &ruleset.rules {
        if !rule_applies_state(rule, state) {
            continue;
        }
        if !rule_matches(&rule.r#match, ctx) {
            continue;
        }
        let better = match best {
            None => true,
            Some(current) => compare_rule(rule, current) > 0,
        };

        if better {
            best = Some(rule);
        }
    }

    if let Some(rule) = best {
        return Ok(EngineDecision {
            kind: EngineDecisionKind::Action,
            rule: Some(rule),
            action: Some(&rule.action),
        });
    }

    Ok(EngineDecision {
        kind: EngineDecisionKind::NoMatch,
        rule: None,
        action: None,
    })
}

fn compare_rule(a: &Rule, b: &Rule) -> i32 {
    if a.priority != b.priority {
        return if a.priority > b.priority { 1 } else { -1 };
    }

    let a_spec = specificity(a);
    let b_spec = specificity(b);
    if a_spec > b_spec {
        1
    } else if a_spec < b_spec {
        -1
    } else {
        0
    }
}

fn specificity(rule: &Rule) -> i32 {
    let m = &rule.r#match;
    let mut count = 0;
    if m.any == Some(true) {
        return 0;
    }
    if m.sni.is_some() {
        count += 1;
    }
    if m.protocol.is_some() {
        count += 1;
    }
    if m.port.is_some() {
        count += 1;
    }
    if m.latency_ms.is_some() {
        count += 1;
    }
    if m.rtt_ms.is_some() {
        count += 1;
    }
    count
}

fn rule_matches(m: &Match, ctx: &MatchContext) -> bool {
    if m.any == Some(true) {
        return true;
    }

    if let Some(ref sni) = m.sni {
        if !match_sni(sni, ctx.sni.as_deref()) {
            return false;
        }
    }

    if let Some(ref proto) = m.protocol {
        let ctx_proto = match ctx.protocol.as_deref() {
            Some(p) => p,
            None => return false,
        };
        if proto.to_lowercase() != ctx_proto.to_lowercase() {
            return false;
        }
    }

    if let Some(ref port) = m.port {
        let ctx_port = match ctx.port {
            Some(p) => p,
            None => return false,
        };
        if !match_port(port, ctx_port) {
            return false;
        }
    }

    if let Some(ref latency) = m.latency_ms {
        let ctx_latency = match ctx.latency_ms {
            Some(v) => v,
            None => return false,
        };
        if !compare_numeric(latency, ctx_latency) {
            return false;
        }
    }

    if let Some(ref rtt) = m.rtt_ms {
        let ctx_rtt = match ctx.rtt_ms {
            Some(v) => v,
            None => return false,
        };
        if !compare_numeric(rtt, ctx_rtt) {
            return false;
        }
    }

    true
}

fn rule_applies_state(rule: &Rule, state: EngineState) -> bool {
    if let Some(ref selector) = rule.disable {
        if selector_contains_state(selector, state) {
            return false;
        }
    }

    if let Some(ref when) = rule.when {
        if let Some(ref selector) = when.state {
            return selector_contains_state(selector, state);
        }
    }

    true
}

fn selector_contains_state(selector: &StateSelector, state: EngineState) -> bool {
    let state_name = state_to_str(state);
    match selector {
        StateSelector::Single(s) => normalize_state(s) == state_name,
        StateSelector::Many(list) => list
            .iter()
            .any(|item| normalize_state(item) == state_name),
    }
}

fn state_to_str(state: EngineState) -> &'static str {
    match state {
        EngineState::Normal => "NORMAL",
        EngineState::Degraded => "DEGRADED",
        EngineState::Failover => "FAILOVER",
        EngineState::Recovery => "RECOVERY",
    }
}

fn normalize_state(value: &str) -> String {
    value.trim().to_uppercase()
}

fn match_sni(pattern: &str, value: Option<&str>) -> bool {
    let value = match value {
        Some(v) => v.to_lowercase(),
        None => return false,
    };
    let pattern = pattern.to_lowercase();

    if pattern == "*" {
        return true;
    }

    if let Some(stripped) = pattern.strip_prefix("*.") {
        return value.ends_with(stripped);
    }

    if let Some(stripped) = pattern.strip_prefix('*') {
        return value.ends_with(stripped);
    }

    if let Some(stripped) = pattern.strip_suffix('*') {
        return value.starts_with(stripped);
    }

    value == pattern
}

fn match_port(pattern: &str, port: u16) -> bool {
    for entry in pattern.split(',') {
        let token = entry.trim();
        if token.is_empty() {
            continue;
        }
        if let Some((start, end)) = token.split_once('-') {
            let start = match start.trim().parse::<u16>() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let end = match end.trim().parse::<u16>() {
                Ok(v) => v,
                Err(_) => continue,
            };
            if start <= port && port <= end {
                return true;
            }
        } else if let Ok(value) = token.parse::<u16>() {
            if value == port {
                return true;
            }
        }
    }
    false
}

fn compare_numeric(expr: &str, value: u32) -> bool {
    let expr = expr.trim();
    let (op, rhs) = match parse_comparator(expr) {
        Some(v) => v,
        None => return false,
    };

    match op {
        Comparator::Gt => value > rhs,
        Comparator::Gte => value >= rhs,
        Comparator::Lt => value < rhs,
        Comparator::Lte => value <= rhs,
        Comparator::Eq => value == rhs,
    }
}

#[derive(Debug, Clone, Copy)]
enum Comparator {
    Gt,
    Gte,
    Lt,
    Lte,
    Eq,
}

fn parse_comparator(expr: &str) -> Option<(Comparator, u32)> {
    let trimmed = expr.trim();
    let (op, rest) = if let Some(s) = trimmed.strip_prefix(">=") {
        (Comparator::Gte, s)
    } else if let Some(s) = trimmed.strip_prefix("<=") {
        (Comparator::Lte, s)
    } else if let Some(s) = trimmed.strip_prefix(">") {
        (Comparator::Gt, s)
    } else if let Some(s) = trimmed.strip_prefix("<") {
        (Comparator::Lt, s)
    } else if let Some(s) = trimmed.strip_prefix("==") {
        (Comparator::Eq, s)
    } else if let Some(s) = trimmed.strip_prefix("=") {
        (Comparator::Eq, s)
    } else {
        return None;
    };

    let value = rest.trim().parse::<u32>().ok()?;
    Some((op, value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::parse_ruleset;

    #[test]
    fn evaluate_ruleset_picks_highest_priority() {
        let yaml = r#"
rules:
  - name: low
    priority: 10
    match:
      any: true
    action:
      route: slow
      log: true
  - name: high
    priority: 90
    match:
      any: true
    action:
      route: fast
"#;

        let ruleset = parse_ruleset(yaml).expect("ruleset should parse");
        let ctx = MatchContext::default();
        let decision =
            evaluate_ruleset(&ruleset, &ctx, EngineState::Normal).expect("decision should be ok");
        assert_eq!(decision.kind, EngineDecisionKind::Action);
        assert_eq!(decision.rule.unwrap().name, "high");
    }

    #[test]
    fn evaluate_ruleset_picks_more_specific_on_tie() {
        let yaml = r#"
rules:
  - name: general
    priority: 50
    match:
      any: true
    action:
      route: slow
      log: true
  - name: specific
    priority: 50
    match:
      protocol: tcp
      port: "443"
    action:
      route: fast
"#;

        let ruleset = parse_ruleset(yaml).expect("ruleset should parse");
        let ctx = MatchContext {
            protocol: Some("tcp".to_string()),
            port: Some(443),
            ..MatchContext::default()
        };
        let decision =
            evaluate_ruleset(&ruleset, &ctx, EngineState::Normal).expect("decision should be ok");
        assert_eq!(decision.rule.unwrap().name, "specific");
    }

    #[test]
    fn evaluate_ruleset_skips_non_matching() {
        let yaml = r#"
rules:
  - name: only_udp
    priority: 100
    match:
      protocol: udp
    action:
      route: slow
  - name: tcp_rule
    priority: 10
    match:
      protocol: tcp
    action:
      route: fast
"#;

        let ruleset = parse_ruleset(yaml).expect("ruleset should parse");
        let ctx = MatchContext {
            protocol: Some("tcp".to_string()),
            ..MatchContext::default()
        };
        let decision =
            evaluate_ruleset(&ruleset, &ctx, EngineState::Normal).expect("decision should be ok");
        assert_eq!(decision.rule.unwrap().name, "tcp_rule");
    }

    #[test]
    fn evaluate_ruleset_respects_state_when() {
        let yaml = r#"
rules:
  - name: normal_rule
    priority: 10
    match:
      any: true
    action:
      route: fast
  - name: failover_rule
    priority: 100
    when:
      state: FAILOVER
    match:
      any: true
    action:
      switch_route: backup
"#;

        let ruleset = parse_ruleset(yaml).expect("ruleset should parse");
        let ctx = MatchContext::default();
        let decision = evaluate_ruleset(&ruleset, &ctx, EngineState::Failover)
            .expect("decision should be ok");
        assert_eq!(decision.rule.unwrap().name, "failover_rule");
    }

    #[test]
    fn evaluate_ruleset_respects_state_disable() {
        let yaml = r#"
rules:
  - name: disabled_in_degraded
    priority: 100
    disable: [DEGRADED]
    match:
      any: true
    action:
      route: fast
  - name: fallback
    priority: 10
    match:
      any: true
    action:
      route: slow
"#;

        let ruleset = parse_ruleset(yaml).expect("ruleset should parse");
        let ctx = MatchContext::default();
        let decision = evaluate_ruleset(&ruleset, &ctx, EngineState::Degraded)
            .expect("decision should be ok");
        assert_eq!(decision.rule.unwrap().name, "fallback");
    }

    #[test]
    fn match_port_supports_ranges_and_lists() {
        let yaml = r#"
rules:
  - name: ssh_and_range
    priority: 10
    match:
      port: "22,1000-2000"
    action:
      route: slow
"#;

        let ruleset = parse_ruleset(yaml).expect("ruleset should parse");
        let ctx = MatchContext {
            port: Some(1500),
            ..MatchContext::default()
        };
        let decision =
            evaluate_ruleset(&ruleset, &ctx, EngineState::Normal).expect("decision should be ok");
        assert_eq!(decision.rule.unwrap().name, "ssh_and_range");
    }
}
