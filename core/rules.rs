use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
pub struct Rule {
    pub name: String,
    pub priority: i32,
    #[serde(rename = "match")]
    pub r#match: Match,
    pub when: Option<RuleWhen>,
    pub disable: Option<StateSelector>,
    pub action: Action,
}

#[derive(Debug, Deserialize, Default)]
pub struct RuleWhen {
    pub state: Option<StateSelector>,
}

#[derive(Debug, Deserialize, Default)]
pub struct Match {
    pub any: Option<bool>,
    pub sni: Option<String>,
    pub protocol: Option<String>,
    pub port: Option<String>,
    pub latency_ms: Option<String>,
    pub rtt_ms: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct Action {
    pub route: Option<String>,
    pub switch_route: Option<String>,
    pub block: Option<bool>,
    pub throttle: Option<String>,
    pub log: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum StateSelector {
    Single(String),
    Many(Vec<String>),
}

#[derive(Debug)]
pub enum RuleError {
    Yaml(String),
    Invalid(String),
}

pub fn parse_ruleset(yaml: &str) -> Result<RuleSet, RuleError> {
    let ruleset: RuleSet = serde_yaml::from_str(yaml)
        .map_err(|e| RuleError::Yaml(e.to_string()))?;
    validate_ruleset(&ruleset)?;
    Ok(ruleset)
}

pub fn validate_ruleset(ruleset: &RuleSet) -> Result<(), RuleError> {
    if ruleset.rules.is_empty() {
        return Err(RuleError::Invalid("rules must not be empty".to_string()));
    }

    for rule in &ruleset.rules {
        validate_rule(rule)?;
    }

    Ok(())
}

fn validate_rule(rule: &Rule) -> Result<(), RuleError> {
    if rule.name.trim().is_empty() {
        return Err(RuleError::Invalid("rule name is required".to_string()));
    }

    if rule.priority < 0 {
        return Err(RuleError::Invalid("priority must be >= 0".to_string()));
    }

    if let Some(ref when) = rule.when {
        if let Some(ref selector) = when.state {
            validate_state_selector(selector)?;
        }
    }

    if let Some(ref selector) = rule.disable {
        validate_state_selector(selector)?;
    }

    validate_match(&rule.r#match)?;
    validate_action(&rule.action)?;

    Ok(())
}

fn validate_match(m: &Match) -> Result<(), RuleError> {
    if m.any == Some(true) {
        return Ok(());
    }

    let has_any = m.sni.is_some()
        || m.protocol.is_some()
        || m.port.is_some()
        || m.latency_ms.is_some()
        || m.rtt_ms.is_some();

    if !has_any {
        return Err(RuleError::Invalid(
            "match must contain at least one field or any: true".to_string(),
        ));
    }

    if let Some(ref port) = m.port {
        validate_port_pattern(port)?;
    }

    Ok(())
}

fn validate_action(a: &Action) -> Result<(), RuleError> {
    let primary = [
        a.route.is_some(),
        a.switch_route.is_some(),
        a.block == Some(true),
        a.throttle.is_some(),
    ];

    let primary_count = primary.iter().filter(|v| **v).count();
    if primary_count == 0 {
        return Err(RuleError::Invalid(
            "action must include one primary action".to_string(),
        ));
    }

    if primary_count > 1 {
        return Err(RuleError::Invalid(
            "action must not include multiple primary actions".to_string(),
        ));
    }

    Ok(())
}

fn validate_port_pattern(value: &str) -> Result<(), RuleError> {
    for entry in value.split(',') {
        let token = entry.trim();
        if token.is_empty() {
            return Err(RuleError::Invalid(
                "port pattern must not contain empty entries".to_string(),
            ));
        }
        if let Some((start, end)) = token.split_once('-') {
            let start = start.trim().parse::<u16>().map_err(|_| {
                RuleError::Invalid(format!("invalid port range start: {}", start))
            })?;
            let end = end.trim().parse::<u16>().map_err(|_| {
                RuleError::Invalid(format!("invalid port range end: {}", end))
            })?;
            if start > end {
                return Err(RuleError::Invalid(format!(
                    "invalid port range (start > end): {}",
                    token
                )));
            }
        } else {
            token.parse::<u16>().map_err(|_| {
                RuleError::Invalid(format!("invalid port value: {}", token))
            })?;
        }
    }
    Ok(())
}

fn validate_state_selector(selector: &StateSelector) -> Result<(), RuleError> {
    match selector {
        StateSelector::Single(s) => validate_state_value(s),
        StateSelector::Many(list) => {
            if list.is_empty() {
                return Err(RuleError::Invalid(
                    "state list must not be empty".to_string(),
                ));
            }
            for item in list {
                validate_state_value(item)?;
            }
            Ok(())
        }
    }
}

fn validate_state_value(value: &str) -> Result<(), RuleError> {
    let normalized = value.trim().to_uppercase();
    let ok = matches!(
        normalized.as_str(),
        "NORMAL" | "DEGRADED" | "FAILOVER" | "RECOVERY"
    );
    if !ok {
        return Err(RuleError::Invalid(format!(
            "invalid state value: {}",
            value
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ruleset_ok() {
        let yaml = r#"
rules:
  - name: zoom_priority
    priority: 100
    match:
      sni: "*.zoom.us"
      protocol: tcp
    action:
      route: tunnel_fast
"#;

        let ruleset = parse_ruleset(yaml).expect("ruleset should parse");
        assert_eq!(ruleset.rules.len(), 1);
        assert_eq!(ruleset.rules[0].name, "zoom_priority");
    }

    #[test]
    fn validate_match_requires_fields() {
        let yaml = r#"
rules:
  - name: empty_match
    priority: 10
    match: {}
    action:
      log: true
"#;

        let err = parse_ruleset(yaml).unwrap_err();
        match err {
            RuleError::Invalid(msg) => {
                assert!(msg.contains("match must contain"));
            }
            _ => panic!("expected invalid error"),
        }
    }

    #[test]
    fn validate_action_single_primary() {
        let yaml = r#"
rules:
  - name: double_action
    priority: 10
    match:
      any: true
    action:
      route: tunnel_fast
      block: true
"#;

        let err = parse_ruleset(yaml).unwrap_err();
        match err {
            RuleError::Invalid(msg) => {
                assert!(msg.contains("multiple primary actions"));
            }
            _ => panic!("expected invalid error"),
        }
    }

    #[test]
    fn validate_any_true_ok() {
        let yaml = r#"
rules:
  - name: any_rule
    priority: 10
    match:
      any: true
    action:
      route: slow
      log: true
"#;

        let ruleset = parse_ruleset(yaml).expect("any true should be valid");
        assert_eq!(ruleset.rules.len(), 1);
    }
}
