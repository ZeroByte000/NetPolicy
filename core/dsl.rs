use crate::rules::{
    validate_ruleset, Action, Match, Rule, RuleError, RuleSet, RuleWhen, StateSelector,
};

#[derive(Debug)]
pub enum DslError {
    Invalid(String),
}

pub fn parse_dsl(input: &str) -> Result<RuleSet, DslError> {
    let mut rules: Vec<Rule> = Vec::new();
    let mut current: Option<Rule> = None;

    for (idx, line) in input.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with("rule ") {
            if let Some(rule) = current.take() {
                rules.push(rule);
            }
            let name = line
                .trim_start_matches("rule ")
                .trim_end_matches(':')
                .trim();
            if name.is_empty() {
                return Err(DslError::Invalid(format!(
                    "line {}: rule name is required",
                    idx + 1
                )));
            }
            current = Some(Rule {
                name: name.to_string(),
                priority: 0,
                r#match: Match::default(),
                when: None,
                disable: None,
                action: Action {
                    route: None,
                    switch_route: None,
                    block: None,
                    throttle: None,
                    log: None,
                },
            });
            continue;
        }

        let rule = current.as_mut().ok_or_else(|| {
            DslError::Invalid(format!(
                "line {}: content must be inside a rule block",
                idx + 1
            ))
        })?;

        if line.starts_with("priority ") {
            let value = line.trim_start_matches("priority ").trim();
            let parsed = value.parse::<i32>().map_err(|_| {
                DslError::Invalid(format!("line {}: invalid priority", idx + 1))
            })?;
            rule.priority = parsed;
            continue;
        }

        if line.starts_with("match ") {
            parse_match_line(line, &mut rule.r#match, idx + 1)?;
            continue;
        }

        if line.starts_with("action ") {
            parse_action_line(line, &mut rule.action, idx + 1)?;
            continue;
        }

        if line.starts_with("when ") {
            rule.when = Some(RuleWhen {
                state: Some(parse_state_selector(line, idx + 1)?),
            });
            continue;
        }

        if line.starts_with("disable ") {
            rule.disable = Some(parse_state_selector(line, idx + 1)?);
            continue;
        }

        return Err(DslError::Invalid(format!(
            "line {}: unknown directive",
            idx + 1
        )));
    }

    if let Some(rule) = current.take() {
        rules.push(rule);
    }

    if rules.is_empty() {
        return Err(DslError::Invalid("no rules defined".to_string()));
    }

    let ruleset = RuleSet { rules };
    validate_ruleset(&ruleset).map_err(|err| match err {
        RuleError::Yaml(msg) => DslError::Invalid(msg),
        RuleError::Invalid(msg) => DslError::Invalid(msg),
    })?;
    Ok(ruleset)
}

fn parse_match_line(line: &str, target: &mut Match, line_no: usize) -> Result<(), DslError> {
    let rest = line.trim_start_matches("match ").trim();
    if rest.is_empty() {
        return Err(DslError::Invalid(format!(
            "line {}: match needs fields",
            line_no
        )));
    }
    for token in rest.split_whitespace() {
        if token == "any" || token == "any=true" {
            target.any = Some(true);
            continue;
        }
        let (key, raw) = token.split_once('=').ok_or_else(|| {
            DslError::Invalid(format!("line {}: invalid match token", line_no))
        })?;
        let value = strip_quotes(raw);
        match key {
            "sni" => target.sni = Some(value),
            "protocol" => target.protocol = Some(value),
            "port" => target.port = Some(value),
            "latency_ms" => target.latency_ms = Some(value),
            "rtt_ms" => target.rtt_ms = Some(value),
            _ => {
                return Err(DslError::Invalid(format!(
                    "line {}: unknown match key {}",
                    line_no, key
                )))
            }
        }
    }
    Ok(())
}

fn parse_action_line(line: &str, target: &mut Action, line_no: usize) -> Result<(), DslError> {
    let rest = line.trim_start_matches("action ").trim();
    if rest.is_empty() {
        return Err(DslError::Invalid(format!(
            "line {}: action needs fields",
            line_no
        )));
    }
    for token in rest.split_whitespace() {
        if token == "block" || token == "block=true" {
            target.block = Some(true);
            continue;
        }
        if token == "log" || token == "log=true" {
            target.log = Some(true);
            continue;
        }
        let (key, raw) = token.split_once('=').ok_or_else(|| {
            DslError::Invalid(format!("line {}: invalid action token", line_no))
        })?;
        let value = strip_quotes(raw);
        match key {
            "route" => target.route = Some(value),
            "switch_route" => target.switch_route = Some(value),
            "throttle" => target.throttle = Some(value),
            "log" => target.log = Some(value == "true"),
            _ => {
                return Err(DslError::Invalid(format!(
                    "line {}: unknown action key {}",
                    line_no, key
                )))
            }
        }
    }
    Ok(())
}

fn parse_state_selector(line: &str, line_no: usize) -> Result<StateSelector, DslError> {
    let rest = line.split_whitespace().skip(1).collect::<Vec<_>>().join(" ");
    let value = rest
        .strip_prefix("state=")
        .unwrap_or(rest.trim())
        .trim();
    if value.is_empty() {
        return Err(DslError::Invalid(format!(
            "line {}: state value is required",
            line_no
        )));
    }
    let items: Vec<String> = value
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if items.len() == 1 {
        Ok(StateSelector::Single(items[0].clone()))
    } else {
        Ok(StateSelector::Many(items))
    }
}

fn strip_quotes(value: &str) -> String {
    let value = value.trim();
    if (value.starts_with('"') && value.ends_with('"'))
        || (value.starts_with('\'') && value.ends_with('\''))
    {
        value[1..value.len() - 1].to_string()
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dsl_basic_rule() {
        let input = r#"
rule zoom_priority:
  priority 100
  match sni="*.zoom.us" protocol=tcp port=443
  action route=tunnel_fast log=true
  when state=DEGRADED,FAILOVER
"#;
        let ruleset = parse_dsl(input).expect("dsl parsed");
        assert_eq!(ruleset.rules.len(), 1);
        assert_eq!(ruleset.rules[0].priority, 100);
    }
}
