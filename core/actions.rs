use crate::rules::Action;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionKind {
    Route(String),
    SwitchRoute(String),
    Block,
    Throttle(String),
    LogOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionDecision {
    pub kind: ActionKind,
    pub log: bool,
}

pub fn plan_action(action: &Action) -> ActionDecision {
    let log = action.log.unwrap_or(false);

    if let Some(ref route) = action.route {
        return ActionDecision {
            kind: ActionKind::Route(route.clone()),
            log,
        };
    }
    if let Some(ref route) = action.switch_route {
        return ActionDecision {
            kind: ActionKind::SwitchRoute(route.clone()),
            log,
        };
    }
    if action.block == Some(true) {
        return ActionDecision {
            kind: ActionKind::Block,
            log,
        };
    }
    if let Some(ref throttle) = action.throttle {
        return ActionDecision {
            kind: ActionKind::Throttle(throttle.clone()),
            log,
        };
    }

    ActionDecision {
        kind: ActionKind::LogOnly,
        log: true,
    }
}

impl ActionDecision {
    pub fn summary(&self) -> String {
        match &self.kind {
            ActionKind::Route(route) => format!("route {}", route),
            ActionKind::SwitchRoute(route) => format!("switch_route {}", route),
            ActionKind::Block => "block".to_string(),
            ActionKind::Throttle(name) => format!("throttle {}", name),
            ActionKind::LogOnly => "log".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Action;

    #[test]
    fn plan_action_prefers_route() {
        let action = Action {
            route: Some("fast".to_string()),
            switch_route: None,
            block: None,
            throttle: None,
            log: Some(true),
        };
        let decision = plan_action(&action);
        assert_eq!(decision.summary(), "route fast");
        assert!(decision.log);
    }

    #[test]
    fn plan_action_block() {
        let action = Action {
            route: None,
            switch_route: None,
            block: Some(true),
            throttle: None,
            log: None,
        };
        let decision = plan_action(&action);
        assert_eq!(decision.summary(), "block");
    }
}
