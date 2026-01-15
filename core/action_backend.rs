use crate::actions::{ActionDecision, ActionKind};
use crate::engine::MatchContext;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    Iptables,
    Nftables,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendPlan {
    pub backend: BackendKind,
    pub commands: Vec<String>,
}

pub fn render_backend(
    backend: BackendKind,
    ctx: &MatchContext,
    decision: &ActionDecision,
) -> BackendPlan {
    let commands = match backend {
        BackendKind::Iptables => render_iptables(ctx, decision),
        BackendKind::Nftables => render_nftables(ctx, decision),
    };
    BackendPlan { backend, commands }
}

fn render_iptables(ctx: &MatchContext, decision: &ActionDecision) -> Vec<String> {
    let mut commands = Vec::new();
    let proto = ctx.protocol.as_deref().unwrap_or("tcp");
    let port = ctx.port;
    let match_part = match_fragment(proto, port, IptRuleStyle::Iptables);

    match &decision.kind {
        ActionKind::Block => {
            commands.push(format!("iptables -A OUTPUT {} -j DROP", match_part));
        }
        ActionKind::Route(route) | ActionKind::SwitchRoute(route) => {
            let mark = route_mark(route);
            commands.push(format!(
                "iptables -A OUTPUT {} -j MARK --set-mark {}",
                match_part, mark
            ));
        }
        ActionKind::Throttle(name) => {
            let mark = route_mark(name);
            commands.push(format!(
                "iptables -A OUTPUT {} -j MARK --set-mark {}",
                match_part, mark
            ));
        }
        ActionKind::LogOnly => {
            commands.push(format!(
                "iptables -A OUTPUT {} -j LOG --log-prefix \"netpolicy\"",
                match_part
            ));
        }
    }

    commands
}

fn render_nftables(ctx: &MatchContext, decision: &ActionDecision) -> Vec<String> {
    let mut commands = Vec::new();
    let proto = ctx.protocol.as_deref().unwrap_or("tcp");
    let port = ctx.port;
    let match_part = match_fragment(proto, port, IptRuleStyle::Nftables);

    match &decision.kind {
        ActionKind::Block => {
            commands.push(format!("nft add rule inet netpolicy output {} drop", match_part));
        }
        ActionKind::Route(route) | ActionKind::SwitchRoute(route) => {
            let mark = route_mark(route);
            commands.push(format!(
                "nft add rule inet netpolicy output {} mark set {}",
                match_part, mark
            ));
        }
        ActionKind::Throttle(name) => {
            let mark = route_mark(name);
            commands.push(format!(
                "nft add rule inet netpolicy output {} mark set {}",
                match_part, mark
            ));
        }
        ActionKind::LogOnly => {
            commands.push(format!(
                "nft add rule inet netpolicy output {} log prefix \"netpolicy\"",
                match_part
            ));
        }
    }

    commands
}

enum IptRuleStyle {
    Iptables,
    Nftables,
}

fn match_fragment(proto: &str, port: Option<u16>, style: IptRuleStyle) -> String {
    match style {
        IptRuleStyle::Iptables => {
            if let Some(port) = port {
                format!("-p {} --dport {}", proto, port)
            } else {
                format!("-p {}", proto)
            }
        }
        IptRuleStyle::Nftables => {
            if let Some(port) = port {
                format!("{} dport {}", proto, port)
            } else {
                proto.to_string()
            }
        }
    }
}

fn route_mark(route: &str) -> String {
    let mut hasher = DefaultHasher::new();
    route.hash(&mut hasher);
    let value = hasher.finish() & 0xffff;
    format!("0x{:x}", value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::ActionDecision;

    #[test]
    fn render_iptables_block() {
        let ctx = MatchContext {
            protocol: Some("tcp".to_string()),
            port: Some(443),
            ..MatchContext::default()
        };
        let decision = ActionDecision {
            kind: ActionKind::Block,
            log: false,
        };
        let plan = render_backend(BackendKind::Iptables, &ctx, &decision);
        assert!(plan.commands[0].contains("iptables"));
        assert!(plan.commands[0].contains("DROP"));
    }

    #[test]
    fn render_nftables_route() {
        let ctx = MatchContext {
            protocol: Some("tcp".to_string()),
            port: Some(80),
            ..MatchContext::default()
        };
        let decision = ActionDecision {
            kind: ActionKind::Route("fast".to_string()),
            log: false,
        };
        let plan = render_backend(BackendKind::Nftables, &ctx, &decision);
        assert!(plan.commands[0].contains("nft add rule"));
        assert!(plan.commands[0].contains("mark set"));
    }
}
