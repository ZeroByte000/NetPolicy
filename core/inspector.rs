use crate::engine::MatchContext;
use serde::Deserialize;
use std::fs;
use std::process::Command;

#[derive(Debug, Clone, Default)]
pub struct ConnectionMeta {
    pub sni: Option<String>,
    pub ip: Option<String>,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub rtt_ms: Option<u32>,
    pub latency_ms: Option<u32>,
    pub error_rate: Option<f32>,
}

pub trait Inspector {
    fn inspect(&self) -> ConnectionMeta;
}

#[derive(Debug, Default)]
pub struct MockInspector {
    pub meta: ConnectionMeta,
}

impl Inspector for MockInspector {
    fn inspect(&self) -> ConnectionMeta {
        self.meta.clone()
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionTarget {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
}

#[derive(Debug)]
pub struct RealInspector {
    pub target: ConnectionTarget,
    pub sni_map_path: Option<String>,
    pub ss_path: String,
}

impl RealInspector {
    pub fn new(target: ConnectionTarget) -> Self {
        Self {
            target,
            sni_map_path: std::env::var("NETPOLICY_SNI_MAP").ok(),
            ss_path: "ss".to_string(),
        }
    }

    pub fn with_sni_map(mut self, path: String) -> Self {
        self.sni_map_path = Some(path);
        self
    }

    pub fn with_ss_path(mut self, path: String) -> Self {
        self.ss_path = path;
        self
    }
}

impl Inspector for RealInspector {
    fn inspect(&self) -> ConnectionMeta {
        let mut meta = ConnectionMeta::default();
        meta.protocol = Some(self.target.protocol.clone());
        meta.ip = Some(self.target.ip.clone());
        meta.port = Some(self.target.port);

        if let Some(ref map_path) = self.sni_map_path {
            if let Some(sni) = lookup_sni(map_path, &self.target.ip, self.target.port) {
                meta.sni = Some(sni);
            }
        }

        if let Some(rtt) = query_rtt(&self.ss_path, &self.target.ip, self.target.port) {
            meta.rtt_ms = Some(rtt);
            meta.latency_ms = Some(rtt);
        }

        meta
    }
}

#[derive(Debug)]
pub struct SystemInspector {
    pub protocol: String,
    pub prefer_port: Option<u16>,
    pub sni_map_path: Option<String>,
    pub ss_path: String,
}

impl SystemInspector {
    pub fn new(protocol: &str) -> Self {
        Self {
            protocol: protocol.to_string(),
            prefer_port: None,
            sni_map_path: std::env::var("NETPOLICY_SNI_MAP").ok(),
            ss_path: "ss".to_string(),
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.prefer_port = Some(port);
        self
    }

    pub fn with_sni_map(mut self, path: String) -> Self {
        self.sni_map_path = Some(path);
        self
    }

    pub fn with_ss_path(mut self, path: String) -> Self {
        self.ss_path = path;
        self
    }
}

impl Inspector for SystemInspector {
    fn inspect(&self) -> ConnectionMeta {
        let mut meta = ConnectionMeta::default();
        let (target, rtt) = match query_connection(&self.ss_path, &self.protocol, self.prefer_port)
        {
            Some(data) => data,
            None => return meta,
        };

        meta.protocol = Some(target.protocol.clone());
        meta.ip = Some(target.ip.clone());
        meta.port = Some(target.port);

        if let Some(ref map_path) = self.sni_map_path {
            if let Some(sni) = lookup_sni(map_path, &target.ip, target.port) {
                meta.sni = Some(sni);
            }
        }

        if let Some(rtt) = rtt {
            meta.rtt_ms = Some(rtt);
            meta.latency_ms = Some(rtt);
        }

        meta
    }
}

pub fn to_match_context(meta: &ConnectionMeta) -> MatchContext {
    MatchContext {
        sni: meta.sni.clone(),
        protocol: meta.protocol.clone(),
        port: meta.port,
        latency_ms: meta.latency_ms,
        rtt_ms: meta.rtt_ms,
    }
}

fn query_rtt(ss_path: &str, ip: &str, port: u16) -> Option<u32> {
    let output = Command::new(ss_path)
        .args(["-tin", "dst", &format!("{}:{}", ip, port)])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    parse_rtt_from_ss(&text)
}

fn parse_rtt_from_ss(text: &str) -> Option<u32> {
    for line in text.lines() {
        if let Some(idx) = line.find("rtt:") {
            let rest = &line[idx + 4..];
            let value = rest.split('/').next()?.trim();
            if let Ok(ms) = value.parse::<f32>() {
                return Some(ms.round() as u32);
            }
        }
    }
    None
}

fn query_connection(
    ss_path: &str,
    protocol: &str,
    prefer_port: Option<u16>,
) -> Option<(ConnectionTarget, Option<u32>)> {
    let args = if protocol.eq_ignore_ascii_case("udp") {
        vec!["-uin"]
    } else {
        vec!["-tin"]
    };
    let output = Command::new(ss_path).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        let local = parts[3];
        let peer = parts[4];
        let (peer_ip, peer_port) = split_addr(peer)?;
        let (_, local_port) = split_addr(local)?;
        if let Some(port) = prefer_port {
            if peer_port != port && local_port != port {
                continue;
            }
        }
        let target = ConnectionTarget {
            ip: peer_ip,
            port: peer_port,
            protocol: protocol.to_string(),
        };
        let rtt = parse_rtt_from_ss(line);
        return Some((target, rtt));
    }
    None
}

fn split_addr(value: &str) -> Option<(String, u16)> {
    let trimmed = value.trim();
    let trimmed = trimmed.strip_prefix('[').unwrap_or(trimmed);
    let trimmed = trimmed.strip_suffix(']').unwrap_or(trimmed);
    let (host, port) = trimmed.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    Some((host.to_string(), port))
}

fn lookup_sni(path: &str, ip: &str, port: u16) -> Option<String> {
    let data = fs::read_to_string(path).ok()?;
    let map: SniMap = serde_json::from_str(&data).ok()?;
    map.get(&format!("{}:{}", ip, port)).cloned()
}

#[derive(Debug, Deserialize)]
#[serde(transparent)]
struct SniMap(std::collections::HashMap<String, String>);

impl SniMap {
    fn get(&self, key: &str) -> Option<&String> {
        self.0.get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_inspector_returns_meta() {
        let meta = ConnectionMeta {
            sni: Some("example.com".to_string()),
            ip: Some("1.2.3.4".to_string()),
            port: Some(443),
            protocol: Some("tcp".to_string()),
            rtt_ms: Some(20),
            latency_ms: Some(15),
            error_rate: Some(0.01),
        };
        let inspector = MockInspector { meta: meta.clone() };
        let out = inspector.inspect();
        assert_eq!(out.sni, meta.sni);
        assert_eq!(out.port, meta.port);
    }

    #[test]
    fn to_match_context_maps_fields() {
        let meta = ConnectionMeta {
            sni: Some("example.com".to_string()),
            port: Some(443),
            protocol: Some("tcp".to_string()),
            rtt_ms: Some(30),
            latency_ms: Some(25),
            ..ConnectionMeta::default()
        };
        let ctx = to_match_context(&meta);
        assert_eq!(ctx.sni, meta.sni);
        assert_eq!(ctx.port, meta.port);
    }

    #[test]
    fn parse_rtt_from_ss_extracts_value() {
        let sample = "ESTAB 0 0 1.1.1.1:443 2.2.2.2:55555 cubic rtt:12.3/3.4";
        let rtt = parse_rtt_from_ss(sample).expect("rtt");
        assert_eq!(rtt, 12);
    }

    #[test]
    fn split_addr_parses_host_and_port() {
        let (host, port) = split_addr("10.0.0.1:443").expect("addr");
        assert_eq!(host, "10.0.0.1");
        assert_eq!(port, 443);
    }
}
