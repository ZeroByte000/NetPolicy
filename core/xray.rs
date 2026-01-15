use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug)]
pub enum XrayError {
    InvalidUrl(String),
    Decode(String),
    Parse(String),
}

#[derive(Debug, Clone)]
pub struct ProxyNode {
    pub tag: String,
    pub protocol: String,
    pub server: String,
    pub port: u16,
    pub uuid: Option<String>,
    pub password: Option<String>,
    pub username: Option<String>,
    pub method: Option<String>,
    pub plugin: Option<String>,
    pub plugin_opts: Option<String>,
    pub security: Option<String>,
    pub grpc_service: Option<String>,
    pub h2_path: Option<String>,
    pub h2_host: Option<String>,
    pub reality_public_key: Option<String>,
    pub reality_short_id: Option<String>,
    pub fingerprint: Option<String>,
    pub network: Option<String>,
    pub tls: bool,
    pub sni: Option<String>,
    pub ws_path: Option<String>,
    pub ws_host: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct XrayConfig {
    pub log: XrayLog,
    pub inbounds: Vec<XrayInbound>,
    pub outbounds: Vec<XrayOutbound>,
    pub routing: XrayRouting,
    pub dns: XrayDns,
}

#[derive(Debug, Serialize)]
pub struct XrayLog {
    pub loglevel: String,
}

#[derive(Debug, Serialize)]
pub struct XrayInbound {
    pub tag: String,
    pub port: u16,
    pub listen: String,
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sniffing: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct XrayOutbound {
    pub tag: String,
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<serde_json::Value>,
    #[serde(rename = "streamSettings", skip_serializing_if = "Option::is_none")]
    pub stream_settings: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct XrayRouting {
    #[serde(rename = "domainStrategy")]
    pub domain_strategy: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub balancers: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct XrayDns {
    pub servers: Vec<serde_json::Value>,
    #[serde(rename = "queryStrategy")]
    pub query_strategy: String,
}

pub fn parse_proxy_urls(urls: &[String]) -> Result<Vec<ProxyNode>, XrayError> {
    if urls.is_empty() {
        return Err(XrayError::InvalidUrl(
            "no proxy urls provided".to_string(),
        ));
    }

    let mut nodes = Vec::new();
    for (idx, raw) in urls.iter().enumerate() {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(XrayError::InvalidUrl(format!(
                "url at index {} is empty",
                idx + 1
            )));
        }
        let node = if raw.starts_with("vmess://") {
            parse_vmess(raw)?
        } else if raw.starts_with("vless://") {
            parse_vless(raw)?
        } else if raw.starts_with("trojan://") {
            parse_trojan(raw)?
        } else if raw.starts_with("ss://") {
            parse_shadowsocks(raw)?
        } else if raw.starts_with("socks5://") || raw.starts_with("socks://") {
            parse_socks(raw)?
        } else if raw.starts_with("http://") || raw.starts_with("https://") {
            parse_http_proxy(raw)?
        } else {
            return Err(XrayError::InvalidUrl(format!(
                "unsupported scheme at index {}: {}",
                idx + 1,
                raw
            )));
        };

        let tag = if node.tag.trim().is_empty() {
            format!("proxy-{}", idx + 1)
        } else {
            node.tag.clone()
        };
        let node = ProxyNode { tag, ..node };
        validate_node(&node).map_err(|msg| {
            XrayError::Parse(format!("invalid node at index {}: {}", idx + 1, msg))
        })?;
        nodes.push(node);
    }
    Ok(nodes)
}

pub fn build_xray_config(nodes: &[ProxyNode]) -> XrayConfig {
    let mut outbounds = Vec::new();
    for node in nodes {
        outbounds.push(node_to_outbound(node));
    }

    outbounds.push(XrayOutbound {
        tag: "direct".to_string(),
        protocol: "freedom".to_string(),
        settings: None,
        stream_settings: None,
    });
    outbounds.push(XrayOutbound {
        tag: "reject".to_string(),
        protocol: "blackhole".to_string(),
        settings: None,
        stream_settings: None,
    });

    let proxy_tags: Vec<String> = nodes.iter().map(|n| n.tag.clone()).collect();
    let balancers = build_balancers(&proxy_tags);

    XrayConfig {
        log: XrayLog {
            loglevel: "warning".to_string(),
        },
        inbounds: build_inbounds(),
        outbounds,
        routing: XrayRouting {
            domain_strategy: "AsIs".to_string(),
            rules: Vec::new(),
            balancers,
        },
        dns: build_dns(),
    }
}

fn build_inbounds() -> Vec<XrayInbound> {
    let mut inbounds = vec![
        XrayInbound {
            tag: "http".to_string(),
            port: 7890,
            listen: "0.0.0.0".to_string(),
            protocol: "http".to_string(),
            settings: None,
            sniffing: Some(json_sniffing()),
        },
        XrayInbound {
            tag: "socks".to_string(),
            port: 7891,
            listen: "0.0.0.0".to_string(),
            protocol: "socks".to_string(),
            settings: Some(serde_json::json!({ "udp": true })),
            sniffing: Some(json_sniffing()),
        },
        XrayInbound {
            tag: "mixed".to_string(),
            port: 7893,
            listen: "0.0.0.0".to_string(),
            protocol: "socks".to_string(),
            settings: Some(serde_json::json!({ "udp": true })),
            sniffing: Some(json_sniffing()),
        },
    ];

    if std::env::consts::OS == "linux" {
        inbounds.push(XrayInbound {
            tag: "redir".to_string(),
            port: 7892,
            listen: "0.0.0.0".to_string(),
            protocol: "dokodemo-door".to_string(),
            settings: Some(serde_json::json!({
                "network": "tcp,udp",
                "followRedirect": true
            })),
            sniffing: Some(json_sniffing()),
        });
        inbounds.push(XrayInbound {
            tag: "tproxy".to_string(),
            port: 7895,
            listen: "0.0.0.0".to_string(),
            protocol: "dokodemo-door".to_string(),
            settings: Some(serde_json::json!({
                "network": "tcp,udp",
                "followRedirect": true,
                "tproxy": "tproxy"
            })),
            sniffing: Some(json_sniffing()),
        });
    }

    inbounds
}

fn json_sniffing() -> serde_json::Value {
    serde_json::json!({
        "enabled": true,
        "destOverride": ["http", "tls", "quic"]
    })
}

fn build_balancers(tags: &[String]) -> Vec<serde_json::Value> {
    if tags.is_empty() {
        return Vec::new();
    }
    vec![
        serde_json::json!({
            "tag": "best_ping",
            "selector": tags,
            "strategy": { "type": "leastPing" }
        }),
        serde_json::json!({
            "tag": "load_balance",
            "selector": tags,
            "strategy": { "type": "random" }
        }),
        serde_json::json!({
            "tag": "fallback",
            "selector": tags,
            "strategy": { "type": "random" }
        }),
    ]
}

fn build_dns() -> XrayDns {
    let servers = vec![
        serde_json::json!({ "address": "8.8.8.8" }),
        serde_json::json!({ "address": "1.0.0.1" }),
        serde_json::json!({ "address": "https://dns.google/dns-query" }),
        serde_json::json!({ "address": "dhcp" }),
        serde_json::json!({ "address": "https://doh.pub/dns-query" }),
        serde_json::json!({ "address": "https://dns.alidns.com/dns-query" }),
        serde_json::json!({ "address": "1.1.1.1" }),
        serde_json::json!({ "address": "8.8.4.4" }),
        serde_json::json!({ "address": "https://cloudflare-dns.com/dns-query" }),
        serde_json::json!({ "address": "112.215.203.254" }),
    ];

    XrayDns {
        servers,
        query_strategy: "UseIPv4".to_string(),
    }
}

fn node_to_outbound(node: &ProxyNode) -> XrayOutbound {
    let (settings, stream_settings) = match node.protocol.as_str() {
        "vmess" => (vmess_settings(node), stream_settings(node)),
        "vless" => (vless_settings(node), stream_settings(node)),
        "trojan" => (trojan_settings(node), stream_settings(node)),
        "shadowsocks" => (shadowsocks_settings(node), None),
        "socks" => (socks_settings(node), None),
        "http" => (http_settings(node), http_stream_settings(node)),
        _ => (None, None),
    };

    XrayOutbound {
        tag: node.tag.clone(),
        protocol: node.protocol.clone(),
        settings,
        stream_settings,
    }
}

fn validate_node(node: &ProxyNode) -> Result<(), String> {
    if node.server.trim().is_empty() {
        return Err("server is empty".to_string());
    }
    if node.port == 0 {
        return Err("port must be > 0".to_string());
    }
    match node.protocol.as_str() {
        "vmess" | "vless" => {
            let uuid = node.uuid.as_deref().unwrap_or("");
            if uuid.is_empty() {
                return Err("uuid is required".to_string());
            }
            if !valid_uuid(uuid) {
                return Err("uuid format is invalid".to_string());
            }
        }
        "trojan" => {
            let password = node.password.as_deref().unwrap_or("");
            if password.is_empty() {
                return Err("password is required".to_string());
            }
            if !valid_password(password) {
                return Err("password format is invalid".to_string());
            }
        }
        "shadowsocks" => {
            let password = node.password.as_deref().unwrap_or("");
            if password.is_empty() {
                return Err("password is required".to_string());
            }
            if !valid_password(password) {
                return Err("password format is invalid".to_string());
            }
            if node.method.as_deref().unwrap_or("").is_empty() {
                return Err("method is required".to_string());
            }
        }
        "socks" | "http" => {}
        _ => {
            return Err(format!("unsupported protocol: {}", node.protocol));
        }
    }

    if node.security.as_deref() == Some("reality") {
        let pbk = node.reality_public_key.as_deref().unwrap_or("");
        let sid = node.reality_short_id.as_deref().unwrap_or("");
        if pbk.is_empty() || sid.is_empty() {
            return Err("reality requires pbk and sid".to_string());
        }
        if !valid_reality_public_key(pbk) {
            return Err("reality pbk format is invalid".to_string());
        }
        if !valid_reality_short_id(sid) {
            return Err("reality sid length is invalid".to_string());
        }
    }
    Ok(())
}

fn vmess_settings(node: &ProxyNode) -> Option<serde_json::Value> {
    Some(serde_json::json!({
        "vnext": [{
            "address": node.server,
            "port": node.port,
            "users": [{
                "id": node.uuid.clone().unwrap_or_default(),
                "alterId": 0,
                "security": "auto"
            }]
        }]
    }))
}

fn vless_settings(node: &ProxyNode) -> Option<serde_json::Value> {
    Some(serde_json::json!({
        "vnext": [{
            "address": node.server,
            "port": node.port,
            "users": [{
                "id": node.uuid.clone().unwrap_or_default(),
                "encryption": "none"
            }]
        }]
    }))
}

fn trojan_settings(node: &ProxyNode) -> Option<serde_json::Value> {
    Some(serde_json::json!({
        "servers": [{
            "address": node.server,
            "port": node.port,
            "password": node.password.clone().unwrap_or_default()
        }]
    }))
}

fn shadowsocks_settings(node: &ProxyNode) -> Option<serde_json::Value> {
    let mut server = serde_json::json!({
        "servers": [{
            "address": node.server,
            "port": node.port,
            "method": node.method.clone().unwrap_or_else(|| "aes-128-gcm".to_string()),
            "password": node.password.clone().unwrap_or_default()
        }]
    });

    if let Some(ref plugin) = node.plugin {
        server["servers"][0]["plugin"] = serde_json::json!(plugin);
    }
    if let Some(ref opts) = node.plugin_opts {
        server["servers"][0]["pluginOpts"] = serde_json::json!(opts);
    }

    Some(server)
}

fn socks_settings(node: &ProxyNode) -> Option<serde_json::Value> {
    let mut server = serde_json::json!({
        "address": node.server,
        "port": node.port
    });
    if node.username.is_some() || node.password.is_some() {
        server["users"] = serde_json::json!([{
            "user": node.username.clone().unwrap_or_default(),
            "pass": node.password.clone().unwrap_or_default()
        }]);
    }
    Some(serde_json::json!({ "servers": [server] }))
}

fn http_settings(node: &ProxyNode) -> Option<serde_json::Value> {
    let mut server = serde_json::json!({
        "address": node.server,
        "port": node.port
    });
    if node.username.is_some() || node.password.is_some() {
        server["users"] = serde_json::json!([{
            "user": node.username.clone().unwrap_or_default(),
            "pass": node.password.clone().unwrap_or_default()
        }]);
    }
    Some(serde_json::json!({ "servers": [server] }))
}

fn http_stream_settings(node: &ProxyNode) -> Option<serde_json::Value> {
    if !node.tls {
        return None;
    }
    Some(serde_json::json!({
        "security": "tls",
        "tlsSettings": {
            "serverName": node.server
        }
    }))
}

fn stream_settings(node: &ProxyNode) -> Option<serde_json::Value> {
    let network = node.network.clone().unwrap_or_else(|| "tcp".to_string());
    let mut settings = serde_json::json!({
        "network": network,
    });

    let security = node.security.clone().unwrap_or_else(|| {
        if node.tls {
            "tls".to_string()
        } else {
            "none".to_string()
        }
    });

    if security == "tls" && node.tls {
        settings["security"] = serde_json::json!("tls");
        if let Some(ref sni) = node.sni {
            settings["tlsSettings"] = serde_json::json!({
                "serverName": sni
            });
        }
    }

    if security == "reality" {
        settings["security"] = serde_json::json!("reality");
        settings["realitySettings"] = serde_json::json!({
            "serverName": node.sni.clone().unwrap_or_default(),
            "publicKey": node.reality_public_key.clone().unwrap_or_default(),
            "shortId": node.reality_short_id.clone().unwrap_or_default(),
            "fingerprint": node.fingerprint.clone().unwrap_or_else(|| "chrome".to_string())
        });
    }

    if node.network.as_deref() == Some("ws") {
        settings["wsSettings"] = serde_json::json!({
            "path": node.ws_path.clone().unwrap_or_else(|| "/".to_string()),
            "headers": {
                "Host": node.ws_host.clone().unwrap_or_default()
            }
        });
    }

    if node.network.as_deref() == Some("grpc") {
        settings["grpcSettings"] = serde_json::json!({
            "serviceName": node.grpc_service.clone().unwrap_or_default()
        });
    }

    if node.network.as_deref() == Some("h2") {
        settings["httpSettings"] = serde_json::json!({
            "path": node.h2_path.clone().unwrap_or_else(|| "/".to_string()),
            "host": [node.h2_host.clone().unwrap_or_default()]
        });
    }

    Some(settings)
}

fn parse_vmess(raw: &str) -> Result<ProxyNode, XrayError> {
    let encoded = raw.trim_start_matches("vmess://");
    if encoded.trim().is_empty() {
        return Err(XrayError::InvalidUrl(
            "vmess url missing payload".to_string(),
        ));
    }
    let decoded = decode_base64(encoded)
        .map_err(|e| XrayError::Decode(e))?;
    let vmess: VmessLink = serde_json::from_slice(&decoded)
        .map_err(|e| XrayError::Parse(e.to_string()))?;

    if vmess.add.trim().is_empty() {
        return Err(XrayError::Parse("vmess missing server".to_string()));
    }
    if vmess.id.trim().is_empty() {
        return Err(XrayError::Parse("vmess missing uuid".to_string()));
    }

    Ok(ProxyNode {
        tag: vmess.ps.unwrap_or_default(),
        protocol: "vmess".to_string(),
        server: vmess.add,
        port: vmess.port.parse::<u16>().map_err(|_| {
            XrayError::Parse(format!("invalid vmess port: {}", vmess.port))
        })?,
        uuid: Some(vmess.id),
        password: None,
        username: None,
        method: None,
        plugin: None,
        plugin_opts: None,
        security: vmess.tls.clone(),
        grpc_service: None,
        h2_path: None,
        h2_host: None,
        reality_public_key: None,
        reality_short_id: None,
        fingerprint: None,
        network: vmess.net,
        tls: vmess.tls.unwrap_or_default().to_lowercase() == "tls",
        sni: vmess.sni.or(vmess.host.clone()),
        ws_path: vmess.path,
        ws_host: vmess.host,
    })
}

fn parse_vless(raw: &str) -> Result<ProxyNode, XrayError> {
    let url = Url::parse(raw).map_err(|e| XrayError::Parse(e.to_string()))?;
    let uuid = url.username().to_string();
    if uuid.trim().is_empty() {
        return Err(XrayError::Parse("vless missing uuid".to_string()));
    }
    let host = url.host_str().ok_or_else(|| {
        XrayError::Parse("vless missing host".to_string())
    })?;
    let port = url.port().ok_or_else(|| {
        XrayError::Parse("vless missing port".to_string())
    })?;
    let tag = url.fragment().unwrap_or("").to_string();
    let mut network = None;
    let mut security = None;
    let mut sni = None;
    let mut host_header = None;
    let mut path = None;
    let mut grpc_service: Option<String> = None;
    let mut h2_path: Option<String> = None;
    let mut h2_host: Option<String> = None;
    let mut reality_public_key: Option<String> = None;
    let mut reality_short_id: Option<String> = None;
    let mut fingerprint: Option<String> = None;

    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "type" => network = Some(value.to_string()),
            "security" => security = Some(value.to_string()),
            "sni" => sni = Some(value.to_string()),
            "host" => {
                host_header = Some(value.to_string());
                h2_host = Some(value.to_string());
            }
            "path" => {
                path = Some(value.to_string());
                h2_path = Some(value.to_string());
            }
            "serviceName" => grpc_service = Some(value.to_string()),
            "pbk" => reality_public_key = Some(value.to_string()),
            "sid" => reality_short_id = Some(value.to_string()),
            "fp" => fingerprint = Some(value.to_string()),
            _ => {}
        }
    }

    Ok(ProxyNode {
        tag,
        protocol: "vless".to_string(),
        server: host.to_string(),
        port,
        uuid: Some(uuid),
        password: None,
        username: None,
        method: None,
        plugin: None,
        plugin_opts: None,
        security: security.clone(),
        grpc_service,
        h2_path,
        h2_host,
        reality_public_key,
        reality_short_id,
        fingerprint,
        network,
        tls: security.clone().unwrap_or_default().to_lowercase() == "tls",
        sni,
        ws_path: path,
        ws_host: host_header,
    })
}

fn parse_trojan(raw: &str) -> Result<ProxyNode, XrayError> {
    let url = Url::parse(raw).map_err(|e| XrayError::Parse(e.to_string()))?;
    let password = url.username().to_string();
    if password.trim().is_empty() {
        return Err(XrayError::Parse("trojan missing password".to_string()));
    }
    let host = url.host_str().ok_or_else(|| {
        XrayError::Parse("trojan missing host".to_string())
    })?;
    let port = url.port().ok_or_else(|| {
        XrayError::Parse("trojan missing port".to_string())
    })?;
    let tag = url.fragment().unwrap_or("").to_string();
    let mut network = None;
    let mut security = None;
    let mut sni = None;
    let mut host_header = None;
    let mut path = None;
    let mut grpc_service: Option<String> = None;
    let mut h2_path: Option<String> = None;
    let mut h2_host: Option<String> = None;
    let mut reality_public_key: Option<String> = None;
    let mut reality_short_id: Option<String> = None;
    let mut fingerprint: Option<String> = None;

    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "type" => network = Some(value.to_string()),
            "security" => security = Some(value.to_string()),
            "sni" => sni = Some(value.to_string()),
            "host" => {
                host_header = Some(value.to_string());
                h2_host = Some(value.to_string());
            }
            "path" => {
                path = Some(value.to_string());
                h2_path = Some(value.to_string());
            }
            "serviceName" => grpc_service = Some(value.to_string()),
            "pbk" => reality_public_key = Some(value.to_string()),
            "sid" => reality_short_id = Some(value.to_string()),
            "fp" => fingerprint = Some(value.to_string()),
            _ => {}
        }
    }

    Ok(ProxyNode {
        tag,
        protocol: "trojan".to_string(),
        server: host.to_string(),
        port,
        uuid: None,
        password: Some(password),
        username: None,
        method: None,
        plugin: None,
        plugin_opts: None,
        security: security.clone(),
        grpc_service,
        h2_path,
        h2_host,
        reality_public_key,
        reality_short_id,
        fingerprint,
        network,
        tls: security.clone().unwrap_or_else(|| "tls".to_string()).to_lowercase() == "tls",
        sni,
        ws_path: path,
        ws_host: host_header,
    })
}

fn parse_shadowsocks(raw: &str) -> Result<ProxyNode, XrayError> {
    let rest = raw.trim_start_matches("ss://");
    if rest.trim().is_empty() {
        return Err(XrayError::InvalidUrl("ss url missing payload".to_string()));
    }

    let mut main = rest;
    let mut tag = "";
    if let Some((before, frag)) = rest.split_once('#') {
        main = before;
        tag = frag;
    }

    let mut plugin = None;
    let mut plugin_opts = None;
    if let Some((before, query)) = main.split_once('?') {
        main = before;
        if let Some(plugin_value) = parse_query_value(query, "plugin") {
            let mut parts = plugin_value.splitn(2, ';');
            plugin = parts.next().map(|v| v.to_string());
            plugin_opts = parts.next().map(|v| v.to_string());
        }
    }

    let (creds, hostport) = if let Some((creds, hostport)) = main.split_once('@') {
        (creds.to_string(), hostport.to_string())
    } else {
        let decoded = decode_base64(main)
            .map_err(|_| XrayError::Decode("ss base64 decode failed".to_string()))?;
        let decoded = String::from_utf8_lossy(&decoded).to_string();
        let mut parts = decoded.splitn(2, '@');
        let creds = parts.next().unwrap_or_default().to_string();
        let hostport = parts.next().unwrap_or_default().to_string();
        (creds, hostport)
    };

    let (method, password) = if creds.contains(':') {
        let mut parts = creds.splitn(2, ':');
        (
            parts.next().unwrap_or_default().to_string(),
            parts.next().unwrap_or_default().to_string(),
        )
    } else {
        let decoded = decode_base64(&creds)
            .map_err(|_| XrayError::Decode("ss base64 decode failed".to_string()))?;
        let decoded = String::from_utf8_lossy(&decoded).to_string();
        let mut parts = decoded.splitn(2, ':');
        (
            parts.next().unwrap_or_default().to_string(),
            parts.next().unwrap_or_default().to_string(),
        )
    };

    let mut host_parts = hostport.splitn(2, ':');
    let host = host_parts.next().unwrap_or_default();
    let port = host_parts
        .next()
        .unwrap_or_default()
        .parse::<u16>()
        .map_err(|_| XrayError::Parse("invalid ss port".to_string()))?;

    Ok(ProxyNode {
        tag: tag.to_string(),
        protocol: "shadowsocks".to_string(),
        server: host.to_string(),
        port,
        uuid: None,
        password: Some(password),
        username: None,
        method: Some(method),
        plugin,
        plugin_opts,
        security: None,
        grpc_service: None,
        h2_path: None,
        h2_host: None,
        reality_public_key: None,
        reality_short_id: None,
        fingerprint: None,
        network: None,
        tls: false,
        sni: None,
        ws_path: None,
        ws_host: None,
    })
}

fn parse_socks(raw: &str) -> Result<ProxyNode, XrayError> {
    let url = Url::parse(raw).map_err(|e| XrayError::Parse(e.to_string()))?;
    let host = url.host_str().ok_or_else(|| {
        XrayError::Parse("socks missing host".to_string())
    })?;
    let port = url.port().ok_or_else(|| {
        XrayError::Parse("socks missing port".to_string())
    })?;
    let tag = url.fragment().unwrap_or("").to_string();
    let username = url.username();
    let password = url.password().unwrap_or("").to_string();
    let user = if username.is_empty() { None } else { Some(username.to_string()) };
    let pass = if password.is_empty() { None } else { Some(password) };

    Ok(ProxyNode {
        tag,
        protocol: "socks".to_string(),
        server: host.to_string(),
        port,
        uuid: None,
        password: pass,
        username: user,
        method: None,
        plugin: None,
        plugin_opts: None,
        security: None,
        grpc_service: None,
        h2_path: None,
        h2_host: None,
        reality_public_key: None,
        reality_short_id: None,
        fingerprint: None,
        network: None,
        tls: false,
        sni: None,
        ws_path: None,
        ws_host: None,
    })
}

fn parse_http_proxy(raw: &str) -> Result<ProxyNode, XrayError> {
    let url = Url::parse(raw).map_err(|e| XrayError::Parse(e.to_string()))?;
    let host = url.host_str().ok_or_else(|| {
        XrayError::Parse("http proxy missing host".to_string())
    })?;
    let port = url.port().ok_or_else(|| {
        XrayError::Parse("http proxy missing port".to_string())
    })?;
    let tag = url.fragment().unwrap_or("").to_string();
    let username = url.username();
    let password = url.password().unwrap_or("").to_string();
    let user = if username.is_empty() { None } else { Some(username.to_string()) };
    let pass = if password.is_empty() { None } else { Some(password) };

    Ok(ProxyNode {
        tag,
        protocol: "http".to_string(),
        server: host.to_string(),
        port,
        uuid: None,
        password: pass,
        username: user,
        method: None,
        plugin: None,
        plugin_opts: None,
        security: if url.scheme() == "https" { Some("tls".to_string()) } else { None },
        grpc_service: None,
        h2_path: None,
        h2_host: None,
        reality_public_key: None,
        reality_short_id: None,
        fingerprint: None,
        network: None,
        tls: url.scheme() == "https",
        sni: None,
        ws_path: None,
        ws_host: None,
    })
}

fn parse_query_value(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        let k = parts.next()?.trim();
        let v = parts.next().unwrap_or("").trim();
        if k == key {
            return Some(v.replace("%3B", ";").replace("%3b", ";"));
        }
    }
    None
}

fn decode_base64(value: &str) -> Result<Vec<u8>, String> {
    STANDARD
        .decode(value)
        .or_else(|_| URL_SAFE_NO_PAD.decode(value))
        .map_err(|e| e.to_string())
}

fn valid_uuid(value: &str) -> bool {
    let lower = value.to_lowercase();
    let bytes = lower.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (idx, ch) in bytes.iter().enumerate() {
        match idx {
            8 | 13 | 18 | 23 => {
                if *ch != b'-' {
                    return false;
                }
            }
            _ => {
                if !matches!(ch, b'0'..=b'9' | b'a'..=b'f') {
                    return false;
                }
            }
        }
    }
    true
}

fn valid_password(value: &str) -> bool {
    if value.trim().is_empty() {
        return false;
    }
    !value.chars().any(char::is_whitespace)
}

fn valid_reality_public_key(value: &str) -> bool {
    let len_ok = (43..=64).contains(&value.len());
    if !len_ok {
        return false;
    }
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=')
}

fn valid_reality_short_id(value: &str) -> bool {
    let len_ok = matches!(value.len(), 8 | 16);
    if !len_ok {
        return false;
    }
    value.chars().all(|c| c.is_ascii_hexdigit())
}

#[derive(Debug, Deserialize)]
struct VmessLink {
    #[serde(default)]
    ps: Option<String>,
    add: String,
    port: String,
    id: String,
    #[serde(default)]
    net: Option<String>,
    #[serde(default)]
    tls: Option<String>,
    #[serde(default)]
    sni: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    path: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_vless_basic() {
        let url = "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?type=ws&security=tls&sni=example.com&path=%2Fws#Test";
        let node = parse_vless(url).expect("parse vless");
        assert_eq!(node.tag, "Test");
        assert_eq!(node.protocol, "vless");
        assert_eq!(node.server, "example.com");
        assert_eq!(node.port, 443);
        assert!(node.tls);
    }

    #[test]
    fn error_empty_url() {
        let urls = vec!["".to_string()];
        let err = parse_proxy_urls(&urls).unwrap_err();
        match err {
            XrayError::InvalidUrl(msg) => assert!(msg.contains("empty")),
            _ => panic!("expected InvalidUrl"),
        }
    }

    #[test]
    fn error_unsupported_scheme() {
        let urls = vec!["ftp://example.com:21".to_string()];
        let err = parse_proxy_urls(&urls).unwrap_err();
        match err {
            XrayError::InvalidUrl(msg) => assert!(msg.contains("unsupported scheme")),
            _ => panic!("expected InvalidUrl"),
        }
    }

    #[test]
    fn error_invalid_port() {
        let urls = vec!["vless://123e4567-e89b-12d3-a456-426614174000@example.com:abc".to_string()];
        let err = parse_proxy_urls(&urls).unwrap_err();
        match err {
            XrayError::Parse(msg) => assert!(msg.contains("missing port") || msg.contains("invalid")),
            _ => panic!("expected Parse"),
        }
    }

    #[test]
    fn error_reality_requires_pbk_sid() {
        let urls = vec![
            "vless://123e4567-e89b-12d3-a456-426614174000@reality.example.com:443?security=reality&sni=example.com#NoKeys".to_string()
        ];
        let err = parse_proxy_urls(&urls).unwrap_err();
        match err {
            XrayError::Parse(msg) => assert!(msg.contains("reality requires pbk and sid")),
            _ => panic!("expected Parse"),
        }
    }
}
