use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use netpolicy::action_backend::{render_backend, BackendKind};
use netpolicy::actions::plan_action;
use netpolicy::engine::{evaluate_ruleset, MatchContext};
use netpolicy::inspector::{to_match_context, Inspector, SystemInspector};
use netpolicy::rules::parse_ruleset;
use netpolicy::state::EngineState;
use netpolicy::telemetry::Telemetry;
use netpolicy::xray::{build_xray_config, parse_proxy_urls};
use serde::{Deserialize, Serialize};
use tiny_http::{Header, Method, Response, Server, StatusCode};

#[derive(Debug)]
struct Args {
    config_path: Option<String>,
    dry_run: bool,
    web: bool,
    bind: String,
    web_root: String,
    log_file: Option<String>,
    xray_output: Option<String>,
    xray_bin: String,
    xray_config: String,
    xray_log: String,
    xray_autostart: bool,
    hot_reload: bool,
    reload_interval_secs: u64,
    live: bool,
    inspect_protocol: String,
    inspect_port: Option<u16>,
    inspect_interval_secs: u64,
    backend: BackendKind,
    apply_actions: bool,
    state: EngineState,
    ctx: MatchContext,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            config_path: None,
            dry_run: false,
            web: false,
            bind: "127.0.0.1:8787".to_string(),
            web_root: "web".to_string(),
            log_file: None,
            xray_output: None,
            xray_bin: "xray".to_string(),
            xray_config: "config.json".to_string(),
            xray_log: "xray.log".to_string(),
            xray_autostart: false,
            hot_reload: false,
            reload_interval_secs: 2,
            live: false,
            inspect_protocol: "tcp".to_string(),
            inspect_port: None,
            inspect_interval_secs: 3,
            backend: BackendKind::Iptables,
            apply_actions: false,
            state: EngineState::Normal,
            ctx: MatchContext::default(),
        }
    }
}

fn main() {
    let args = parse_args();

    if args.web {
        start_web_server(&args);
        return;
    }

    let path = match args.config_path.as_deref() {
        Some(p) => p.to_string(),
        None => {
            eprintln!("usage: netpolicyd --config <path> [--dry-run] [--live] [--inspect-protocol <tcp|udp>] [--inspect-port <n>] [--inspect-interval <secs>] [--backend <iptables|nftables>] [--apply-actions] [--state <normal|degraded|failover|recovery>] [--sni <host>] [--protocol <tcp|udp>] [--port <n>] [--latency-ms <n>] [--rtt-ms <n>] [--log-file <path>] [--web] [--bind <addr>] [--web-root <path>] [--xray-gen <output>] [--xray-bin <path>] [--xray-config <path>] [--xray-log <path>] [--xray-autostart] [--hot-reload] [--reload-interval <secs>]");
            std::process::exit(1);
        }
    };

    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("failed to read config {}: {}", path, err);
            std::process::exit(1);
        }
    };

    let ruleset = match parse_ruleset(&content) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("invalid ruleset: {:?}", err);
            std::process::exit(1);
        }
    };

    if args.dry_run {
        match evaluate_ruleset(&ruleset, &args.ctx, args.state) {
            Ok(decision) => {
                if let Some(rule) = decision.rule {
                    println!(
                        "dry-run decision: state={:?} rule={}",
                        args.state,
                        rule.name
                    );
                    println!(
                        "context: sni={:?} protocol={:?} port={:?} latency_ms={:?} rtt_ms={:?}",
                        args.ctx.sni, args.ctx.protocol, args.ctx.port, args.ctx.latency_ms, args.ctx.rtt_ms
                    );
                    let action = action_summary(rule);
                    println!("action: {}", action);
                    if let Some(ref log_file) = args.log_file {
                        let _ = append_log(log_file, args.state, rule.name.as_str(), &action);
                    }
                } else {
                    println!("dry-run decision: state={:?} no match", args.state);
                    println!(
                        "context: sni={:?} protocol={:?} port={:?} latency_ms={:?} rtt_ms={:?}",
                        args.ctx.sni, args.ctx.protocol, args.ctx.port, args.ctx.latency_ms, args.ctx.rtt_ms
                    );
                }
            }
            Err(err) => {
                eprintln!("engine error: {:?}", err);
                std::process::exit(1);
            }
        }
    }

    if args.live {
        run_live(&args, &path);
    }

    if args.hot_reload {
        watch_ruleset(&path, args.reload_interval_secs);
    }
}

fn parse_args() -> Args {
    let args: Vec<String> = env::args().collect();
    let mut out = Args {
        bind: "127.0.0.1:8787".to_string(),
        web_root: "web".to_string(),
        state: EngineState::Normal,
        ..Args::default()
    };

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                if i + 1 >= args.len() {
                    exit_with("missing value for --config");
                }
                out.config_path = Some(args[i + 1].clone());
                i += 1;
            }
            "--dry-run" => {
                out.dry_run = true;
            }
            "--web" => {
                out.web = true;
            }
            "--bind" => {
                if i + 1 >= args.len() {
                    exit_with("missing value for --bind");
                }
                out.bind = args[i + 1].clone();
                i += 1;
            }
            "--web-root" => {
                if i + 1 >= args.len() {
                    exit_with("missing value for --web-root");
                }
                out.web_root = args[i + 1].clone();
                i += 1;
            }
            "--xray-gen" => {
                if i + 1 >= args.len() {
                    exit_with("missing value for --xray-gen");
                }
                out.xray_output = Some(args[i + 1].clone());
                i += 1;
            }
            "--xray-bin" => {
                if i + 1 >= args.len() {
                    exit_with("missing value for --xray-bin");
                }
                out.xray_bin = args[i + 1].clone();
                i += 1;
            }
            "--xray-config" => {
                if i + 1 >= args.len() {
                    exit_with("missing value for --xray-config");
                }
                out.xray_config = args[i + 1].clone();
                i += 1;
            }
            "--xray-log" => {
                if i + 1 >= args.len() {
                    exit_with("missing value for --xray-log");
                }
                out.xray_log = args[i + 1].clone();
                i += 1;
            }
            "--xray-autostart" => {
                out.xray_autostart = true;
            }
            "--hot-reload" => {
                out.hot_reload = true;
            }
            "--reload-interval" => {
                if i + 1 >= args.len() {
                    exit_with("missing value for --reload-interval");
                }
                out.reload_interval_secs = args[i + 1].parse::<u64>().unwrap_or(2);
                i += 1;
            }
            "--live" => {
                out.live = true;
            }
            "--inspect-protocol" => {
                if i + 1 >= args.len() {
                    exit_with("missing value for --inspect-protocol");
                }
                out.inspect_protocol = args[i + 1].clone();
                i += 1;
            }
            "--inspect-port" => {
                if i + 1 >= args.len() {
                    exit_with("missing value for --inspect-port");
                }
                out.inspect_port = args[i + 1].parse::<u16>().ok();
                i += 1;
            }
            "--inspect-interval" => {
                if i + 1 >= args.len() {
                    exit_with("missing value for --inspect-interval");
                }
                out.inspect_interval_secs = args[i + 1].parse::<u64>().unwrap_or(3);
                i += 1;
            }
            "--backend" => {
                if i + 1 >= args.len() {
                    exit_with("missing value for --backend");
                }
                out.backend = parse_backend(&args[i + 1]).unwrap_or_else(|msg| exit_with(&msg));
                i += 1;
            }
            "--apply-actions" => {
                out.apply_actions = true;
            }
            "--log-file" => {
                if i + 1 >= args.len() {
                    exit_with("missing value for --log-file");
                }
                out.log_file = Some(args[i + 1].clone());
                i += 1;
            }
            "--state" => {
                if i + 1 >= args.len() {
                    exit_with("missing value for --state");
                }
                out.state = parse_state(&args[i + 1]).unwrap_or_else(|msg| exit_with(&msg));
                i += 1;
            }
            "--sni" => {
                if i + 1 >= args.len() {
                    exit_with("missing value for --sni");
                }
                out.ctx.sni = Some(args[i + 1].clone());
                i += 1;
            }
            "--protocol" => {
                if i + 1 >= args.len() {
                    exit_with("missing value for --protocol");
                }
                out.ctx.protocol = Some(args[i + 1].clone());
                i += 1;
            }
            "--port" => {
                if i + 1 >= args.len() {
                    exit_with("missing value for --port");
                }
                out.ctx.port = args[i + 1].parse::<u16>().ok();
                i += 1;
            }
            "--latency-ms" => {
                if i + 1 >= args.len() {
                    exit_with("missing value for --latency-ms");
                }
                out.ctx.latency_ms = args[i + 1].parse::<u32>().ok();
                i += 1;
            }
            "--rtt-ms" => {
                if i + 1 >= args.len() {
                    exit_with("missing value for --rtt-ms");
                }
                out.ctx.rtt_ms = args[i + 1].parse::<u32>().ok();
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }

    out
}

fn run_live(args: &Args, path: &str) {
    let mut ruleset = match load_ruleset(path) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("invalid ruleset: {}", err);
            std::process::exit(1);
        }
    };
    let mut last_modified = file_mtime(path);

    let inspector = if let Some(port) = args.inspect_port {
        SystemInspector::new(&args.inspect_protocol).with_port(port)
    } else {
        SystemInspector::new(&args.inspect_protocol)
    };

    loop {
        if args.hot_reload {
            let current = file_mtime(path);
            let changed = match (last_modified, current) {
                (Some(prev), Some(now)) => now > prev,
                (None, Some(_)) => true,
                _ => false,
            };
            if changed {
                match load_ruleset(path) {
                    Ok(updated) => {
                        ruleset = updated;
                        last_modified = current;
                        println!("ruleset reloaded: {}", path);
                    }
                    Err(err) => eprintln!("ruleset reload failed: {}", err),
                }
            }
        }

        let meta = inspector.inspect();
        let ctx = to_match_context(&meta);
        match evaluate_ruleset(&ruleset, &ctx, args.state) {
            Ok(decision) => {
                if let Some(rule) = decision.rule {
                    let action = plan_action(&rule.action);
                    let plan = render_backend(args.backend, &ctx, &action);
                    println!(
                        "live decision: rule={} action={} backend={:?}",
                        rule.name,
                        action.summary(),
                        args.backend
                    );
                    if args.apply_actions {
                        if let Err(err) = execute_plan(&plan) {
                            eprintln!("apply failed: {}", err);
                        }
                    } else {
                        for cmd in &plan.commands {
                            println!("plan: {}", cmd);
                        }
                    }
                } else {
                    println!("live decision: no match");
                }
            }
            Err(err) => {
                eprintln!("engine error: {:?}", err);
            }
        }

        std::thread::sleep(Duration::from_secs(args.inspect_interval_secs.max(1)));
    }
}

fn load_ruleset(path: &str) -> Result<netpolicy::rules::RuleSet, String> {
    let content = fs::read_to_string(path).map_err(|e| e.to_string())?;
    parse_ruleset(&content).map_err(|e| format!("{:?}", e))
}

fn file_mtime(path: &str) -> Option<SystemTime> {
    fs::metadata(path).ok().and_then(|m| m.modified().ok())
}

fn execute_plan(plan: &netpolicy::action_backend::BackendPlan) -> Result<(), String> {
    for cmd in &plan.commands {
        let status = Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .status()
            .map_err(|e| format!("{} ({})", cmd, e))?;
        if !status.success() {
            return Err(format!("command failed: {}", cmd));
        }
    }
    Ok(())
}

fn parse_backend(value: &str) -> Result<BackendKind, String> {
    match value.to_lowercase().as_str() {
        "iptables" => Ok(BackendKind::Iptables),
        "nftables" => Ok(BackendKind::Nftables),
        _ => Err(format!("invalid backend: {}", value)),
    }
}

fn start_web_server(args: &Args) {
    let manager = Arc::new(Mutex::new(XrayManager::new(
        args.xray_bin.clone(),
        args.xray_config.clone(),
        args.xray_log.clone(),
    )));
    let telemetry = Arc::new(Telemetry::new());
    if args.xray_autostart {
        if let Ok(mut mgr) = manager.lock() {
            if mgr.start().is_ok() {
                telemetry.record_xray_start();
            }
        }
    }

    let server = match Server::http(&args.bind) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("failed to bind {}: {}", args.bind, err);
            std::process::exit(1);
        }
    };

    println!("netpolicyd web listening on http://{}", args.bind);

    for mut request in server.incoming_requests() {
        let method = request.method().clone();
        let url = request.url().to_string();

        if method == Method::Post && url == "/api/xray/start" {
            let response = handle_xray_start(&manager, &telemetry);
            let body = serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string());
            let resp = Response::from_string(body)
                .with_header(json_header())
                .with_status_code(StatusCode(200));
            let _ = request.respond(resp);
            continue;
        }

        if method == Method::Post && url == "/api/xray/stop" {
            let response = handle_xray_stop(&manager, &telemetry);
            let body = serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string());
            let resp = Response::from_string(body)
                .with_header(json_header())
                .with_status_code(StatusCode(200));
            let _ = request.respond(resp);
            continue;
        }

        if method == Method::Post && url == "/api/xray/restart" {
            let response = handle_xray_restart(&manager, &telemetry);
            let body = serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string());
            let resp = Response::from_string(body)
                .with_header(json_header())
                .with_status_code(StatusCode(200));
            let _ = request.respond(resp);
            continue;
        }

        if method == Method::Get && url == "/api/xray/status" {
            let response = handle_xray_status(&manager);
            let body = serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string());
            let resp = Response::from_string(body)
                .with_header(json_header())
                .with_status_code(StatusCode(200));
            let _ = request.respond(resp);
            continue;
        }

        if method == Method::Get && url == "/api/xray/logs" {
            let response = handle_xray_logs(&manager);
            let body = serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string());
            let resp = Response::from_string(body)
                .with_header(json_header())
                .with_status_code(StatusCode(200));
            let _ = request.respond(resp);
            continue;
        }

        if method == Method::Get && url == "/api/logs" {
            let response = handle_logs(args.log_file.as_deref());
            let body = serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string());
            let resp = Response::from_string(body)
                .with_header(json_header())
                .with_status_code(StatusCode(200));
            let _ = request.respond(resp);
            continue;
        }

        if method == Method::Post && url == "/api/dry-run" {
            let response = handle_dry_run(&mut request, args.log_file.as_deref(), &telemetry);
            let body = serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string());
            let resp = Response::from_string(body)
                .with_header(json_header())
                .with_status_code(StatusCode(200));
            let _ = request.respond(resp);
            continue;
        }

        if method == Method::Post && url == "/api/xray-gen" {
            let response = handle_xray_gen(
                &mut request,
                args.xray_output.as_deref(),
                Some(args.xray_config.as_str()),
            );
            let body = serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string());
            let resp = Response::from_string(body)
                .with_header(json_header())
                .with_status_code(StatusCode(200));
            let _ = request.respond(resp);
            continue;
        }

        if method == Method::Get && url == "/api/telemetry" {
            let response = telemetry.snapshot();
            let body = serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string());
            let resp = Response::from_string(body)
                .with_header(json_header())
                .with_status_code(StatusCode(200));
            let _ = request.respond(resp);
            continue;
        }

        if method == Method::Get {
            let resp = serve_static(&url, &args.web_root);
            let _ = request.respond(resp);
            continue;
        }

        let resp = Response::from_string("not found")
            .with_status_code(StatusCode(404))
            .with_header(text_header());
        let _ = request.respond(resp);
    }
}

#[derive(Debug, Deserialize)]
struct DryRunRequest {
    ruleset: String,
    state: Option<String>,
    context: Option<ContextRequest>,
}

#[derive(Debug, Deserialize)]
struct ContextRequest {
    sni: Option<String>,
    protocol: Option<String>,
    port: Option<u16>,
    latency_ms: Option<u32>,
    rtt_ms: Option<u32>,
}

#[derive(Debug, Serialize)]
struct DryRunResponse {
    ok: bool,
    state: String,
    rule: Option<String>,
    action: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct LogsResponse {
    ok: bool,
    content: String,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct XrayGenRequest {
    urls: Option<Vec<String>>,
    urls_text: Option<String>,
}

#[derive(Debug, Serialize)]
struct XrayGenResponse {
    ok: bool,
    config: Option<String>,
    error: Option<String>,
    saved_to: Option<String>,
}

#[derive(Debug, Serialize)]
struct XrayStatusResponse {
    ok: bool,
    running: bool,
    pid: Option<u32>,
    error: Option<String>,
}

fn handle_dry_run(
    request: &mut tiny_http::Request,
    log_file: Option<&str>,
    telemetry: &Telemetry,
) -> DryRunResponse {
    let mut body = String::new();
    if request.as_reader().read_to_string(&mut body).is_err() {
        telemetry.record_error("failed to read request".to_string());
        return DryRunResponse {
            ok: false,
            state: "NORMAL".to_string(),
            rule: None,
            action: None,
            error: Some("failed to read request".to_string()),
        };
    }

    let payload: DryRunRequest = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(err) => {
            telemetry.record_error(format!("invalid json: {}", err));
            return DryRunResponse {
                ok: false,
                state: "NORMAL".to_string(),
                rule: None,
                action: None,
                error: Some(format!("invalid json: {}", err)),
            }
        }
    };

    let state = payload
        .state
        .as_deref()
        .and_then(|s| parse_state(s).ok())
        .unwrap_or(EngineState::Normal);

    let ctx = match payload.context {
        Some(c) => MatchContext {
            sni: c.sni,
            protocol: c.protocol,
            port: c.port,
            latency_ms: c.latency_ms,
            rtt_ms: c.rtt_ms,
        },
        None => MatchContext::default(),
    };

    let ruleset = match parse_ruleset(&payload.ruleset) {
        Ok(r) => r,
        Err(err) => {
            telemetry.record_error(format!("invalid ruleset: {:?}", err));
            return DryRunResponse {
                ok: false,
                state: state_to_str(state).to_string(),
                rule: None,
                action: None,
                error: Some(format!("invalid ruleset: {:?}", err)),
            }
        }
    };

    match evaluate_ruleset(&ruleset, &ctx, state) {
        Ok(decision) => {
            if let Some(rule) = decision.rule {
                let action = action_summary(rule);
                if let Some(path) = log_file {
                    let _ = append_log(path, state, rule.name.as_str(), action.as_str());
                }
                telemetry.record_decision(true);
                DryRunResponse {
                    ok: true,
                    state: state_to_str(state).to_string(),
                    rule: Some(rule.name.clone()),
                    action: Some(action),
                    error: None,
                }
            } else {
                telemetry.record_decision(false);
                DryRunResponse {
                    ok: true,
                    state: state_to_str(state).to_string(),
                    rule: None,
                    action: None,
                    error: None,
                }
            }
        }
        Err(err) => {
            telemetry.record_error(format!("engine error: {:?}", err));
            DryRunResponse {
                ok: false,
                state: state_to_str(state).to_string(),
                rule: None,
                action: None,
                error: Some(format!("engine error: {:?}", err)),
            }
        }
    }
}

fn handle_xray_gen(
    request: &mut tiny_http::Request,
    output: Option<&str>,
    default_output: Option<&str>,
) -> XrayGenResponse {
    let mut body = String::new();
    if request.as_reader().read_to_string(&mut body).is_err() {
        return XrayGenResponse {
            ok: false,
            config: None,
            error: Some("failed to read request".to_string()),
            saved_to: None,
        };
    }

    let payload: XrayGenRequest = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(err) => {
            return XrayGenResponse {
                ok: false,
                config: None,
                error: Some(format!("invalid json: {}", err)),
                saved_to: None,
            }
        }
    };

    let mut urls = payload.urls.unwrap_or_default();
    if let Some(text) = payload.urls_text {
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            urls.push(trimmed.to_string());
        }
    }

    if urls.is_empty() {
        return XrayGenResponse {
            ok: false,
            config: None,
            error: Some("no urls provided".to_string()),
            saved_to: None,
        };
    }

    let nodes = match parse_proxy_urls(&urls) {
        Ok(n) => n,
        Err(err) => {
            return XrayGenResponse {
                ok: false,
                config: None,
                error: Some(format!("parse error: {:?}", err)),
                saved_to: None,
            }
        }
    };

    let config = build_xray_config(&nodes);
    let json = serde_json::to_string_pretty(&config).unwrap_or_else(|_| "{}".to_string());
    let target = output.or(default_output);
    let saved_to = if let Some(path) = target {
        if fs::write(path, &json).is_ok() {
            Some(path.to_string())
        } else {
            None
        }
    } else {
        None
    };
    XrayGenResponse {
        ok: true,
        config: Some(json),
        error: None,
        saved_to,
    }
}

fn handle_logs(log_file: Option<&str>) -> LogsResponse {
    let path = match log_file {
        Some(p) => p,
        None => {
            return LogsResponse {
                ok: false,
                content: "".to_string(),
                error: Some("log file not configured".to_string()),
            }
        }
    };

    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(err) => {
            return LogsResponse {
                ok: false,
                content: "".to_string(),
                error: Some(format!("failed to read log file: {}", err)),
            }
        }
    };

    let lines: Vec<&str> = content.lines().collect();
    let start = lines.len().saturating_sub(200);
    let sliced = lines[start..].join("\n");

    LogsResponse {
        ok: true,
        content: sliced,
        error: None,
    }
}

fn watch_ruleset(path: &str, interval_secs: u64) {
    let mut last_modified: Option<SystemTime> = None;
    loop {
        if let Ok(meta) = fs::metadata(path) {
            if let Ok(modified) = meta.modified() {
                let changed = match last_modified {
                    Some(prev) => modified > prev,
                    None => true,
                };
                if changed {
                    match reload_ruleset(path) {
                        Ok(_) => println!("ruleset reloaded: {}", path),
                        Err(err) => eprintln!("ruleset reload failed: {}", err),
                    }
                    last_modified = Some(modified);
                }
            }
        }
        std::thread::sleep(Duration::from_secs(interval_secs.max(1)));
    }
}

fn reload_ruleset(path: &str) -> Result<(), String> {
    let content = fs::read_to_string(path).map_err(|e| e.to_string())?;
    parse_ruleset(&content).map_err(|e| format!("{:?}", e))?;
    Ok(())
}

fn handle_xray_start(
    manager: &Arc<Mutex<XrayManager>>,
    telemetry: &Telemetry,
) -> XrayStatusResponse {
    match manager.lock() {
        Ok(mut mgr) => match mgr.start() {
            Ok(_) => {
                telemetry.record_xray_start();
                mgr.status()
            }
            Err(err) => {
                telemetry.record_error(err.clone());
                XrayStatusResponse {
                    ok: false,
                    running: false,
                    pid: None,
                    error: Some(err),
                }
            }
        },
        Err(_) => {
            telemetry.record_error("xray manager lock failed".to_string());
            XrayStatusResponse {
                ok: false,
                running: false,
                pid: None,
                error: Some("xray manager lock failed".to_string()),
            }
        }
    }
}

fn handle_xray_stop(
    manager: &Arc<Mutex<XrayManager>>,
    telemetry: &Telemetry,
) -> XrayStatusResponse {
    match manager.lock() {
        Ok(mut mgr) => match mgr.stop() {
            Ok(_) => {
                telemetry.record_xray_stop();
                mgr.status()
            }
            Err(err) => {
                telemetry.record_error(err.clone());
                XrayStatusResponse {
                    ok: false,
                    running: false,
                    pid: None,
                    error: Some(err),
                }
            }
        },
        Err(_) => {
            telemetry.record_error("xray manager lock failed".to_string());
            XrayStatusResponse {
                ok: false,
                running: false,
                pid: None,
                error: Some("xray manager lock failed".to_string()),
            }
        }
    }
}

fn handle_xray_restart(
    manager: &Arc<Mutex<XrayManager>>,
    telemetry: &Telemetry,
) -> XrayStatusResponse {
    match manager.lock() {
        Ok(mut mgr) => match mgr.restart() {
            Ok(_) => {
                telemetry.record_xray_restart();
                mgr.status()
            }
            Err(err) => {
                telemetry.record_error(err.clone());
                XrayStatusResponse {
                    ok: false,
                    running: false,
                    pid: None,
                    error: Some(err),
                }
            }
        },
        Err(_) => {
            telemetry.record_error("xray manager lock failed".to_string());
            XrayStatusResponse {
                ok: false,
                running: false,
                pid: None,
                error: Some("xray manager lock failed".to_string()),
            }
        }
    }
}

fn handle_xray_status(manager: &Arc<Mutex<XrayManager>>) -> XrayStatusResponse {
    match manager.lock() {
        Ok(mut mgr) => mgr.status(),
        Err(_) => XrayStatusResponse {
            ok: false,
            running: false,
            pid: None,
            error: Some("xray manager lock failed".to_string()),
        },
    }
}

fn handle_xray_logs(manager: &Arc<Mutex<XrayManager>>) -> LogsResponse {
    let path = match manager.lock() {
        Ok(mgr) => mgr.log_path.clone(),
        Err(_) => {
            return LogsResponse {
                ok: false,
                content: "".to_string(),
                error: Some("xray manager lock failed".to_string()),
            }
        }
    };
    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(err) => {
            return LogsResponse {
                ok: false,
                content: "".to_string(),
                error: Some(format!("failed to read xray log: {}", err)),
            }
        }
    };
    let lines: Vec<&str> = content.lines().collect();
    let start = lines.len().saturating_sub(200);
    let sliced = lines[start..].join("\n");
    LogsResponse {
        ok: true,
        content: sliced,
        error: None,
    }
}

struct XrayManager {
    bin_path: String,
    config_path: String,
    log_path: String,
    process: Option<Child>,
}

impl XrayManager {
    fn new(bin_path: String, config_path: String, log_path: String) -> Self {
        Self {
            bin_path,
            config_path,
            log_path,
            process: None,
        }
    }

    fn start(&mut self) -> Result<(), String> {
        self.refresh_status();
        if self.process.is_some() {
            return Ok(());
        }

        let log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .map_err(|e| format!("failed to open xray log: {}", e))?;

        let child = Command::new(&self.bin_path)
            .args(["-config", &self.config_path])
            .stdout(Stdio::from(log.try_clone().map_err(|e| e.to_string())?))
            .stderr(Stdio::from(log))
            .spawn()
            .map_err(|e| format!("failed to start xray: {}", e))?;

        self.process = Some(child);
        Ok(())
    }

    fn stop(&mut self) -> Result<(), String> {
        self.refresh_status();
        if let Some(mut child) = self.process.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        Ok(())
    }

    fn restart(&mut self) -> Result<(), String> {
        self.stop()?;
        self.start()
    }

    fn status(&mut self) -> XrayStatusResponse {
        self.refresh_status();
        let (running, pid) = match self.process {
            Some(ref child) => (true, Some(child.id())),
            None => (false, None),
        };
        XrayStatusResponse {
            ok: true,
            running,
            pid,
            error: None,
        }
    }

    fn refresh_status(&mut self) {
        if let Some(child) = &mut self.process {
            if let Ok(Some(_)) = child.try_wait() {
                self.process = None;
            }
        }
    }

}

fn serve_static(url: &str, root: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut path = url.trim_start_matches('/').to_string();
    if path.is_empty() {
        path = "index.html".to_string();
    }

    if path.contains("..") {
        return Response::from_string("not found").with_status_code(StatusCode(404));
    }

    let full_path = Path::new(root).join(&path);
    let data = match fs::read(&full_path) {
        Ok(b) => b,
        Err(_) => {
            return Response::from_string("not found").with_status_code(StatusCode(404));
        }
    };

    let mime = content_type_for_path(&path);
    Response::from_data(data)
        .with_status_code(StatusCode(200))
        .with_header(Header::from_bytes(&b"Content-Type"[..], mime.as_bytes()).unwrap())
}

fn content_type_for_path(path: &str) -> &str {
    if path.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if path.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if path.ends_with(".js") {
        "application/javascript; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}

fn parse_state(value: &str) -> Result<EngineState, String> {
    match value.trim().to_lowercase().as_str() {
        "normal" => Ok(EngineState::Normal),
        "degraded" => Ok(EngineState::Degraded),
        "failover" => Ok(EngineState::Failover),
        "recovery" => Ok(EngineState::Recovery),
        _ => Err("invalid --state value (normal|degraded|failover|recovery)".to_string()),
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

fn action_summary(rule: &netpolicy::rules::Rule) -> String {
    let action = &rule.action;
    if let Some(ref route) = action.route {
        return format!("route {}", route);
    }
    if let Some(ref route) = action.switch_route {
        return format!("switch_route {}", route);
    }
    if action.block == Some(true) {
        return "block".to_string();
    }
    if let Some(ref throttle) = action.throttle {
        return format!("throttle {}", throttle);
    }
    "log".to_string()
}

fn append_log(path: &str, state: EngineState, rule: &str, action: &str) -> std::io::Result<()> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let line = format!("{} state={} rule={} action={}\n", ts, state_to_str(state), rule, action);
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?
        .write_all(line.as_bytes())
}

fn json_header() -> Header {
    Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap()
}

fn text_header() -> Header {
    Header::from_bytes(&b"Content-Type"[..], &b"text/plain"[..]).unwrap()
}

fn exit_with(msg: &str) -> ! {
    eprintln!("{}", msg);
    std::process::exit(1);
}
