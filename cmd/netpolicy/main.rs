use std::env;
use std::fs;

use serde::Serialize;

use netpolicy::dsl::parse_dsl;
use netpolicy::rules::parse_ruleset;
use netpolicy::xray::{build_xray_config, parse_proxy_urls};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_help();
        std::process::exit(1);
    }

    match args[1].as_str() {
        "lint" => handle_lint(&args),
        "dsl-lint" => handle_dsl_lint(&args),
        "xray-gen" => handle_xray_gen(&args),
        _ => {
            print_help();
            std::process::exit(1);
        }
    }
}

fn handle_lint(args: &[String]) {
    if args.len() < 3 {
        eprintln!("usage: netpolicy lint <ruleset.yaml> [--json]");
        std::process::exit(1);
    }
    let path = &args[2];
    let json = args.iter().any(|arg| arg == "--json");
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(err) => {
            if json {
                print_json(false, path, Some(format!("failed to read {}: {}", path, err)));
            } else {
                eprintln!("failed to read {}: {}", path, err);
            }
            std::process::exit(1);
        }
    };

    match parse_ruleset(&content) {
        Ok(_) => {
            if json {
                print_json(true, path, None);
            } else {
                println!("lint ok: {}", path);
            }
        }
        Err(err) => {
            if json {
                print_json(false, path, Some(format!("lint failed: {:?}", err)));
            } else {
                eprintln!("lint failed: {:?}", err);
            }
            std::process::exit(1);
        }
    }
}

fn handle_xray_gen(args: &[String]) {
    let mut output = "config.json".to_string();
    let mut urls: Vec<String> = Vec::new();
    let mut url_file: Option<String> = None;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--output" => {
                if i + 1 >= args.len() {
                    eprintln!("missing value for --output");
                    std::process::exit(1);
                }
                output = args[i + 1].clone();
                i += 1;
            }
            "--url" => {
                if i + 1 >= args.len() {
                    eprintln!("missing value for --url");
                    std::process::exit(1);
                }
                urls.push(args[i + 1].clone());
                i += 1;
            }
            "--url-file" => {
                if i + 1 >= args.len() {
                    eprintln!("missing value for --url-file");
                    std::process::exit(1);
                }
                url_file = Some(args[i + 1].clone());
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }

    if let Some(path) = url_file {
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(err) => {
                eprintln!("failed to read {}: {}", path, err);
                std::process::exit(1);
            }
        };
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            urls.push(trimmed.to_string());
        }
    }

    if urls.is_empty() {
        eprintln!("usage: netpolicy xray-gen --output config.json --url <vmess://...> [--url ...] [--url-file urls.txt]");
        std::process::exit(1);
    }

    let nodes = match parse_proxy_urls(&urls) {
        Ok(n) => n,
        Err(err) => {
            eprintln!("failed to parse proxy urls: {:?}", err);
            std::process::exit(1);
        }
    };

    let config = build_xray_config(&nodes);
    let json = serde_json::to_string_pretty(&config).unwrap_or_else(|_| "{}".to_string());
    if let Err(err) = fs::write(&output, json) {
        eprintln!("failed to write {}: {}", output, err);
        std::process::exit(1);
    }
    println!("xray config generated: {}", output);
}

fn print_help() {
    eprintln!("usage:");
    eprintln!("  netpolicy lint <ruleset.yaml> [--json]");
    eprintln!("  netpolicy dsl-lint <ruleset.dsl> [--json]");
    eprintln!("  netpolicy xray-gen --output config.json --url <vmess://...> [--url ...] [--url-file urls.txt]");
}

#[derive(Serialize)]
struct LintResponse {
    ok: bool,
    path: String,
    error: Option<String>,
}

fn print_json(ok: bool, path: &str, error: Option<String>) {
    let payload = LintResponse {
        ok,
        path: path.to_string(),
        error,
    };
    let json = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string());
    println!("{}", json);
}

fn handle_dsl_lint(args: &[String]) {
    if args.len() < 3 {
        eprintln!("usage: netpolicy dsl-lint <ruleset.dsl> [--json]");
        std::process::exit(1);
    }
    let path = &args[2];
    let json = args.iter().any(|arg| arg == "--json");
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(err) => {
            if json {
                print_json(false, path, Some(format!("failed to read {}: {}", path, err)));
            } else {
                eprintln!("failed to read {}: {}", path, err);
            }
            std::process::exit(1);
        }
    };

    match parse_dsl(&content) {
        Ok(_) => {
            if json {
                print_json(true, path, None);
            } else {
                println!("dsl lint ok: {}", path);
            }
        }
        Err(err) => {
            if json {
                print_json(false, path, Some(format!("dsl lint failed: {:?}", err)));
            } else {
                eprintln!("dsl lint failed: {:?}", err);
            }
            std::process::exit(1);
        }
    }
}
