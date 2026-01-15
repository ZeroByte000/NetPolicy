use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn write_temp_ruleset(contents: &str) -> std::path::PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(format!("netpolicy_ruleset_{}_{}.yaml", ts, id));
    fs::write(&path, contents).expect("write temp ruleset");
    path
}

#[test]
fn lint_json_success() {
    let rules = r#"
rules:
  - name: default_route
    priority: 10
    match:
      any: true
    action:
      route: direct
      log: true
"#;
    let path = write_temp_ruleset(rules);

    let exe = env!("CARGO_BIN_EXE_netpolicy");
    let output = Command::new(exe)
        .args(["lint", path.to_str().unwrap(), "--json"])
        .output()
        .expect("run netpolicy lint");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"ok\":true"));
}

#[test]
fn lint_json_failure() {
    let rules = r#"
rules:
  - name: invalid_action
    priority: 10
    match:
      any: true
    action:
      log: true
"#;
    let path = write_temp_ruleset(rules);

    let exe = env!("CARGO_BIN_EXE_netpolicy");
    let output = Command::new(exe)
        .args(["lint", path.to_str().unwrap(), "--json"])
        .output()
        .expect("run netpolicy lint");

    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"ok\":false"));
}
