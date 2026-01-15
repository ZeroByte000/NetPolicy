# Rules Schema v1

This document defines the initial YAML schema for NetPolicy rules.
It is designed to be simple, deterministic, and easy to validate.

## Top-Level

```yaml
rules:
  - name: <string>
    priority: <number>
    match: <match-object>
    action: <action-object>
```

- `rules` (required): list of rule objects.

## Rule Object

```yaml
- name: zoom_priority
  priority: 100
  match:
    sni: "*.zoom.us"
    protocol: tcp
  action:
    route: tunnel_fast
```

Fields:
- `name` (required, string): unique rule name.
- `priority` (required, number): higher value wins when multiple rules match.
- `match` (required, object): match conditions.
- `when` (optional, object): state constraints.
- `disable` (optional, string or list): disable rule on specific states.
- `action` (required, object): action to execute.

## Match Object

Supported keys:

- `any` (bool): if true, rule always matches.
- `sni` (string): wildcard pattern, e.g. `"*.zoom.us"`.
- `protocol` (string): `tcp` or `udp`.
- `port` (string): single port or list string, e.g. `"443"` or `"80,443"`.
- `latency_ms` (string): numeric comparator, e.g. `">120"`, `"<=50"`.
- `rtt_ms` (string): alias for latency comparisons.

Notes:
- If `any: true` is present, other match fields are ignored.
- Comparators supported: `>`, `>=`, `<`, `<=`, `==`.
- Port format supports single, list, and ranges: `"443"`, `"80,443"`, `"1000-2000"`, `"22,80,1000-2000"`.

## Action Object

Supported keys:

- `route` (string): select a route profile, e.g. `tunnel_fast`.
- `switch_route` (string): switch to another route, e.g. `backup`.
- `block` (bool): block the connection if true.
- `throttle` (string): throttle profile name, e.g. `slow`
- `log` (bool): emit decision log if true.

Notes:
- Only one primary action is expected (`route`, `switch_route`, `block`, `throttle`).
- `log` can be combined with any action.

## When Object

```yaml
when:
  state: FAILOVER
```

Supported keys:
- `state` (string or list): `NORMAL`, `DEGRADED`, `FAILOVER`, `RECOVERY`.

## Disable Field

```yaml
disable: [DEGRADED, FAILOVER]
```

- Accepts a string or list of strings.
- If current engine state is in `disable`, the rule is skipped.

## Deterministic Evaluation

1. Collect all matching rules.
2. Sort by `priority` descending.
3. If tie, prefer more specific match (more fields).
4. Apply the first rule after sorting.

## Example Ruleset

```yaml
rules:
  - name: zoom_priority
    priority: 100
    match:
      sni: "*.zoom.us"
      protocol: tcp
    action:
      route: tunnel_fast

  - name: fallback_if_high_latency
    priority: 80
    match:
      latency_ms: ">120"
    action:
      switch_route: backup

  - name: default_log
    priority: 10
    match:
      any: true
    action:
      log: true
```

## Examples by State

```yaml
rules:
  - name: normal_fast_route
    priority: 100
    when:
      state: NORMAL
    match:
      protocol: tcp
    action:
      route: tunnel_fast

  - name: degraded_failover
    priority: 90
    when:
      state: [DEGRADED, FAILOVER]
    match:
      latency_ms: ">120"
    action:
      switch_route: backup

  - name: disable_in_failover
    priority: 80
    disable: FAILOVER
    match:
      port: "6667"
    action:
      block: true
```
