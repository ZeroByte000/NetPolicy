# NetPolicy Roadmap v2 (Rencana Lanjutan)

Tujuan: menaikkan NetPolicy dari "engine keputusan" ke sistem routing/traffic
yang lebih matang, aman, dan siap dipakai di perangkat nyata.

## Phase 5 - Live Inspector v2
- x eBPF real (program + loader) untuk SNI/IP/port/RTT.
- x Fallback user-space jika eBPF tidak tersedia.
- x Kolektor error rate sederhana (conn reset/timeouts).
- x Integrasi state otomatis dari telemetry (auto DEGRADED/FAILOVER).

Deliverables:
- x `ebpf/` program + loader.
- x `inspector` auto fallback dan mode live stabil.

## Phase 6 - Action Backend v2
- x Eksekusi iptables/nftables yang aman (idempotent + cleanup).
- x Rule tagging + table/chain khusus `netpolicy`.
- x Integrasi route marks ke routing table (ip rule/ip route).
- x Dry-run diff (preview perubahan).

Deliverables:
- x `action_backend` executor + rollback.
- x Dokumentasi pola routing.

## Phase 7 - Xray Orchestration
- x Sinkronisasi tag outbound dengan ruleset (direct/reject/best_ping/load_balance/fallback).
- x Template config untuk OpenWrt/Android/Linux.
- x Health check + restart policy.
- x UI untuk log, status, dan auto-restart.

Deliverables:
- x `xray` config sync + health check.
- x UI kontrol lengkap.

## Phase 8 - DSL & Tooling
- x DSL v1 dengan parser + formatter.
- x `netpolicy fmt` untuk standar format DSL.
- x CLI migrasi YAML -> DSL.
- x Syntax highlight sederhana (VSCode extension opsional).

Deliverables:
- x DSL yang stabil + tool lint/format.

## Phase 9 - Observability
- x JSON logs terstruktur (decision, action, error).
- x Metrics endpoint (Prometheus/JSON).
- x Export log ke file rotate.
- x Ring buffer in-memory untuk UI.

Deliverables:
- x `/api/metrics` + log pipeline.

## Phase 10 - Packaging & Distribution
- x CI build ipk OpenWrt multi-arch (22.03 - latest).
- x CI build Android APK + bundle xray.
- x Release notes otomatis + checksum.
- x Installer script untuk Linux (deb/rpm atau tarball).

Deliverables:
- x Release artifacts siap pakai.

## Definition of Done v2
- x Live inspector stabil di device nyata.
- x Action backend aman dan reversible.
- x Xray orchestration matang.
- x Observability dasar siap produksi.

## Lampiran - Peta Metode SSH Tunneling/Inject

Metode dasar (yang paling umum):
- Direct SSH.
- SSH + SNI (TLS handshake pakai SNI).
- SSH + Payload (custom HTTP header/payload).
- SSH + HTTP Proxy (CONNECT/forward via proxy).

Transport/Wrapper tambahan:
- SSH over WebSocket (CDN-friendly).
- SSH over HTTP/2.
- SSH over gRPC.

SSH di atas tunnel/VPN:
- SSH over OpenVPN/WireGuard/IPsec (layering).

Port forwarding (SSH native):
- Local (-L), Remote (-R), Dynamic/SOCKS (-D).

Eksperimental/edge:
- SSH over QUIC (rare).
- SSH over DNS tunnel (sangat lambat).

Obfuscation layer:
- stunnel, obfsproxy, cloak, udp2raw.

Relevansi ke NetPolicy:
- Abstraksikan sebagai route tag (contoh: `ssh_ws`, `ssh_grpc`, `ssh_direct`).
