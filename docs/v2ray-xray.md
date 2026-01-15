# Integrasi V2Ray / Xray (Konsep Awal)

NetPolicy saat ini fokus di decision engine. Untuk penggunaan dengan V2Ray/Xray,
pendekatan awal adalah menyamakan nama route di ruleset dengan outbound tag di
konfigurasi V2Ray/Xray, lalu menjalankan action routing via skrip eksternal.

## Generator Xray dari URL

NetPolicy menyediakan generator sederhana dari URL `vmess://`, `vless://`,
`trojan://`, `ss://` (SIP003 plugin didukung), `socks://`, dan `http://`
agar output `config.json` bisa dipakai di Xray.

Contoh query untuk transport/security:

- gRPC: `?type=grpc&serviceName=svc&security=tls&sni=example.com`
- h2: `?type=h2&path=/h2&host=example.com&security=tls&sni=example.com`
- Reality: `?security=reality&sni=example.com&pbk=PUBLICKEY&sid=SHORTID&fp=chrome`

```bash
cargo run --bin netpolicy -- xray-gen --output config.json --url "vmess://..." --url "vless://..."
```

Atau dari file:

```bash
cargo run --bin netpolicy -- xray-gen --output config.json --url-file urls.txt
```

Catatan:
- Generator membuat `inbounds` sesuai port OpenClash (7890/7891/7892/7893/7895).
- `best_ping`, `load_balance`, dan `fallback` dibuat sebagai `balancers` Xray.
- DNS diisi dari daftar OpenClash (DoH + plain + dhcp) dalam bentuk yang kompatibel.
- `type=grpc` / `type=h2` / `security=reality` didukung untuk vless/trojan.
- SIP003 plugin (ss://?plugin=...) didukung untuk Shadowsocks.

## Contoh Ruleset

```yaml
rules:
  - name: vpn_fast
    priority: 100
    match:
      sni: "*.googlevideo.com"
      protocol: tcp
    action:
      route: v2ray_fast

  - name: vpn_backup
    priority: 80
    match:
      latency_ms: ">120"
    action:
      switch_route: v2ray_backup

  - name: default
    priority: 10
    match:
      any: true
    action:
      route: direct
      log: true
```

## Contoh Mapping ke Xray

Di Xray/V2Ray, buat outbound tag dengan nama yang sama:

- `v2ray_fast`
- `v2ray_backup`
- `direct`

NetPolicy akan mengeluarkan keputusan `route`/`switch_route` yang bisa dipetakan
ke tag outbound tersebut.

## Eksekusi Action (placeholder)

Saat ini action executor masih sederhana (planning). Untuk integrasi nyata,
opsi yang bisa digunakan:

- Script yang membaca log keputusan dan mengubah rule iptables/nftables.
- Update config Xray melalui API management (jika tersedia).
- Gunakan policy engine sebagai input untuk routing policy di OS (future work).

## Catatan

Integrasi runtime penuh belum diimplementasi di repo ini. Dokumen ini menjadi
panduan awal desain agar naming route konsisten dengan outbound V2Ray/Xray.

## Contoh Mapping Route

Gunakan `route` / `switch_route` di ruleset agar sesuai tag outbound/balancer:

- `direct`
- `reject`
- `best_ping`
- `load_balance`
- `fallback`
