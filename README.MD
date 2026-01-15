# NetPolicy Engine

Programmable network policy engine in Rust. Focused on decision logic first,
with a clear path to traffic inspection and OS integration later.

Repo: https://github.com/ZeroByte000/NetPolicy.git

## Alur Sistem

```
Packet / Connection
   ↓
Inspector (SNI, IP, Port, Proto, RTT)
   ↓
Policy Engine (rules + state)
   ↓
Action
   ├─ route A
   ├─ route B
   ├─ block
   ├─ throttle
   └─ log / notify
```

Dokumentasi schema rule: `docs/rules-schema.md`.

## Fungsi Utama

NetPolicy Engine bisa dipakai untuk:

- Menentukan rute koneksi secara deklaratif (tanpa hardcode).
- Memprioritaskan traffic tertentu (misal VoIP/video conference).
- Melakukan failover otomatis saat latency tinggi atau error rate naik.
- Memblokir traffic berdasarkan pola (SNI, port, protocol).
- Melakukan throttle atau limit pada jenis koneksi tertentu.
- Mencatat keputusan policy (log/telemetry) untuk audit dan analisis.

## Contoh Use Case Singkat

1. Prioritaskan Zoom/Meet ke rute tercepat.
2. Jika latency di atas 120ms, pindah ke backup route.
3. Blokir port tertentu yang dianggap berisiko.

## Roadmap Ringkas

Fase-fase utama diambil dari `ROADMAP.MD`.

1. Scope and Foundations: schema rule v1, struktur repo, tipe data inti, unit test.
2. Core Engine v1: evaluasi deterministik, state machine, action executor, config load.
3. Inspector v1: user-space inspector, metadata koneksi, integrasi engine.
4. Real World Policies: runtime context, failover, contoh skenario, dokumentasi.
5. Hardening: benchmark, linting, diagnostics, telemetry.

## Status

Roadmap sudah tersedia di `ROADMAP.MD`.

## Download

Opsi 1 (source):
```bash
git clone https://github.com/ZeroByte000/NetPolicy.git
cd NetPolicy
```

Opsi 2 (binary):
- Download dari halaman Releases: https://github.com/ZeroByte000/NetPolicy/releases
- Nama file release per platform:
  - Linux x86_64: `netpolicyd-linux-x86_64.tar.gz`
  - Linux ARM64: `netpolicyd-linux-aarch64.tar.gz`
  - macOS Intel: `netpolicyd-macos-x86_64.tar.gz`
  - macOS Apple Silicon: `netpolicyd-macos-arm64.tar.gz`
  - Windows x86_64: `netpolicyd-windows-x86_64.zip`
  - Windows ARM64: `netpolicyd-windows-arm64.zip`

OpenWrt (HG680/HG680P):
- Download `.ipk` dari release (22.03, 23.05, snapshot) dan install via `opkg`.
- Instal:
  ```bash
  opkg update
  opkg install ./netpolicyd_*.ipk
  opkg install ./luci-app-netpolicyd_*.ipk
  ```
- Simpan ruleset ke `/etc/netpolicyd/rules.yaml`.
- Contoh ruleset singkat:
  ```yaml
  rules:
    - name: default_route
      priority: 10
      match:
        any: true
      action:
        route: direct
        log: true
  ```
- Jalankan service:
  ```bash
  service netpolicyd enable
  service netpolicyd start
  ```

Android:
- Download binary `netpolicyd-android-arm64` (arm64-v8a) atau `netpolicyd-android-armv7` (armeabi-v7a) dari release.
- APK: download `netpolicyd-android.apk`, install di device, lalu buka aplikasi.
- Termux contoh:
  ```bash
  chmod +x netpolicyd-android-arm64
  ./netpolicyd-android-arm64 --web --bind 127.0.0.1:8787 --web-root web --log-file /data/data/com.termux/files/usr/tmp/netpolicyd.log
  ```
- APK menyediakan tombol VPN gateway (best effort) dan kontrol Xray via UI.

Build APK lokal (Android Studio/SDK):
```bash
cd android
./gradlew assembleRelease
```
APK ada di `android/app/build/outputs/apk/release/app-release.apk`.

## Penggunaan

Build lokal:
```bash
cargo build --release
```

Jalankan dry-run dengan ruleset contoh:
```bash
cargo run --bin netpolicyd -- --config examples/ruleset.v1.yaml --dry-run --state failover --protocol tcp --port 443 --latency-ms 150
```

Jalankan UI web lokal:
```bash
cargo run --bin netpolicyd -- --web --bind 127.0.0.1:8787 --web-root web --log-file /tmp/netpolicyd.log --xray-gen /tmp/xray_config.json
```

Lihat dokumentasi UI: `docs/ui-web.md`

Xray manager:
- Flag opsional: `--xray-bin`, `--xray-config`, `--xray-log`, `--xray-autostart`
- Import akun Xray bisa multi-line (1 akun per baris) via halaman Xray.
- Panel VPN gateway hanya muncul di Android (WebView).

## OpenWrt (HG680 / HG680P)

Dukungan awal untuk OpenWrt tersedia di folder `openwrt/`.
Detail build dan instalasi ada di `docs/openwrt.md`.

## Usage (netpolicyd)

```bash
cargo run --bin netpolicyd -- --config examples/ruleset.v1.yaml --dry-run --sni "api.zoom.us" --protocol tcp --port 443 --latency-ms 80
```

Mode live + backend (jalankan dari repo):
```bash
cargo run --bin netpolicyd -- --config rules.yaml --live --inspect-protocol tcp --inspect-interval 3 --backend nftables --apply-actions
```
Catatan: `--apply-actions` butuh privilege/root agar bisa menjalankan iptables/nftables.

Jika ingin binary tetap:
```bash
cargo build --release
./target/release/netpolicyd --config rules.yaml --live --inspect-protocol tcp --inspect-interval 3 --backend nftables --apply-actions
```

## Usage (netpolicy lint)

```bash
cargo run --bin netpolicy -- lint examples/ruleset.v1.yaml
```

## Usage (xray-gen)

```bash
cargo run --bin netpolicy -- xray-gen --output config.json --url "vmess://..." --url "vless://..."
```

Contoh dari file:
```bash
cargo run --bin netpolicy -- xray-gen --output config.json --url-file examples/urls.txt
```

## Integrasi V2Ray/Xray

Panduan integrasi awal tersedia di `docs/v2ray-xray.md`.

Flag opsional untuk konteks match:
`--sni`, `--protocol`, `--port`, `--latency-ms`, `--rtt-ms`.
