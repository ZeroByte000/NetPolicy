# Local Web UI

UI web lokal tersedia untuk simulasi policy tanpa LuCI.

## Jalankan UI

```bash
cargo run --bin netpolicyd -- --web --bind 127.0.0.1:8787 --web-root web --log-file /tmp/netpolicyd.log --xray-config /tmp/xray_config.json
```

Buka browser:
- `http://127.0.0.1:8787`

## Halaman

- `/ruleset.html` untuk dry-run ruleset.
- `/xray.html` untuk import akun + kontrol Xray.
- `/settings.html` untuk VPN gateway Android.

## Fitur

- Input ruleset YAML.
- Load ruleset dari file lokal.
- Context match (SNI, protocol, port, latency, RTT).
- State selector (NORMAL/DEGRADED/FAILOVER/RECOVERY).
- Dry-run decision.
- Tail log dari `--log-file`.
- Xray generator auto-save ke `--xray-config` (default `config.json`), bisa override dengan `--xray-gen`.
- Import akun Xray multi-line (1 akun per baris).
- Kontrol Xray: start/stop/restart/status + log Xray.
- MetaCube/YACD tersedia saat Xray running (set host + base path).
- Android: tombol VPN gateway hanya muncul di WebView Android (best effort).

## Contoh Alur (3 Langkah)

1. Buka `http://127.0.0.1:8787/xray.html` dan tempel akun (1 baris per akun), lalu klik **Import & Save**.
2. Klik **Start** di panel Xray Control, lalu cek status `running=true`.
3. Klik **Refresh** di panel Xray Logs untuk memastikan proses berjalan.

## Android (Termux)

1. Download binary arm64-v8a dari Releases.
2. Simpan binary di direktori kerja dan buat executable:
   ```bash
   chmod +x netpolicyd-android-arm64
   ```
3. Jalankan UI lokal:
   ```bash
   ./netpolicyd-android-arm64 --web --bind 127.0.0.1:8787 --web-root web --log-file /data/data/com.termux/files/usr/tmp/netpolicyd.log
   ```
4. Buka browser Android ke `http://127.0.0.1:8787`.
