# OpenWrt Support (HG680 / HG680P)

Target perangkat:
- HG680 / HG680P (Amlogic S905X, aarch64)
- Target OpenWrt: `armsr/armv8` (OpenWrt 24.10.x)

## Build Binary

Opsi 1: build via OpenWrt SDK (direkomendasikan)
1. Install OpenWrt SDK untuk target `armsr/armv8` (OpenWrt 24.10.x).
2. Masukkan package dari folder `openwrt/package/` ke tree OpenWrt kamu.
3. Salin binary `netpolicyd` hasil build ke `openwrt/package/netpolicyd/files/netpolicyd`.
4. Build paket:
   - `./scripts/feeds update -a`
   - `./scripts/feeds install -a`
   - `make package/netpolicyd/compile V=s`
   - `make package/luci-app-netpolicyd/compile V=s`

Opsi 2: cross-compile Rust
- Gunakan toolchain dari OpenWrt SDK (lebih stabil daripada `cross`).
- Set `CC`/`AR` ke toolchain SDK, lalu build target `aarch64-unknown-linux-musl`.

## Install & Run

Install paket:
- `opkg install netpolicyd_*.ipk`
- `opkg install luci-app-netpolicyd_*.ipk`

Konfigurasi UCI ada di:
- `/etc/config/netpolicyd`

Service:
- `service netpolicyd enable`
- `service netpolicyd start`

UI LuCI:
- Menu: Services -> NetPolicy
- UI LuCI akan memanggil web API lokal `http://127.0.0.1:8787`.
- Pastikan `netpolicyd` berjalan dengan `--web`.

## Catatan

- Web assets diletakkan di `/usr/share/netpolicyd`.
- Log default: `/var/log/netpolicyd.log`.
- Default Xray config: `/etc/xray/config.json`, log: `/var/log/xray.log`.
- Set `xray_autostart` ke `1` di `/etc/config/netpolicyd` untuk auto-start Xray.
- UI generator akan auto-save ke `/etc/xray/config.json` jika `--xray-gen` aktif.
