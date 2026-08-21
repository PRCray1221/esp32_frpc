# esp32_frpc — A Platform-Independent ESP32 frp Client

> **[简体中文](README.md) | English**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![frp v1 compatible](https://img.shields.io/badge/frp-v1_compatible-green.svg)](https://github.com/fatedier/frp)
[![Platform: ESP32-S3](https://img.shields.io/badge/Platform-ESP32--S3-orange.svg)](https://www.espressif.com)

This project started from a personal need of the author and was entirely developed with
deepseek-harness. It consumed 1,188,490,821 tokens and cost about ¥110.76 (RMB) in total.
Following the fine tradition of "waste not, want not," the author decided to publish it on
GitHub as a humble offering. If it helps anyone with similarly "picky" needs, it will have
served its purpose.

It is a minimal, **platform-independent** frp client (frpc) implementation running on the
ESP32-S3, compatible with the frp v1 wire protocol. The core `frpc.h` depends on **no
platform-specific network API** and can be ported to any dev board that supports TCP/UDP
sockets.

## References & Acknowledgments

This project references and borrows from the protocol implementations and design ideas of
the following open-source projects. Many thanks to their authors:

- **[frp](https://github.com/fatedier/frp) (author [fatedier](https://github.com/fatedier))** — frp protocol spec (message framing, yamux multiplexing, auth, data-plane encryption); this project stays protocol-compatible with it. frp is licensed under Apache-2.0.
- **[xfrpc](https://github.com/liudf0716/xfrpc) (author [liudf0716](https://github.com/liudf0716))** — reference for the core frp interaction flow (login, IV exchange, NewProxy/NewWorkConn sequences, etc.). Licensed under GPL-3.0.
- **[ESP8266-FRP-Client](https://github.com/rwhystyewsrt/ESP8266-FRP-Client) (author [rwhystyewsrt](https://github.com/rwhystyewsrt))** — the basis adapted to ESP32 and the platform-independent architecture; much of the TCPMux framing, connection management, and data-plane forwarding originates from or is inspired by it. Licensed under GPL-3.0.

This project is an **independent rewrite and platform-independent refactor** of the above
protocols, not a simple copy; each reference is also credited in inline comments at the
corresponding places in `frpc.h`. It should be noted that from protocol analysis to code
implementation, the entire process was carried out by an AI assistant
(deepseek-harness). The author's skill is limited, so the resulting code inevitably has
rough edges and is provided for reference only. Furthermore, since AI is trained on large
amounts of open-source code, this implementation may resemble or even coincide with some
existing projects. This is absolutely not intentional plagiarism, but an inadvertent
coincidence. If you find that this project references your code without proper
attribution, please accept our sincere apologies and feel free to point it out — the
author will promptly add the acknowledgment and source. With that, sincere apologies and
respect to all open-source authors.

## Project Structure

```
esp32_frpc.ino         ← Minimal entry (assembly + scheduling + platform config + optional serial log)
frpc.h                  ← ★Platform-independent core: frp protocol / crypto / data plane
frpc_toml.h             ← frp config (field names match the official frpc.toml exactly)
esp32_network.h         ← ESP32 platform implementation (WiFi + abstraction interfaces, incl. a porting guide)
frpc_random.h           ← Optional platform hardware random source (auto-detected by frpc.h; safe to delete)
build_opt.h             ← Optional: USB/WiFi conflict fix (see below)
```

## Minimal Entry

The main program is extremely simple — `setup()` only does one-time networking/init and
`loop()` only does scheduling:

```cpp
void setup() {                     // runs once: connect WiFi + inject network + sync time + start
    wifi.begin(WIFI_SSID, WIFI_PASSWORD, 15000);   // ① connect WiFi (platform-specific)
    frpc.setNetwork(&netFactory);  // ② inject network impl (frpc core doesn't know the platform network)
    frpc.syncTime("203.107.6.88"); // ③ SNTP time sync (pure SNTP, platform-independent; needed for frps auth)
    frpc.start();                  // ④ go (config auto-loaded from frpc_toml.h)
}

void loop() {
    wifi.loop();                 // maintain WiFi (auto-reconnect on drop)
    frpc.loop();                 // maintain frpc main loop (login/data/reconnect)
    logStatus();                 // optional serial status log (remove this line to disable)
    delay(10);                   // prevent busy loop, yield CPU
}
```

- **`frpc.syncTime(ntp_ip)`**: pure SNTP time sync (platform-independent, no `configTime()`). frps auth uses `token+timestamp`; an inaccurate clock gets rejected. Pass `nullptr` to skip time sync.
- **`frpc.start(hostname, os, arch)`**: device identity (defaults `ESP32`/`FreeRTOS`/`xtensa`); server/proxy config is auto-loaded from `frpc_toml.h`.
- **NTP IP note**: NTP server IPs may change as providers adjust them (e.g. Aliyun NTP `203.107.6.88`). If the log shows `Time sync FAILED`, update the IP passed to `syncTime()` to a currently available NTP server.
- **Only `setNetwork` must be explicitly injected** (the network factory is a platform-specific object; frpc.h doesn't know the concrete platform implementation).
- `logStatus()`: purely for debugging — prints state changes plus a diagnostic every 5 seconds. **Deleting it has no effect on functionality.**

## Code Structure (frpc.h)

`frpc.h` is ~2900 lines, split into 6 sections by dependency order (collapsible with `#pragma region` in the IDE):

| Section | Content | Namespace |
|---------|---------|-----------|
| Section 1 | Network abstraction interfaces (NetStream/NetUDPStream/NetStreamFactory) | global |
| Section 2 | Crypto engine (AES-128-CFB + PBKDF2 key derivation) | `crypto` |
| Section 3 | Protocol dictionary (frp message structures + JSON encode/decode) | `proto` |
| Section 4 | yamux frame layer (TCP connection + multiplexing) | global |
| Section 5 | Data plane (TCP/UDP relay) | global |
| Section 6 | frpc core (state machine + frame loop + work-stream management) | global |

Notes:
- Internal crypto/protocol utilities are tucked into the `crypto`/`proto` namespaces; `using namespace` re-exports them so external call sites need zero changes.
- Business classes (FrpcClient/FrpcTcp/FrpcProxy) stay global (they reference each other, so keeping them in one scope avoids prefixes).

## Platform Independence

`frpc.h` depends only on three abstraction interfaces (implemented by the platform file):
- `NetStream` (TCP stream)
- `NetUDPStream` (UDP endpoint)
- `NetStreamFactory` (factory)

Plus one platform random source `frpc_platform_random()` (provided by the optional `frpc_random.h`; falls back to pseudo-random otherwise).

**Scope of this file**: ESP32/ESP32-S3 series over WiFi (lwIP sockets) — usable as-is without modification.

**When modification is needed**: when switching to a non-ESP32 platform (STM32/Raspberry Pi, etc.), or to wired Ethernet on ESP32, just rewrite `esp32_network.h`. For which interfaces to rewrite and what methods each interface requires, see the "porting guide" comment at the top of that file.

**Dependency order**: the entry `esp32_frpc.ino` explicitly includes `frpc.h` (interface definitions) before `esp32_network.h` (platform implementation); `esp32_network.h` does not include frpc.h itself.

## Features

- frp v1 wire protocol + yamux multiplexing + AES-128-CFB control-stream encryption
- TCP/UDP proxies, data-stream encryption (useEncryption), HTTP proxy (customDomains)
- Reconnect with exponential backoff, non-blocking large-frame receive, self-healing on drop
- **Correct FIN detection** (select-based): properly forwards peer-close, avoiding hung long-lived connections
- **UDP session self-healing**: when the socket pool runs low, the least-recently-active session is evicted, preventing connection buildup
- **Runtime socket buffer enlargement** (SO_RCVBUF/SO_SNDBUF=64KB): boosts data-plane throughput
- Tested: HTTPS proxy, concurrent multi-proxy, and lossless large-file (2.4MB) forwarding all work

## Configuration (frpc_toml.h)

Modify `frpc_toml.h` to complete all frp configuration — no code changes needed:

```c
// Server & auth
#define serverAddr   "your_frps_server_host"   // frps server address
#define serverPort   7000                       // frps listen port
#define auth_token   "your_frps_token"          // auth token (must match frps)

// Proxy list (field names correspond to the official [[proxies]])
static const ProxyConfig PROXIES[] = {
    { .name = "ssh",  .type = "tcp", .localIP = "192.168.1.100",
      .localPort = 22, .remotePort = 6000, .customDomains = "",
      .useEncryption = false, .useCompression = false },
    { .name = "web",  .type = "http", .localIP = "192.168.1.100",
      .localPort = 80, .remotePort = 0, .customDomains = "example.com",
      .useEncryption = false, .useCompression = false },
};
// Adding a proxy = copy a block and modify it; PROXY_COUNT is computed automatically.
```

### About Auth

The frp server (frps) supports two auth methods (`auth.method`):

| Method | Description |
|--------|-------------|
| `token` | Simple token auth; configure the same token on frpc and frps (**frp default**) |
| `oidc`  | Based on OpenID Connect; needs client_id/client_secret/issuer, more complex |

**This project (frpc.h) only implements `token` auth**, not oidc. Therefore:
- If frps uses **token** auth: set `auth_token` in `frpc_toml.h` to the same token as frps.
- If frps uses **oidc** auth: this project cannot interoperate; switch frps to token auth.

**About an empty `auth_token`**:
- frp's token auth allows an empty token by default. If frps has no token, set `auth_token` to the empty string `""` (both empty should match, in theory).
- **Do not delete the `#define auth_token` line** — besides auth signing (`MD5(token+timestamp)`), it is also used for **control-stream encryption key derivation** (`PBKDF2(token, "crypto")`). Deleting it breaks compilation.

WiFi config lives at the top of the entry `esp32_frpc.ino` (platform connection config, kept separate from frp config):

```c
// top of esp32_frpc.ino
#define WIFI_SSID       "your_wifi_ssid"
#define WIFI_PASSWORD   "your_wifi_password"
```

## Random Source (frpc_random.h, optional)

Encryption and reconnect jitter need randomness. A platform can supply hardware true-random (more secure); otherwise frpc.h automatically falls back to pseudo-random:

- Provide `frpc_random.h` (e.g. `esp_random()` on ESP32): frpc.h auto-uses hardware random via `__has_include`
- Delete `frpc_random.h`: frpc.h falls back to built-in pseudo-random (still compiles/runs; slightly less secure crypto)
- New platform: write a new `frpc_random.h` using that platform's true-random source

## build_opt.h (USB/WiFi Conflict Fix)

`build_opt.h` is the Arduino-ESP32 core's "inject extra compile flags" hook (its contents are appended as GCC args at build time). This project's `build_opt.h`:

```
-UARDUINO_USB_MODE
-UARDUINO_USB_CDC_ON_BOOT
-UARDUINO_USB_MSC_ON_BOOT
-UARDUINO_USB_DFU_ON_BOOT
```

`-U` means **undefine a macro**, i.e. **disable USB functionality** (CDC serial/MSC disk/DFU).

**When you need it**: on certain hardware + core version combinations (e.g. XIAO ESP32-S3 + core 4.0.0-alpha1), **USB and WiFi conflict at runtime** — if USB is not disabled, WiFi periodically drops, frpc repeatedly reconnects, and tunneling is unusable. **Verified necessary in this scenario.**

**Side effect**: the USB serial is disabled; `Serial` logs go to **UART0 (GPIO43/44)** and need a USB-UART adapter to view.

**Other boards/core versions** usually don't need this file; delete it to restore USB serial logs. If you hit a USB/WiFi conflict (WiFi drop, frpc reconnect loop), keep this file to fix it.

## Compiling & Flashing

Open this directory in the Arduino IDE, select your ESP32-S3 board, and click Upload (`build_opt.h` takes effect automatically).

**Wait ~2 minutes after flashing before testing**: flashing resets the ESP32; it must reconnect WiFi + wait for the old frps session timeout cleanup (default 90s) + proxy-conflict backoff. Proxies being unavailable during this window is normal.

## Known Limitations (measured)

Data-plane throughput is bounded by the board's wireless WiFi physical limit (measured ~2.6 Mbps upload to frps on ESP32-S3). Per-scenario public-network tunneling experience, for reference:

| Scenario | Measured experience |
|----------|--------------------|
| **SSH** | Usable; only slightly more latency than direct, no other issues |
| **Remote desktop (RDP)** | Clear picture, usable (for emergencies). Typing etc. has ~0.5–1 s latency, frame rate ~0-2 FPS |
| **Proxmox VE Web** | Usable; page loading is a bit sluggish |
| **Sunshine/Moonlight streaming** | Stream establishes without errors, but **completely unusable** (throughput can't carry video) |

**Conclusion**: this implementation suits **low-bandwidth, interactive** scenarios such as SSH, remote desktop, and web management; **high-bitrate real-time video streaming** (e.g. Moonlight game streaming) is limited by wireless WiFi throughput and is not recommended. For streaming, switch to wired Ethernet or higher-throughput hardware.

## Protocol Compatibility

Compatible with the official frp server (frps); verified end-to-end through frp protocol handshake, proxy registration, TCP/UDP data plane, and data-stream encryption.

## License

[GNU General Public License v3.0](LICENSE)

> This project references and borrows from [xfrpc](https://github.com/liudf0716/xfrpc) and [ESP8266-FRP-Client](https://github.com/rwhystyewsrt/ESP8266-FRP-Client) (both GPL-3.0), so it is licensed **GPL-3.0** for consistency. It stays protocol-compatible with official [frp](https://github.com/fatedier/frp) (frp itself is Apache-2.0; protocol compatibility does not constitute a derivative).
