# esp32_frpc — 平台无关的 ESP32 frp 客户端

> **[简体中文](README.md) | [English](README_EN.md)**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![frp v1 compatible](https://img.shields.io/badge/frp-v1_compatible-green.svg)](https://github.com/fatedier/frp)
[![Platform: ESP32-S3](https://img.shields.io/badge/Platform-ESP32--S3-orange.svg)](https://www.espressif.com)

本项目源于作者的一点个人需求，全程使用 deepseek-harness 完成。前后共消耗 1,188,490,821 词元、花费人民币 110.76 元，最终产出这么一坨代码。本着"废物利用"的优良传统，作者决定将其发布到 GitHub，权当抛砖引玉——若能帮到与我有相似"苛刻"需求的朋友，也算物尽其用了。

该项目是一个极简、**平台无关**的 frp 客户端（frpc）实现，运行在 ESP32-S3 上，兼容 frp v1 线协议。核心代码 `frpc.h` 不依赖任何平台网络 API，可移植到任意支持 TCP/UDP socket 的开发板。

## 参考来源与致谢

本项目在实现过程中参考并借用了以下开源项目的协议实现与设计思路，特此致谢：

- **[frp](https://github.com/fatedier/frp)（作者 [fatedier](https://github.com/fatedier)）** — frp 协议规范（消息帧、yamux 多路复用、认证、数据面加密），本项目与其保持协议兼容。frp 采用 Apache-2.0 许可证。
- **[xfrpc](https://github.com/liudf0716/xfrpc)（作者 [liudf0716](https://github.com/liudf0716)）** — frp 协议的核心交互流程参考（登录、IV 交换、NewProxy/NewWorkConn 时序等）。采用 GPL-3.0 许可证。
- **[ESP8266-FRP-Client](https://github.com/rwhystyewsrt/ESP8266-FRP-Client)（作者 [rwhystyewsrt](https://github.com/rwhystyewsrt)）** — 以该项目为基础适配到 ESP32/平台无关架构，TCPMux 帧封装、连接管理、数据面转发等大量实现源自或受其启发。采用 GPL-3.0 许可证。

本项目系对上述项目协议的**独立重写与平台无关化改造**，并非简单复制，各参考项目的出处亦已在 `frpc.h` 相应位置以注释标明。须予说明的是，自协议分析至代码实现，整个过程均由 AI 助手（deepseek-harness）完成，笔者才疏学浅，所成代码难免疏漏粗糙，仅作参考之用。此外，鉴于 AI 于训练过程中接触过大量开源代码，本实现或存在与某些既有项目相似乃至雷同之处，此绝非有意抄袭，实属无意之失。若阁下发现本项目引用了贵方代码而未及注明，敬请海涵，并欢迎随时指正，笔者将第一时间补充致谢与出处。谨此，向诸位开源作者致以诚挚歉意与敬意。

## 项目结构

```
esp32_frpc.ino         ← 精简入口（组装 + 调度 + 平台配置 + 可选串口日志）
frpc.h                  ← ★平台无关核心：frp 协议/加密/数据面
frpc_toml.h             ← frp 配置（字段名与官方 frpc.toml 完全一致）
esp32_network.h         ← ESP32 平台实现（WiFi + 抽象接口，含换平台重写指南）
frpc_random.h           ← 平台硬件随机源（可选，frpc.h 自动检测，删了不影响）
build_opt.h             ← 可选：USB/WiFi 冲突补救（见下方说明）
```

## 精简入口

主程序极简，`setup()` 只做一次性的联网/初始化，`loop()` 只做调度：

```cpp
void setup() {                     // 只运行一次：联网 + 注入网络 + 校时 + 启动
    wifi.begin(WIFI_SSID, WIFI_PASSWORD, 15000);   // ① 连 WiFi（平台相关）
    frpc.setNetwork(&netFactory);  // ② 注入网络实现（frpc 核心不认识平台网络）
    frpc.syncTime("203.107.6.88"); // ③ SNTP 校时（纯 SNTP 平台无关，frps 认证需要）
    frpc.start();                  // ④ 开工（配置自动从 frpc_toml.h 读取）
}

void loop() {
    wifi.loop();                 // 维护 WiFi（断线自动重连）
    frpc.loop();                 // 维护 frpc（登录/数据/重连）
    logStatus();                 // 可选：串口状态日志（删除本行即关）
    delay(10);                   // 防 busy loop，让出 CPU
}
```

- **`frpc.syncTime(ntp_ip)`**：纯 SNTP 校时（平台无关，不依赖 `configTime()`）。frps 认证用 `token+时间戳`，时间不准会被拒登。传 `nullptr` 可跳过校时。
- **`frpc.start(hostname, os, arch)`**：设备身份（默认 `ESP32`/`FreeRTOS`/`xtensa`），服务器/代理配置自动从 `frpc_toml.h` 读取。
- **NTP IP 变动说明**：NTP 服务器 IP 可能随服务商调整而变动（如阿里云 NTP `203.107.6.88`）。若日志提示 `Time sync FAILED`，请更新 `syncTime()` 的 IP 为当前可用的 NTP 服务器。
- **只有 `setNetwork` 是必须显式注入的**（网络工厂是平台相关对象，frpc.h 不认识具体平台实现）。
- `logStatus()`：纯调试，输出状态变化 + 每 5 秒一次诊断，**删除不影响任何功能**。

## 代码结构（frpc.h）

`frpc.h` 约 2900 行，按依赖顺序分为 6 个分区（用 `#pragma region` 折叠，IDE 里可收起/展开）：

| 分区 | 内容 | 命名空间 |
|------|------|---------|
| 第 1 区 | 网络抽象接口（NetStream/NetUDPStream/NetStreamFactory） | 全局 |
| 第 2 区 | 加密引擎（AES-128-CFB + PBKDF2 密钥派生） | `crypto` |
| 第 3 区 | 协议字典（frp 消息结构 + JSON 编解码） | `proto` |
| 第 4 区 | yamux 帧层（TCP 连接 + 多路复用） | 全局 |
| 第 5 区 | 数据面（TCP/UDP 中继） | 全局 |
| 第 6 区 | frpc 核心（状态机 + 帧循环 + work 流管理） | 全局 |

说明：
- 加密/协议内部工具收进 `crypto`/`proto` 命名空间（有归属感），通过 `using namespace` 让外部调用点零改动。
- 业务类（FrpcClient/FrpcTcp/FrpcProxy）保持全局（它们互相引用，放同一作用域免前缀）。

## 平台无关性

`frpc.h` 只依赖三个抽象接口（由平台文件实现）：
- `NetStream`（TCP 流）
- `NetUDPStream`（UDP 端点）
- `NetStreamFactory`（工厂）

外加一个平台随机数源 `frpc_platform_random()`（由可选的 `frpc_random.h` 提供，缺省回退伪随机）。

**本文件适用范围**：ESP32/ESP32-S3 系列 + WiFi 联网（基于 lwIP socket），这种情况可直接使用无需修改。

**什么情况需要修改**：换非 ESP32 平台（STM32/树莓派等）、或 ESP32 改用有线以太网时，重写 `esp32_network.h` 即可。具体要重写哪些接口、各接口要求哪些方法，见该文件顶部的"换平台重写指南"注释。

**依赖关系**：入口 `esp32_frpc.ino` 显式先 include `frpc.h`（接口定义）再 include `esp32_network.h`（平台实现）；`esp32_network.h` 不自行 include frpc.h。

## 功能

- frp v1 线协议 + yamux 多路复用 + AES-128-CFB 控制流加密
- TCP/UDP 代理、数据流加密（useEncryption）、HTTP 代理（customDomains）
- 重连指数退避、非阻塞大帧接收、断线自愈
- **FIN 正确检测**（select 探测）：正确转发对端关闭连接，避免长连接悬挂
- **UDP 会话自愈**：socket 池不足时自动驱逐最久未活动会话，防止连接堆积
- **运行时 socket 缓冲增大**（SO_RCVBUF/SO_SNDBUF=64KB）：提升数据面吞吐
- 实测：HTTPS 代理、多代理并发、大文件（2.4MB）无损转发均正常

## 配置（frpc_toml.h）

修改 `frpc_toml.h` 即可完成全部 frp 配置，无需改动任何代码：

```c
// 服务器与认证
#define serverAddr   "your_frps_server_host"   // frps 服务器地址
#define serverPort   7000                       // frps 监听端口
#define auth_token   "your_frps_token"          // 认证 token（与 frps 一致）

// 代理列表（字段名与官方 frpc.toml 的 [[proxies]] 对应）
static const ProxyConfig PROXIES[] = {
    { .name = "ssh",  .type = "tcp", .localIP = "192.168.1.100",
      .localPort = 22, .remotePort = 6000, .customDomains = "",
      .useEncryption = false, .useCompression = false },
    { .name = "web",  .type = "http", .localIP = "192.168.1.100",
      .localPort = 80, .remotePort = 0, .customDomains = "example.com",
      .useEncryption = false, .useCompression = false },
};
// 新增代理 = 复制一个块修改即可，PROXY_COUNT 自动计算，无需改数量。
```

### 关于认证（auth）的说明

frp 服务端（frps）支持两种认证方式（`auth.method`）：

| 方式 | 说明 |
|------|------|
| `token` | 简单 token 认证，frpc/frps 配置相同 token 即可（**frp 默认方式**） |
| `oidc` | 基于 OpenID Connect，需 client_id/client_secret/issuer 等，较复杂 |

**本项目（frpc.h）只实现了 `token` 认证**，不支持 oidc。因此：
- 若 frps 使用 **token** 认证：在 `frpc_toml.h` 设置与 frps 相同的 `auth_token` 即可。
- 若 frps 使用 **oidc** 认证：本项目无法配合，需将 frps 改为 token 方式。

**关于 `auth_token` 为空的情况**：
- frp 的 token 认证默认 token 可为空。若 frps 未设置 token，可将 `auth_token` 设为空字符串 `""`（两边都为空，理论上可匹配）。
- **切勿删除 `#define auth_token` 这一行**——该宏除了用于认证签名（`MD5(token+时间戳)`），还被用于**控制流加密的密钥派生**（`PBKDF2(token, "crypto")`）。删除会导致编译失败。

WiFi 配置在入口 `esp32_frpc.ino` 顶部（平台连接配置，与 frp 配置分离）：

```c
// esp32_frpc.ino 顶部
#define WIFI_SSID       "your_wifi_ssid"
#define WIFI_PASSWORD   "your_wifi_password"
```

## 随机数源（frpc_random.h，可选）

加密与重连抖动需要随机数。平台可提供硬件真随机（更安全），否则 frpc.h 自动回退伪随机：

- 提供 `frpc_random.h`（如 ESP32 用 `esp_random()`）：frpc.h 通过 `__has_include` 自动使用硬件随机
- 删除 `frpc_random.h`：frpc.h 回退内置伪随机（仍可编译运行，加密安全性略降）
- 换平台：写新的 `frpc_random.h` 用该平台的真随机源即可

## build_opt.h 说明（USB/WiFi 冲突补救）

`build_opt.h` 是 Arduino-ESP32 core 的"注入额外编译参数"钩子（构建时把其内容作为 GCC 参数追加）。本项目的 `build_opt.h` 内容：

```
-UARDUINO_USB_MODE
-UARDUINO_USB_CDC_ON_BOOT
-UARDUINO_USB_MSC_ON_BOOT
-UARDUINO_USB_DFU_ON_BOOT
```

`-U` 意为**取消宏定义**，作用是**禁用 USB 功能**（CDC 串口/MSC 磁盘/DFU）。

**何时需要它**：在特定硬件 + core 版本组合（如 XIAO ESP32-S3 + core 4.0.0-alpha1）上，**USB 与 WiFi 存在运行时冲突**——若不禁用 USB，WiFi 会周期性断开、frpc 反复重连，内网穿透不可用。**实测证明此场景下该文件必需**。

**副作用**：USB 串口被禁用，`Serial` 日志改走 **UART0（GPIO43/44）**，需 USB-UART 适配器查看。

**其他板子/core 版本**通常不需要此文件，删除它即可恢复 USB 串口日志。若遇 USB/WiFi 冲突（WiFi 掉线、frpc 反复重连），保留本文件即可解决。

## 编译与烧录

Arduino IDE 打开本目录，选择你的 ESP32-S3 开发板，直接点上传即可（`build_opt.h` 自动生效）。

**烧录后等待约 2 分钟再测试**：烧录会复位 ESP32，需重新连 WiFi + 等 frps 旧会话超时清理（默认 90 秒）+ 代理冲突退避，此窗口内代理暂不可用属正常。

## 已知限制（实测体验）

数据面吞吐受开发板无线 WiFi 物理上限约束（实测 ESP32-S3 无线 frps 上行约 2.6Mbps）。以下是各典型场景的公网穿透实测体验，供参考：

| 场景 | 实测体验 |
|------|---------|
| **SSH** | 可用，仅延迟比直连略增，无其他问题 |
| **远程桌面（RDP）** | 画面清晰，可用（应急可用）。打字等操作约 0.5~1 秒延迟，帧率约 0-2 FPS |
| **Proxmox VE Web** | 可用，页面加载有卡顿 |
| **Sunshine/Moonlight 串流** | 能建立串流、无报错，但**完全不可用**（吞吐不足以承载视频流） |

**结论**：本实现适用于 SSH、远程桌面、Web 管理等**低带宽、交互型**场景；**高码率实时视频串流**（如 Moonlight 游戏串流）受无线 WiFi 吞吐限制，不建议。若需串流，改用有线以太网或更高吞吐的硬件可提升。

## 协议兼容性

与官方 frp 服务端（frps）兼容，已通过 frp 协议握手、代理注册、TCP/UDP 数据面、数据流加密等完整流程验证。

## License

[GNU General Public License v3.0](LICENSE)

> 本项目参考并借用了 [xfrpc](https://github.com/liudf0716/xfrpc) 与 [ESP8266-FRP-Client](https://github.com/rwhystyewsrt/ESP8266-FRP-Client) 的实现（二者均为 GPL-3.0），故本项目采用 **GPL-3.0** 许可证以保持一致。与官方 [frp](https://github.com/fatedier/frp) 保持协议兼容（frp 本身为 Apache-2.0，协议兼容不构成衍生）。
