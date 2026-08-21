/**
 * @file frpc_toml.h
 * @brief frpc 配置文件 —— 字段名与官方 frpc.toml 完全一致
 *
 * 官方参考：frp-0.70.1/conf/frpc.toml（最小示例）与 frpc_full_example.toml（完整示例）
 * 本项目使用的字段是官方 TOML 配置的 C 语言投影：
 *   - 服务器/认证：宏名 = 官方字段名（serverAddr / serverPort / auth.token → auth_token）
 *   - 代理列表：结构体 + C99 指定初始化器（字段名与官方 [[proxies]] 逐项对应）
 *
 * 修改本文件即可完成全部配置，无需改动任何代码。
 */

#ifndef FRPC_TOML_H
#define FRPC_TOML_H

#include <Arduino.h>

/* ============================================================
 * 服务器（对应官方 frpc.toml 顶层字段）
 * ============================================================ */

// serverAddr = "frps 服务器地址"        frps 服务器地址
#define serverAddr   "frps 服务器地址"
// serverPort = 7000                  frps 监听端口
#define serverPort   7000

/* ============================================================
 * 认证（对应官方 auth 表）
 * ============================================================ */

// auth.token = "frps设置token"            认证 token（须与 frps 一致）
// 注：官方为 auth.token（带点），C 宏不允许点号，用下划线代替
// 说明：本项目仅支持 frp 的 token 认证（不支持 oidc）。
//       - frps 用 token 认证：此处设与 frps 相同的 token。
//       - frps 未设 token：将值改为空串 ""（两边都空，可匹配）。
//       - 切勿删除本行：该宏还用于控制流加密密钥派生，删除会编译失败。
#define auth_token   ""

/* ============================================================
 * 代理列表（对应官方 [[proxies]]）
 *
 * 字段与官方一一对应：
 *   name            = "代理名称"
 *   type            = "tcp" / "udp" / "http"
 *   localIP         = 内网服务 IP
 *   localPort       = 内网服务端口
 *   remotePort      = 公网端口（填 0 由 frps 随机分配；http 代理填 0 用 customDomains）
 *   customDomains   = 域名（http/https 代理用，tcp 留空）
 *   useEncryption   = transport.useEncryption  数据流加密
 *   useCompression  = transport.useCompression 数据流压缩
 *
 * 新增代理 = 复制一个块修改即可，PROXY_COUNT 自动计算，无需手动改数量。
 * ============================================================ */

struct ProxyConfig {
    char     name[64];            // name
    char     type[16];            // type
    char     localIP[16];         // localIP
    uint16_t localPort;           // localPort
    uint16_t remotePort;          // remotePort
    char     customDomains[64];   // customDomains
    bool     useEncryption;       // transport.useEncryption
    bool     useCompression;      // transport.useCompression
};

static const ProxyConfig PROXIES[] = {
    // ===== 示例 1：TCP —— 内网 SSH 穿透到公网 6000 端口 =====
    // 公网 ssh -p 6000 user@frps 即可访问内网 192.168.1.100 的 SSH(22)
    {
        .name = "ssh", .type = "tcp",
        .localIP = "192.168.1.100", .localPort = 22,
        .remotePort = 6000, .customDomains = "",
        .useEncryption = false, .useCompression = false,
    },
    // ===== 示例 2：TCP —— 远程桌面（RDP）穿透 =====
    // 公网连接 frps:3389 即可访问内网 Windows 远程桌面
    {
        .name = "rdp", .type = "tcp",
        .localIP = "192.168.1.100", .localPort = 3389,
        .remotePort = 3389, .customDomains = "",
        .useEncryption = false, .useCompression = false,
    },
    // ===== 示例 3：HTTP —— 内网 Web 服务通过域名暴露 =====
    // 需在 frps 配置 vhost_http_port，且域名解析到 frps
    {
        .name = "web", .type = "http",
        .localIP = "192.168.1.100", .localPort = 8080,
        .remotePort = 0, .customDomains = "web.example.com",
        .useEncryption = false, .useCompression = false,
    },
    // ===== 示例 4：TCP —— 内网数据库穿透（加密+压缩）=====
    // 演示 useEncryption / useCompression 用法
    {
        .name = "mysql", .type = "tcp",
        .localIP = "192.168.1.100", .localPort = 3306,
        .remotePort = 3306, .customDomains = "",
        .useEncryption = true, .useCompression = true,
    },
};

// 代理数量自动计算（新增代理无需修改）
#define PROXY_COUNT  (sizeof(PROXIES) / sizeof(PROXIES[0]))

#endif // FRPC_TOML_H
