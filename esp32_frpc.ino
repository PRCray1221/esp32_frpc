/**
 * @file esp32_frpc.ino
 * @brief ESP32 frpc —— 精简入口
 *
 * 架构（平台无关）：
 *   frpc.h          协议核心（frp/加密/数据面）
 *   frpc_toml.h     配置（改这里即可）
 *   esp32_network.h 平台网络实现（WiFi + 抽象接口）
 *   frpc_random.h   平台真随机源（可选）
 *
 * 本文件职责：组装 + 调度 + 可选日志。
 */

// ============ 平台配置 ============
// WiFi（平台相关；不用 WiFi 的平台（以太网等）改这里即可）
#define WIFI_SSID       "WiFi名称"
#define WIFI_PASSWORD   "WiFi密码"

// ============ 依赖顺序：先核心后平台 ============
#include "frpc.h"            // ① 协议核心（接口定义 + 随机源检测）
#include "esp32_network.h"   // ② 平台网络实现（实现 frpc.h 接口）
                             //    frpc_random.h 由 frpc.h 自动检测包含（可选）

// ============ 全局对象 ============
Esp32NetFactory netFactory;   // 网络工厂（注入 frpc，实现平台无关）
WiFiManager     wifi;         // WiFi 连接管理
FrpcClient      frpc;         // frpc 核心

// ============ 主流程 ============
// setup：只运行一次的初始化（联网 + 注入网络 + 校时 + 启动）
void setup() {
    // ① 连 WiFi（平台相关；换以太网就替换这一句）
    wifi.begin(WIFI_SSID, WIFI_PASSWORD, 15000);
    // ② 注入网络实现（frpc 核心不认识平台网络，必须由这里提供）
    frpc.setNetwork(&netFactory);
    // ③ 校时（可选）：start() 会自动用默认 NTP IP 校时，本行可省略。
    //    如需指定其他 NTP 服务器，可调用 frpc.syncTime("自定义IP")
    // frpc.syncTime();
    // ④ 开工：服务器/代理/身份自动从 frpc_toml.h 读取
    frpc.start();
}

void loop() {
    wifi.loop();    // 维护 WiFi 连接（断线自动重连）
    frpc.loop();    // 维护 frpc 主循环（登录/数据/重连）
    logStatus();    // 可选：输出状态日志（删除本行即关日志）
    delay(10);      // 防 busy loop，让出 CPU
}

// ============ 日志（纯调试，删除不影响功能）============
// 串口输出状态：状态变化时打印 + 每 5 秒一次诊断
static void logStatus() {
    static ClientState lastState = ClientState::IDLE;
    static TcpState    lastTcp   = TcpState::IDLE;
    ClientState curState = frpc.state();          // 当前 frpc 状态
    TcpState    curTcp   = frpc.tcp().state();    // 当前 TCP 状态

    // 状态变化时打印（避免每帧都打）
    if (curState != lastState) {
        lastState = curState;
        const char *names[] = {"IDLE","CONNECTING","LOGIN_SENT","WAIT_IV","READY","ERROR"};
        Serial.print("[STATE] ");
        Serial.println(names[(int)curState]);
    }
    if (curTcp != lastTcp) {
        lastTcp = curTcp;
        const char *tcpNames[] = {"IDLE","CONNECTING","CONNECTED","CLOSED"};
        Serial.print("[TCP] ");
        Serial.println(tcpNames[(int)curTcp]);
    }

    // 每 5 秒一次诊断
    static uint32_t last = 0;
    if (millis() - last > 5000) {
        last = millis();
        Serial.printf("[ALIVE] state=%d tcp=%d avail=%d conn=%d proxy=%d work=%d runid=%s heap=%u rssi=%d pend=%u/%u buf=%u\n",
            (int)frpc.state(), (int)frpc.tcp().state(), frpc.tcp().raw_available(),
            frpc.tcp().raw_connected(), (int)frpc.proxyCount(), (int)frpc.workConnCount(),
            frpc.serverRunId(), ESP.getFreeHeap(), wifi.getRSSI(),
            (unsigned)frpc.tcp().diagPendingLen(), (unsigned)frpc.tcp().diagPendingNeed(),
            (unsigned)frpc.tcp().diagBufLen());
    }
}
