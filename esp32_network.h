/**
 * @file esp32_network.h
 * @brief ESP32 平台网络实现 —— frpc.h 抽象接口的 ESP32 适配层
 *
 * ================================================================
 *  换平台重写指南（重要！阅读本文件前先看这里）
 * ================================================================
 *  【本文件适用于什么情况】
 *   - 目标平台：ESP32 / ESP32-S3 系列，使用 WiFi 联网
 *   - 网络栈：基于 lwIP socket（Arduino-ESP32 core 内置）
 *   - 若你的平台是 ESP32 且走 WiFi，本文件可直接用，无需修改。
 *
 *  【什么情况需要修改本文件】
 *   - 换成非 ESP32 平台（STM32/树莓派/ESP8266 等）：重写本文件
 *   - ESP32 但改用有线以太网：替换 WiFiManager 部分为以太网初始化
 *   - 换任意平台：只需按下方接口清单，用新平台的网络库重新实现
 *     NetStream / NetUDPStream / NetStreamFactory，frpc.h 与
 *     frpc_toml.h 完全不用改。
 *
 *  frpc.h 是平台无关核心，它通过下列"抽象接口"使用网络能力。
 *  换到新平台时，只需用新平台的网络库重新实现这些接口。
 *
 *  【必须实现的三部分】
 *  ① NetStream       —— TCP 流（对应本文件 NetSocket）
 *  ② NetUDPStream    —— UDP 端点（对应本文件 NetUDP）
 *  ③ NetStreamFactory —— 工厂：new 出上面的具体对象（对应 Esp32NetFactory）
 *
 *  【各接口必须提供的方法】
 *  ┌ NetStream（TCP）───────────────────────────────────────────┐
 *  │ bool   connect(host, port)     连接服务器                     │
 *  │ size_t write(data, len)        发数据（可部分写入）            │
 *  │ int    read(buf, len)          收数据（>0数据/0关闭/-1超时）   │
 *  │ int    available()             还有 N 字节可读                │
 *  │ bool   connected()             是否仍连接                     │
 *  │ bool   isPeerClosed()          对端是否已关闭(EOF)             │
 *  │ void   stop()                  关闭连接                       │
 *  │ void   setTimeout(ms)          读写超时                       │
 *  │ void   setLingerOff()          关闭时发RST(避免TIME_WAIT)      │
 *  └─────────────────────────────────────────────────────────────┘
 *  ┌ NetUDPStream（UDP）─────────────────────────────────────────┐
 *  │ bool   begin(port)             绑定本地端口                    │
 *  │ void   beginPacket(ip,port)    设目标地址+清发送缓冲            │
 *  │ size_t write(data, len)        攒进发送缓冲(不立即发)           │
 *  │ bool   endPacket()             整体发出(一个UDP报文)           │
 *  │ int    parsePacket()           有包可读?返回可读字节数          │
 *  │ int    read(buf, max)          读收到的包                     │
 *  │ void   stop()                  关闭                           │
 *  └─────────────────────────────────────────────────────────────┘
 *  ┌ NetStreamFactory ───────────────────────────────────────────┐
 *  │ NetStream *createStream()        new 一个 TCP 实现           │
 *  │ NetUDPStream *createUDPStream()  new 一个 UDP 实现           │
 *  └─────────────────────────────────────────────────────────────┘
 *
 *
 *  本文件其余部分（WiFiManager）是 ESP32 连接管理，非 frpc 接口，
 *  换平台时替换为对应平台的联网方式即可。
 * ================================================================
 *
 *  注：NetStream 等接口定义在 frpc.h，由入口 esp32_frpc.ino 先 include，
 *      本文件不直接 include frpc.h（保持上层统一提供接口的依赖方向）。
 */

#ifndef ESP32_NETWORK_H
#define ESP32_NETWORK_H

#include <WiFi.h>
#include <lwip/sockets.h>
#include <lwip/netdb.h>
#include <lwip/inet.h>
#include <lwip/errno.h>
#include <string.h>


// ============================================================
// NetSocket — TCP 实现（基于 ESP32 lwIP socket）
// ============================================================
class NetSocket : public NetStream {
public:
    NetSocket() : _fd(-1), _connected(false), _timeout_ms(1000), _eof_pending(false) {}
    ~NetSocket() { stop(); }

    /**
     * @brief 连接服务器（带超时，不阻塞主循环）
     * @param host 服务器主机名或 IP
     * @param port 服务器端口
     * @return true 连接成功；false 失败（超时/无法解析/连接被拒）
     */
    bool connect(const char *host, uint16_t port) override {
        stop();
        _fd = lwip_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (_fd < 0) return false;

        struct hostent *he = lwip_gethostbyname(host);
        if (!he) { stop(); return false; }

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        memcpy(&addr.sin_addr, he->h_addr, he->h_length);

        // 非阻塞 connect + select 超时（10s），frps 不可达时不会无限阻塞
        int fl = lwip_fcntl(_fd, F_GETFL, 0);
        lwip_fcntl(_fd, F_SETFL, fl | O_NONBLOCK);
        int rc = lwip_connect(_fd, (struct sockaddr *)&addr, sizeof(addr));
        if (rc != 0 && errno != EINPROGRESS && errno != EWOULDBLOCK && errno != EAGAIN) {
            stop();
            return false;
        }
        if (rc != 0) {
            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(_fd, &wfds);
            struct timeval tv;
            tv.tv_sec = 10;
            tv.tv_usec = 0;
            int sr = lwip_select(_fd + 1, nullptr, &wfds, nullptr, &tv);
            if (sr <= 0 || !FD_ISSET(_fd, &wfds)) { stop(); return false; }
            int soerr = 0;
            socklen_t slen = sizeof(soerr);
            lwip_getsockopt(_fd, SOL_SOCKET, SO_ERROR, &soerr, &slen);
            if (soerr != 0) { stop(); return false; }
        }
        // 恢复阻塞模式（连接后由 SO_RCVTIMEO/SNDTIMEO 控制超时）
        lwip_fcntl(_fd, F_SETFL, fl);
        // 与官方 frpc（Go net 默认 TCP_NODELAY）行为对齐：禁用 Nagle
        int nodelay = 1;
        lwip_setsockopt(_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
        // 增大 TCP 收发缓冲：lwIP 默认窗口小，frps 上行吞吐受限（实测仅 ~2.5Mbps），
        // 视频串流需要更高吞吐。socket 级 SO_SNDBUF/SO_RCVBUF 可提升。
        int sndbuf = 65536;
        lwip_setsockopt(_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        int rcvbuf = 65536;
        lwip_setsockopt(_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
        _applyTimeouts();
        _connected = true;
        return true;
    }

    /**
     * @brief 发送数据（可能部分写入）
     * @param data 数据指针
     * @param len  请求发送的字节数
     * @return 实际发送的字节数；0 表示缓冲满需稍后重试（连接仍可用）
     */
    size_t write(const uint8_t *data, size_t len) override {
        if (_fd < 0 || !_connected) return 0;
        int n = lwip_send(_fd, data, len, 0);
        if (n <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            _connected = false;
            return 0;
        }
        return (size_t)n;
    }

    /**
     * @brief 接收数据
     * @param buf 接收缓冲
     * @param len 缓冲容量
     * @return >0 读到的字节数；0 对端已关闭；-1 超时/无数据（连接仍可用）
     */
    int read(uint8_t *buf, size_t len) override {
        if (_fd < 0 || !_connected) return -1;
        int n = lwip_recv(_fd, buf, len, 0);
        if (n == 0) { _connected = false; return 0; }
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return -1;
            _connected = false;
            return -1;
        }
        return n;
    }

    /**
     * @brief 查询当前可读字节数（不消耗数据）
     * @return 可读字节数；0 表示无可读数据
     */
    int available() override {
        if (_fd < 0 || !_connected) return 0;
        int n = 0;
        if (lwip_ioctl(_fd, FIONREAD, &n) != 0) return 0;
        return n;
    }

    /**
     * @brief 连接是否仍有效
     * @return true 连接可用；false 已关闭
     */
    bool connected() override { return _fd >= 0 && _connected; }

    /**
     * @brief 检测对端是否已关闭连接（EOF）
     *
     * 用 select 探测可读事件（lwIP 中收到 FIN 也触发可读），再用
     * recv(MSG_PEEK) 区分"有数据"还是"对端关闭"。为防 select 瞬时误报，
     * EOF 需连续两轮探测到才判定（_eof_pending 延迟确认）。
     *
     * @return true 对端已关闭；false 仍连接（或暂不可判定）
     */
    bool isPeerClosed() override {
        if (_fd < 0 || !_connected) return true;
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(_fd, &rfds);
        struct timeval tv = { 0, 0 };
        int sr = lwip_select(_fd + 1, &rfds, nullptr, nullptr, &tv);
        if (sr <= 0 || !FD_ISSET(_fd, &rfds)) { _eof_pending = false; return false; }
        char c;
        int r = lwip_recv(_fd, &c, 1, MSG_PEEK);
        if (r == 0) {
            if (_eof_pending) { _connected = false; return true; }  // 连续两轮确认 EOF
            _eof_pending = true;
            return false;
        }
        if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            if (_eof_pending) { _connected = false; return true; }
            _eof_pending = true;
            return false;
        }
        _eof_pending = false;                                       // 有数据：不是 EOF
        return false;
    }

    /**
     * @brief 关闭连接并释放 socket
     */
    void stop() override {
        if (_fd >= 0) { lwip_close(_fd); _fd = -1; }
        _connected = false;
    }

    /**
     * @brief 设置读写超时（仅下次 connect 时生效）
     * @param ms 超时毫秒数
     */
    void setTimeout(uint32_t ms) override { _timeout_ms = ms; }

    /**
     * @brief 关闭时发 RST（SO_LINGER=0），不进入 TIME_WAIT
     *
     * 避免高频短连接耗尽 lwIP 的 socket/PCB 池（默认 CONFIG_LWIP_MAX_SOCKETS=10）
     */
    void setLingerOff() override {
        struct linger lg;
        lg.l_onoff = 1;
        lg.l_linger = 0;
        if (_fd >= 0) lwip_setsockopt(_fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
    }

private:
    void _applyTimeouts() {
        struct timeval tv;
        tv.tv_sec = _timeout_ms / 1000;
        tv.tv_usec = (_timeout_ms % 1000) * 1000;
        lwip_setsockopt(_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        lwip_setsockopt(_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }

    int      _fd;
    bool     _connected;
    uint32_t _timeout_ms;
    bool     _eof_pending;   // EOF 延迟确认标志（连续两轮探测到才判定）
};

// ============================================================
// NetUDP — UDP 实现（基于 ESP32 lwIP socket）
// ============================================================
class NetUDP : public NetUDPStream {
public:
    NetUDP() : _fd(-1), _pkt_len(0) { memset(&_dst, 0, sizeof(_dst)); }
    ~NetUDP() { stop(); }

    /**
     * @brief 绑定本地 UDP 端口
     * @param port 要绑定的本地端口
     * @return true 绑定成功；false 失败（socket 创建或 bind 失败）
     */
    bool begin(uint16_t port) override {
        stop();
        _fd = lwip_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (_fd < 0) return false;
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_ANY);
        a.sin_port = htons(port);
        if (lwip_bind(_fd, (struct sockaddr *)&a, sizeof(a)) != 0) { stop(); return false; }
        // 增大 UDP 接收缓冲：视频流（sunshine 突发几百包/秒）默认缓冲溢出丢包
        // （实测：ESP32 转发的视频序号缺口大，sunshine 发送远多于转发量）
        int rcvbuf = 65536;
        lwip_setsockopt(_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        lwip_setsockopt(_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        return true;
    }

    /**
     * @brief 开始组装一个 UDP 报文（设置目标地址并清空发送缓冲）
     * @param ip   目标 IP
     * @param port 目标端口
     */
    void beginPacket(const char *ip, uint16_t port) override {
        memset(&_dst, 0, sizeof(_dst));
        _dst.sin_family = AF_INET;
        _dst.sin_port = htons(port);
        lwip_inet_pton(AF_INET, ip, &_dst.sin_addr);
        _pkt_len = 0;
    }

    /**
     * @brief 把数据写入发送缓冲（攒进报文，不立即发送）
     * @param data 数据指针
     * @param len  字节数
     * @return 实际写入字节数（缓冲满时可能少于 len）
     */
    size_t write(const uint8_t *data, size_t len) override {
        if (_pkt_len + len > sizeof(_pkt)) {
            size_t room = sizeof(_pkt) - _pkt_len;
            if (room == 0) return 0;
            memcpy(_pkt + _pkt_len, data, room);
            _pkt_len += room;
            return room;
        }
        memcpy(_pkt + _pkt_len, data, len);
        _pkt_len += len;
        return len;
    }

    /**
     * @brief 把缓冲中的报文作为一个 UDP 包整体发出
     * @return true 发送成功；false 失败（无 socket 或 sendto 错误）
     */
    bool endPacket() override {
        if (_fd < 0) return false;
        int n = lwip_sendto(_fd, _pkt, _pkt_len, 0, (struct sockaddr *)&_dst, sizeof(_dst));
        return n >= 0;
    }

    /**
     * @brief 查询是否有收到 UDP 包
     * @return 可读字节数；0 表示暂无数据
     */
    int parsePacket() override {
        if (_fd < 0) return 0;
        int n = 0;
        if (lwip_ioctl(_fd, FIONREAD, &n) != 0 || n <= 0) return 0;
        return n;
    }

    /**
     * @brief 读取收到的 UDP 包
     * @param buf 接收缓冲
     * @param max 缓冲容量
     * @return >0 读到的字节数；0 暂无数据；-1 错误
     */
    int read(uint8_t *buf, size_t max) override {
        if (_fd < 0) return -1;
        int n = lwip_recv(_fd, buf, max, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            return -1;
        }
        return n;
    }

    /**
     * @brief 关闭并释放 UDP socket
     */
    void stop() override {
        if (_fd >= 0) { lwip_close(_fd); _fd = -1; }
    }

private:
    int      _fd;
    uint8_t  _pkt[1500];
    size_t   _pkt_len;
    struct sockaddr_in _dst;
};

// ============================================================
// Esp32NetFactory — 平台网络工厂
// ============================================================
class Esp32NetFactory : public NetStreamFactory {
public:
    /**
     * @brief 创建 TCP 流对象
     * @return 新的 NetSocket 实例（NetStream*）
     */
    NetStream *createStream() override { return new NetSocket(); }
    /**
     * @brief 创建 UDP 端点对象
     * @return 新的 NetUDP 实例（NetUDPStream*）
     */
    NetUDPStream *createUDPStream() override { return new NetUDP(); }
};

// ============================================================
// WiFi 连接管理（ESP32 平台专用）
// ============================================================
typedef void (*WiFiEventCallback)(void *arg);

class WiFiManager {
public:
    WiFiManager() : _state(0), _autoReconnect(true), _reconnectInterval(5000),
                    _lastReconnectAttempt(0), _connectStartTime(0), _connectTimeout(0),
                    _onDisconnected(nullptr), _onDisconnectedArg(nullptr) {
        memset(_ssid, 0, sizeof(_ssid));
        memset(_password, 0, sizeof(_password));
        _instance = this;
        WiFi.onEvent(_wifiEventCallback);
    }

    ~WiFiManager() {
        WiFi.disconnect(true);
        if (_instance == this) _instance = nullptr;
    }

    bool begin(const char *ssid, const char *password, uint32_t timeout_ms = 15000) {
        if (!ssid || !password) return false;
        strncpy(_ssid, ssid, sizeof(_ssid) - 1);
        strncpy(_password, password, sizeof(_password) - 1);
        _connectTimeout = timeout_ms;
        _startConnect();
        uint32_t t0 = millis();
        while (WiFi.status() != WL_CONNECTED) {
            if (timeout_ms > 0 && millis() - t0 > timeout_ms) {
                Serial.println("[WiFi] Connection timeout");
                return false;
            }
            delay(100);
        }
        _state = 1;
        Serial.printf("[WiFi] Connected! IP: %s, RSSI: %d dBm\n", getLocalIP(), getRSSI());
        return true;
    }

    void loop() {
        if (WiFi.status() != WL_CONNECTED) {
            if (_state == 1) {
                Serial.println("[WiFi] Polling detected disconnection");
                _state = 0;
                if (_onDisconnected) _onDisconnected(_onDisconnectedArg);
            }
            if (_autoReconnect && _ssid[0]) {
                uint32_t now = millis();
                if (now - _lastReconnectAttempt >= _reconnectInterval) {
                    _lastReconnectAttempt = now;
                    Serial.printf("[WiFi] Auto-reconnecting to %s...\n", _ssid);
                    _startConnect();
                }
            }
        }
    }

    bool isConnected() const { return WiFi.status() == WL_CONNECTED; }
    const char *getLocalIP() {
        static char buf[16];
        IPAddress ip = WiFi.localIP();
        snprintf(buf, sizeof(buf), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
        return buf;
    }
    int8_t getRSSI() const { return WiFi.RSSI(); }

    void onDisconnected(WiFiEventCallback cb, void *arg = nullptr) {
        _onDisconnected = cb;
        _onDisconnectedArg = arg;
    }

private:
    void _startConnect() {
        WiFi.disconnect(false, true);
        delay(100);
        WiFi.mode(WIFI_STA);
        Serial.printf("[WiFi] Connecting to SSID: %s\n", _ssid);
        WiFi.setSleep(false);   // 禁用省电：modem sleep 会导致周期性丢包
        WiFi.begin(_ssid, _password);
    }

    static void _wifiEventCallback(arduino_event_t *event) {
        if (_instance && event && event->event_id == ARDUINO_EVENT_WIFI_STA_DISCONNECTED) {
            uint8_t reason = event->event_info.wifi_sta_disconnected.reason;
            Serial.printf("[WiFi] Event: Disconnected! Reason: %d\n", reason);
        }
    }

    static WiFiManager *_instance;
    char _ssid[33];
    char _password[65];
    uint8_t _state;             // 0=未连接 1=已连接
    bool _autoReconnect;
    uint32_t _reconnectInterval;
    uint32_t _lastReconnectAttempt;
    uint32_t _connectTimeout;
    uint32_t _connectStartTime;
    WiFiEventCallback _onDisconnected;
    void *_onDisconnectedArg;
};

// 静态成员类外定义（头文件模式必需）
WiFiManager *WiFiManager::_instance = nullptr;

#endif // ESP32_NETWORK_H
