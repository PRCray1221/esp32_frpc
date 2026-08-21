/**
 * @file frpc.h
 * @brief 平台无关的 frp 客户端核心（一体化头文件）
 *
 * 设计目标：本文件可原样搬到任意开发板（ESP32/STM32/树莓派…），
 * 不依赖任何平台网络 API。平台只需实现三个接口
 * （NetStream / NetUDPStream / NetStreamFactory）+ 一个随机数函数
 * （frpc_platform_random），并通过 FrpcClient::setNetwork() 注入。
 *
 * 分区（按依赖顺序）：
 *   第 1 区：网络抽象接口
 *   第 2 区：加密引擎（crypto）
 *   第 3 区：协议字典（proto）
 *   第 4 区：yamux 帧层
 *   第 5 区：数据面
 *   第 6 区：frpc 核心
 *
 * 配置见 frpc_toml.h。
 */

#ifndef FRPC_H
#define FRPC_H

#include <Arduino.h>
#include "frpc_toml.h"

// 默认 NTP 服务器 IP（纯 SNTP 校时用，平台无关）
// 注意：NTP 服务器 IP 可能随服务商调整而变动，若校时失败请更新此处
#ifndef FRPC_DEFAULT_NTP_IP
#define FRPC_DEFAULT_NTP_IP "203.107.6.88"
#endif

/* ============================================================
 * 第 1 区：网络抽象接口
 * 说明：平台无关的 TCP/UDP 流抽象，由平台文件实现。
 * ============================================================ */
#pragma region 第1区:网络抽象接口

// TCP 流抽象（对应官方 net.Conn 的最小接口）
class NetStream {
public:
    virtual ~NetStream() {}
    virtual bool connect(const char *host, uint16_t port) = 0;
    virtual size_t write(const uint8_t *data, size_t len) = 0;
    virtual int read(uint8_t *buf, size_t len) = 0;      // >0 数据；0 对端关闭；-1 超时/无数据
    virtual int available() = 0;
    virtual bool connected() = 0;
    virtual void stop() = 0;
    virtual void setTimeout(uint32_t ms) = 0;
    // 可选：关闭时发 RST 而非 FIN（避免 TIME_WAIT 占用 lwIP socket 池；
    // 高频短连接如本地代理连接应启用；长连接如控制连接保持默认）
    virtual void setLingerOff() {}
    // 对端是否已关闭连接（EOF 检测）。默认实现依赖 connected()；
    // 平台实现应主动探测（如 recv MSG_PEEK）——否则 EOF 且无 pending 数据时
    // 连接悬挂不关闭（实测：moonlight RTSP 握手悬挂的根因）
    virtual bool isPeerClosed() { return !connected(); }
};

// UDP 端点抽象（对齐 WiFiUDP 用法）
class NetUDPStream {
public:
    virtual ~NetUDPStream() {}
    virtual bool begin(uint16_t port) = 0;
    virtual void beginPacket(const char *ip, uint16_t port) = 0;
    virtual size_t write(const uint8_t *data, size_t len) = 0;
    virtual bool endPacket() = 0;
    virtual int parsePacket() = 0;
    virtual int read(uint8_t *buf, size_t max) = 0;
    virtual void stop() = 0;
};

// 网络流工厂：平台注入，供核心按需创建流（控制流 + 每个代理的本地流）
class NetStreamFactory {
public:
    virtual ~NetStreamFactory() {}
    virtual NetStream *createStream() = 0;
    virtual NetUDPStream *createUDPStream() = 0;
};

// 随机数源：平台可提供硬件真随机（frpc_random.h，可选），否则回退伪随机。
// - 存在 frpc_random.h：自动 include 它（提供 frpc_platform_random 硬件实现）
// - 不存在：本文件用 Arduino random() 兜底（仍可编译运行，加密安全性略降）
// 这样 frpc_random.h 可整体删除而不影响编译，换平台只换 frpc_random.h 内容。
#if __has_include("frpc_random.h")
#include "frpc_random.h"
#else
inline uint32_t frpc_platform_random(void) {
    // 伪随机兜底：用 micros() 做种子，保证每次启动序列不同。
    // 注意：伪随机用于加密不够安全，建议接入平台硬件 RNG（见 frpc_random.h）。
    static bool _seeded = false;
    if (!_seeded) { randomSeed(micros()); _seeded = true; }
    return random();
}
#endif

#pragma endregion // 第1区:网络抽象接口

/* ============================================================
 * 第 2 区：加密引擎（crypto）
 * 说明：AES-128-CFB 加解密 + PBKDF2 密钥派生（兼容 frp 协议）。
 * ============================================================ */
#pragma region 第2区:加密引擎(crypto)
namespace crypto {

// ============================================================
// AES-128 核心（纯软件实现，无外部依赖）
// ============================================================

// AES S-box
static const uint8_t AES_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

static void aes128_key_expand(const uint8_t key[16], uint8_t rk[176]) {
    memcpy(rk, key, 16);
    uint8_t rc = 1;
    for (int i = 16; i < 176; i += 4) {
        uint8_t t[4];
        memcpy(t, rk + i - 4, 4);
        if (i % 16 == 0) {
            uint8_t tmp = t[0]; t[0] = t[1]; t[1] = t[2]; t[2] = t[3]; t[3] = tmp;
            t[0] = AES_SBOX[t[0]]; t[1] = AES_SBOX[t[1]]; t[2] = AES_SBOX[t[2]]; t[3] = AES_SBOX[t[3]];
            t[0] ^= rc;
            rc = (uint8_t)((rc << 1) ^ ((rc & 0x80) ? 0x1b : 0));
        }
        rk[i + 0] = rk[i - 16 + 0] ^ t[0];
        rk[i + 1] = rk[i - 16 + 1] ^ t[1];
        rk[i + 2] = rk[i - 16 + 2] ^ t[2];
        rk[i + 3] = rk[i - 16 + 3] ^ t[3];
    }
}

static void aes128_encrypt_block(const uint8_t rk[176], uint8_t blk[16]) {
    uint8_t s[4][4];
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            s[r][c] = blk[c * 4 + r];
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            s[r][c] ^= rk[c * 4 + r];
    for (int round = 1; round <= 10; round++) {
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                s[r][c] = AES_SBOX[s[r][c]];
        for (int r = 1; r < 4; r++) {
            uint8_t tmp[4];
            for (int c = 0; c < 4; c++) tmp[c] = s[r][(c + r) & 3];
            for (int c = 0; c < 4; c++) s[r][c] = tmp[c];
        }
        if (round < 10) {
            for (int c = 0; c < 4; c++) {
                uint8_t a0 = s[0][c], a1 = s[1][c], a2 = s[2][c], a3 = s[3][c];
                s[0][c] = gmul(2, a0) ^ gmul(3, a1) ^ a2 ^ a3;
                s[1][c] = a0 ^ gmul(2, a1) ^ gmul(3, a2) ^ a3;
                s[2][c] = a0 ^ a1 ^ gmul(2, a2) ^ gmul(3, a3);
                s[3][c] = gmul(3, a0) ^ a1 ^ a2 ^ gmul(2, a3);
            }
        }
        for (int c = 0; c < 4; c++)
            for (int r = 0; r < 4; r++)
                s[r][c] ^= rk[round * 16 + c * 4 + r];
    }
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            blk[c * 4 + r] = s[r][c];
}

// ============================================================
// SHA1（用于 PBKDF2）
// ============================================================

#define SHA1_ROTL(x,n) (((x) << (n)) | ((x) >> (32-(n))))

struct Sha1Ctx {
    uint32_t state[5];
    uint64_t count;
    uint8_t  buffer[64];
};

static void sha1_transform(uint32_t state[5], const uint8_t block[64]) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)block[i*4]<<24 | (uint32_t)block[i*4+1]<<16 | (uint32_t)block[i*4+2]<<8 | (uint32_t)block[i*4+3];
    for (int i = 16; i < 80; i++)
        w[i] = SHA1_ROTL(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20)      { f = (b & c) | (~b & d);          k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d;                   k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else             { f = b ^ c ^ d;                   k = 0xCA62C1D6; }
        uint32_t t = SHA1_ROTL(a, 5) + f + e + k + w[i];
        e = d; d = c; c = SHA1_ROTL(b, 30); b = a; a = t;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

static void sha1_init(Sha1Ctx *ctx) {
    ctx->state[0] = 0x67452301; ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE; ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count = 0;
}

static void sha1_update(Sha1Ctx *ctx, const uint8_t *data, size_t len) {
    size_t i = (size_t)(ctx->count >> 3) & 63;
    ctx->count += (uint64_t)len << 3;
    if (i + len >= 64) {
        memcpy(ctx->buffer + i, data, 64 - i);
        sha1_transform(ctx->state, ctx->buffer);
        data += 64 - i; len -= 64 - i; i = 0;
        while (len >= 64) {
            sha1_transform(ctx->state, data);
            data += 64; len -= 64;
        }
    }
    memcpy(ctx->buffer + i, data, len);
}

static void sha1_final(uint8_t digest[20], Sha1Ctx *ctx) {
    uint8_t finalcount[8];
    for (int i = 0; i < 8; i++) finalcount[i] = (uint8_t)(ctx->count >> ((7-i)*8));
    uint8_t pad = 0x80;
    sha1_update(ctx, &pad, 1);
    while ((ctx->count >> 3 & 63) != 56) { pad = 0; sha1_update(ctx, &pad, 1); }
    sha1_update(ctx, finalcount, 8);
    for (int i = 0; i < 5; i++) {
        digest[i*4]   = (uint8_t)(ctx->state[i]>>24);
        digest[i*4+1] = (uint8_t)(ctx->state[i]>>16);
        digest[i*4+2] = (uint8_t)(ctx->state[i]>>8);
        digest[i*4+3] = (uint8_t)(ctx->state[i]);
    }
}

static void hmac_sha1(const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len, uint8_t out[20]) {
    uint8_t ipad[64], opad[64];
    memset(ipad, 0x36, 64); memset(opad, 0x5c, 64);
    for (size_t i = 0; i < key_len && i < 64; i++) {
        ipad[i] ^= key[i]; opad[i] ^= key[i];
    }
    Sha1Ctx sha;
    uint8_t inner[20];
    sha1_init(&sha); sha1_update(&sha, ipad, 64); sha1_update(&sha, data, data_len); sha1_final(inner, &sha);
    sha1_init(&sha); sha1_update(&sha, opad, 64); sha1_update(&sha, inner, 20); sha1_final(out, &sha);
}

static void pbkdf2_sha1(const uint8_t *pw, size_t pw_len,
                        const uint8_t *salt, size_t salt_len,
                        uint32_t iters, uint8_t *out, size_t out_len) {
    uint8_t U[20], T[20];
    uint8_t msg[128];
    size_t mlen = salt_len;
    if (mlen > sizeof(msg) - 4) mlen = sizeof(msg) - 4;
    memcpy(msg, salt, mlen);
    msg[mlen+0]=0; msg[mlen+1]=0; msg[mlen+2]=0; msg[mlen+3]=1;
    hmac_sha1(pw, pw_len, msg, mlen+4, U);
    memcpy(T, U, 20);
    for (uint32_t j = 1; j < iters; j++) {
        hmac_sha1(pw, pw_len, U, 20, U);
        for (int k = 0; k < 20; k++) T[k] ^= U[k];
    }
    memcpy(out, T, out_len);
}

// ============================================================
// AES-128-CFB 流加密上下文
// ============================================================

struct FrpCrypto {
    uint8_t key[16];
    uint8_t iv[16];
    uint8_t rk[176];
    size_t  offset;
    bool    initialized;
    bool    encrypt;   // true=加密方向(反馈=输出密文), false=解密方向(反馈=输入密文)
};

/**
 * @brief 从 token 派生 AES 密钥（PBKDF2-HMAC-SHA1, salt="frp", iter=64）
 */
inline void crypto_derive_key(const char *token, uint8_t key[16]) {
    pbkdf2_sha1((const uint8_t *)token, strlen(token),
                (const uint8_t *)"frp", 3, 64, key, 16);
}

/**
 * @brief 初始化加密器
 */
inline void crypto_encoder_init(FrpCrypto &c, const uint8_t key[16], const uint8_t iv[16]) {
    memcpy(c.key, key, 16);
    memcpy(c.iv, iv, 16);
    aes128_key_expand(key, c.rk);
    c.offset = 0;
    c.initialized = true;
    c.encrypt = true;
}

/**
 * @brief 初始化解密器
 */
inline void crypto_decoder_init(FrpCrypto &c, const uint8_t key[16], const uint8_t iv[16]) {
    memcpy(c.key, key, 16);
    memcpy(c.iv, iv, 16);
    aes128_key_expand(key, c.rk);
    c.offset = 0;
    c.initialized = true;
    c.encrypt = false;
}

/**
 * @brief AES-CFB 加密/解密（对称操作）
 *
 * 注意：CFB 模式的反馈必须是**密文**——
 *   - 加密方向：反馈 = 输出（明文 ^ keystream = 密文）
 *   - 解密方向：反馈 = 输入（收到的密文）
 * 绝不能把解密后的明文写回反馈缓冲，否则部分块（非 16 字节对齐）之后
 * 密钥流会与对端（frps 的 Go CFB128 实现）失步。
 */
inline void crypto_cfb_crypt(FrpCrypto &c, uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (c.offset == 0)
            aes128_encrypt_block(c.rk, c.iv);
        uint8_t k = c.iv[c.offset];
        uint8_t in = data[i];
        uint8_t out = in ^ k;
        data[i] = out;
        // 反馈必须是密文：加密时 out 是密文，解密时 in 是密文
        c.iv[c.offset] = c.encrypt ? out : in;
        c.offset = (c.offset + 1) & 0x0F;
    }
}

/**
 * @brief 生成随机 IV
 */
inline void crypto_gen_iv(uint8_t iv[16]) {
    for (int i = 0; i < 16; i++) {
        iv[i] = (uint8_t)(frpc_platform_random() & 0xFF);
    }
}

} // namespace crypto
using namespace crypto;   // 外部继续以短名调用加密函数（无需 crypto:: 前缀）
#pragma endregion // 第2区:加密引擎(crypto)

/* ============================================================
 * 第 3 区：协议字典（proto）
 * 说明：frp 消息帧定义、JSON 序列化、认证。
 * ============================================================ */
#pragma region 第3区:协议字典(proto)
#include <Arduino.h>
#include <ArduinoJson.h>
namespace proto {

// ============================================================
// 消息类型枚举（兼容 frp v0.10.0）
// ============================================================
enum MsgType : uint8_t {
    TypeLogin              = 'o',
    TypeLoginResp          = '1',
    TypeNewProxy           = 'p',
    TypeNewProxyResp       = '2',
    TypeCloseProxy         = 'c',
    TypeNewWorkConn        = 'w',
    TypeReqWorkConn        = 'r',
    TypeStartWorkConn      = 's',
    TypeNewVisitorConn     = 'v',
    TypeNewVisitorConnResp = '3',
    TypePing               = 'h',
    TypePong               = '4',
    TypeUDPPacket          = 'u',
    TypeNatHoleVisitor     = 'i',
    TypeNatHoleClient      = 'n',
    TypeNatHoleResp        = 'm',
    TypeNatHoleClientDetectOK = 'd',
    TypeNatHoleSid         = '5',
    TypeNatHoleReport      = '6'
};

// ============================================================
// 消息帧头（packed，兼容 frp 二进制格式）
// ============================================================
#pragma pack(push, 1)
struct MsgHdr {
    uint8_t  type;
    uint64_t length;    // 大端序，数据体长度
    uint8_t  data[];    // 柔性数组，指向数据体
};
#pragma pack(pop)

#define MSG_HDR_SIZE  9   // type(1) + length(8)

// 大端序 64 位转换（ESP32 是小端序）
inline uint64_t hton64(uint64_t v) {
    return ((uint64_t)htonl(v & 0xFFFFFFFF) << 32) | htonl(v >> 32);
}
inline uint64_t ntoh64(uint64_t v) {
    return ((uint64_t)ntohl(v & 0xFFFFFFFF) << 32) | ntohl(v >> 32);
}

// ============================================================
// 协议版本
// ============================================================
#define FRP_VERSION  "0.51.0"

// ============================================================
// 数据结构
// ============================================================

struct LoginReq {
    const char *version;
    const char *hostname;
    const char *os;
    const char *arch;
    const char *user;
    const char *privilege_key;
    int64_t     timestamp;
    const char *run_id;
    int         pool_count;
};

struct LoginResp {
    char version[32];
    char run_id[64];
    char error[128];
    bool has_error;
};

struct NewProxyReq {
    const char *proxy_name;
    const char *proxy_type;     // "tcp", "udp", "http", "https", "stcp", "xtcp", "tcpmux"
    bool        use_encryption;
    bool        use_compression;
    const char *group;
    const char *group_key;
    int         remote_port;
    const char *custom_domains;
    const char *subdomain;
    const char *locations;
    const char *host_header_rewrite;
    const char *http_user;
    const char *http_pwd;
    const char *sk;             // STCP/XTCP secret key
    const char *allow_users;
    const char *multiplexer;    // tcpmux
};

struct NewProxyResp {
    char proxy_name[64];
    char run_id[64];
    char error[128];
    int  remote_port;
};

struct WorkConn {
    const char *run_id;
    const char *privilege_key;
    int         timestamp;
};

struct StartWorkConnResp {
    char proxy_name[64];
};

// ============================================================
// MD5 计算（自包含实现，不依赖 mbedTLS 私有头文件）
// 参考 RFC 1321
// ============================================================

typedef struct {
    uint32_t total[2];
    uint32_t state[4];
    uint8_t  buffer[64];
} md5_context_t;

// MD5 常量
static const uint32_t MD5_T[] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

#define MD5_S(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define MD5_F(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
#define MD5_G(x, y, z) (((x) & (z)) | ((y) & (~(z))))
#define MD5_H(x, y, z) ((x) ^ (y) ^ (z))
#define MD5_I(x, y, z) ((y) ^ ((x) | (~(z))))

#define MD5_STEP(f, a, b, c, d, x, t, s) \
    (a) += f((b), (c), (d)) + (x) + (t); \
    (a) = MD5_S((a), (s)); \
    (a) += (b);

static void md5_init(md5_context_t *ctx) {
    ctx->total[0] = 0;
    ctx->total[1] = 0;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
}

static void md5_process(md5_context_t *ctx, const uint8_t data[64]) {
    uint32_t X[16];
    for (int i = 0; i < 16; i++) {
        X[i] = (uint32_t)data[i * 4]
             | ((uint32_t)data[i * 4 + 1] << 8)
             | ((uint32_t)data[i * 4 + 2] << 16)
             | ((uint32_t)data[i * 4 + 3] << 24);
    }

    uint32_t A = ctx->state[0];
    uint32_t B = ctx->state[1];
    uint32_t C = ctx->state[2];
    uint32_t D = ctx->state[3];

    // Round 1
    MD5_STEP(MD5_F, A, B, C, D, X[ 0], MD5_T[ 0],  7);
    MD5_STEP(MD5_F, D, A, B, C, X[ 1], MD5_T[ 1], 12);
    MD5_STEP(MD5_F, C, D, A, B, X[ 2], MD5_T[ 2], 17);
    MD5_STEP(MD5_F, B, C, D, A, X[ 3], MD5_T[ 3], 22);
    MD5_STEP(MD5_F, A, B, C, D, X[ 4], MD5_T[ 4],  7);
    MD5_STEP(MD5_F, D, A, B, C, X[ 5], MD5_T[ 5], 12);
    MD5_STEP(MD5_F, C, D, A, B, X[ 6], MD5_T[ 6], 17);
    MD5_STEP(MD5_F, B, C, D, A, X[ 7], MD5_T[ 7], 22);
    MD5_STEP(MD5_F, A, B, C, D, X[ 8], MD5_T[ 8],  7);
    MD5_STEP(MD5_F, D, A, B, C, X[ 9], MD5_T[ 9], 12);
    MD5_STEP(MD5_F, C, D, A, B, X[10], MD5_T[10], 17);
    MD5_STEP(MD5_F, B, C, D, A, X[11], MD5_T[11], 22);
    MD5_STEP(MD5_F, A, B, C, D, X[12], MD5_T[12],  7);
    MD5_STEP(MD5_F, D, A, B, C, X[13], MD5_T[13], 12);
    MD5_STEP(MD5_F, C, D, A, B, X[14], MD5_T[14], 17);
    MD5_STEP(MD5_F, B, C, D, A, X[15], MD5_T[15], 22);

    // Round 2
    MD5_STEP(MD5_G, A, B, C, D, X[ 1], MD5_T[16],  5);
    MD5_STEP(MD5_G, D, A, B, C, X[ 6], MD5_T[17],  9);
    MD5_STEP(MD5_G, C, D, A, B, X[11], MD5_T[18], 14);
    MD5_STEP(MD5_G, B, C, D, A, X[ 0], MD5_T[19], 20);
    MD5_STEP(MD5_G, A, B, C, D, X[ 5], MD5_T[20],  5);
    MD5_STEP(MD5_G, D, A, B, C, X[10], MD5_T[21],  9);
    MD5_STEP(MD5_G, C, D, A, B, X[15], MD5_T[22], 14);
    MD5_STEP(MD5_G, B, C, D, A, X[ 4], MD5_T[23], 20);
    MD5_STEP(MD5_G, A, B, C, D, X[ 9], MD5_T[24],  5);
    MD5_STEP(MD5_G, D, A, B, C, X[14], MD5_T[25],  9);
    MD5_STEP(MD5_G, C, D, A, B, X[ 3], MD5_T[26], 14);
    MD5_STEP(MD5_G, B, C, D, A, X[ 8], MD5_T[27], 20);
    MD5_STEP(MD5_G, A, B, C, D, X[13], MD5_T[28],  5);
    MD5_STEP(MD5_G, D, A, B, C, X[ 2], MD5_T[29],  9);
    MD5_STEP(MD5_G, C, D, A, B, X[ 7], MD5_T[30], 14);
    MD5_STEP(MD5_G, B, C, D, A, X[12], MD5_T[31], 20);

    // Round 3
    MD5_STEP(MD5_H, A, B, C, D, X[ 5], MD5_T[32],  4);
    MD5_STEP(MD5_H, D, A, B, C, X[ 8], MD5_T[33], 11);
    MD5_STEP(MD5_H, C, D, A, B, X[11], MD5_T[34], 16);
    MD5_STEP(MD5_H, B, C, D, A, X[14], MD5_T[35], 23);
    MD5_STEP(MD5_H, A, B, C, D, X[ 1], MD5_T[36],  4);
    MD5_STEP(MD5_H, D, A, B, C, X[ 4], MD5_T[37], 11);
    MD5_STEP(MD5_H, C, D, A, B, X[ 7], MD5_T[38], 16);
    MD5_STEP(MD5_H, B, C, D, A, X[10], MD5_T[39], 23);
    MD5_STEP(MD5_H, A, B, C, D, X[13], MD5_T[40],  4);
    MD5_STEP(MD5_H, D, A, B, C, X[ 0], MD5_T[41], 11);
    MD5_STEP(MD5_H, C, D, A, B, X[ 3], MD5_T[42], 16);
    MD5_STEP(MD5_H, B, C, D, A, X[ 6], MD5_T[43], 23);
    MD5_STEP(MD5_H, A, B, C, D, X[ 9], MD5_T[44],  4);
    MD5_STEP(MD5_H, D, A, B, C, X[12], MD5_T[45], 11);
    MD5_STEP(MD5_H, C, D, A, B, X[15], MD5_T[46], 16);
    MD5_STEP(MD5_H, B, C, D, A, X[ 2], MD5_T[47], 23);

    // Round 4
    MD5_STEP(MD5_I, A, B, C, D, X[ 0], MD5_T[48],  6);
    MD5_STEP(MD5_I, D, A, B, C, X[ 7], MD5_T[49], 10);
    MD5_STEP(MD5_I, C, D, A, B, X[14], MD5_T[50], 15);
    MD5_STEP(MD5_I, B, C, D, A, X[ 5], MD5_T[51], 21);
    MD5_STEP(MD5_I, A, B, C, D, X[12], MD5_T[52],  6);
    MD5_STEP(MD5_I, D, A, B, C, X[ 3], MD5_T[53], 10);
    MD5_STEP(MD5_I, C, D, A, B, X[10], MD5_T[54], 15);
    MD5_STEP(MD5_I, B, C, D, A, X[ 1], MD5_T[55], 21);
    MD5_STEP(MD5_I, A, B, C, D, X[ 8], MD5_T[56],  6);
    MD5_STEP(MD5_I, D, A, B, C, X[15], MD5_T[57], 10);
    MD5_STEP(MD5_I, C, D, A, B, X[ 6], MD5_T[58], 15);
    MD5_STEP(MD5_I, B, C, D, A, X[13], MD5_T[59], 21);
    MD5_STEP(MD5_I, A, B, C, D, X[ 4], MD5_T[60],  6);
    MD5_STEP(MD5_I, D, A, B, C, X[11], MD5_T[61], 10);
    MD5_STEP(MD5_I, C, D, A, B, X[ 2], MD5_T[62], 15);
    MD5_STEP(MD5_I, B, C, D, A, X[ 9], MD5_T[63], 21);

    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
}

static void md5_update(md5_context_t *ctx, const uint8_t *input, size_t len) {
    size_t fill = ctx->total[0] & 0x3F;
    ctx->total[0] += (uint32_t)len;
    if (ctx->total[0] < (uint32_t)len) ctx->total[1]++;
    ctx->total[1] += (uint32_t)(len >> 29);

    if (fill && (fill + len >= 64)) {
        size_t copy = 64 - fill;
        memcpy(ctx->buffer + fill, input, copy);
        md5_process(ctx, ctx->buffer);
        input += copy;
        len -= copy;
        fill = 0;
    }

    while (len >= 64) {
        md5_process(ctx, input);
        input += 64;
        len -= 64;
    }

    if (len > 0) {
        memcpy(ctx->buffer + fill, input, len);
    }
}

static void md5_finish(md5_context_t *ctx, uint8_t digest[16]) {
    uint8_t pad[64];
    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;

    uint32_t lo = ctx->total[0] * 8;
    uint32_t hi = (ctx->total[1] << 3) | (ctx->total[0] >> 29);

    size_t fill = ctx->total[0] & 0x3F;
    size_t pad_len = (fill < 56) ? (56 - fill) : (120 - fill);

    md5_update(ctx, pad, pad_len);

    // 追加长度（小端序）
    uint8_t len_buf[8];
    len_buf[0] = (uint8_t)(lo);
    len_buf[1] = (uint8_t)(lo >> 8);
    len_buf[2] = (uint8_t)(lo >> 16);
    len_buf[3] = (uint8_t)(lo >> 24);
    len_buf[4] = (uint8_t)(hi);
    len_buf[5] = (uint8_t)(hi >> 8);
    len_buf[6] = (uint8_t)(hi >> 16);
    len_buf[7] = (uint8_t)(hi >> 24);
    md5_update(ctx, len_buf, 8);

    for (int i = 0; i < 4; i++) {
        digest[i * 4]     = (uint8_t)(ctx->state[i]);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i] >> 24);
    }
}

inline bool calc_md5(const uint8_t *data, size_t len, uint8_t digest[16]) {
    if (!data || len == 0) return false;

    md5_context_t ctx;
    md5_init(&ctx);
    md5_update(&ctx, data, len);
    md5_finish(&ctx, digest);
    return true;
}

// ============================================================
// 认证密钥生成
// auth_key = MD5(token + timestamp)
// ============================================================

/**
 * @brief 纯 SNTP 校时 + 自维护时间（平台无关）
 *
 * 用 NetUDPStream 发 SNTP 请求获取 Unix 时间，之后用 millis() 自维护，
 * 完全不依赖平台专属的 configTime()，换任意平台（树莓派/STM32/ESP32）皆可。
 *
 * NTP 服务器 IP 需由调用方传入（见 FrpcClient::syncTime 的 ntp_ip 参数）。
 * 注意：NTP 服务器 IP 可能变动，若校时失败请检查/更新 IP。
 */
class Clock {
public:
    /**
     * @brief 校时：向 NTP 服务器发 SNTP 请求
     * @param factory 网络工厂（创建 UDP 用）
     * @param ntp_ip  NTP 服务器 IP（如 "203.107.6.88" 阿里云 NTP）
     * @param timeout_ms 等待响应超时
     * @return true 校时成功
     */
    bool sync(NetStreamFactory *factory, const char *ntp_ip, uint32_t timeout_ms = 2000) {
        if (!factory || !ntp_ip) return false;
        NetUDPStream *udp = factory->createUDPStream();
        if (!udp) return false;
        udp->begin(0);

        // SNTP 请求包（48 字节，NTP v4 client，li=0 vn=4 mode=3 => 0x1B）
        uint8_t req[48];
        memset(req, 0, sizeof(req));
        req[0] = 0x1B;

        udp->beginPacket(ntp_ip, 123);
        udp->write(req, sizeof(req));
        bool sent = udp->endPacket();

        // 等待响应
        bool ok = false;
        uint32_t t0 = millis();
        uint8_t resp[48];
        while (sent && millis() - t0 < timeout_ms) {
            if (udp->parsePacket() >= 48) {
                int n = udp->read(resp, sizeof(resp));
                if (n >= 48) {
                    // SNTP 响应第 40-43 字节 = 发送时间戳（自 1900 年秒数）
                    uint32_t secs1900 = ((uint32_t)resp[40] << 24) | ((uint32_t)resp[41] << 16)
                                       | ((uint32_t)resp[42] << 8) | resp[43];
                    _unix_time = secs1900 - 2208988800UL;  // 1900→1970 偏移
                    _base_ms = millis();
                    _synced = true;
                    ok = true;
                }
                break;
            }
            delay(1);
        }
        udp->stop();
        delete udp;
        return ok;
    }

    /**
     * @brief 获取当前 Unix 时间（秒）
     * @return 当前 Unix 时间戳；未校时返回 0
     */
    uint32_t now() {
        if (!_synced) return 0;
        // millis() 约 49.7 天溢出归零：若差值变负说明已溢出，时钟失效返回 0
        // （上层会因此触发重新校时）
        int32_t elapsed_ms = (int32_t)(millis() - _base_ms);
        if (elapsed_ms < 0) {
            _synced = false;   // 标记失效，触发重新校时
            return 0;
        }
        return _unix_time + (uint32_t)elapsed_ms / 1000;
    }

    bool synced() const { return _synced; }

private:
    uint32_t _unix_time = 0;   // 校时时刻的 Unix 时间（秒）
    uint32_t _base_ms   = 0;   // 校时时刻的 millis
    bool     _synced    = false;
};

inline char *get_auth_key(const char *token, time_t *out_timestamp, Clock &clock) {
    if (!token || !out_timestamp) return nullptr;

    *out_timestamp = clock.now();

    // 构造 seed: token + timestamp
    char seed[256];
    int n = snprintf(seed, sizeof(seed), "%s%lld", token, (long long)*out_timestamp);
    if (n < 0 || n >= (int)sizeof(seed)) return nullptr;

    // MD5
    uint8_t digest[16];
    if (!calc_md5((const uint8_t *)seed, strlen(seed), digest)) return nullptr;

    // 转 hex 字符串
    char *auth_key = (char *)malloc(33);
    if (!auth_key) return nullptr;

    for (int i = 0; i < 16; i++) {
        snprintf(auth_key + i * 2, 3, "%02x", digest[i]);
    }
    auth_key[32] = '\0';
    return auth_key;
}

// ============================================================
// JSON 序列化 — Login 请求
// ============================================================
inline size_t login_request_marshal(const LoginReq &req, char **out) {
    if (!out) return 0;

    JsonDocument doc;
    doc["version"]       = req.version ? req.version : "";
    doc["hostname"]      = req.hostname ? req.hostname : "";
    doc["os"]            = req.os ? req.os : "";
    doc["arch"]          = req.arch ? req.arch : "";
    doc["privilege_key"] = req.privilege_key ? req.privilege_key : "";
    doc["timestamp"]     = req.timestamp;
    doc["run_id"]        = req.run_id ? req.run_id : "";
    doc["pool_count"]    = req.pool_count;

    if (req.user && req.user[0]) {
        doc["user"] = req.user;
    }

    size_t len = measureJson(doc);
    *out = (char *)malloc(len + 1);
    if (!*out) return 0;

    serializeJson(doc, *out, len + 1);
    return len;
}

// ============================================================
// JSON 序列化 — NewProxy 请求
// ============================================================
inline size_t new_proxy_marshal(const NewProxyReq &req, char **out) {
    if (!out) return 0;

    JsonDocument doc;
    doc["proxy_name"]     = req.proxy_name ? req.proxy_name : "";

    // 代理类型映射: socks5/mstsc → "tcp"
    const char *ptype = req.proxy_type ? req.proxy_type : "tcp";
    if (strcmp(ptype, "socks5") == 0 || strcmp(ptype, "mstsc") == 0) {
        ptype = "tcp";
    }
    doc["proxy_type"]     = ptype;
    doc["use_encryption"] = req.use_encryption;
    doc["use_compression"] = req.use_compression;

    if (req.group && req.group[0]) {
        doc["group"] = req.group;
    }
    if (req.group_key && req.group_key[0]) {
        doc["group_key"] = req.group_key;
    }

    // custom_domains 或 remote_port
    if (req.custom_domains && req.custom_domains[0]) {
        JsonArray arr = doc["custom_domains"].to<JsonArray>();
        // 逗号分隔
        char buf[256];
        strncpy(buf, req.custom_domains, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        char *p = strtok(buf, ",");
        while (p) {
            arr.add(p);
            p = strtok(nullptr, ",");
        }
    } else {
        doc["remote_port"] = req.remote_port;
    }

    if (req.subdomain && req.subdomain[0]) {
        doc["subdomain"] = req.subdomain;
    }

    if (req.locations && req.locations[0]) {
        JsonArray arr = doc["locations"].to<JsonArray>();
        char buf[256];
        strncpy(buf, req.locations, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        char *p = strtok(buf, ",");
        while (p) {
            arr.add(p);
            p = strtok(nullptr, ",");
        }
    }

    if (req.host_header_rewrite && req.host_header_rewrite[0]) {
        doc["host_header_rewrite"] = req.host_header_rewrite;
    }
    if (req.http_user && req.http_user[0]) {
        doc["http_user"] = req.http_user;
    }
    if (req.http_pwd && req.http_pwd[0]) {
        doc["http_pwd"] = req.http_pwd;
    }

    // STCP/XTCP
    if (req.sk && req.sk[0]) {
        doc["sk"] = req.sk;
    }
    if (req.allow_users && req.allow_users[0]) {
        JsonArray arr = doc["allow_users"].to<JsonArray>();
        char buf[256];
        strncpy(buf, req.allow_users, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        char *p = strtok(buf, ",");
        while (p) {
            while (*p == ' ') p++;
            arr.add(p);
            p = strtok(nullptr, ",");
        }
    }

    // TCPMux
    if (req.multiplexer && req.multiplexer[0]) {
        doc["multiplexer"] = req.multiplexer;
    }

    size_t len = measureJson(doc);
    *out = (char *)malloc(len + 1);
    if (!*out) return 0;

    serializeJson(doc, *out, len + 1);
    return len;
}

// ============================================================
// JSON 序列化 — NewWorkConn 请求
// ============================================================
inline size_t work_conn_marshal(const WorkConn &wc, char **out) {
    if (!out) return 0;

    JsonDocument doc;
    doc["run_id"] = wc.run_id ? wc.run_id : "";

    // frp 0.51.0+ 需要 privilege_key 和 timestamp
    if (wc.privilege_key && wc.privilege_key[0]) {
        doc["privilege_key"] = wc.privilege_key;
    }
    if (wc.timestamp != 0) {
        doc["timestamp"] = wc.timestamp;
    }

    size_t len = measureJson(doc);
    *out = (char *)malloc(len + 1);
    if (!*out) return 0;

    serializeJson(doc, *out, len + 1);
    return len;
}

// ============================================================
// JSON 反序列化 — Login 响应
// ============================================================
inline bool login_resp_unmarshal(const char *json, LoginResp &resp) {
    if (!json) return false;

    memset(&resp, 0, sizeof(resp));

    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, json);
    if (err) return false;

    if (doc["version"].is<const char *>()) {
        strncpy(resp.version, doc["version"], sizeof(resp.version) - 1);
    }
    if (doc["run_id"].is<const char *>()) {
        strncpy(resp.run_id, doc["run_id"], sizeof(resp.run_id) - 1);
    }
    if (doc["error"].is<const char *>() && strlen(doc["error"]) > 0) {
        strncpy(resp.error, doc["error"], sizeof(resp.error) - 1);
        resp.has_error = true;
    }

    // 验证: run_id 必须有效
    return (strlen(resp.run_id) > 1);
}

// ============================================================
// JSON 反序列化 — NewProxy 响应
// ============================================================
inline bool new_proxy_resp_unmarshal(const char *json, NewProxyResp &resp) {
    if (!json) return false;

    memset(&resp, 0, sizeof(resp));

    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, json);
    if (err) return false;

    if (doc["proxy_name"].is<const char *>()) {
        strncpy(resp.proxy_name, doc["proxy_name"], sizeof(resp.proxy_name) - 1);
    }
    if (doc["run_id"].is<const char *>()) {
        strncpy(resp.run_id, doc["run_id"], sizeof(resp.run_id) - 1);
    }
    if (doc["error"].is<const char *>()) {
        strncpy(resp.error, doc["error"], sizeof(resp.error) - 1);
    }
    if (doc["remote_port"].is<int>()) {
        resp.remote_port = doc["remote_port"];
    }

    return (strlen(resp.proxy_name) > 0);
}

// ============================================================
// JSON 反序列化 — StartWorkConn 响应
// ============================================================
inline bool start_work_conn_unmarshal(const char *json, StartWorkConnResp &resp) {
    if (!json) return false;

    memset(&resp, 0, sizeof(resp));

    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, json);
    if (err) return false;

    if (doc["proxy_name"].is<const char *>()) {
        strncpy(resp.proxy_name, doc["proxy_name"], sizeof(resp.proxy_name) - 1);
    }

    return (strlen(resp.proxy_name) > 0);
}

// ============================================================
// 消息帧构建与发送辅助
// ============================================================

/**
 * @brief 构建完整的消息帧
 * @param type   消息类型
 * @param data   数据体
 * @param len    数据体长度
 * @param out    输出缓冲区（调用者负责 free）
 * @return       帧总大小，0 表示失败
 */
inline size_t build_msg_frame(MsgType type, const char *data, size_t len, uint8_t **out) {
    if (!out) return 0;

    size_t total = MSG_HDR_SIZE + len;
    *out = (uint8_t *)malloc(total);
    if (!*out) return 0;

    MsgHdr *hdr = (MsgHdr *)*out;
    hdr->type   = (uint8_t)type;
    hdr->length = hton64(len);

    if (len > 0 && data) {
        memcpy(hdr->data, data, len);
    }

    return total;
}

// ============================================================
// base64 编解码（RFC 4648 标准，带 padding）
// 用于 UDPPacket 消息的 data 字段（Go []byte 的 JSON 序列化）
// ============================================================

static const char B64_ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * @brief base64 编码
 * @return 编码后长度（不含 NUL），失败返回 0
 */
inline size_t base64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap) {
    if (!in || !out) return 0;
    size_t olen = ((in_len + 2) / 3) * 4;
    if (olen + 1 > out_cap) return 0;
    size_t i = 0, o = 0;
    while (i + 3 <= in_len) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[o++] = B64_ALPHABET[(v >> 18) & 0x3F];
        out[o++] = B64_ALPHABET[(v >> 12) & 0x3F];
        out[o++] = B64_ALPHABET[(v >> 6) & 0x3F];
        out[o++] = B64_ALPHABET[v & 0x3F];
        i += 3;
    }
    size_t rem = in_len - i;
    if (rem == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        out[o++] = B64_ALPHABET[(v >> 18) & 0x3F];
        out[o++] = B64_ALPHABET[(v >> 12) & 0x3F];
        out[o++] = '=';
        out[o++] = '=';
    } else if (rem == 2) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
        out[o++] = B64_ALPHABET[(v >> 18) & 0x3F];
        out[o++] = B64_ALPHABET[(v >> 12) & 0x3F];
        out[o++] = B64_ALPHABET[(v >> 6) & 0x3F];
        out[o++] = '=';
    }
    out[o] = '\0';
    return o;
}

inline int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/**
 * @brief base64 解码
 * @return 解码后字节数，失败返回 0
 */
inline size_t base64_decode(const char *in, size_t in_len, uint8_t *out, size_t out_cap) {
    if (!in || !out) return 0;
    size_t o = 0;
    uint32_t buf = 0;
    int bits = 0;
    for (size_t i = 0; i < in_len; i++) {
        char c = in[i];
        if (c == '=' || c == '\0') break;
        int v = b64_val(c);
        if (v < 0) continue;
        buf = (buf << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o < out_cap) out[o++] = (uint8_t)((buf >> bits) & 0xFF);
        }
    }
    return o;
}

// ============================================================
// UDP 数据包消息（frp v1 wire protocol，JSON 帧）
// 服务器/客户端互发：{"c":"<base64数据>","r":{"IP":"用户IP","Port":用户端口}}
// l（LocalAddr）通常省略
// ============================================================
struct UdpPacketMsg {
    uint8_t *data;          // 数据（调用者 free）
    size_t   data_len;
    char     remote_ip[16]; // 用户侧 IP（r.IP）
    uint16_t remote_port;   // 用户侧端口（r.Port）
};

/**
 * @brief 解析 UDPPacket JSON
 */
inline bool udp_packet_unmarshal(const char *json, UdpPacketMsg &out) {
    if (!json) return false;
    memset(&out, 0, sizeof(out));

    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, json);
    if (err) return false;

    const char *c = doc["c"] | "";
    size_t clen = strlen(c);
    if (clen > 0) {
        out.data = (uint8_t *)malloc(clen);  // base64 解码后 ≤ 原长
        if (!out.data) return false;
        out.data_len = base64_decode(c, clen, out.data, clen);
    }
    strncpy(out.remote_ip, doc["r"]["IP"] | "", sizeof(out.remote_ip) - 1);
    out.remote_port = doc["r"]["Port"] | 0;
    return true;
}

/**
 * @brief 序列化 UDPPacket JSON
 * @note 手动拼接（不用 ArduinoJson）：视频流每包都要序列化，ArduinoJson 的
 *       JsonDocument 创建/序列化开销大，是吞吐瓶颈之一。
 */
inline size_t udp_packet_marshal(const UdpPacketMsg &pkt, char **out) {
    if (!out) return 0;
    if (!pkt.data || pkt.data_len == 0) return 0;

    char b64[4096];
    size_t blen = base64_encode(pkt.data, pkt.data_len, b64, sizeof(b64));
    if (blen == 0) return 0;

    // {"c":"<b64>","r":{"IP":"<ip>","Port":<port>}}
    size_t cap = blen + 64;
    char *json = (char *)malloc(cap);
    if (!json) return 0;
    int n = snprintf(json, cap, "{\"c\":\"%s\",\"r\":{\"IP\":\"%s\",\"Port\":%u}}",
                     b64, pkt.remote_ip, (unsigned)pkt.remote_port);
    if (n <= 0) { free(json); return 0; }
    *out = json;
    return (size_t)n;
}

} // namespace proto
using namespace proto;   // 外部继续以短名调用协议结构/函数（无需 proto:: 前缀）
#pragma endregion // 第3区:协议字典(proto)

/* ============================================================
 * 第 4 区：yamux 帧层（frpc_tcp）
 * 说明：TCP 连接管理 + yamux 多路复用帧封装。
 * ============================================================ */
#pragma region 第4区:yamux帧层(frpc_tcp)


// 网络抽象层：基于 lwIP 系统 socket，与 WiFi/以太网介质完全解耦
// （WiFi 连接由 wifi_manager.h 负责，这里只做 TCP 通信）

// ============================================================
// TCPMux 协议常量（与 frp 兼容）
// ============================================================
#define TMUX_VER            0   // frp TCPMux 协议版本号为 0（不是 1！）
#define TMUX_HDR_SIZE       12   // ver(1)+type(1)+flags(2)+stream_id(4)+length(4)

enum TcpMuxType  { TMUX_DATA = 0, TMUX_WIN_UPDATE = 1, TMUX_PING = 2, TMUX_GO_AWAY = 3 };
enum TcpMuxFlag  { TMUX_FLAG_ZERO = 0, TMUX_FLAG_SYN = 1, TMUX_FLAG_ACK = 2, TMUX_FLAG_FIN = 4, TMUX_FLAG_RST = 8 };
enum TcpMuxState { TMUX_INIT = 0, TMUX_SYN_SEND, TMUX_SYN_RECEIVED, TMUX_ESTABLISHED, TMUX_LOCAL_CLOSE, TMUX_REMOTE_CLOSE, TMUX_CLOSED, TMUX_RESET };

#pragma pack(push, 1)
struct TmuxHdr {
    uint8_t  version;
    uint8_t  type;
    uint16_t flags;       // 网络序
    uint32_t stream_id;   // 网络序
    uint32_t length;      // 网络序
};
#pragma pack(pop)

// ============================================================
// TCP 连接状态
// ============================================================
enum class TcpState : uint8_t {
    IDLE, CONNECTING, CONNECTED, CLOSED
};

// ============================================================
// FrpcTcp — TCP 连接 + TCPMux
// ============================================================
class FrpcTcp {
public:
    FrpcTcp();
    ~FrpcTcp();

    // ---- 连接 ----
    bool connect(const char *host, uint16_t port);
    void close();
    void loop();

    // 注入平台网络工厂（创建底层 NetStream；在 connect 前调用）
    void setFactory(NetStreamFactory *f) { _factory = f; }

    TcpState state() const { return _state; }
    bool isConnected() const { return _state == TcpState::CONNECTED; }

    // ---- TCPMux 发送 ----

    /**
     * @brief 发送 WINDOW_UPDATE 帧（用于建立/维护 TCPMux 流）
     * @param stream_id 流 ID
     * @param flags     SYN/ACK/FIN 等标志
     * @param length    窗口增量
     */
    void send_win_update(uint32_t stream_id, uint16_t flags, uint32_t length);

    /**
     * @brief 通知 frps 关闭 work 流（yamux FIN：WINDOW_UPDATE+FIN, len=0）
     * 本地连接断开删除 work 流时必须发送，否则 frps 的 work 流悬挂、
     * 对应公网连接不被关闭（实测：moonlight RTSP 握手悬挂超时的根因）
     */
    void send_fin(uint32_t stream_id);

    /**
     * @brief 通过 TCPMux DATA 帧发送数据
     * @param stream_id 流 ID
     * @param flags     标志（首次发送用 SYN）
     * @param data      数据
     * @param len       长度
     * @return 实际发送字节数（含帧头）
     */
    size_t send_data(uint32_t stream_id, uint16_t flags, const uint8_t *data, size_t len);

    /**
     * @brief 发送 frp 消息（通过 TCPMux DATA 帧）
     * @param stream_id 流 ID
     * @param type      frp 消息类型
     * @param data      JSON 数据
     * @param len       JSON 长度
     */
    bool send_msg(uint32_t stream_id, MsgType type, const char *data, size_t len);

    // ---- TCPMux 接收 ----

    /**
     * @brief 尝试接收一个 TCPMux 帧
     * @param out_hdr  输出帧头
     * @param out_data 输出数据（调用者 free），可能为 nullptr
     * @param out_len  输出数据长度
     * @return true 收到完整帧
     */
    bool recv_frame(TmuxHdr &out_hdr, uint8_t **out_data, size_t &out_len);

    /**
     * @brief 接收并解析 frp 消息（自动处理 TCPMux 解封装）
     * @param out_stream_id 输出流 ID
     * @param out_type      输出消息类型
     * @param out_data      输出数据（调用者 free）
     * @param out_len       输出数据长度
     * @return true 收到完整消息
     */
    bool recv_msg(uint32_t &out_stream_id, MsgType &out_type, uint8_t **out_data, size_t &out_len);

    // ---- 原始读写（绕过 TCPMux） ----
    size_t raw_write(const uint8_t *data, size_t len);
    int raw_available();
    int raw_read(uint8_t *buf, size_t max_len);
    bool raw_connected();

    // ---- 诊断 ----
    size_t diagPendingLen() const { return _pending ? _pending_len : 0; }
    size_t diagPendingNeed() const { return _pending ? _pending_need : 0; }
    size_t diagBufLen() const { return _buf_len; }

private:
    void _recv_to_buf();

    NetStream *_client;
    NetStreamFactory *_factory;   // 平台注入：创建底层网络流
    TcpState   _state;
    char       _host[64];
    uint16_t   _port;
    uint32_t   _connect_start;

    // 流状态（用于管理 TCPMux SYN/ACK 标志）
    TcpMuxState _stream_state;

    // 接收缓冲（32KB：frps 的 yamux 帧最大 16KB，需容纳多个帧 + 帧头）
    static const size_t BUF_SIZE = 32768;
    uint8_t  _buf[BUF_SIZE];
    size_t   _buf_len;

    // 非阻塞大帧读取状态（frps 的 yamux 帧最大可达 256KB，
    // 同步凑满会冻结帧循环导致 yamux PING 无 ACK 被 frps 关闭——实测根因）
    uint8_t *_pending;       // 已读部分（malloc），帧未完成时为非空
    size_t   _pending_len;   // 已读字节数
    size_t   _pending_need;  // 帧总数据长度
    uint32_t _pending_sid;   // 帧所属 stream_id
    uint32_t _pending_last_log;  // 诊断：pending 卡住时限频打印
};

// ============================================================
// 实现
// ============================================================

FrpcTcp::FrpcTcp()
    : _client(nullptr), _state(TcpState::IDLE), _port(0), _connect_start(0), _buf_len(0),
      _stream_state(TMUX_INIT), _factory(nullptr), _pending(nullptr), _pending_len(0), _pending_need(0), _pending_sid(0)
{
    memset(_host, 0, sizeof(_host));
    memset(_buf, 0, sizeof(_buf));
}

FrpcTcp::~FrpcTcp() { close(); }

bool FrpcTcp::connect(const char *host, uint16_t port) {
    // 释放旧连接
    if (_client) {
        if (_client->connected()) _client->stop();
        delete _client;
        _client = nullptr;
    }
    _client = (_factory ? _factory->createStream() : nullptr);
    _client->setTimeout(1000);  // 读取超时 1 秒（readBytes 需凑满帧长；100ms 在公网链路下帧易截断）

    strncpy(_host, host, sizeof(_host) - 1);
    _host[sizeof(_host) - 1] = '\0';
    _port = port;
    _connect_start = millis();
    _buf_len = 0;
    _stream_state = TMUX_INIT;
    if (_pending) { free(_pending); _pending = nullptr; _pending_len = 0; _pending_need = 0; }

    if (_client->connect(host, port)) {
        _state = TcpState::CONNECTED;
        Serial.printf("[TCP] Connected to %s:%d\n", host, port);
        return true;
    }
    _state = TcpState::CONNECTING;
    Serial.printf("[TCP] Connecting to %s:%d...\n", host, port);
    return false;
}

void FrpcTcp::close() {
    if (_client) {
        if (_client->connected()) _client->stop();
        delete _client;
        _client = nullptr;
    }
    _state = TcpState::CLOSED;
    _buf_len = 0;
    if (_pending) { free(_pending); _pending = nullptr; _pending_len = 0; _pending_need = 0; }
}

void FrpcTcp::loop() {
    if (!_client) return;
    if (_state == TcpState::CONNECTING) {
        if (_client->connected()) {
            _state = TcpState::CONNECTED;
            Serial.printf("[TCP] Connected to %s:%d\n", _host, _port);
        } else if (millis() - _connect_start > 15000) {
            Serial.printf("[TCP] Timeout: %s:%d\n", _host, _port);
            close();
        }
        return;
    }
    // 注意：NetSocket::connected() 基于内部状态 + recv/send 失败自动更新
    // 不要仅凭它来判断断开，让 recv 失败来自然检测
    _recv_to_buf();
}

// ---- 发送 ----

void FrpcTcp::send_win_update(uint32_t stream_id, uint16_t flags, uint32_t length) {
    if (_state != TcpState::CONNECTED || !_client) return;

    TmuxHdr hdr;
    hdr.version   = TMUX_VER;
    hdr.type      = TMUX_WIN_UPDATE;
    hdr.flags     = htons(flags);
    hdr.stream_id = htonl(stream_id);
    hdr.length    = htonl(length);

    // 循环写入确保全部发送
    size_t total = 0;
    uint32_t t0 = millis();
    while (total < sizeof(hdr)) {
        size_t n = _client->write((const uint8_t *)&hdr + total, sizeof(hdr) - total);
        if (n > 0) { total += n; t0 = millis(); continue; }
        delay(1);
        // 短超时：写 WU 帧卡住会阻塞帧循环导致 yamux keepalive PING ACK 延迟（frps 超时关闭）
        if (millis() - t0 > 1000) {
            Serial.printf("[TCP] win_update timeout sid=%u, marking CLOSED\n", stream_id);
            _state = TcpState::CLOSED;
            break;
        }
    }
    // 注意：不能调用 flush()！lwIP 发送缓冲满时 write 返回 0（由调用方循环处理），
    // 数据流量大时会造成秒级阻塞，帧循环被冻结 → frps yamux PING 无 ACK → keepalive timeout（实测根因）

    // 更新流状态（参考 frpc.ino get_send_flags）
    if ((flags & TMUX_FLAG_SYN) && _stream_state == TMUX_INIT) {
        _stream_state = TMUX_SYN_SEND;
    }
}

void FrpcTcp::send_fin(uint32_t stream_id) {
    // yamux 流关闭帧：WINDOW_UPDATE + FIN，len=0（与 fatedier/yamux Stream.Close 一致）
    send_win_update(stream_id, TMUX_FLAG_FIN, 0);
}

size_t FrpcTcp::send_data(uint32_t stream_id, uint16_t flags, const uint8_t *data, size_t len) {
    if (_state != TcpState::CONNECTED || !_client) return 0;

    TmuxHdr hdr;
    hdr.version   = TMUX_VER;
    hdr.type      = TMUX_DATA;
    hdr.flags     = htons(flags);
    hdr.stream_id = htonl(stream_id);
    hdr.length    = htonl((uint32_t)len);

    // 循环写入确保全部发送
    size_t w1 = 0;
    {
        size_t total = 0;
        uint32_t t0 = millis();
        uint32_t blocked = 0;
        while (total < sizeof(hdr)) {
            size_t w = _client->write((const uint8_t *)&hdr + total, sizeof(hdr) - total);
            if (w > 0) { total += w; t0 = millis(); continue; }
            delay(1);
            blocked++;
            // 发送超时：标记连接错误，禁止部分发送（yamux 帧不完整会错乱导致 frps 关闭）
            if (millis() - t0 > 1000) {
                Serial.printf("[TCP] send hdr timeout sid=%u len=%u (wrote %u), marking CLOSED\n",
                              stream_id, (unsigned)len, (unsigned)total);
                _state = TcpState::CLOSED;
                return w1 + total;
            }
        }
        if (blocked > 20) {
            Serial.printf("[TCP] write blocked %u times (hdr)\n", (unsigned)blocked);
        }
        w1 = total;
    }
    size_t w2 = 0;
    if (data && len > 0) {
        size_t total = 0;
        uint32_t t0 = millis();
        uint32_t blocked = 0;
        // 分小块（4KB）写入：lwIP 发送缓冲小（默认 ~5KB），整块 16KB 写会
        // 被缓冲满阻塞（write 返回 0 → delay 循环），大流量时拖死帧循环。
        // 小块写让 lwIP 缓冲吸收积压，帧循环不被写操作长时间阻塞。
        while (total < len) {
            size_t chunk = (len - total > 4096) ? 4096 : (len - total);
            size_t w = _client->write(data + total, chunk);
            if (w > 0) { total += w; t0 = millis(); continue; }
            delay(1);
            blocked++;
            if (millis() - t0 > 1000) {
                Serial.printf("[TCP] send data timeout sid=%u len=%u (wrote %u), marking CLOSED\n",
                              stream_id, (unsigned)len, (unsigned)total);
                _state = TcpState::CLOSED;
                return w1 + total;
            }
        }
        if (blocked > 20) {
            Serial.printf("[TCP] write blocked %u times (data)\n", (unsigned)blocked);
        }
        w2 = total;
    }
    return w1 + w2;
}

bool FrpcTcp::send_msg(uint32_t stream_id, MsgType type, const char *data, size_t len) {
    // 构建 frp 消息帧
    uint8_t *frame = nullptr;
    size_t total = build_msg_frame(type, data, len, &frame);
    if (!frame || total == 0) return false;

    // 根据流状态决定 flags（参考 frpc.ino get_send_flags）
    uint16_t flags = 0;
    switch (_stream_state) {
        case TMUX_INIT:
            flags |= TMUX_FLAG_SYN;
            _stream_state = TMUX_SYN_SEND;
            break;
        case TMUX_SYN_RECEIVED:
            flags |= TMUX_FLAG_ACK;
            _stream_state = TMUX_ESTABLISHED;
            break;
        default:
            break;
    }

    // 通过 TCPMux DATA 帧发送
    size_t sent = send_data(stream_id, flags, frame, total);
    free(frame);

    return (sent >= TMUX_HDR_SIZE + total);
}

// ---- 接收 ----

void FrpcTcp::_recv_to_buf() {
    if (_state != TcpState::CONNECTED || !_client) return;
    int avail = _client->available();
    if (avail <= 0) return;

    size_t space = BUF_SIZE - _buf_len;
    if (space == 0) {
        // 缓冲满：不读取也不清空（清空会丢帧导致 yamux 流错乱！），
        // 等帧循环消费；lwIP 侧 TCP 窗口会自动停住 frps 发送（正确流控）
        return;
    }
    size_t to_read = (size_t)avail < space ? (size_t)avail : space;
    int n = _client->read(_buf + _buf_len, to_read);
    if (n > 0) _buf_len += n;
}

bool FrpcTcp::recv_frame(TmuxHdr &out_hdr, uint8_t **out_data, size_t &out_len) {
    *out_data = nullptr;
    out_len = 0;

    // ---- 非阻塞大帧读取：帧数据未到齐时留在 _pending，返回 false 等下次 loop ----
    if (_pending) {
        size_t from_buf = _buf_len < (_pending_need - _pending_len) ? _buf_len : (_pending_need - _pending_len);
        if (from_buf > 0) {
            memcpy(_pending + _pending_len, _buf, from_buf);
            memmove(_buf, _buf + from_buf, _buf_len - from_buf);
            _buf_len -= from_buf;
            _pending_len += from_buf;
        }
        // 诊断：pending 帧超过 1s 未完成且无进展时限频打印（限 2s 一次）
        if (_pending_len < _pending_need) {
            uint32_t now = millis();
            if (now - _pending_last_log > 2000) {
                _pending_last_log = now;
                Serial.printf("[TCP] PENDING stall: %u/%u buf=%u avail=%d\n",
                              (unsigned)_pending_len, (unsigned)_pending_need,
                              (unsigned)_buf_len, raw_available());
            }
        }
        if (_pending_len >= _pending_need) {
            // 帧完成
            TmuxHdr h;
            h.version   = 0;
            h.type      = TMUX_DATA;
            h.flags     = 0;
            h.stream_id = htonl(_pending_sid);
            h.length    = htonl((uint32_t)_pending_need);
            out_hdr = h;
            *out_data = _pending;
            out_len = _pending_need;
            _pending = nullptr;
            _pending_len = 0;
            _pending_need = 0;
            return true;
        }
        return false;  // 等下次 loop（不阻塞帧循环，PING 可及时响应）
    }

    // 帧头必须完整在缓冲中
    if (_buf_len < TMUX_HDR_SIZE) return false;

    TmuxHdr *hdr = (TmuxHdr *)_buf;
    // 先保存帧头字段（memmove 后 hdr 指针失效！）
    const uint8_t ver = hdr->version;
    const uint8_t type = hdr->type;
    const uint32_t data_len = ntohl(hdr->length);
    const uint32_t sid = ntohl(hdr->stream_id);
    (void)ver;

    // 检查版本
    if (ver != TMUX_VER) {
        Serial.printf("[TCP] Bad TMUX version: %d (buf_len=%u)\n", ver, (unsigned)_buf_len);
        _buf_len = 0;
        return false;
    }

    out_hdr = *hdr;  // 网络序原样（调用方自行 ntohl）
    // 消费帧头
    memmove(_buf, _buf + TMUX_HDR_SIZE, _buf_len - TMUX_HDR_SIZE);
    _buf_len -= TMUX_HDR_SIZE;

    // PING / WINDOW_UPDATE / GO_AWAY：无 payload（length 是 ping_id / 窗口增量 / 错误码）
    if (type != TMUX_DATA) {
        return true;
    }

    // DATA 帧：从缓冲拿数据，未到齐则启动 pending（非阻塞）
    if (data_len > 0) {
        uint8_t *buf = (uint8_t *)malloc(data_len);
        if (!buf) {
            _state = TcpState::CLOSED;
            return false;
        }
        size_t from_buf = _buf_len < data_len ? _buf_len : data_len;
        if (from_buf > 0) {
            memcpy(buf, _buf, from_buf);
            memmove(_buf, _buf + from_buf, _buf_len - from_buf);
            _buf_len -= from_buf;
        }
        if (from_buf >= data_len) {
            *out_data = buf;
            out_len = data_len;
            return true;
        }
        // 未到齐：挂起等下次 loop（绝不阻塞等网络！）
        _pending = buf;
        _pending_len = from_buf;
        _pending_need = data_len;
        _pending_sid = sid;
        return false;
    }
    return true;
}

bool FrpcTcp::recv_msg(uint32_t &out_stream_id, MsgType &out_type, uint8_t **out_data, size_t &out_len) {
    TmuxHdr hdr;
    uint8_t *payload = nullptr;
    size_t payload_len = 0;

    if (!recv_frame(hdr, &payload, payload_len)) return false;

    out_stream_id = ntohl(hdr.stream_id);

    // 只处理 DATA 帧
    if (hdr.type != TMUX_DATA) {
        if (payload) free(payload);
        return false;
    }

    // 解析 frp 消息
    if (payload_len < MSG_HDR_SIZE) {
        if (payload) free(payload);
        return false;
    }

    MsgHdr *msg = (MsgHdr *)payload;
    out_type = (MsgType)msg->type;
    out_len  = (size_t)ntoh64(msg->length);

    if (out_len > 0 && out_len <= payload_len - MSG_HDR_SIZE) {
        *out_data = (uint8_t *)malloc(out_len);
        if (*out_data) {
            memcpy(*out_data, msg->data, out_len);
        }
    } else if (out_len == 0) {
        // 空消息体（如 Ping "{}"），合法
        *out_data = nullptr;
        out_len = 0;
    } else {
        *out_data = nullptr;
        out_len = 0;
    }

    free(payload);
    return true;
}

// ---- 原始读写 ----

size_t FrpcTcp::raw_write(const uint8_t *data, size_t len) {
    if (_state != TcpState::CONNECTED || !_client) return 0;
    // 循环写入确保全部发送（参考 frpc_test.ino 的 frp_write_all）
    size_t total = 0;
    uint32_t t0 = millis();
    while (total < len) {
        size_t w = _client->write(data + total, len - total);
        if (w > 0) {
            total += w;
            t0 = millis();
            continue;
        }
        delay(1);
        // 发送超时：标记连接错误，禁止部分发送（yamux 帧不完整会错乱）
        if (millis() - t0 > 1000) {
            Serial.printf("[TCP] raw_write timeout (%u/%u), marking CLOSED\n",
                          (unsigned)total, (unsigned)len);
            _state = TcpState::CLOSED;
            break;
        }
    }
    return total;
}

int FrpcTcp::raw_available() {
    if (_state != TcpState::CONNECTED || !_client) return 0;
    return _client->available();
}

int FrpcTcp::raw_read(uint8_t *buf, size_t max_len) {
    if (_state != TcpState::CONNECTED || !_client) return -1;
    // 循环读取直到凑满 max_len（帧必须完整，部分读取会导致流错乱）
    // 1500ms 无新数据才超时返回（公网+WiFi 下大帧分段到达较慢；
    // 超时由 recv_frame 判定 CLOSED，配合上层 CLOSED 检测立即重连自愈）
    size_t total = 0;
    uint32_t t0 = millis();
    while (total < max_len) {
        int n = _client->read(buf + total, max_len - total);
        if (n > 0) {
            total += (size_t)n;
            t0 = millis();
        } else {
            if (millis() - t0 > 1500) break;
            delay(1);
        }
    }
    return (int)total;
}

bool FrpcTcp::raw_connected() {
    if (!_client) return false;
    return _client->connected();
}
#pragma endregion // 第4区:yamux帧层(frpc_tcp)

/* ============================================================
 * 第 5 区：数据面（frpc_proxy）
 * 说明：WorkConn 基类 + TCP/UDP 中继。
 * ============================================================ */
#pragma region 第5区:数据面(frpc_proxy)

enum class WorkState : uint8_t { IDLE, CONNECTING, RELAYING, CLOSED };

// ============================================================
// WorkConn 基类
// ============================================================
class FrpcWorkConn {
public:
    FrpcWorkConn() : _tcp(nullptr), _factory(nullptr), _state(WorkState::IDLE), _stream_id(0) {}
    virtual ~FrpcWorkConn() {}

    void init(FrpcTcp *tcp, uint32_t stream_id, NetStreamFactory *factory) {
        _tcp = tcp;
        _factory = factory;
        _stream_id = stream_id;
        _state = WorkState::CONNECTING;
    }

    virtual bool isUdp() const { return false; }
    virtual void onStartWorkConn(const ProxyConfig &cfg) = 0;
    virtual void onRemoteData(uint8_t *data, size_t len) = 0;   // 非 const：数据流加密需原地解密
    virtual void onUdpPacket(const uint8_t *data, size_t len, const char *ip, uint16_t port) {}
    virtual void loop() = 0;

    WorkState state() const { return _state; }
    uint32_t streamId() const { return _stream_id; }

protected:
    FrpcTcp           *_tcp;
    NetStreamFactory  *_factory;   // 平台注入：创建本地连接流
    WorkState  _state;
    uint32_t   _stream_id;
};

// ============================================================
// TCP 数据面
// ============================================================
class FrpcProxy : public FrpcWorkConn {
public:
    FrpcProxy() : _local_client(nullptr), _last_retry(0), _use_enc(false), _enc_iv_sent(false), _dec_iv_got(0), _dec_ready(false) {
        memset(&_cfg, 0, sizeof(_cfg));
        memset(&_enc, 0, sizeof(_enc));
        memset(&_dec, 0, sizeof(_dec));
    }
    ~FrpcProxy() {
        if (_local_client) { _local_client->stop(); delete _local_client; }
    }

    bool isUdp() const override { return false; }

    void onStartWorkConn(const ProxyConfig &cfg) override {
        _cfg = cfg;
        _use_enc = cfg.useEncryption;
        // 通过平台工厂创建本地连接流（平台无关）
        if (_factory) {
            _local_client = _factory->createStream();
            if (_local_client) _local_client->setLingerOff();   // RST 关闭：避免 TIME_WAIT 耗尽 socket 池
        }
        _last_io = millis();   // 空闲超时基准：防 socket 堆积（lwIP 池仅 10 个）
        if (_use_enc) {
            // 数据流加密（use_encryption）：与 frp 官方一致
            // - 发送方向：首写时先发 16B 随机 IV，再发 AES-128-CFB 密文
            // - 接收方向：首读 16B IV（frps 的），之后解密（IV 可能跨帧，需累积）
            // - 密钥与控制流相同：PBKDF2(token, salt="crypto", 64, 16B)
            uint8_t key[16];
            crypto_derive_key(auth_token, key);
            crypto_gen_iv(_enc_iv);
            crypto_encoder_init(_enc, key, _enc_iv);
            _enc_iv_sent = false;
            _dec_iv_got = 0;
            _dec_ready = false;
        }
        _connect_local();
    }

    void onRemoteData(uint8_t *data, size_t len) override {
        if (_state != WorkState::RELAYING) {
            return;
        }
        if (!_local_client || !_local_client->connected()) {
            return;
        }
        if (_use_enc && len > 0) {
            // 先收集 frps 的 IV（前 16B，可能跨帧）
            size_t off = 0;
            if (!_dec_ready) {
                while (off < len && _dec_iv_got < 16) {
                    _dec_iv[_dec_iv_got++] = data[off++];
                }
                if (_dec_iv_got == 16) {
                    uint8_t key[16];
                    crypto_derive_key(auth_token, key);
                    crypto_decoder_init(_dec, key, _dec_iv);
                    _dec_ready = true;
                }
            }
            if (off >= len) return;           // 本帧只有 IV
            if (_dec_ready) {
                crypto_cfb_crypt(_dec, data + off, len - off);   // 原地解密
            }
            data += off;
            len -= off;
        }
        // 循环写入确保全部发送（NetSocket::write 可能部分写入）
        // 注意：此处严禁每帧打印（高吞吐时 Serial 阻塞帧循环导致 yamux PING 超时）
        size_t off = 0;
        uint32_t t0 = millis();
        while (off < len) {
            size_t w = _local_client->write(data + off, len - off);
            if (w > 0) { off += w; _last_io = millis(); t0 = millis(); continue; }
            if (!_local_client || !_local_client->connected()) {
                Serial.printf("[PROXY] local lost during write (%u/%u)\n", (unsigned)off, (unsigned)len);
                return;
            }
            delay(1);
            // 短超时：写本地卡住会阻塞帧循环导致 yamux PING ACK 延迟
            if (millis() - t0 > 2000) {
                Serial.printf("[PROXY] local write timeout (%u/%u), closing\n", (unsigned)off, (unsigned)len);
                _state = WorkState::CLOSED;
                if (_local_client->connected()) _local_client->stop();
                return;
            }
        }
    }

    void loop() override {
        if (_state == WorkState::CONNECTING) {
            // 本地连接失败后的重试（1s 间隔）：避免 socket 池瞬时耗尽/服务临时不可达时
            // 该 work 流永久瘫痪（无重试会导致公网连接挂起超时）
            if (millis() - _last_retry > 1000) {
                _connect_local();
            }
            return;
        }
        if (_state == WorkState::RELAYING) {
            _relay_local_to_remote();
            if (!_local_client || !_local_client->connected() || _local_client->isPeerClosed()) {
                // 本地连接断开（含 EOF 无数据场景）：work 流已无意义，置 CLOSED 由上层清理
                // （frps 也会关闭该 work 流，下次连接重新建立）
                Serial.printf("[PROXY] local conn lost (%s), closing work conn\n", _cfg.name);
                _state = WorkState::CLOSED;
                if (_local_client && _local_client->connected()) _local_client->stop();
            } else if (millis() - _last_io > 45000) {
                // 空闲超时：45s 无任何数据 → 关闭 work 流，释放本地 socket。
                // 防客户端"连接堆积"占满 lwIP socket 池（实测：moonlight 在线检测失败后
                // 每秒重连 47984，每个悬挂连接占一个 socket，池满后所有新连接失败，
                // 形成恶性循环，47984 全挂）。
                Serial.printf("[PROXY] idle timeout (%s), closing work conn\n", _cfg.name);
                _state = WorkState::CLOSED;
                if (_local_client && _local_client->connected()) _local_client->stop();
            }
        }
    }

private:
    void _connect_local() {
        if (_cfg.localIP[0] == '\0' || _cfg.localPort == 0) {
            _state = WorkState::CLOSED;
            return;
        }
        if (!_local_client) {
            _state = WorkState::CLOSED;
            return;
        }
        if (_local_client->connected()) _local_client->stop();
        Serial.printf("[PROXY] Connecting local %s:%d...\n", _cfg.localIP, _cfg.localPort);
        _local_client->setTimeout(2000);
        uint32_t t0 = millis();
        bool ok = _local_client->connect(_cfg.localIP, _cfg.localPort);
        uint32_t dt = millis() - t0;
        if (ok) {
            _state = WorkState::RELAYING;
            Serial.printf("[PROXY] Local connected (%s) in %ums\n", _cfg.name, (unsigned)dt);
        } else {
            _state = WorkState::CONNECTING;
            _last_retry = millis();
            Serial.printf("[PROXY] Local connect FAILED (%s) in %ums\n", _cfg.name, (unsigned)dt);
        }
    }

    void _relay_local_to_remote() {
        if (!_local_client->connected() || !_tcp) return;
        // 批量读空本地缓冲：sunshine 的响应可能分多个 TCP 段连续到达，
        // 旧实现每轮只读一批——TLS 1.2 握手中间的独立小段（CCS+Finished）
        // 与后续段分轮读取时可能滞留/丢失（实测 47984 握手断链根因）。
        for (int batch = 0; batch < 8; batch++) {
            int avail = _local_client->available();
            if (avail <= 0) break;
            if (avail > 4096) avail = 4096;
            uint8_t *buf = (uint8_t *)malloc(avail);
            if (!buf) break;
            int n = _local_client->read(buf, avail);
            if (n > 0) {
                _last_io = millis();
                if (_use_enc) {
                    // 首写先发 IV（16B 单独一帧，与官方 Writer.Write 行为一致）
                    if (!_enc_iv_sent) {
                        _tcp->send_data(_stream_id, 0, _enc_iv, 16);
                        _enc_iv_sent = true;
                    }
                    crypto_cfb_crypt(_enc, buf, n);   // 原地加密
                }
                _tcp->send_data(_stream_id, 0, buf, n);
            }
            free(buf);
            if (n <= 0) break;
        }
    }

    ProxyConfig _cfg;
    NetStream *_local_client;
    uint32_t _last_retry;
    uint32_t _last_io;         // 最近一次数据收发时间（空闲超时防 socket 堆积）
    // ---- 数据流加密（use_encryption）----
    bool _use_enc;
    FrpCrypto _enc;          // 发送方向（加密）
    FrpCrypto _dec;          // 接收方向（解密）
    uint8_t   _enc_iv[16];
    bool      _enc_iv_sent;
    uint8_t   _dec_iv[16];
    uint8_t   _dec_iv_got;
    bool      _dec_ready;
};

// ============================================================
// UDP 数据面
// frp 的 UDP 代理：UDP 包封装在 work 流（TCP）的 UDPPacket('u') 消息中传输
// 服务器→客户端：{"c":"<base64>","r":{"IP":用户IP,"Port":用户端口}}
// 客户端→服务器：同样格式（r 为对应用户），服务器据此回传
//
// 每个"用户会话"（r.IP:r.Port）对应一个本地 UDP socket（独立本地端口），
// 本地服务响应按会话路由回对应用户。30 秒无活动清理。
// work 流需每 30 秒发 msg Ping 保持存活（服务器 60s 无消息会关闭）。
// ============================================================
class FrpcUdpProxy : public FrpcWorkConn {
public:
    FrpcUdpProxy() : _local_port(0), _next_local_port(41000), _last_heartbeat(0) {
        memset(&_cfg, 0, sizeof(_cfg));
    }
    ~FrpcUdpProxy() {
        for (auto *s : _sessions) delete s;
        _sessions.clear();
    }

    bool isUdp() const override { return true; }

    void onStartWorkConn(const ProxyConfig &cfg) override {
        _cfg = cfg;
        _local_port = cfg.localPort;
        _state = WorkState::RELAYING;
        _last_heartbeat = millis();
        Serial.printf("[UDP] Proxy %s ready, local %s:%d\n", _cfg.name, _cfg.localIP, _cfg.localPort);
    }

    void onRemoteData(uint8_t *data, size_t len) override {
        // UDP work 流的字节流由 FrpcClient 按消息帧（UDPPacket/Ping）解析后
        // 调用 onUdpPacket，原始数据不会路由到这里
        (void)data;
        (void)len;
    }

    void onUdpPacket(const uint8_t *data, size_t len, const char *remote_ip, uint16_t remote_port) override {
        if (_state != WorkState::RELAYING || !data || len == 0) return;
        UdpSession *s = _find_session(remote_ip, remote_port, true);
        if (!s) return;
        s->last_active = millis();
        s->_udp->beginPacket(_cfg.localIP, _cfg.localPort);
        s->_udp->write(data, len);
        s->_udp->endPacket();
    }

    void loop() override {
        if (_state != WorkState::RELAYING) return;

        // 读取本地 UDP 响应 → 回传服务器
        // 注意：视频流(47998)是几千包/秒的大流量，每会话每轮只读 1 包
        // （10ms/轮 ≈ 100 包/秒）严重不足导致画面卡顿。批量读取提升吞吐。
        for (auto *s : _sessions) {
            int batch = 0;
            int n;
            while ((n = s->_udp->parsePacket()) > 0 && batch < 48) {
                uint8_t buf[1500];
                int r = s->_udp->read(buf, sizeof(buf));
                if (r > 0) {
                    _send_udp_packet(buf, r, s->remote_ip, s->remote_port);
                    s->last_active = millis();
                }
                batch++;
            }
        }

        // work 流心跳（服务器 60s 无消息关闭连接）
        if (millis() - _last_heartbeat > 30000) {
            _last_heartbeat = millis();
            _tcp->send_msg(_stream_id, TypePing, "{}", 2);
        }

        // 会话超时清理
        uint32_t now = millis();
        for (auto it = _sessions.begin(); it != _sessions.end();) {
            if (now - (*it)->last_active > 30000) {
                Serial.printf("[UDP] session %s:%u expired\n", (*it)->remote_ip, (*it)->remote_port);
                delete *it;
                it = _sessions.erase(it);
            } else {
                ++it;
            }
        }
    }

private:
    static const size_t MAX_SESSIONS = 8;

    struct UdpSession {
        char remote_ip[16];
        uint16_t remote_port;
        NetUDPStream *_udp;
        uint32_t last_active;
        ~UdpSession() { if (_udp) delete _udp; }
    };

    UdpSession *_find_session(const char *remote_ip, uint16_t remote_port, bool create) {
        for (auto *s : _sessions) {
            if (s->remote_port == remote_port && strcmp(s->remote_ip, remote_ip) == 0) {
                return s;
            }
        }
        if (!create) return nullptr;
        if (_sessions.size() >= MAX_SESSIONS) {
            Serial.println("[UDP] session limit reached, dropping");
            return nullptr;
        }
        UdpSession *s = new UdpSession();
        strncpy(s->remote_ip, remote_ip, sizeof(s->remote_ip) - 1);
        s->remote_port = remote_port;
        s->last_active = millis();
        s->_udp = (_factory ? _factory->createUDPStream() : nullptr);
        if (!s->_udp) { delete s; return nullptr; }
        if (!s->_udp->begin(_next_local_port++)) {
            // begin 失败（lwIP socket 池耗尽或 bind 失败）：驱逐最久未活动的会话释放
            // socket 后重试一次。实测：moonlight 串流时多个 TCP keep-alive 连接 +
            // 音频 UDP 会话把 CONFIG_LWIP_MAX_SOCKETS(10) 占满，后续 control(47999)
            // 会话创建失败 → control stream 建立失败 error 11。
            Serial.printf("[UDP] begin(%u) failed, evicting oldest session to retry\n",
                          (unsigned)(_next_local_port - 1));
            UdpSession *oldest = nullptr;
            for (auto *x : _sessions) {
                if (!oldest || x->last_active < oldest->last_active) oldest = x;
            }
            if (oldest) {
                for (auto it = _sessions.begin(); it != _sessions.end(); ++it) {
                    if (*it == oldest) { _sessions.erase(it); break; }
                }
                delete oldest;
            }
            if (!s->_udp->begin(_next_local_port++)) {
                Serial.println("[UDP] begin retry failed, session dropped");
                delete s;
                return nullptr;
            }
        }
        if (_next_local_port > 42000) _next_local_port = 41000;
        // 每个会话独立本地端口（本地服务按源端口区分会话）
        _sessions.push_back(s);
        Serial.printf("[UDP] new session %s:%u -> local port %u\n", remote_ip, remote_port, _next_local_port - 1);
        return s;
    }

    void _send_udp_packet(const uint8_t *data, size_t len, const char *remote_ip, uint16_t remote_port) {
        UdpPacketMsg pkt;
        memset(&pkt, 0, sizeof(pkt));
        pkt.data = (uint8_t *)data;   // 只读使用
        pkt.data_len = len;
        strncpy(pkt.remote_ip, remote_ip, sizeof(pkt.remote_ip) - 1);
        pkt.remote_port = remote_port;

        char *json = nullptr;
        size_t jlen = udp_packet_marshal(pkt, &json);
        if (!json || jlen == 0) return;

        uint8_t *frame = nullptr;
        size_t total = build_msg_frame(TypeUDPPacket, json, jlen, &frame);
        free(json);
        if (!frame) return;

        _tcp->send_data(_stream_id, 0, frame, total);
        free(frame);
    }

    ProxyConfig _cfg;
    uint16_t _local_port;
    uint16_t _next_local_port;
    uint32_t _last_heartbeat;
    std::vector<UdpSession *> _sessions;
};
#pragma endregion // 第5区:数据面(frpc_proxy)

/* ============================================================
 * 第 6 区：frpc 核心（frpc_client）
 * 说明：FrpcClient 状态机（登录/心跳/重连）+ 帧循环 + work 流管理。
 * ============================================================ */
#pragma region 第6区:frpc核心(frpc_client)

// 生命周期：IDLE → CONNECTING → LOGIN_SENT → WAIT_IV → READY
// 多代理：配置来自 frpc_toml.h（PROXIES 数组）；收到 ReqWorkConn 时注册代理，
//         每个 ReqWorkConn 建一个 work 流，StartWorkConn 按 proxy_name 创建数据面。
#include <vector>

// ============================================================
// 客户端状态
// ============================================================
enum class ClientState : uint8_t {
    IDLE,           // 未连接
    CONNECTING,     // TCP 连接中
    LOGIN_SENT,     // 已发送 Login，等待 LoginResp
    WAIT_IV,        // 已收到 LoginResp，等待服务器 IV
    READY,          // 已就绪（NewProxy 已发送）
    ERROR           // 错误状态
};

// ============================================================
// FrpcClient 类
// ============================================================
class FrpcClient {
public:
    FrpcClient();
    ~FrpcClient();

    // ---- 配置 ----

    /**
     * @brief 注入平台网络工厂（必须在 start() 前调用）
     * 平台实现 NetStream/NetUDPStream/NetStreamFactory 后注入，核心零平台依赖
     */
    void setNetwork(NetStreamFactory *factory) {
        _factory = factory;
        _tcp.setFactory(factory);
    }

    /**
     * @brief 校时（纯 SNTP，平台无关，不依赖 configTime）
     *
     * 用 NetUDPStream 向 NTP 服务器发 SNTP 请求，获取 Unix 时间。
     * 之后用 millis() 自维护，误差不累计（重连时重新校时归零）。
     *
     * @param ntp_ip NTP 服务器 IP。默认用 FRPC_DEFAULT_NTP_IP；
     *               传 nullptr 跳过校时。
     * @return true 校时成功
     */
    bool syncTime(const char *ntp_ip = FRPC_DEFAULT_NTP_IP) {
        if (!ntp_ip || !ntp_ip[0]) return false;
        bool ok = _clock.sync(_factory, ntp_ip);
        Serial.printf("[FRPC] Time sync %s\n", ok ? "OK" : "FAILED (check NTP IP)");
        return ok;
    }

    // ---- 生命周期 ----

    /**
     * @brief 启动连接（非阻塞）
     * @param hostname 设备标识（上报 frps，默认 "ESP32"）
     * @param os       操作系统标识（默认 "FreeRTOS"）
     * @param arch     架构标识（默认 "xtensa"）
     */
    void start(const char *hostname = "ESP32",
               const char *os = "FreeRTOS",
               const char *arch = "xtensa");

    /**
     * @brief 停止并断开
     */
    void stop();

    /**
     * @brief 必须在 loop() 中周期性调用
     */
    void loop();

    // ---- 状态查询 ----

    ClientState state() const { return _state; }
    bool isReady() const { return _state == ClientState::READY; }
    bool isError() const { return _state == ClientState::ERROR; }

    // ---- 数据转发（READY 状态下使用） ----

    FrpcTcp &tcp() { return _tcp; }
    FrpCrypto &crypto() { return _encoder; }
    const char *serverRunId() const { return _server_run_id; }
    const char *privilegeKey() const { return _privilege_key; }
    size_t proxyCount() const { return _proxy_cfgs.size(); }
    size_t workConnCount() const { return _work_conns.size(); }

private:
    // 状态机步骤
    void _step_connect();
    void _step_send_login();
    void _step_process_response();
    void _step_handle_ping(TmuxHdr &hdr);
    void _step_handle_data(TmuxHdr &hdr, uint8_t *payload, size_t len);
    void _step_handle_start_work_conn(uint32_t sid, MsgHdr *msg, size_t dlen);

    // 发送辅助
    void _send_login();
    void _send_new_proxies();
    void _send_encrypted_msg(uint32_t sid, MsgType type, const char *data, size_t len);
    void _create_work_conn(uint32_t stream_id);

    // work 流管理
    FrpcWorkConn *_find_work_conn(uint32_t stream_id);
    const ProxyConfig *_find_cfg(const char *proxy_name);
    void _remove_work_conn(uint32_t stream_id);
    void _cleanup_work_conns();

    FrpcTcp _tcp;
    NetStreamFactory *_factory;   // 平台注入的网络工厂（创建 work 流用）
    ClientState _state;
    Clock _clock;                 // 纯 SNTP 校时 + 自维护时间（平台无关）

    // 加密
    FrpCrypto _encoder;
    FrpCrypto _decoder;
    uint8_t _aes_key[16];
    bool _crypto_ready;
    uint8_t _client_iv[16];   // 客户端生成的 IV_A（用于加密客户端→服务器的消息）
    bool _client_iv_ready;    // 客户端 IV 是否已生成
    bool _client_iv_sent;     // 客户端 IV 是否已发送

    // 服务器配置
    char _host[64];
    uint16_t _port;
    char _token[64];

    // 代理配置（来自 frpc_toml.h）
    std::vector<ProxyConfig> _proxy_cfgs;

    // 设备标识
    char _run_id[32];
    char _hostname[32];
    char _os[16];
    char _arch[16];
    bool _auto_runid;   // true = 每次连接自动生成 run_id（推荐）

    // 运行时状态
    char _server_run_id[64];
    char _privilege_key[64];
    int  _login_timestamp;
    bool _iv_received;
    bool _new_proxy_sent;
    bool _proxy_conflict;   // 代理注册冲突（frps 旧会话未清理）
    uint32_t _login_time;
    uint32_t _last_ping;

    // 数据面 work 流列表
    std::vector<FrpcWorkConn *> _work_conns;
    uint32_t _next_sid;  // 下一个 work stream 的 stream_id
    uint8_t  _req_work_budget;  // 本轮帧循环可建 work 流上限（防 frps 池满）
    uint8_t  _retry_count;      // 连续重连次数（指数退避用，成功后清零）
};

// ============================================================
// 实现
// ============================================================

FrpcClient::FrpcClient()
    : _state(ClientState::IDLE)
    , _port(0)
    , _factory(nullptr)
    , _crypto_ready(false)
    , _iv_received(false)
    , _new_proxy_sent(false)
    , _proxy_conflict(false)
    , _login_time(0)
    , _last_ping(0)
    , _next_sid(3)
    , _req_work_budget(2)
    , _retry_count(0)
    , _client_iv_ready(false)
    , _client_iv_sent(false)
    , _auto_runid(true)
{
    memset(_host, 0, sizeof(_host));
    memset(_token, 0, sizeof(_token));
    memset(_run_id, 0, sizeof(_run_id));
    memset(_hostname, 0, sizeof(_hostname));
    memset(_os, 0, sizeof(_os));
    memset(_arch, 0, sizeof(_arch));
    memset(_server_run_id, 0, sizeof(_server_run_id));
    memset(_privilege_key, 0, sizeof(_privilege_key));
    _login_timestamp = 0;
    memset(_aes_key, 0, sizeof(_aes_key));
    memset(&_encoder, 0, sizeof(_encoder));
    memset(&_decoder, 0, sizeof(_decoder));
}

FrpcClient::~FrpcClient() { stop(); }

void FrpcClient::start(const char *hostname,
                       const char *os, const char *arch) {
    // 若未校时，自动用默认 NTP IP 校时（frps 认证用 token+时间戳）。
    // 重连时 _clock 仍有效则跳过；millis 溢出后 _clock 失效会重新校时。
    if (!_clock.synced()) {
        syncTime();   // 用默认 FRPC_DEFAULT_NTP_IP
    }
    // 首次启动从 frpc_toml.h 读取配置（重连时已配置则跳过）
    if (_host[0] == '\0') {
        strncpy(_host, serverAddr, sizeof(_host) - 1);
        _port = serverPort;
        strncpy(_token, auth_token, sizeof(_token) - 1);
    }
    if (_proxy_cfgs.empty()) {
        _proxy_cfgs.clear();
        for (size_t i = 0; i < PROXY_COUNT; i++) {
            _proxy_cfgs.push_back(PROXIES[i]);
        }
        Serial.printf("[FRPC] %d proxies configured\n", (int)_proxy_cfgs.size());
        for (auto &c : _proxy_cfgs) {
            Serial.printf("  - %s: %s %s:%d -> :%d\n", c.name, c.type,
                          c.localIP, c.localPort, c.remotePort);
        }
    }
    if (_hostname[0] == '\0') {
        _auto_runid = true;   // 每次连接自动生成 run_id（避免 frps 旧会话冲突）
        if (hostname) strncpy(_hostname, hostname, sizeof(_hostname) - 1);
        if (os) strncpy(_os, os, sizeof(_os) - 1);
        if (arch) strncpy(_arch, arch, sizeof(_arch) - 1);
    }

    stop();
    _state = ClientState::CONNECTING;
    _iv_received = false;
    _new_proxy_sent = false;
    _crypto_ready = false;
    _client_iv_ready = false;
    _client_iv_sent = false;
    _login_time = 0;
    _last_ping = 0;
    memset(_server_run_id, 0, sizeof(_server_run_id));
    memset(&_encoder, 0, sizeof(_encoder));
    memset(&_decoder, 0, sizeof(_decoder));

    // 每次连接（含重连）重新生成 run_id：frps 对同 run_id 的新连接
    // 在旧会话未清理时会拒绝（"already online"），随机化可避免冲突
    if (_auto_runid) {
        snprintf(_run_id, sizeof(_run_id), "ESP32_%06lx",
                 (unsigned long)(frpc_platform_random() & 0xFFFFFF));
        Serial.printf("[FRPC] run_id=%s\n", _run_id);
    }

    _cleanup_work_conns();
    _next_sid = 3;  // 重置 stream_id 计数器

    _tcp.connect(_host, _port);
}

void FrpcClient::stop() {
    _tcp.close();
    _cleanup_work_conns();
    _state = ClientState::IDLE;
}

void FrpcClient::loop() {
    // 注意：不要调用 _tcp.loop()，因为 _step_process_response 直接使用 raw_read
    // _tcp.loop() 中的 _recv_to_buf 会消耗数据

    switch (_state) {
        case ClientState::CONNECTING:
            _step_connect();
            break;
        case ClientState::LOGIN_SENT:
        case ClientState::WAIT_IV:
            _step_process_response();
            break;
        case ClientState::READY:
            // 检测连接是否断开：
            // 1) WiFiClient::connected() 在 TCP 被对端关闭后可能仍返回 true（ESP32 Arduino 已知行为，
            //    纯等待无 I/O 时不更新状态），所以还要检查内部 CLOSED 标记——send/recv 超时都会置 CLOSED，
            //    不检查会导致帧循环死后永久卡在 READY 不重连（实测：frps keepalive timeout 关 TCP 后
            //    ESP32 卡死 7 分钟不重连，代理完全不可用）
            if (!_tcp.raw_connected() || _tcp.state() == TcpState::CLOSED) {
                Serial.println("[FRPC] Connection lost, reconnecting...");
                _state = ClientState::ERROR;
                _login_time = millis();
                break;
            }
            _step_process_response();
            // 处理所有数据面 work 流，并清理已关闭的对象
            for (auto it = _work_conns.begin(); it != _work_conns.end();) {
                FrpcWorkConn *w = *it;
                w->loop();
                if (w->state() == WorkState::CLOSED) {
                    // 先通知 frps 关闭该 work 流（否则 frps 的对应公网连接悬挂）
                    _tcp.send_fin(w->streamId());
                    Serial.printf("[FRPC] removing closed work conn sid=%u\n", w->streamId());
                    delete w;
                    it = _work_conns.erase(it);
                } else {
                    ++it;
                }
            }
            // 控制连接心跳：每 30 秒发送加密 Ping
            if (millis() - _last_ping > 30000) {
                _last_ping = millis();
                const char *ping_msg = "{}";
                _send_encrypted_msg(1, TypePing, ping_msg, strlen(ping_msg));
                Serial.println("[FRPC] Ping sent");
            }
            break;
        case ClientState::ERROR:
            // 代理冲突时等待更久（frps 需清理旧会话，默认 heartbeat 超时 90 秒）
            {
                uint32_t retry;
                if (_proxy_conflict) {
                    retry = 95000;  // 冲突（already exists）等 95s 让 frps 清理旧会话
                } else {
                    // 指数退避 + 随机抖动：1s→2s→4s→8s→16s→30s 封顶（50%~150% 抖动）
                    // 避免固定 5s 重连在 frps 异常时造成"重连风暴"
                    uint32_t base = (_retry_count < 5) ? (1000u << _retry_count) : 30000u;
                    retry = base / 2 + (frpc_platform_random() % base);
                    _retry_count++;
                }
                if (millis() - _login_time > retry) {
                    _proxy_conflict = false;
                    _retry_count = 0;
                    Serial.println("[FRPC] Reconnecting...");
                    start();
                }
            }
            break;
        default:
            break;
    }
}

// ---- 状态机步骤 ----

void FrpcClient::_step_connect() {
    if (_tcp.isConnected()) {
        // 发送 WINDOW_UPDATE(SYN) + Login
        _tcp.send_win_update(1, TMUX_FLAG_SYN, 0);
        _send_login();
        _state = ClientState::LOGIN_SENT;
        _login_time = millis();
        Serial.println("[FRPC] Login sent");
    } else if (_tcp.state() == TcpState::CLOSED) {
        // 连接失败，5 秒后重试
        Serial.println("[FRPC] Connect failed, will retry...");
        _state = ClientState::ERROR;
    }
    // CONNECTING 状态：等待 _tcp.connect() 完成
}

void FrpcClient::_step_process_response() {
    // 登录超时检查
    if (_state == ClientState::LOGIN_SENT) {
        if (millis() - _login_time > 20000) {
            Serial.println("[FRPC] Login timeout");
            _state = ClientState::ERROR;
            return;
        }
    }

    // 让 lwIP 处理接收，并把数据读入帧缓冲
    // 2ms 节流（原 10ms）：提高轮频率——视频流 UDP 读取更及时，减少 lwIP 接收缓冲溢出丢包
    delay(2);
    _tcp.loop();  // 内部 _recv_to_buf：available 数据 → _buf（不阻塞）

    // 每轮帧循环重置 work 流建立预算（防 frps work 池满被关闭）
    _req_work_budget = 2;

    // 处理所有完整帧（帧不完整时 recv_frame 返回 false，等下次 loop）
    // 每轮最多 10 个 DATA 帧：避免数据转发阻塞时 PING/yamux keepalive 响应延迟
    // （frps 的 ConnectionWriteTimeout=10s，帧循环卡住会导致 frps 判定保活超时关闭连接）
    // 注意：WINDOW_UPDATE（窗口归还）不占 DATA 预算——视频流时 frps 每帧都归还
    // 窗口，若积压未处理，ESP32 的发送窗口恢复慢 → 吞吐受限（实测视频卡顿因素之一）。
    // 总处理上限 200 帧/轮防饿死其他逻辑。
    int frame_count = 0;
    int processed = 0;
    while (frame_count < 10 && processed < 200) {
        processed++;
        TmuxHdr hdr;
        uint8_t *payload = nullptr;
        size_t dlen = 0;
        if (!_tcp.recv_frame(hdr, &payload, dlen)) {
            break;
        }
        TmuxHdr *h = &hdr;
        uint32_t sid = ntohl(h->stream_id);

        if (h->type == TMUX_PING) {
            _step_handle_ping(*h);
            if (payload) free(payload);
            continue;  // 继续处理下一个帧
        }

        if (h->type != TMUX_DATA) {
            // WINDOW_UPDATE / GO_AWAY 等帧：处理 FIN/RST（对端关闭 work 流）
            uint16_t fl = ntohs(h->flags);
            if ((fl & (TMUX_FLAG_FIN | TMUX_FLAG_RST)) && sid != 1) {
                Serial.printf("[FRPC] peer closed work conn sid=%u (flags=0x%x)\n", sid, fl);
                _remove_work_conn(sid);
            }
            if (payload) free(payload);
            if (h->type == TMUX_WIN_UPDATE) continue;  // 窗口归还不占预算
            frame_count++;
            continue;
        }

        // DATA 帧也检查 FIN/RST：yamux 流关闭是 DATA+FIN(len=0)（frps 关闭 work 流时发），
        // 必须转发"连接关闭"语义——否则对端关闭后客户端连接悬挂无响应
        // （实测：moonlight RTSP 握手 error 110 的根因——sunshine 关闭连接时 FIN 被吞）
        frame_count++;   // DATA 帧计入预算
        {
            uint16_t fl = ntohs(h->flags);
            if ((fl & (TMUX_FLAG_FIN | TMUX_FLAG_RST)) && sid != 1) {
                Serial.printf("[FRPC] peer closed work conn sid=%u (flags=0x%x)\n", sid, fl);
                _remove_work_conn(sid);
                if (payload) free(payload);
                continue;
            }
        }

        if (dlen == 0) {
            if (payload) free(payload);
            continue;
        }

        if (sid == 1) {
            // ---- 控制流 ----

            // 检查是否是 IV（服务器生成的 IV_B，用于解密服务器→客户端的消息）
            if (_state == ClientState::WAIT_IV && !_iv_received && dlen == 16) {
                crypto_derive_key(_token, _aes_key);
                // frp 协议：双向 IV 交换
                // - decoder 用服务器发的 IV_B 初始化（解密服务器→客户端）
                // - encoder 用客户端自己生成的 IV_A 初始化（加密客户端→服务器）
                // - 与 xfrpc 一致：收到 IV_B 后只初始化 decoder，等收到 ReqWorkConn 后再初始化 encoder 并发送 NewProxy
                uint8_t client_iv[16];
                crypto_gen_iv(client_iv);
                crypto_decoder_init(_decoder, _aes_key, payload);
                memcpy(_client_iv, client_iv, 16);
                _client_iv_ready = true;
                _iv_received = true;
                _crypto_ready = true;
                Serial.println("[FRPC] IV exchanged, decoder ready (encoder deferred)");
                free(payload);

                // 发送 WINDOW_UPDATE 确认
                _tcp.send_win_update(1, 0, 16);
                continue;
            }

            // 解密（控制流才加密）
            if (_crypto_ready) {
                crypto_cfb_crypt(_decoder, payload, dlen);
            }

            // 解析 frp 消息
            if (dlen >= MSG_HDR_SIZE) {
                _step_handle_data(*h, payload, dlen);
            }
            free(payload);

            // 发送 WINDOW_UPDATE 确认接收
            _tcp.send_win_update(1, 0, dlen);
        } else {
            // ---- work 流数据 ----
            FrpcWorkConn *wc = _find_work_conn(sid);
            if (!wc) {
                // 尚无对象：可能是 StartWorkConn（服务器在 work 流上发送）
                if (dlen >= MSG_HDR_SIZE) {
                    MsgHdr *msg = (MsgHdr *)payload;
                    if (msg->type == TypeStartWorkConn) {
                        _step_handle_start_work_conn(sid, msg, dlen);
                    } else {
                        Serial.printf("[FRPC] No work conn for sid=%u, dropping %u bytes\n", sid, dlen);
                    }
                } else {
                    Serial.printf("[FRPC] No work conn for sid=%u, dropping %u bytes\n", sid, dlen);
                }
            } else if (wc->isUdp()) {
                // UDP work 流：消息帧（'u' UDPPacket / 'h' Ping / '4' Pong）
                if (dlen >= MSG_HDR_SIZE) {
                    MsgHdr *msg = (MsgHdr *)payload;
                    size_t dataLen = (size_t)ntoh64(msg->length);
                    if (msg->type == TypeUDPPacket && dataLen > 0 && dataLen + MSG_HDR_SIZE <= dlen) {
                        char tmp[2048];
                        size_t cp = dataLen < sizeof(tmp) - 1 ? dataLen : sizeof(tmp) - 1;
                        memcpy(tmp, msg->data, cp);
                        tmp[cp] = '\0';
                        UdpPacketMsg up;
                        if (udp_packet_unmarshal(tmp, up)) {
                            wc->onUdpPacket(up.data, up.data_len, up.remote_ip, up.remote_port);
                            if (up.data) free(up.data);
                        }
                    }
                    // Ping/Pong 忽略（服务器对 UDP work 流 Ping 不回 Pong）
                }
            } else {
                // TCP work 流：原始字节
                wc->onRemoteData(payload, dlen);
            }
            free(payload);

            // work 流 WINDOW_UPDATE：必须全量归还（yamux 窗口会计）。
            // 注意：绝不能少归还！frps 的 sendWindow 会净减归零 → frps 停发数据
            // （join 后 TLS 数据发不出，curl 超时——实测教训）。
            // 大帧（16KB）由非阻塞 recv_frame（pending）+ 32KB 缓冲处理，
            // 帧循环短暂等待不会触发 keepalive timeout（frps 已配 120s 间隔）。
            _tcp.send_win_update(sid, 0, dlen);
        }
    }  // for 循环结束
}

void FrpcClient::_step_handle_ping(TmuxHdr &hdr) {
    // 诊断：记录 yamux PING 收到 → ACK 发送的耗时
    uint32_t t0 = millis();
    TmuxHdr pong;
    pong.version   = 0;
    pong.type      = TMUX_PING;
    pong.flags     = htons(TMUX_FLAG_ACK);
    pong.stream_id = hdr.stream_id;
    pong.length    = hdr.length;
    _tcp.raw_write((const uint8_t *)&pong, sizeof(pong));
    uint32_t dt = millis() - t0;
    if (dt > 200) {
        Serial.printf("[FRPC] PING ACK slow: %ums\n", (unsigned)dt);
    }
    _last_ping = millis();
}

void FrpcClient::_step_handle_data(TmuxHdr &hdr, uint8_t *payload, size_t plen) {
    MsgHdr *msg = (MsgHdr *)payload;
    uint8_t msgType = msg->type;
    size_t dataLen = (size_t)ntoh64(msg->length);
    // 注意：这里不能打印每条消息（Pong 每 30s 一次，但 ReqWorkConn 在高频访问时也会很频繁）

    switch (msgType) {
        case TypeLoginResp: {  // '1'
            // 提取 run_id（从 JSON 中解析）
            if (dataLen > 0 && dataLen < 256) {
                char tmp[256];
                memcpy(tmp, msg->data, dataLen);
                tmp[dataLen] = '\0';
                LoginResp resp;
                if (login_resp_unmarshal(tmp, resp)) {
                    strncpy(_server_run_id, resp.run_id, sizeof(_server_run_id) - 1);
                    Serial.printf("[FRPC] LoginResp: run_id=%s\n", _server_run_id);
                }
            }

            if (_state == ClientState::LOGIN_SENT) {
                _state = ClientState::WAIT_IV;
                Serial.println("[FRPC] Waiting for IV...");
            }
            break;
        }

        case TypePong:  // '4'
            break;

        case TypeReqWorkConn:
            // 与 xfrpc 一致：收到 ReqWorkConn 后才初始化 encoder 并发送 NewProxy
            if (!_new_proxy_sent && !_proxy_cfgs.empty()) {
                crypto_encoder_init(_encoder, _aes_key, _client_iv);
                Serial.println("[FRPC] Encoder initialized, sending NewProxy...");
                _send_new_proxies();
                _new_proxy_sent = true;
                _state = ClientState::READY;
                _retry_count = 0;   // 连接成功，重置退避计数
            }
            // 建立 work 流（服务器会通过 StartWorkConn 分配代理）
            // 每轮帧循环最多补 2 个流：frps 的 work 池容量 = poolCount+10，
            // 一次性建太多流会导致池满、frps 关闭连接
            if (_req_work_budget > 0) {
                _create_work_conn(_next_sid);
                _next_sid += 2;
                _req_work_budget--;
            }
            break;

        case TypeNewProxyResp: {  // '2'
            Serial.printf("[FRPC] NewProxyResp: %.*s\n", (int)dataLen, msg->data);
            // 检测代理冲突（frps 上旧会话未清理，同名代理仍存在）
            char tmp[256];
            size_t cp = dataLen < sizeof(tmp) - 1 ? dataLen : sizeof(tmp) - 1;
            memcpy(tmp, msg->data, cp);
            tmp[cp] = 0;
            if (strstr(tmp, "already exists")) {
                _proxy_conflict = true;
                Serial.println("[FRPC] Proxy conflict (old session not cleaned yet), will retry later...");
                _state = ClientState::ERROR;
                _login_time = millis();
            }
            break;
        }

        default:
            Serial.printf("[FRPC] Unknown msg type: 0x%02x\n", msgType);
            break;
    }
}

/**
 * @brief 处理在 work 流上到达的 StartWorkConn（服务器把 work 流分配给某代理）
 * @param sid  work 流 stream_id（消息所在帧）
 * @param msg  消息头
 * @param dlen 帧数据长度
 */
void FrpcClient::_step_handle_start_work_conn(uint32_t sid, MsgHdr *msg, size_t dlen) {
    size_t dataLen = (size_t)ntoh64(msg->length);
    if (dataLen == 0 || dataLen + MSG_HDR_SIZE > dlen) return;
    Serial.printf("[FRPC] StartWorkConn on sid=%u: %.*s\n", sid, (int)dataLen, msg->data);

    char tmp[128];
    size_t cp = dataLen < 127 ? dataLen : 127;
    memcpy(tmp, msg->data, cp);
    tmp[cp] = 0;
    StartWorkConnResp swr;
    if (!start_work_conn_unmarshal(tmp, swr)) return;

    const ProxyConfig *cfg = _find_cfg(swr.proxy_name);
    if (!cfg) {
        Serial.printf("[FRPC] WARNING: no config for proxy %s\n", swr.proxy_name);
        return;
    }

    // 同一流上的旧对象（若有）先清理
    _remove_work_conn(sid);
    FrpcWorkConn *wc = (strcmp(cfg->type, "udp") == 0)
        ? (FrpcWorkConn *)new FrpcUdpProxy()
        : (FrpcWorkConn *)new FrpcProxy();
    wc->init(&_tcp, sid, _factory);
    wc->onStartWorkConn(*cfg);
    _work_conns.push_back(wc);
    Serial.printf("[FRPC] Work conn sid=%u bound to proxy %s (%s)\n",
                  sid, swr.proxy_name, cfg->type);
}

// ---- work 流管理 ----

FrpcWorkConn *FrpcClient::_find_work_conn(uint32_t stream_id) {
    for (auto *w : _work_conns) {
        if (w->streamId() == stream_id) return w;
    }
    return nullptr;
}

const ProxyConfig *FrpcClient::_find_cfg(const char *proxy_name) {
    if (!proxy_name) return nullptr;
    for (auto &c : _proxy_cfgs) {
        if (strcmp(c.name, proxy_name) == 0) return &c;
    }
    return nullptr;
}

void FrpcClient::_remove_work_conn(uint32_t stream_id) {
    for (auto it = _work_conns.begin(); it != _work_conns.end();) {
        if ((*it)->streamId() == stream_id) {
            // 通知 frps 关闭该 work 流（对端 FIN 的回确认；主动清理时确保 frps 同步关闭）
            _tcp.send_fin(stream_id);
            delete *it;
            it = _work_conns.erase(it);
        } else {
            ++it;
        }
    }
}

void FrpcClient::_cleanup_work_conns() {
    for (auto *w : _work_conns) delete w;
    _work_conns.clear();
}

// ---- 发送 ----

void FrpcClient::_send_login() {
    time_t ts;
    char *ak = get_auth_key(_token, &ts, _clock);

    // 保存 privilege_key 和 timestamp 供 NewWorkConn 使用
    if (ak) strncpy(_privilege_key, ak, sizeof(_privilege_key) - 1);
    _login_timestamp = (int)ts;

    LoginReq req;
    memset(&req, 0, sizeof(req));
    req.version       = FRP_VERSION;
    req.hostname      = _hostname;
    req.os            = _os;
    req.arch          = _arch;
    req.privilege_key = ak ? ak : "";
    req.timestamp     = ts;
    req.run_id        = _run_id;
    req.pool_count    = 1;  // 与官方 frpc 一致（多代理时按需补流）

    char *json = nullptr;
    size_t jlen = login_request_marshal(req, &json);
    if (json && jlen > 0) {
        _tcp.send_msg(1, TypeLogin, json, jlen);
        free(json);
    }
    if (ak) free(ak);
}

void FrpcClient::_send_new_proxies() {
    for (auto &cfg : _proxy_cfgs) {
        NewProxyReq req;
        memset(&req, 0, sizeof(req));
        req.proxy_name      = cfg.name;
        req.proxy_type      = cfg.type[0] ? cfg.type : "tcp";
        req.remote_port     = cfg.remotePort;
        req.use_encryption  = cfg.useEncryption;
        req.use_compression = cfg.useCompression;
        req.custom_domains  = cfg.customDomains[0] ? cfg.customDomains : nullptr;

        char *json = nullptr;
        size_t jlen = new_proxy_marshal(req, &json);
        if (json && jlen > 0) {
            _send_encrypted_msg(1, TypeNewProxy, json, jlen);
            Serial.printf("[FRPC] NewProxy sent: %s\n", json);
            free(json);
        }
    }
}

void FrpcClient::_send_encrypted_msg(uint32_t sid, MsgType type, const char *data, size_t len) {
    // 构建 frp 消息帧
    uint8_t *frame = nullptr;
    size_t total = build_msg_frame(type, data, len, &frame);
    if (!frame || total == 0) return;

    // AES-CFB 加密
    crypto_cfb_crypt(_encoder, frame, total);

    // 第一次发送加密数据时，先单独发送 IV_A（一个 DATA 帧），再发送加密数据（另一个 DATA 帧）
    // 与 xfrpc 的 initialize_encoder + send_enc_msg_frp_server 保持一致
    if (_client_iv_ready && !_client_iv_sent) {
        _client_iv_sent = true;
        _tcp.send_data(sid, 0, _client_iv, 16);
        Serial.println("[FRPC] Client IV_A sent");
    }

    // 通过 TCPMux DATA 帧发送加密数据
    _tcp.send_data(sid, 0, frame, total);
    free(frame);
}

void FrpcClient::_create_work_conn(uint32_t stream_id) {
    WorkConn wc;
    wc.run_id = _server_run_id;
    // frps 0.70+ 对 NewWorkConn 有时间戳时效检查（±90s），必须用当前时间重新计算 auth key
    time_t ts;
    char *ak = get_auth_key(_token, &ts, _clock);
    wc.privilege_key = ak ? ak : nullptr;
    wc.timestamp = (int)ts;

    char *json = nullptr;
    size_t len = work_conn_marshal(wc, &json);
    if (ak) free(ak);
    if (!json || len == 0) return;
    Serial.printf("[FRPC] NewWorkConn JSON: %s\n", json);

    uint8_t *frame = nullptr;
    size_t total = build_msg_frame(TypeNewWorkConn, json, len, &frame);
    free(json);
    if (!frame) return;

    // 参考原版 xfrpc init_tcp_mux_client 流程：
    // 1. 先发 WINDOW_UPDATE(SYN) 建立流
    // 2. 再发 DATA 携带 NewWorkConn 数据
    TmuxHdr win_hdr;
    win_hdr.version   = 0;
    win_hdr.type      = TMUX_WIN_UPDATE;
    win_hdr.flags     = htons(TMUX_FLAG_SYN);
    win_hdr.stream_id = htonl(stream_id);
    win_hdr.length    = htonl(0);

    _tcp.raw_write((const uint8_t *)&win_hdr, sizeof(win_hdr));

    TmuxHdr hdr;
    hdr.version   = 0;
    hdr.type      = TMUX_DATA;
    hdr.flags     = htons(0);
    hdr.stream_id = htonl(stream_id);
    hdr.length    = htonl(total);

    _tcp.raw_write((const uint8_t *)&hdr, sizeof(hdr));
    _tcp.raw_write(frame, total);
    Serial.printf("[FRPC] NewWorkConn sent: stream=%u len=%d (t=%u)\n",
                  stream_id, (int)total, (unsigned)millis());
    free(frame);
}
#pragma endregion // 第6区:frpc核心(frpc_client)

#endif // FRPC_H

