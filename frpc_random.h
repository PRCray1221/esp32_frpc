/**
 * @file frpc_random.h
 * @brief 平台真随机源（可选）
 *
 * 提供硬件真随机数给 frpc.h 使用（生成加密 IV/密钥、重连抖动等）。
 *
 * 使用方法：
 *   在入口程序（如 esp32_frpc.ino）中 include 本文件即可，
 *   它会定义 FRPC_USE_HW_RANDOM=1，使 frpc.h 使用硬件真随机。
 *
 * 删除本文件：frpc.h 自动回退到伪随机（仍可编译运行，但加密安全性降低）。
 *
 * 换平台：写新的 frpc_random.h（内容用该平台的真随机源），
 *         在入口 include，frpc.h 无需修改。
 */
#ifndef FRPC_RANDOM_H
#define FRPC_RANDOM_H

// 使 frpc.h 使用硬件真随机
#define FRPC_USE_HW_RANDOM 1

#include "esp_system.h"   // esp_random()

// 真随机实现：ESP32 硬件 RNG（基于芯片热噪声，不可预测）
inline uint32_t frpc_platform_random(void) {
    return esp_random();
}

#endif // FRPC_RANDOM_H
