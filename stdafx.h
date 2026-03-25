// stdafx.h - 预编译头文件
// 包含频繁使用但很少修改的系统头文件，加快编译速度。
//

#pragma once

// 目标 Windows 版本：Windows XP (0x0501) 及以上
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

// 用于 getaddrinfo 测试，引入 IPv6 兼容的网络地址解析 API
#include <WS2tcpip.h>
#pragma comment(lib, "ws2_32")

#include <windows.h>
#include <stdio.h>



