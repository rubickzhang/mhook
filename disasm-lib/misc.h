// Copyright (C) 2002, Matt Conover (mconover@gmail.com)
//
// misc.h - 通用工具宏和辅助函数声明
// 提供范围判断、地址有效性检测以及十六进制字符串转换等公共工具。

#ifndef MISC_H
#define MISC_H
#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>

// 取两个值中的较小值
#define MIN(a, b) ((a) < (b) ? (a) : (b))
// 取两个值中的较大值
#define MAX(a, b) ((a) > (b) ? (a) : (b))

// 判断值 x 是否在 [s, e) 范围内（起始值包含，结束值不包含）
// 特殊情况：若 s == e 且 x == s，也视为在范围内（区间退化为单点）
#define IS_IN_RANGE(x, s, e) \
( \
	((ULONG_PTR)(x) == (ULONG_PTR)(s) && (ULONG_PTR)(x) == (ULONG_PTR)(e)) || \
	((ULONG_PTR)(x) >= (ULONG_PTR)(s) && (ULONG_PTR)(x) < (ULONG_PTR)(e)) \
)

// 禁用 MSVC 对不安全 CRT 函数的弃用警告（版本 2005 及以上）
#if _MSC_VER >= 1400
#pragma warning(disable:4996)
#endif

// 根据平台定义有效用户态地址的最大值和 ULONG_PTR 类型
#if defined(_WIN64)
	// Win64：用户态地址空间上限（约 128 TB）
	#define VALID_ADDRESS_MAX 0x7FFEFFFFFFFFFFFF // Win64 specific
	typedef unsigned __int64 ULONG_PTR, *PULONG_PTR;
#else
	// Win32：用户态地址空间上限（约 2 GB）
	#define VALID_ADDRESS_MAX 0x7FFEFFFF // Win32 specific
	typedef unsigned long ULONG_PTR, *PULONG_PTR;
#endif

// 内存对齐声明辅助宏，用于结构体的对齐要求
#ifndef DECLSPEC_ALIGN
	#if (_MSC_VER >= 1300) && !defined(MIDL_PASS)
		#define DECLSPEC_ALIGN(x) __declspec(align(x))
	#else
		#define DECLSPEC_ALIGN(x)
	#endif
#endif

// 有效用户态地址的最小值（低于此值的页面通常不可访问）
#define VALID_ADDRESS_MIN 0x10000    // Win32 specific
// 判断地址 a 是否在合法的用户态地址范围内
#define IS_VALID_ADDRESS(a) IS_IN_RANGE(a, VALID_ADDRESS_MIN, VALID_ADDRESS_MAX+1)

// 判断字符 ch 是否是合法的十六进制字符（0-9、A-F、a-f）
BOOL IsHexChar(BYTE ch);

// 将十六进制字符串转换为二进制字节数组
// 参数：Input        - 输入的十六进制字符串
//       InputLength  - 输入字符串的字节长度
//       OutputLength - 输出缓冲区的字节数（由函数填写）
// 返回值：成功时返回分配的字节数组指针（调用者负责 free），失败时返回 NULL
BYTE *HexToBinary(char *Input, DWORD InputLength, DWORD *OutputLength);

#ifdef __cplusplus
}
#endif
#endif // MISC_H
