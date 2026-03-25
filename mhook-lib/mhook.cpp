//Copyright (c) 2007-2008, Marton Anka
//
//Permission is hereby granted, free of charge, to any person obtaining a 
//copy of this software and associated documentation files (the "Software"), 
//to deal in the Software without restriction, including without limitation 
//the rights to use, copy, modify, merge, publish, distribute, sublicense, 
//and/or sell copies of the Software, and to permit persons to whom the 
//Software is furnished to do so, subject to the following conditions:
//
//The above copyright notice and this permission notice shall be included 
//in all copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
//OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL 
//THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
//FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS 
//IN THE SOFTWARE.
//
// mhook.cpp - Windows API 内联 Hook 核心实现
//
// 实现思路（Trampoline/Detour 技术）：
//   1. 反汇编目标函数入口处足够多的字节（>= 5），确保在指令边界截断。
//   2. 在目标函数附近（±2GB 以内）分配一段可执行内存，构建"跳板"函数：
//      跳板 = [原始入口字节] + [跳回目标函数后续代码的跳转指令]
//   3. 将目标函数入口处替换为跳转到 Hook 函数的指令（5 字节 jmp）。
//   4. 卸载 Hook 时，将原始字节写回，恢复目标函数。

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include "mhook.h"
#include "../disasm-lib/disasm.h"

//=========================================================================
// cntof(a) - 获取静态数组元素个数
#ifndef cntof
#define cntof(a) (sizeof(a)/sizeof(a[0]))
#endif

//=========================================================================
// GOOD_HANDLE(a) - 判断句柄是否有效（非 INVALID_HANDLE_VALUE 且非 NULL）
#ifndef GOOD_HANDLE
#define GOOD_HANDLE(a) ((a!=INVALID_HANDLE_VALUE)&&(a!=NULL))
#endif

//=========================================================================
// gle - GetLastError 的缩写宏，用于简化错误代码获取
#ifndef gle
#define gle GetLastError
#endif

//=========================================================================
// ODPRINTF - 调试输出宏：仅在 Debug 配置下将格式化字符串输出到调试器
#ifndef ODPRINTF

#ifdef _DEBUG
#define ODPRINTF(a) odprintf a
#else
#define ODPRINTF(a)
#endif

inline void __cdecl odprintf(PCSTR format, ...) {
	va_list	args;
	va_start(args, format);
	int len = _vscprintf(format, args);
	if (len > 0) {
		len += (1 + 2);
		PSTR buf = (PSTR) malloc(len);
		if (buf) {
			len = vsprintf_s(buf, len, format, args);
			if (len > 0) {
				while (len && isspace(buf[len-1])) len--;
				buf[len++] = '\r';
				buf[len++] = '\n';
				buf[len] = 0;
				OutputDebugStringA(buf);
			}
			free(buf);
		}
		va_end(args);
	}
}

inline void __cdecl odprintf(PCWSTR format, ...) {
	va_list	args;
	va_start(args, format);
	int len = _vscwprintf(format, args);
	if (len > 0) {
		len += (1 + 2);
		PWSTR buf = (PWSTR) malloc(sizeof(WCHAR)*len);
		if (buf) {
			len = vswprintf_s(buf, len, format, args);
			if (len > 0) {
				while (len && iswspace(buf[len-1])) len--;
				buf[len++] = L'\r';
				buf[len++] = L'\n';
				buf[len] = 0;
				OutputDebugStringW(buf);
			}
			free(buf);
		}
		va_end(args);
	}
}

#endif //#ifndef ODPRINTF

//=========================================================================
// 跳板代码区和 RIP 相对寻址修复相关常量
#define MHOOKS_MAX_CODE_BYTES	32  // 跳板或被覆写代码区的最大字节数
#define MHOOKS_MAX_RIPS			 4  // 每次 Hook 最多需要修复的 RIP 相对寻址指令数量

//=========================================================================
// 跳板结构体 —— 存储一个 Hook 所需的全部信息
struct MHOOKS_TRAMPOLINE {
	PBYTE	pSystemFunction;								// 原始系统函数的实际入口地址
	DWORD	cbOverwrittenCode;								// 被跳转指令覆写的字节数
	PBYTE	pHookFunction;									// Hook 函数的入口地址
	BYTE	codeJumpToHookFunction[MHOOKS_MAX_CODE_BYTES];	// 跳转到 Hook 函数的中转代码区（距离 > 2GB 时使用）
	BYTE	codeTrampoline[MHOOKS_MAX_CODE_BYTES];			// 跳板代码：存放展开的功能代码（原始入口指令 + 跳回原始函数的跳转）
	BYTE	codeUntouched[MHOOKS_MAX_CODE_BYTES];			// 未修改的原始入口字节备份（关闭 Hook 时用于恢复）
	MHOOKS_TRAMPOLINE* pPrevTrampoline;						// 在空闲列表中：指向上一节点。在使用中：指向前一个跳板。
	MHOOKS_TRAMPOLINE* pNextTrampoline;						// 在空闲列表中：指向下一节点。在使用中：指向后一个跳板。
};

//=========================================================================
// Hook 安装期间收集的 RIP 相对寻址指令信息（仅 x64 使用）
struct MHOOKS_RIPINFO
{
	DWORD	dwOffset;      // 指令内需要修复的位移字段偏移量
	S64		nDisplacement; // 原始 RIP 相对位移（相对于原始函数入口）
};

// Hook 安装期间使用的补丁辅助数据
struct MHOOKS_PATCHDATA
{
	S64				nLimitUp;   // RIP 相对寻址导致的分配上限偏移量
	S64				nLimitDown; // RIP 相对寻址导致的分配下限偏移量
	DWORD			nRipCnt;    // 需要修复的 RIP 指令数量
	MHOOKS_RIPINFO	rips[MHOOKS_MAX_RIPS]; // 各个 RIP 指令的中转信息
};

//=========================================================================
// 全局变量
static BOOL g_bVarsInitialized = FALSE;         // 临界区是否已初始化
static CRITICAL_SECTION g_cs;                   // 保护 Hook 操作的临界区（防止多线程竞争）
static MHOOKS_TRAMPOLINE* g_pHooks = NULL;      // 正在使用的跳板链表头部
static MHOOKS_TRAMPOLINE* g_pFreeList = NULL;   // 空闲跳板内存的链表头部
static DWORD g_nHooksInUse = 0;                 // 当前已安装的 Hook 数量
static HANDLE* g_hThreadHandles = NULL;         // 被挂起的线程句柄数组
static DWORD g_nThreadHandles = 0;              // 被挂起的线程数量
#define MHOOK_JMPSIZE 5         // 相对 jmp 指令的最小字节数（x86/x64 均为 5）
#define MHOOK_MINALLOCSIZE 4096 // 每次分配跳板内存的最小粒度（一页大小）

//=========================================================================
// Toolhelp 函数指针类型定义，用于运行时动态绑定，避免在旧系统上的链接问题
typedef HANDLE (WINAPI * _CreateToolhelp32Snapshot)(
	DWORD dwFlags,	   
	DWORD th32ProcessID  
	);

typedef BOOL (WINAPI * _Thread32First)(
									   HANDLE hSnapshot,	 
									   LPTHREADENTRY32 lpte
									   );

typedef BOOL (WINAPI * _Thread32Next)(
									  HANDLE hSnapshot,	 
									  LPTHREADENTRY32 lpte
									  );

//=========================================================================
// 从 kernel32.dll 中动态获取线程枚举函数（用于挂起/恢复其他线程）
_CreateToolhelp32Snapshot fnCreateToolhelp32Snapshot = (_CreateToolhelp32Snapshot) GetProcAddress(GetModuleHandle(L"kernel32"), "CreateToolhelp32Snapshot");
_Thread32First fnThread32First = (_Thread32First) GetProcAddress(GetModuleHandle(L"kernel32"), "Thread32First");
_Thread32Next fnThread32Next = (_Thread32Next) GetProcAddress(GetModuleHandle(L"kernel32"), "Thread32Next");

//=========================================================================
// Internal function:
//
// Remove the trampoline from the specified list, updating the head pointer
// if necessary.
//=========================================================================
static VOID ListRemove(MHOOKS_TRAMPOLINE** pListHead, MHOOKS_TRAMPOLINE* pNode) {
	if (pNode->pPrevTrampoline) {
		pNode->pPrevTrampoline->pNextTrampoline = pNode->pNextTrampoline;
	}

	if (pNode->pNextTrampoline) {
		pNode->pNextTrampoline->pPrevTrampoline = pNode->pPrevTrampoline;
	}

	if ((*pListHead) == pNode) {
		(*pListHead) = pNode->pNextTrampoline;
		assert((*pListHead)->pPrevTrampoline == NULL);
	}

	pNode->pPrevTrampoline = NULL;
	pNode->pNextTrampoline = NULL;
}

//=========================================================================
// Internal function:
//
// Prepend the trampoline from the specified list and update the head pointer.
//=========================================================================
static VOID ListPrepend(MHOOKS_TRAMPOLINE** pListHead, MHOOKS_TRAMPOLINE* pNode) {
	pNode->pPrevTrampoline = NULL;
	pNode->pNextTrampoline = (*pListHead);
	if ((*pListHead)) {
		(*pListHead)->pPrevTrampoline = pNode;
	}
	(*pListHead) = pNode;
}

//=========================================================================
static VOID EnterCritSec() {
	if (!g_bVarsInitialized) {
		InitializeCriticalSection(&g_cs);
		g_bVarsInitialized = TRUE;
	}
	EnterCriticalSection(&g_cs);
}

//=========================================================================
static VOID LeaveCritSec() {
	LeaveCriticalSection(&g_cs);
}

/*
author: rubickzhang
description:
SkipJumps函数用于跳过指定地址的跳转指令（跳转偏移量）的函数，
这个函数是在Hook函数中常常用到的一个工具函数。在Hook函数中，我们需要通过跳转指令
将函数的控制权转移到Hook函数中进行处理，但是有时候函数的前面可能会有多个跳转指令，
这会导致我们无法准确地知道函数的实际起始位置，从而无法正确地进行Hook。因此，我们
需要一个函数来跳过这些跳转指令，以便我们找到函数的实际起始位置。

逻辑：
1、保存当前函数地址，对当前地址进行循环判断，如果是跳转指令或者间接跳转指令，则根据跳转偏移
量来调整指针的位置；
2、当其字节不是跳转指令或者间接跳转指令，则退出循环；
3、返回指针指向的位置，即函数实际的起始地址；

跳转指令和对应的机器码
0xE8 CALL 后面的四个字节是地址
0xE9 JMP 后面的四个字节是偏移
0xEB JMP 后面的二个字节是偏移
0xFF15 CALL 后面的四个字节是存放地址的地址
0xFF25 JMP 后面的四个字节是存放地址的地址

0x68 PUSH 后面的四个字节入栈
0x6A PUSH 后面的一个字节入栈

如下：
0xE9：相对跳转指令（JMP），指令长度为5个字节。该指令使用32位带符号整数表示跳转偏移量，
表示相对于跳转指令下一条指令的偏移量。
0xEB：短跳转指令（JMP），指令长度为2个字节。该指令使用8位带符号整数表示跳转偏移量，表示相
对于跳转指令下一条指令的偏移量。


相对跳转指令的跳转目的地可以是当前代码段内的任意位置，也可以跳转到其他代码段。跳转偏移量
可以是正数或者负数，正数表示向后跳转，负数表示向前跳转。短跳转指令的跳转范围比相对跳转指
令小，只能跳转到当前代码段内的相对短的距离内。因此，短跳转指令通常用于实现短小的跳转。

SkipJumps函数使用0xE9和0xEB指令来跳过跳转指令，以便找到函数的实际起始位置。

ff 25  和 48 ff 25的解释：
这两个指令都是间接绝对跳转指令，前者为x86(32位)下，后者为64位模式下的
以64位为例,绝对跳转指令的格式为：
48 ff 25 xx xx xx xx 
其中48是REX前缀，用于指示使用64位寻址模式。ff 25是操作码，表示这是一条绝对跳转指令。
xx xx xx xx是指针地址，用于指向实际的目标地址。

所以综上所述，在进行x64的绝对跳转指令的跳转下，pbCode 是一个指向相对跳转指令的指针，而 
pbCode+7 指向相对跳转指令中偏移量的位置，lOffset 是我们希望跳转到的目标相对偏移量，因此
pbCode+7+lOffset 就是目标地址的指针。由于相对跳转指令的偏移量是相对于当前指令地址的，所以
在计算目标地址时，需要使用当前指令的地址加上相对偏移量来得到目标地址。

绝对跳转指令的代码，example:

#include <stdio.h>

// 定义一个函数，用于输出一条消息
void printMessage(const char* message) {
	printf("%s\n", message);
}

// 定义一个函数指针类型
typedef void (*PrintMessageFunc)(const char*);

int main() {
	// 定义一个函数指针，并初始化为 printMessage 函数的地址
	PrintMessageFunc pFunc = printMessage;

	// 使用绝对跳转指令，跳转到 pFunc 指向的函数
	// 使用 call eax 而不是 jmp eax，因为 call 指令会保存返回地址，
	// 从而允许函数正常返回到 main 函数。
	__asm {
		mov eax, pFunc
		call eax
	}

	return 0;
}
这里使用了绝对跳转指令 jmp eax，将 eax 寄存器中的地址作为跳转目标。由于 pFunc 指向
的是 printMessage 函数，因此 eax 中存储的就是 printMessage 函数的地址。执行 jmp eax 指令
后，处理器会跳转到 printMessage 函数，并在控制台中输出一条消息。

在实际开发中，绝对跳转指令通常用于实现一些低级别的功能，例如在Hooking中修改函数入口地址，
或者在反汇编中跳转到指定的地址等。

该函数的主要步骤如下：

保存原始代码地址：保存传入的代码地址 pbOrgCode。
处理特定平台的指令：
x86 平台：
跳过 mov edi, edi 指令（热补丁点）。
跳过 push ebp; mov ebp, esp; pop ebp 指令（MSVC 生成的“折叠”栈帧）。
x86 和 x64 平台：
如果指令是 jmp [address]（绝对跳转），则递归调用 SkipJumps 跳转到目标地址。
如果指令是 jmp offset（相对跳转），则递归调用 SkipJumps 跳转到目标地址。
如果指令是 jmp short offset（短跳转），则递归调用 SkipJumps 跳转到目标地址。
返回实际的函数入口地址：如果没有跳转指令，则返回原始代码地址 pbOrgCode。
这个函数在 Hook 函数中非常有用，因为它可以跳过目标函数前面的跳转指令，找到实际
的函数入口地址，从而确保 Hook 操作的准确性。

机器码解释：
0x8b:

mov 指令：用于将数据从一个位置移动到另一个位置。
0x8b 是 mov 指令的操作码，具体的操作取决于后续的字节。例如，0x8b 0xff 表示 mov edi, edi，这是一个常见的热补丁点（hot patch point）。
0xff:

jmp 或 call 指令：用于跳转或调用函数。
0xff 是多功能操作码，具体的操作取决于后续的字节。例如，0xff 0x25 表示 jmp [address]，这是一个绝对间接跳转。
0x55:

push 指令：用于将数据压入堆栈。
0x55 表示 push ebp，将基址指针寄存器 ebp 的值压入堆栈。这通常用于函数的栈帧设置。
0xec:
in 指令：用于从 I/O 端口读取数据。
0xec 表示 in al, dx，从端口 dx 读取一个字节到累加器 al 中。

0x5d：   pop ebp 指令的操作码。

0xe9 是 jmp 指令的操作码，表示一个相对跳转（relative jump）。具体来说，0xe9 后面跟随一个 32 位的偏移量，用于指定跳转目标地址。

以下是 0xe9 指令的详细解释：

jmp 指令：用于无条件跳转到指定的目标地址。
相对跳转：跳转目标地址是相对于当前指令的地址加上偏移量计算得出的。


0x8b 0xff       ; mov edi, edi
                ; 这是一个热补丁点，通常用于在运行时替换函数代码。

0xff 0x25       ; jmp [address]
                ; 这是一个绝对间接跳转，跳转到存储在指定地址的目标地址。

0x55            ; push ebp
                ; 将基址指针寄存器 `ebp` 的值压入堆栈，通常用于函数的栈帧设置。

0xec            ; in al, dx
                ; 从端口 `dx` 读取一个字节到累加器 `al` 中。
pop ebp:
pop 指令：用于从堆栈中弹出数据。
ebp：基址指针寄存器。

e9 xx xx xx xx
e9：jmp 指令的操作码。
xx xx xx xx：32 位的偏移量（以小端序存储），表示从当前指令的下一条指令开始的偏移量。
0xe9 0x05 0x00 0x00 0x00  ; jmp 0x00000005
这条指令表示从当前指令的下一条指令开始跳转 5 个字节。



以下是一个典型的函数栈帧设置和清理的汇编代码示例：
push ebp        ; 保存调用者的栈帧指针
mov ebp, esp    ; 设置当前栈帧指针
; 函数体
pop ebp         ; 恢复调用者的栈帧指针
ret             ; 返回调用者
在这个示例中，push ebp 和 mov ebp, esp 用于设置新的栈帧，而 pop ebp 和 ret
 用于清理栈帧并返回调用者。0x5d 操作码对应的 pop ebp 指令在函数结束时恢复调用者的栈帧指针。


*/

//=========================================================================
// 内部函数：SkipJumps
//
// 功能：跳过目标地址处的跳转存根（import 跳转表、热补丁跳板等），
//       返回实际的函数入口地址。
//
// 具体处理的指令序列（仅 x86/x64 平台）：
// [仅 x86]
//   0x8B 0xFF               : mov edi, edi——Windows 热补丁占位符，直接跳过
//   0x55 0x8B 0xEC 0x5D     : push ebp; mov ebp, esp; pop ebp——MSVC 折叠栈帧，直接跳过
// [x86 和 x64 均适用]
//   0xFF 0x25 [4 字节]       : jmp [addr32]（x86）或 jmp [rip+off32]（x64间接绝对跳）
//   0x48 0xFF 0x25 [4 字节]  : REX.W jmp [rip+off32]（x64 带 REX 前缀版本）
//   0xE9 [4 字节]            : jmp rel32——32 位相对跳转，目标 = pbCode+5+off32
//   0xEB [1 字节]            : jmp rel8——8 位短跳转，目标 = pbCode+2+off8（有符号）
//=========================================================================
static PBYTE SkipJumps(PBYTE pbCode) {
	PBYTE pbOrgCode = pbCode;
#ifdef _M_IX86_X64
#ifdef _M_IX86
	// mov edi, edi：Windows 热补丁占位符（2 字节 NOP 等效），跳过
	if (pbCode[0] == 0x8b && pbCode[1] == 0xff)
		pbCode += 2;
	// push ebp; mov ebp, esp; pop ebp：MSVC "折叠"栈帧，跳过 4 字节
	if (pbCode[0] == 0x55 && pbCode[1] == 0x8b && pbCode[2] == 0xec && pbCode[3] == 0x5d)
		pbCode += 4;
#endif	
	if (pbCode[0] == 0xff && pbCode[1] == 0x25) {
#ifdef _M_IX86
		// x86：后跟一个 32 位绝对地址（指向真实目标地址的指针所在地址）
		PBYTE pbTarget = *(PBYTE *)&pbCode[2];
		// 读取该地址处的内容，得到真实目标地址，继续递归
		return SkipJumps(*(PBYTE *)pbTarget);
#elif defined _M_X64
		// x64：后跟 32 位 RIP 相对偏移，*(rip+6+offset32) 才是真实目标
		INT32 lOffset = *(INT32 *)&pbCode[2];
		return SkipJumps(*(PBYTE*)(pbCode + 6 + lOffset));
	} else if (pbCode[0] == 0x48 && pbCode[1] == 0xff && pbCode[2] == 0x25) {
		// x64 带 REX 前缀（0x48）版本：指令长 7 字节，*(rip+7+offset32) 是真实目标
		INT32 lOffset = *(INT32 *)&pbCode[3];
		return SkipJumps(*(PBYTE*)(pbCode + 7 + lOffset));
#endif
	} else if (pbCode[0] == 0xe9) {
		// 0xE9：32 位相对跳转（jmp rel32），指令长 5 字节
		// 目标 = 当前指令地址 + 5 + 有符号 32 位偏移量
		return SkipJumps(pbCode + 5 + *(INT32 *)&pbCode[1]);
	} else if (pbCode[0] == 0xeb) {
		// 0xEB：8 位短跳转（jmp rel8），指令长 2 字节
		// 目标 = 当前指令地址 + 2 + 有符号 8 位偏移量
		return SkipJumps(pbCode + 2 + *(CHAR *)&pbCode[1]);
	}
#else
#error unsupported platform
#endif
	return pbOrgCode;
}

//=========================================================================
// 内部函数：EmitJump
//
// 在 pbCode 处写入跳转到 pbJumpTo 的机器码，尽量使用最少字节：
//   - 若两者距离 <= 0x7fff0000（约 ±2GB）：写入 5 字节相对跳转 (0xE9 + 4 字节偏移)
//   - 否则：写入 14 字节（x64）或 6 字节（x86）的间接绝对跳转 (0xFF 0x25 + 地址)
// 返回写入完成后的下一个可用代码地址。
//=========================================================================
static PBYTE EmitJump(PBYTE pbCode, PBYTE pbJumpTo) {
#ifdef _M_IX86_X64
	PBYTE pbJumpFrom = pbCode + 5;
	SIZE_T cbDiff = pbJumpFrom > pbJumpTo ? pbJumpFrom - pbJumpTo : pbJumpTo - pbJumpFrom;
	ODPRINTF((L"mhooks: EmitJump: Jumping from %p to %p, diff is %p", pbJumpFrom, pbJumpTo, cbDiff));
	if (cbDiff <= 0x7fff0000) {
		// 使用 5 字节相对跳转（0xE9 + 32 位有符号偏移）
		pbCode[0] = 0xe9;
		pbCode += 1;
		*((PDWORD)pbCode) = (DWORD)(DWORD_PTR)(pbJumpTo - pbJumpFrom);
		pbCode += sizeof(DWORD);
	} else {
		pbCode[0] = 0xff;
		pbCode[1] = 0x25;
		pbCode += 2;
#ifdef _M_IX86
		// on x86 we write an absolute address (just behind the instruction)
		*((PDWORD)pbCode) = (DWORD)(DWORD_PTR)(pbCode + sizeof(DWORD));
#elif defined _M_X64
		// on x64 we write the relative address of the same location
		*((PDWORD)pbCode) = (DWORD)0;
#endif
		pbCode += sizeof(DWORD);
		*((PDWORD_PTR)pbCode) = (DWORD_PTR)(pbJumpTo);
		pbCode += sizeof(DWORD_PTR);
	}
#else 
#error unsupported platform
#endif
	return pbCode;
}


//=========================================================================
// 内部函数：RoundDown
// 将地址 addr 向下取整为 rndDown 的整数倍
//=========================================================================
static size_t RoundDown(size_t addr, size_t rndDown)
{
	return (addr / rndDown) * rndDown;
}

//=========================================================================
// 内部函数：BlockAlloc
//
// 在 [pbLower, pbUpper) 范围内、尽可能靠近 pSystemFunction 的位置，
// 以螺旋搜索策略批量分配一页可执行内存，并将其切分为多个跳板槽位链接
// 到全局空闲链表；分配失败时返回 NULL。
//=========================================================================
static MHOOKS_TRAMPOLINE* BlockAlloc(PBYTE pSystemFunction, PBYTE pbLower, PBYTE pbUpper) {
	SYSTEM_INFO sSysInfo =  {0};
	::GetSystemInfo(&sSysInfo);

	// 批量分配时使用系统分配粒度与 MHOOK_MINALLOCSIZE 中的较大值，以节省 VirtualAlloc 调用次数
	const ptrdiff_t cAllocSize = max(sSysInfo.dwAllocationGranularity, MHOOK_MINALLOCSIZE);

	MHOOKS_TRAMPOLINE* pRetVal = NULL;
	PBYTE pModuleGuess = (PBYTE) RoundDown((size_t)pSystemFunction, cAllocSize);
	int loopCount = 0;
	for (PBYTE pbAlloc = pModuleGuess; pbLower < pbAlloc && pbAlloc < pbUpper; ++loopCount) {
		// 查询目标地址的内存状态
		MEMORY_BASIC_INFORMATION mbi;
		ODPRINTF((L"mhooks: BlockAlloc: Looking at address %p", pbAlloc));
		if (!VirtualQuery(pbAlloc, &mbi, sizeof(mbi)))
			break;
		// 仅在空闲且足够大的内存区域尝试分配
		if (mbi.State == MEM_FREE && mbi.RegionSize >= (unsigned)cAllocSize) {
			// 尝试在此地址分配可执行读写内存
			pRetVal = (MHOOKS_TRAMPOLINE*) VirtualAlloc(pbAlloc, cAllocSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (pRetVal) {
				size_t trampolineCount = cAllocSize / sizeof(MHOOKS_TRAMPOLINE);
				ODPRINTF((L"mhooks: BlockAlloc: Allocated block at %p as %d trampolines", pRetVal, trampolineCount));

				pRetVal[0].pPrevTrampoline = NULL;
				pRetVal[0].pNextTrampoline = &pRetVal[1];

				// prepare them by having them point down the line at the next entry.
				for (size_t s = 1; s < trampolineCount; ++s) {
					pRetVal[s].pPrevTrampoline = &pRetVal[s - 1];
					pRetVal[s].pNextTrampoline = &pRetVal[s + 1];
				}

				// last entry points to the current head of the free list
				pRetVal[trampolineCount - 1].pNextTrampoline = g_pFreeList;
				break;
			}
		}
				
		// This is a spiral, should be -1, 1, -2, 2, -3, 3, etc. (* cAllocSize)
		ptrdiff_t bytesToOffset = (cAllocSize * (loopCount + 1) * ((loopCount % 2 == 0) ? -1 : 1));
		pbAlloc = pbAlloc + bytesToOffset;
	}
	
	return pRetVal;
}

//=========================================================================
// 内部函数：FindTrampolineInRange
//
// 在空闲跳板链表（g_pFreeList）中查找地址位于 [pLower, pUpper) 之间的跳板，
// 找到后从空闲链表中移除并返回；未找到则返回 NULL。
//=========================================================================
static MHOOKS_TRAMPOLINE* FindTrampolineInRange(PBYTE pLower, PBYTE pUpper) {
	if (!g_pFreeList) {
		return NULL;
	}

	// 标准空闲链表搜索，使用双向链表以便安全移除节点
	MHOOKS_TRAMPOLINE* curEntry = g_pFreeList;
	while (curEntry) {
		if ((MHOOKS_TRAMPOLINE*) pLower < curEntry && curEntry < (MHOOKS_TRAMPOLINE*) pUpper) {
			ListRemove(&g_pFreeList, curEntry);

			return curEntry;
		}

		curEntry = curEntry->pNextTrampoline;
	}

	return NULL;
}

/*
// 分配跳板内存时上下界的计算说明：
//
// x86/x64 的相对跳转指令（jmp rel32）范围限制为 ±2GB。
// pLower / pUpper 是允许分配跳板的地址范围，基于以下规则计算：
//
//   pLower = pSystemFunction + nLimitUp（考虑 RIP 相对指令的最大负向偏移）
//            调整为 (pLower - 0x7fff0000) 以留出 ~2GB 的空间
//            若溢出地址空间下界则截断为 0x1
//   pUpper = pSystemFunction + nLimitDown（考虑 RIP 相对指令的最大正向偏移）
//            调整为 (pUpper + 0x7ff80000) 以留出 ~2GB 的空间
//            若溢出地址空间上界则截断为 0xfffffffffff80000
//
// 0x7ff80000 ≈ 2047 MB ≈ 2GB，确保跳板在目标函数的 ±2GB RIP 可达范围内。
//=========================================================================
// 内部函数：TrampolineAlloc
//
// 在目标函数附近（±2GB 内）分配一个跳板结构体槽位。
// 若已有符合条件的空闲槽位，直接复用；否则调用 BlockAlloc 新分配内存页。
//=========================================================================
static MHOOKS_TRAMPOLINE* TrampolineAlloc(PBYTE pSystemFunction, S64 nLimitUp, S64 nLimitDown) {

	MHOOKS_TRAMPOLINE* pTrampoline = NULL;

	// 计算可分配地址的下界和上界（基本情况是 ±2GB，有 RIP 相对指令时范围更小）
	PBYTE pLower = pSystemFunction + nLimitUp;
	pLower = pLower < (PBYTE)(DWORD_PTR)0x0000000080000000 ? 
						(PBYTE)(0x1) : (PBYTE)(pLower - (PBYTE)0x7fff0000);
	PBYTE pUpper = pSystemFunction + nLimitDown;
	pUpper = pUpper < (PBYTE)(DWORD_PTR)0xffffffff80000000 ? 
		(PBYTE)(pUpper + (DWORD_PTR)0x7ff80000) : (PBYTE)(DWORD_PTR)0xfffffffffff80000;
	ODPRINTF((L"mhooks: TrampolineAlloc: Allocating for %p between %p and %p", pSystemFunction, pLower, pUpper));

	// 优先在空闲链表中查找满足地址范围要求的跳板槽位
	pTrampoline = FindTrampolineInRange(pLower, pUpper);
	if (!pTrampoline) {
		// 空闲链表中没有合适的，尝试向系统申请新的内存块并再次查找
		g_pFreeList = BlockAlloc(pSystemFunction, pLower, pUpper);
		pTrampoline = FindTrampolineInRange(pLower, pUpper);
	}

	// 成功分配后插入正在使用的跳板链表头部
	if (pTrampoline) {
		ListPrepend(&g_pHooks, pTrampoline);
	}

	return pTrampoline;
}

//=========================================================================
// 内部函数：TrampolineGet
// 在已安装 Hook 的跳板链表（g_pHooks）中查找 Hook 函数地址为 pHookedFunction
// 的跳板节点，未找到返回 NULL。
//=========================================================================
static MHOOKS_TRAMPOLINE* TrampolineGet(PBYTE pHookedFunction) {
	MHOOKS_TRAMPOLINE* pCurrent = g_pHooks;

	while (pCurrent) {
		if (pCurrent->pHookFunction == pHookedFunction) {
			return pCurrent;
		}

		pCurrent = pCurrent->pNextTrampoline;
	}

	return NULL;
}

//=========================================================================
// Internal function:
//
// Free a trampoline structure.
//=========================================================================
static VOID TrampolineFree(MHOOKS_TRAMPOLINE* pTrampoline, BOOL bNeverUsed) {
	ListRemove(&g_pHooks, pTrampoline);

	// If a thread could feasinbly have some of our trampoline code 
	// on its stack and we yank the region from underneath it then it will
	// surely crash upon returning. So instead of freeing the 
	// memory we just let it leak. Ugly, but safe.
	if (bNeverUsed) {
		ListPrepend(&g_pFreeList, pTrampoline);
	}

	g_nHooksInUse--;
}

//=========================================================================
// 内部函数：SuspendOneThread
//
// 挂起指定线程，并确保其指令指针（IP/RIP）不在即将被修改的代码范围内。
// 若 IP 正位于要覆写的区域，最多重试 3 次（每次等待 100ms）；
// 若 3 次后 IP 仍在范围内，则放弃并关闭句柄（返回 NULL）。
//=========================================================================
static HANDLE SuspendOneThread(DWORD dwThreadId, PBYTE pbCode, DWORD cbBytes) {
	// 以最高访问权限打开线程
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadId);
	if (GOOD_HANDLE(hThread)) {
		// 挂起线程
		DWORD dwSuspendCount = SuspendThread(hThread);
		if (dwSuspendCount != -1) {
			// 检查线程当前的指令指针位置
			CONTEXT ctx;
			ctx.ContextFlags = CONTEXT_CONTROL;
			int nTries = 0;
			while (GetThreadContext(hThread, &ctx)) {
#ifdef _M_IX86
				PBYTE pIp = (PBYTE)(DWORD_PTR)ctx.Eip;
#elif defined _M_X64
				PBYTE pIp = (PBYTE)(DWORD_PTR)ctx.Rip;
#endif
				if (pIp >= pbCode && pIp < (pbCode + cbBytes)) {
					if (nTries < 3) {
						// IP 在要覆写的区域内，恢复线程等待其执行出该区域，然后再次挂起
						ODPRINTF((L"mhooks: SuspendOneThread: suspended thread %d - IP is at %p - IS COLLIDING WITH CODE", dwThreadId, pIp));
						ResumeThread(hThread);
						Sleep(100);
						SuspendThread(hThread);
						nTries++;
					} else {
						// 3 次重试后 IP 仍在冲突区域（通常不会发生，除非线程已经被其他代码挂起）
						ODPRINTF((L"mhooks: SuspendOneThread: suspended thread %d - IP is at %p - IS COLLIDING WITH CODE - CAN'T FIX", dwThreadId, pIp));
						ResumeThread(hThread);
						CloseHandle(hThread);
						hThread = NULL;
						break;
					}
				} else {
					// success, the IP is not conflicting
					ODPRINTF((L"mhooks: SuspendOneThread: Successfully suspended thread %d - IP is at %p", dwThreadId, pIp));
					break;
				}
			}
		} else {
			// couldn't suspend
			CloseHandle(hThread);
			hThread = NULL;
		}
	}
	return hThread;
}

//=========================================================================
// 内部函数：ResumeOtherThreads
// 恢复之前挂起的所有线程，并关闭其句柄。操作期间临时提升当前线程优先级。
//=========================================================================
static VOID ResumeOtherThreads() {
	// 提升优先级以便尽快完成恢复操作
	INT nOriginalPriority = GetThreadPriority(GetCurrentThread());
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
	// 遍历挂起的线程列表，逐一恢复并关闭句柄
	for (DWORD i=0; i<g_nThreadHandles; i++) {
		ResumeThread(g_hThreadHandles[i]);
		CloseHandle(g_hThreadHandles[i]);
	}
	// 释放句柄数组
	free(g_hThreadHandles);
	g_hThreadHandles = NULL;
	g_nThreadHandles = 0;
	SetThreadPriority(GetCurrentThread(), nOriginalPriority);
}

//=========================================================================
// 内部函数：SuspendOtherThreads
//
// 挂起当前进程中所有其他线程，确保它们的 IP 不在即将被修改的代码区域内。
// 操作期间临时提升当前线程优先级，以减少窗口期。
//=========================================================================
static BOOL SuspendOtherThreads(PBYTE pbCode, DWORD cbBytes) {
	BOOL bRet = FALSE;
	// 提升优先级，减少其他线程在此期间被调度的可能性
	INT nOriginalPriority = GetThreadPriority(GetCurrentThread());
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
	// 获取当前进程中所有线程的快照
	HANDLE hSnap = fnCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
	if (GOOD_HANDLE(hSnap)) {
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		// 统计当前进程中除自身外的线程数量
		DWORD nThreadsInProcess = 0;
		if (fnThread32First(hSnap, &te)) {
			do {
				if (te.th32OwnerProcessID == GetCurrentProcessId()) {
					if (te.th32ThreadID != GetCurrentThreadId()) {
						nThreadsInProcess++;
					}
				}
				te.dwSize = sizeof(te);
			} while(fnThread32Next(hSnap, &te));
		}
		ODPRINTF((L"mhooks: SuspendOtherThreads: counted %d other threads", nThreadsInProcess));
		if (nThreadsInProcess) {
			// alloc buffer for the handles we really suspended
			g_hThreadHandles = (HANDLE*)malloc(nThreadsInProcess*sizeof(HANDLE));
			if (g_hThreadHandles) {
				ZeroMemory(g_hThreadHandles, nThreadsInProcess*sizeof(HANDLE));
				DWORD nCurrentThread = 0;
				BOOL bFailed = FALSE;
				te.dwSize = sizeof(te);
				// go through every thread
				if (fnThread32First(hSnap, &te)) {
					do {
						if (te.th32OwnerProcessID == GetCurrentProcessId()) {
							if (te.th32ThreadID != GetCurrentThreadId()) {
								// attempt to suspend it
								g_hThreadHandles[nCurrentThread] = SuspendOneThread(te.th32ThreadID, pbCode, cbBytes);
								if (GOOD_HANDLE(g_hThreadHandles[nCurrentThread])) {
									ODPRINTF((L"mhooks: SuspendOtherThreads: successfully suspended %d", te.th32ThreadID));
									nCurrentThread++;
								} else {
									ODPRINTF((L"mhooks: SuspendOtherThreads: error while suspending thread %d: %d", te.th32ThreadID, gle()));
									// TODO: this might not be the wisest choice
									// but we can choose to ignore failures on
									// thread suspension. It's pretty unlikely that
									// we'll fail - and even if we do, the chances
									// of a thread's IP being in the wrong place
									// is pretty small.
									// bFailed = TRUE;
								}
							}
						}
						te.dwSize = sizeof(te);
					} while(fnThread32Next(hSnap, &te) && !bFailed);
				}
				g_nThreadHandles = nCurrentThread;
				bRet = !bFailed;
			}
		}
		CloseHandle(hSnap);
		//TODO: we might want to have another pass to make sure all threads
		// in the current process (including those that might have been
		// created since we took the original snapshot) have been 
		// suspended.
	} else {
		ODPRINTF((L"mhooks: SuspendOtherThreads: can't CreateToolhelp32Snapshot: %d", gle()));
	}
	SetThreadPriority(GetCurrentThread(), nOriginalPriority);
	if (!bRet) {
		ODPRINTF((L"mhooks: SuspendOtherThreads: Had a problem (or not running multithreaded), resuming all threads."));
		ResumeOtherThreads();
	}
	return bRet;
}

//=========================================================================
// if IP-relative addressing has been detected, fix up the code so the
// offset points to the original location
static void FixupIPRelativeAddressing(PBYTE pbNew, PBYTE pbOriginal, MHOOKS_PATCHDATA* pdata)
{
#if defined _M_X64
	// 计算跳板代码相对于原始代码的偏移差值
	S64 diff = pbNew - pbOriginal;
	for (DWORD i = 0; i < pdata->nRipCnt; i++) {
		// 将原始位移减去偏移差，使 RIP 相对指令在跳板新位置上仍能访问正确地址
		DWORD dwNewDisplacement = (DWORD)(pdata->rips[i].nDisplacement - diff);
		ODPRINTF((L"mhooks: fixing up RIP instruction operand for code at 0x%p: "
			L"old displacement: 0x%8.8x, new displacement: 0x%8.8x", 
			pbNew + pdata->rips[i].dwOffset, 
			(DWORD)pdata->rips[i].nDisplacement, 
			dwNewDisplacement));
		*(PDWORD)(pbNew + pdata->rips[i].dwOffset) = dwNewDisplacement;
	}
#endif
}

//=========================================================================
// 内部函数：DisassembleAndSkip
//
// 从 pFunction 处开始反汇编，跳过至少 dwMinLen 字节（确保始终在指令边界结束）。
// 遇到以下情况时立即停止：RET / 无条件或条件分支 / 调用指令。
// 对于 x64 下的 RIP 相对寻址指令（mov/lea reg, [rip+imm32]），
// 记录其位移信息到 pdata，以便后续在跳板中修复地址。
//
// 参数：
//   pFunction - 待反汇编的函数/代码起始地址
//   dwMinLen  - 最少需要覆盖的字节数
//   pdata     - 输出：RIP 相对寻址修复信息及分配范围限制
// 返回值：
//   成功跳过的字节总数（>= dwMinLen 时才足以安全安装 Hook）
//=========================================================================
static DWORD DisassembleAndSkip(PVOID pFunction, DWORD dwMinLen, MHOOKS_PATCHDATA* pdata) {
	DWORD dwRet = 0;
	pdata->nLimitDown = 0;
	pdata->nLimitUp = 0;
	pdata->nRipCnt = 0;
#ifdef _M_IX86
	ARCHITECTURE_TYPE arch = ARCH_X86;
#elif defined _M_X64
	ARCHITECTURE_TYPE arch = ARCH_X64;
#else
	#error unsupported platform
#endif
	DISASSEMBLER dis;
	if (InitDisassembler(&dis, arch)) {
		INSTRUCTION* pins = NULL;
		U8* pLoc = (U8*)pFunction;
		// 启用解码 + 生成反汇编字符串 + 对齐输出（便于调试输出）
		DWORD dwFlags = DISASM_DECODE | DISASM_DISASSEMBLE | DISASM_ALIGNOUTPUT;

		ODPRINTF((L"mhooks: DisassembleAndSkip: Disassembling %p", pLoc));
		while ( (dwRet < dwMinLen) && (pins = GetInstruction(&dis, (ULONG_PTR)pLoc, pLoc, dwFlags)) ) {
			ODPRINTF(("mhooks: DisassembleAndSkip: %p:(0x%2.2x) %s", pLoc, pins->Length, pins->String));
			if (pins->Type == ITYPE_RET		) break;
			if (pins->Type == ITYPE_BRANCH	) break;
			if (pins->Type == ITYPE_BRANCHCC) break;
			if (pins->Type == ITYPE_CALL	) break;
			if (pins->Type == ITYPE_CALLCC	) break;

			#if defined _M_X64
				BOOL bProcessRip = FALSE;
				// mov or lea to register from rip+imm32
				if ((pins->Type == ITYPE_MOV || pins->Type == ITYPE_LEA) && (pins->X86.Relative) && 
					(pins->X86.OperandSize == 8) && (pins->OperandCount == 2) &&
					(pins->Operands[1].Flags & OP_IPREL) && (pins->Operands[1].Register == AMD64_REG_RIP))
				{
					// rip-addressing "mov reg, [rip+imm32]"
					ODPRINTF((L"mhooks: DisassembleAndSkip: found OP_IPREL on operand %d with displacement 0x%x (in memory: 0x%x)", 1, pins->X86.Displacement, *(PDWORD)(pLoc+3)));
					bProcessRip = TRUE;
				}
				// mov or lea to rip+imm32 from register
				else if ((pins->Type == ITYPE_MOV || pins->Type == ITYPE_LEA) && (pins->X86.Relative) && 
					(pins->X86.OperandSize == 8) && (pins->OperandCount == 2) &&
					(pins->Operands[0].Flags & OP_IPREL) && (pins->Operands[0].Register == AMD64_REG_RIP))
				{
					// rip-addressing "mov [rip+imm32], reg"
					ODPRINTF((L"mhooks: DisassembleAndSkip: found OP_IPREL on operand %d with displacement 0x%x (in memory: 0x%x)", 0, pins->X86.Displacement, *(PDWORD)(pLoc+3)));
					bProcessRip = TRUE;
				}
				else if ( (pins->OperandCount >= 1) && (pins->Operands[0].Flags & OP_IPREL) )
				{
					// unsupported rip-addressing
					ODPRINTF((L"mhooks: DisassembleAndSkip: found unsupported OP_IPREL on operand %d", 0));
					// dump instruction bytes to the debug output
					for (DWORD i=0; i<pins->Length; i++) {
						ODPRINTF((L"mhooks: DisassembleAndSkip: instr byte %2.2d: 0x%2.2x", i, pLoc[i]));
					}
					break;
				}
				else if ( (pins->OperandCount >= 2) && (pins->Operands[1].Flags & OP_IPREL) )
				{
					// unsupported rip-addressing
					ODPRINTF((L"mhooks: DisassembleAndSkip: found unsupported OP_IPREL on operand %d", 1));
					// dump instruction bytes to the debug output
					for (DWORD i=0; i<pins->Length; i++) {
						ODPRINTF((L"mhooks: DisassembleAndSkip: instr byte %2.2d: 0x%2.2x", i, pLoc[i]));
					}
					break;
				}
				else if ( (pins->OperandCount >= 3) && (pins->Operands[2].Flags & OP_IPREL) )
				{
					// unsupported rip-addressing
					ODPRINTF((L"mhooks: DisassembleAndSkip: found unsupported OP_IPREL on operand %d", 2));
					// dump instruction bytes to the debug output
					for (DWORD i=0; i<pins->Length; i++) {
						ODPRINTF((L"mhooks: DisassembleAndSkip: instr byte %2.2d: 0x%2.2x", i, pLoc[i]));
					}
					break;
				}
				// follow through with RIP-processing if needed
				if (bProcessRip) {
					// calculate displacement relative to function start
					S64 nAdjustedDisplacement = pins->X86.Displacement + (pLoc - (U8*)pFunction);
					// store displacement values furthest from zero (both positive and negative)
					if (nAdjustedDisplacement < pdata->nLimitDown)
						pdata->nLimitDown = nAdjustedDisplacement;
					if (nAdjustedDisplacement > pdata->nLimitUp)
						pdata->nLimitUp = nAdjustedDisplacement;
					// store patch info
					if (pdata->nRipCnt < MHOOKS_MAX_RIPS) {
						pdata->rips[pdata->nRipCnt].dwOffset = dwRet + 3;
						pdata->rips[pdata->nRipCnt].nDisplacement = pins->X86.Displacement;
						pdata->nRipCnt++;
					} else {
						// no room for patch info, stop disassembly
						break;
					}
				}
			#endif

			dwRet += pins->Length;
			pLoc  += pins->Length;
		}

		CloseDisassembler(&dis);
	}

	return dwRet;
}

//=========================================================================
// Mhook_SetHook - 为指定系统函数安装内联 Hook
//
// 执行步骤：
//   1. 通过 SkipJumps 找到真实函数入口（越过导入跳转表/热补丁存根）
//   2. 使用 DisassembleAndSkip 确定需要覆写的字节数（>= 5）
//   3. 挂起当前进程中所有其他线程，防止多线程竞态
//   4. 在目标函数附近分配跳板内存（TrampolineAlloc）
//   5. 将原始入口字节复制到跳板，并在其后追加跳回原始函数后续代码的跳转
//   6. 修复跳板中的 RIP 相对寻址指令（x64）
//   7. 将目标函数入口写入跳转到 Hook 函数的指令
//   8. 更新 *ppSystemFunction 指向跳板，供调用方调用原始逻辑
//   9. 恢复被挂起的其他线程
//=========================================================================
BOOL Mhook_SetHook(PVOID *ppSystemFunction, PVOID pHookFunction) {
	MHOOKS_TRAMPOLINE* pTrampoline = NULL;
	PVOID pSystemFunction = *ppSystemFunction;
	// 进入临界区，保证线程安全
	EnterCritSec();
	ODPRINTF((L"mhooks: Mhook_SetHook: Started on the job: %p / %p", pSystemFunction, pHookFunction));
	// 跳过导入跳转表等存根，找到真实的函数入口地址
	pSystemFunction = SkipJumps((PBYTE)pSystemFunction);
	pHookFunction   = SkipJumps((PBYTE)pHookFunction);
	ODPRINTF((L"mhooks: Mhook_SetHook: Started on the job: %p / %p", pSystemFunction, pHookFunction));
	// figure out the length of the overwrite zone
	MHOOKS_PATCHDATA patchdata = {0};
	DWORD dwInstructionLength = DisassembleAndSkip(pSystemFunction, MHOOK_JMPSIZE, &patchdata);
	if (dwInstructionLength >= MHOOK_JMPSIZE) {
		ODPRINTF((L"mhooks: Mhook_SetHook: disassembly signals %d bytes", dwInstructionLength));
		// suspend every other thread in this process, and make sure their IP 
		// is not in the code we're about to overwrite.
		SuspendOtherThreads((PBYTE)pSystemFunction, dwInstructionLength);
		// allocate a trampoline structure (TODO: it is pretty wasteful to get
		// VirtualAlloc to grab chunks of memory smaller than 100 bytes)
		pTrampoline = TrampolineAlloc((PBYTE)pSystemFunction, patchdata.nLimitUp, patchdata.nLimitDown);
		if (pTrampoline) {
			ODPRINTF((L"mhooks: Mhook_SetHook: allocated structure at %p", pTrampoline));
			DWORD dwOldProtectSystemFunction = 0;
			DWORD dwOldProtectTrampolineFunction = 0;
			// set the system function to PAGE_EXECUTE_READWRITE
			if (VirtualProtect(pSystemFunction, dwInstructionLength, PAGE_EXECUTE_READWRITE, &dwOldProtectSystemFunction)) {
				ODPRINTF((L"mhooks: Mhook_SetHook: readwrite set on system function"));
				// mark our trampoline buffer to PAGE_EXECUTE_READWRITE
				if (VirtualProtect(pTrampoline, sizeof(MHOOKS_TRAMPOLINE), PAGE_EXECUTE_READWRITE, &dwOldProtectTrampolineFunction)) {
					ODPRINTF((L"mhooks: Mhook_SetHook: readwrite set on trampoline structure"));

					// create our trampoline function
					PBYTE pbCode = pTrampoline->codeTrampoline;
					// save original code..
					for (DWORD i = 0; i<dwInstructionLength; i++) {
						pTrampoline->codeUntouched[i] = pbCode[i] = ((PBYTE)pSystemFunction)[i];
					}
					pbCode += dwInstructionLength;
					// plus a jump to the continuation in the original location
					pbCode = EmitJump(pbCode, ((PBYTE)pSystemFunction) + dwInstructionLength);
					ODPRINTF((L"mhooks: Mhook_SetHook: updated the trampoline"));

					// fix up any IP-relative addressing in the code
					FixupIPRelativeAddressing(pTrampoline->codeTrampoline, (PBYTE)pSystemFunction, &patchdata);

					DWORD_PTR dwDistance = (PBYTE)pHookFunction < (PBYTE)pSystemFunction ? 
						(PBYTE)pSystemFunction - (PBYTE)pHookFunction : (PBYTE)pHookFunction - (PBYTE)pSystemFunction;
					if (dwDistance > 0x7fff0000) {
						// create a stub that jumps to the replacement function.
						// we need this because jumping from the API to the hook directly 
						// will be a long jump, which is 14 bytes on x64, and we want to 
						// avoid that - the API may or may not have room for such stuff. 
						// (remember, we only have 5 bytes guaranteed in the API.)
						// on the other hand we do have room, and the trampoline will always be
						// within +/- 2GB of the API, so we do the long jump in there. 
						// the API will jump to the "reverse trampoline" which
						// will jump to the user's hook code.
						pbCode = pTrampoline->codeJumpToHookFunction;
						pbCode = EmitJump(pbCode, (PBYTE)pHookFunction);
						ODPRINTF((L"mhooks: Mhook_SetHook: created reverse trampoline"));
						FlushInstructionCache(GetCurrentProcess(), pTrampoline->codeJumpToHookFunction, 
							pbCode - pTrampoline->codeJumpToHookFunction);

						// update the API itself
						pbCode = (PBYTE)pSystemFunction;
						pbCode = EmitJump(pbCode, pTrampoline->codeJumpToHookFunction);
					} else {
						// the jump will be at most 5 bytes so we can do it directly
						// update the API itself
						pbCode = (PBYTE)pSystemFunction;
						pbCode = EmitJump(pbCode, (PBYTE)pHookFunction);
					}

					// update data members
					pTrampoline->cbOverwrittenCode = dwInstructionLength;
					pTrampoline->pSystemFunction = (PBYTE)pSystemFunction;
					pTrampoline->pHookFunction = (PBYTE)pHookFunction;

					// flush instruction cache and restore original protection
					FlushInstructionCache(GetCurrentProcess(), pTrampoline->codeTrampoline, dwInstructionLength);
					VirtualProtect(pTrampoline, sizeof(MHOOKS_TRAMPOLINE), dwOldProtectTrampolineFunction, &dwOldProtectTrampolineFunction);
				} else {
					ODPRINTF((L"mhooks: Mhook_SetHook: failed VirtualProtect 2: %d", gle()));
				}
				// flush instruction cache and restore original protection
				FlushInstructionCache(GetCurrentProcess(), pSystemFunction, dwInstructionLength);
				VirtualProtect(pSystemFunction, dwInstructionLength, dwOldProtectSystemFunction, &dwOldProtectSystemFunction);
			} else {
				ODPRINTF((L"mhooks: Mhook_SetHook: failed VirtualProtect 1: %d", gle()));
			}
			if (pTrampoline->pSystemFunction) {
				// Hook 成功：将 *ppSystemFunction 指向跳板，供调用方调用原始逻辑
				*ppSystemFunction = pTrampoline->codeTrampoline;
				ODPRINTF((L"mhooks: Mhook_SetHook: Hooked the function!"));
			} else {
				// Hook 失败：丢弃跳板（强制释放内存）
				TrampolineFree(pTrampoline, TRUE);
				pTrampoline = NULL;
			}
		}
		// 恢复被挂起的其他线程
		ResumeOtherThreads();
	} else {
		ODPRINTF((L"mhooks: disassembly signals %d bytes (unacceptable)", dwInstructionLength));
	}
	LeaveCritSec();
	return (pTrampoline != NULL);
}

//=========================================================================
// Mhook_Unhook - 卸载已安装的 Hook，恢复原始函数行为
//
// 执行步骤：
//   1. 查找与 *ppHookedFunction（跳板地址）对应的跳板结构
//   2. 挂起其他线程，防止并发访问被修改的代码区
//   3. 将原始入口字节从 codeUntouched 写回目标函数起始处
//   4. 刷新指令缓存，恢复内存保护属性
//   5. 将 *ppHookedFunction 还原为原始函数地址
//   6. 释放（归还）跳板槽位到空闲链表（内存不真正释放，防止崩溃）
//   7. 恢复其他线程
//=========================================================================
BOOL Mhook_Unhook(PVOID *ppHookedFunction) {
	ODPRINTF((L"mhooks: Mhook_Unhook: %p", *ppHookedFunction));
	BOOL bRet = FALSE;
	EnterCritSec();
	// 根据跳板中存储的 Hook 函数地址查找跳板结构体
	MHOOKS_TRAMPOLINE* pTrampoline = TrampolineGet((PBYTE)*ppHookedFunction);
	if (pTrampoline) {
		// make sure nobody's executing code where we're about to overwrite a few bytes
		SuspendOtherThreads(pTrampoline->pSystemFunction, pTrampoline->cbOverwrittenCode);
		ODPRINTF((L"mhooks: Mhook_Unhook: found struct at %p", pTrampoline));
		DWORD dwOldProtectSystemFunction = 0;
		// make memory writable
		if (VirtualProtect(pTrampoline->pSystemFunction, pTrampoline->cbOverwrittenCode, PAGE_EXECUTE_READWRITE, &dwOldProtectSystemFunction)) {
			ODPRINTF((L"mhooks: Mhook_Unhook: readwrite set on system function"));
			PBYTE pbCode = (PBYTE)pTrampoline->pSystemFunction;
			for (DWORD i = 0; i<pTrampoline->cbOverwrittenCode; i++) {
				pbCode[i] = pTrampoline->codeUntouched[i];
			}
			// flush instruction cache and make memory unwritable
			FlushInstructionCache(GetCurrentProcess(), pTrampoline->pSystemFunction, pTrampoline->cbOverwrittenCode);
			VirtualProtect(pTrampoline->pSystemFunction, pTrampoline->cbOverwrittenCode, dwOldProtectSystemFunction, &dwOldProtectSystemFunction);
			// return the original function pointer
			*ppHookedFunction = pTrampoline->pSystemFunction;
			bRet = TRUE;
			ODPRINTF((L"mhooks: Mhook_Unhook: sysfunc: %p", *ppHookedFunction));
			// free the trampoline while not really discarding it from memory
			TrampolineFree(pTrampoline, FALSE);
			ODPRINTF((L"mhooks: Mhook_Unhook: unhook successful"));
		} else {
			ODPRINTF((L"mhooks: Mhook_Unhook: failed VirtualProtect 1: %d", gle()));
		}
		// make the other guys runnable
		ResumeOtherThreads();
	}
	LeaveCritSec();
	return bRet;
}

//=========================================================================
