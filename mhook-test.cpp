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
// mhook-test.cpp - mhook 库功能测试程序
//
// 演示如何使用 Mhook_SetHook / Mhook_Unhook 对多个 Windows API 进行拦截：
//   - NtOpenProcess  (ntdll.dll)
//   - SelectObject   (gdi32.dll)
//   - getaddrinfo    (ws2_32.dll)
//   - HeapAlloc      (kernel32.dll)
//   - NtClose        (ntdll.dll)
//
// 每个 Hook 函数在调用原始函数前打印一条调试信息，展示拦截效果。

#include "stdafx.h"
#include "mhook-lib/mhook.h"

//=========================================================================
// NtOpenProcess 的类型定义（动态绑定，避免直接链接 ntdll 导入库）
//
typedef struct _CLIENT_ID {
	DWORD_PTR UniqueProcess;  // 进程 ID
	DWORD_PTR UniqueThread;   // 线程 ID
} CLIENT_ID, *PCLIENT_ID;

typedef ULONG (WINAPI* _NtOpenProcess)(OUT PHANDLE ProcessHandle, 
	     IN ACCESS_MASK AccessMask, IN PVOID ObjectAttributes, 
		 IN PCLIENT_ID ClientId ); 

//=========================================================================
// SelectObject 的函数指针类型定义（动态绑定）
typedef HGDIOBJ (WINAPI* _SelectObject)(HDC hdc, HGDIOBJ hgdiobj); 

//=========================================================================
// getaddrinfo 的函数指针类型定义（动态绑定）
typedef int (WSAAPI* _getaddrinfo)(const char* nodename, const char* servname, const struct addrinfo* hints, struct addrinfo** res);

//=========================================================================
// HeapAlloc 的函数指针类型定义（动态绑定）
typedef LPVOID (WINAPI *_HeapAlloc)(HANDLE, DWORD, SIZE_T);

//=========================================================================
// NtClose 的函数指针类型定义（动态绑定）
typedef ULONG (WINAPI* _NtClose)(IN HANDLE Handle);

//=========================================================================
// 保存各函数的原始地址（Hook 安装后这些指针指向跳板，可间接调用原始逻辑）
//
_NtOpenProcess TrueNtOpenProcess = (_NtOpenProcess)
	GetProcAddress(GetModuleHandle(L"ntdll"), "NtOpenProcess");

_SelectObject TrueSelectObject = (_SelectObject)
	GetProcAddress(GetModuleHandle(L"gdi32"), "SelectObject");

_getaddrinfo Truegetaddrinfo = (_getaddrinfo)GetProcAddress(GetModuleHandle(L"ws2_32"), "getaddrinfo");

_HeapAlloc TrueHeapAlloc = (_HeapAlloc)GetProcAddress(GetModuleHandle(L"kernel32"), "HeapAlloc");

_NtClose TrueNtClose = (_NtClose)GetProcAddress(GetModuleHandle(L"ntdll"), "NtClose");

//=========================================================================
// NtOpenProcess 的 Hook 函数：
// 打印进程 ID 后透传给原始函数，不影响正常行为。
//
ULONG WINAPI HookNtOpenProcess(OUT PHANDLE ProcessHandle, 
							   IN ACCESS_MASK AccessMask, 
							   IN PVOID ObjectAttributes, 
							   IN PCLIENT_ID ClientId)
{
	printf("***** Call to open process %d\n", ClientId->UniqueProcess);
	return TrueNtOpenProcess(ProcessHandle, AccessMask, 
		ObjectAttributes, ClientId);
}

//=========================================================================
// SelectObject 的 Hook 函数：
// 打印 HDC 和 HGDIOBJ 后透传给原始函数。
// （SelectObject 在 XP x64 的跳板中使用了 RIP 相对寻址，是 mhook 特殊处理的测试用例。）
//
HGDIOBJ WINAPI HookSelectobject(HDC hdc, HGDIOBJ hgdiobj)
{
	printf("***** Call to SelectObject(0x%p, 0x%p)\n", hdc, hgdiobj);
	return TrueSelectObject(hdc, hgdiobj);
}

//=========================================================================
// getaddrinfo 的 Hook 函数：
// 打印所有参数后透传给原始函数。
//
int WSAAPI Hookgetaddrinfo(const char* nodename, const char* servname, const struct addrinfo* hints, struct addrinfo** res)
{
	printf("***** Call to getaddrinfo(0x%p, 0x%p, 0x%p, 0x%p)\n", nodename, servname, hints, res);
	return Truegetaddrinfo(nodename, servname, hints, res);
}

//=========================================================================
// HeapAlloc 的 Hook 函数：
// 打印堆句柄和分配大小后透传给原始函数。
//
LPVOID WINAPI HookHeapAlloc(HANDLE a_Handle, DWORD a_Bla, SIZE_T a_Bla2) {
	printf("***** Call to HeapAlloc(0x%p, %u, 0x%p)\n", a_Handle, a_Bla, a_Bla2);
	return TrueHeapAlloc(a_Handle, a_Bla, a_Bla2);
}

//=========================================================================
// NtClose 的 Hook 函数：
// 打印句柄值后透传给原始函数。
//
ULONG WINAPI HookNtClose(HANDLE hHandle) {
	printf("***** Call to NtClose(0x%p)\n", hHandle);
	return TrueNtClose(hHandle);
}

//=========================================================================
// wmain - 测试程序入口
// 依次测试每个 API 的 Hook 安装与卸载，并观察输出验证拦截效果。
//
int wmain(int argc, WCHAR* argv[])
{
	HANDLE hProc = NULL;

	// ---- 测试 NtOpenProcess Hook ----
	if (Mhook_SetHook((PVOID*)&TrueNtOpenProcess, HookNtOpenProcess)) {
		// OpenProcess 内部会调用 NtOpenProcess，此时应触发 Hook 输出
		hProc = OpenProcess(PROCESS_ALL_ACCESS, 
			FALSE, GetCurrentProcessId());
		if (hProc) {
			printf("Successfully opened self: %p\n", hProc);
			CloseHandle(hProc);
		} else {
			printf("Could not open self: %d\n", GetLastError());
		}
		// 卸载 Hook，恢复原始 NtOpenProcess
		Mhook_Unhook((PVOID*)&TrueNtOpenProcess);
	}

	// 验证卸载后不再触发 Hook 输出
	hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
	if (hProc) {
		printf("Successfully opened self: %p\n", hProc);
		CloseHandle(hProc);
	} else {
		printf("Could not open self: %d\n", GetLastError());
	}

	// ---- 测试 SelectObject Hook ----
	// 具体意义：在 Windows XP x64 上，SelectObject 的第二条指令使用 RIP 相对寻址，
	// 这是测试 mhook 是否能正确修复跳板中 RIP 相对指令的关键用例。
	printf("Testing SelectObject.\n");
	if (Mhook_SetHook((PVOID*)&TrueSelectObject, HookSelectobject)) {
		HDC hdc = GetDC(NULL);
		HDC hdcMem = CreateCompatibleDC(hdc);
		HBITMAP hbm = CreateCompatibleBitmap(hdc, 32, 32);
		HBITMAP hbmOld = (HBITMAP)SelectObject(hdcMem, hbm);
		SelectObject(hdcMem, hbmOld);
		DeleteObject(hbm);
		DeleteDC(hdcMem);
		ReleaseDC(NULL, hdc);
		// 卸载 Hook
		Mhook_Unhook((PVOID*)&TrueSelectObject);
	}

	printf("Testing getaddrinfo.\n");
	// ---- 测试 getaddrinfo Hook ----
	if (Mhook_SetHook((PVOID*)&Truegetaddrinfo, Hookgetaddrinfo)) {
		WSADATA wd = {0};
		WSAStartup(MAKEWORD(2, 2), &wd);
		char* ip = "localhost";
		struct addrinfo aiHints;
		struct addrinfo *res = NULL;
		memset(&aiHints, 0, sizeof(aiHints));
		aiHints.ai_family = PF_UNSPEC;
		aiHints.ai_socktype = SOCK_STREAM;
		if (getaddrinfo(ip, NULL, &aiHints, &res)) {
			printf("getaddrinfo failed\n");
		} else {
			int n = 0;
			while(res) {
				res = res->ai_next;
				n++;
			}
			printf("got %d addresses\n", n);
		}
		WSACleanup();
		// 卸载 getaddrinfo Hook
		Mhook_Unhook((PVOID*)&Truegetaddrinfo);
	}

	// ---- 测试 HeapAlloc Hook ----
	printf("Testing HeapAlloc.\n");
	if (Mhook_SetHook((PVOID*)&TrueHeapAlloc, HookHeapAlloc))
	{
		// malloc 内部会调用 HeapAlloc，应触发 Hook 输出
		free(malloc(10));
		// 卸载 HeapAlloc Hook
		Mhook_Unhook((PVOID*)&TrueHeapAlloc);
	}

	// ---- 测试 NtClose Hook ----
	printf("Testing NtClose.\n");
	if (Mhook_SetHook((PVOID*)&TrueNtClose, HookNtClose))
	{
		// CloseHandle(NULL) 内部会调用 NtClose，应触发 Hook 输出
		CloseHandle(NULL);
		// 卸载 NtClose Hook
		Mhook_Unhook((PVOID*)&TrueNtClose);
	}

	return 0;
}

