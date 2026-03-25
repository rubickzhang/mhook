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
// mhook.h - Windows API 内联 Hook 库公共接口头文件
//
// mhook 是一个轻量级 Windows API Hook 库，支持 x86（32 位）和 x64（64 位）平台。
// 内部原理：
//   1. 反汇编目标函数开头的若干字节（至少 5 字节，以便放入跳转指令）。
//   2. 将这些字节复制到"跳板"(trampoline)内存区域，并在其末尾追加跳回原函数的跳转。
//   3. 将目标函数开头替换为跳转到 Hook 函数的指令。
//   4. 调用方可通过原始函数指针（已指向跳板）来调用原始逻辑，实现"透明拦截"。

// 平台检测宏：统一用 _M_IX86_X64 判断是否运行于 x86/x64
#ifdef _M_IX86
#define _M_IX86_X64
#elif defined _M_X64
#define _M_IX86_X64
#endif

// 为指定系统函数安装 Hook。
//
// 参数：
//   ppSystemFunction [in/out] - 指向目标函数指针的指针。
//                               入参为原始函数地址；成功后被修改为指向跳板的地址，
//                               调用方应使用该值来调用原始函数（而非原地址）。
//   pHookFunction    [in]     - Hook 函数的地址，此后对系统函数的调用将跳转到这里。
//
// 返回值：成功返回 TRUE，失败返回 FALSE。
BOOL Mhook_SetHook(PVOID *ppSystemFunction, PVOID pHookFunction);

// 卸载之前通过 Mhook_SetHook 安装的 Hook，恢复原始函数行为。
//
// 参数：
//   ppHookedFunction [in/out] - 指向跳板函数指针的指针（即 Mhook_SetHook 成功后
//                               *ppSystemFunction 所指向的值）。
//                               成功后被还原为原始函数地址。
//
// 返回值：成功返回 TRUE，失败返回 FALSE。
BOOL Mhook_Unhook(PVOID *ppHookedFunction);
