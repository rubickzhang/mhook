// Copyright (C) 2003, Matt Conover (mconover@gmail.com)
//
// cpu.h - x86/x64 CPU 内部结构定义
// 包含 GDT、IDT、门描述符、TSS、页表等 CPU 内部数据结构的定义，
// 主要用于内核级分析和反汇编场景下的 CPU 状态解析。
#ifndef CPU_H
#define CPU_H
#ifdef __cplusplus
extern "C" {
#endif
#pragma pack(push,1)  // 按 1 字节对齐（与硬件结构保持一致）

#include <windows.h>
#include "misc.h"

////////////////////////////////////////////////////////
// 系统描述符（GDT 项 —— 兴趣生成的选择子存储 x86 Windows NT 核心）
////////////////////////////////////////////////////////

// 空描述符，仝不可使用
#define GDT_NULL 0
// R0（特权级 0 ）代码段选择子
#define GDT_R0_CODE 0x08
// R0 数据段选择子
#define GDT_R0_DATA 0x10
// R3（用户态特权级 3）代码段选择子
#define GDT_R3_CODE 0x18
// R3 数据段选择子
#define GDT_R3_DATA 0x20
// 任务状态段（TSS）选择子
#define GDT_TSS 0x28
// 处理器控制块（PCR）选择子
#define GDT_PCR 0x30
// R3 线程环境块（TEB）选择子
#define GDT_R3_TEB 0x38
// VDM（虚拟 DOS 机）选择子
#define GDT_VDM 0x40
// 局部描述符表（LDT）选择子
#define GDT_LDT 0x48
// 双故障 TSS 选择子
#define GDT_DOUBLEFAULT_TSS 0x50
// NMI（非可屏蔽中断）TSS 选择子
#define GDT_NMI_TSS 0x58

// 16 位 GDT 项（ABIOS 层）：
// TODO: #define GDT_ABIOS_UNKNOWN   0x60  (22F30-32F2F)
#define GDT_ABIOS_VIDEO 0x68                        // ABIOS 显示适配器段
#define GDT_ABIOS_GDT   0x70 // 描述 ABIOS GDT 自身的描述符
#define GDT_ABIOS_NTOS  0x78 // NTOSKRNL 的前 64K
#define GDT_ABIOS_CDA   0xE8 // 公共数据区
#define GDT_ABIOS_CODE  0xF0 // KiI386AbiosCall
#define GDT_ABIOS_STACK 0xF8

// 选择子的请求特权级（RPL）掌码，占 bit 0-1
#define SELECTOR_RPL_MASK 0x03 // bits 0-1
// 指示选择子属于 LDT（局部描述符表）bit 2
#define SELECTOR_LDT      0x04 // bit 2

// 数据段选择子属性掌码
#define DATA_ACCESS_MASK       (1<<0)  // 已访问标志
#define DATA_WRITE_ENABLE_MASK (1<<1)  // 可写标志
#define DATA_EXPAND_DOWN_MASK  (1<<2)  // 向下扩展段（用于栈段）

// 代码段选择子属性掌码
#define CODE_ACCESS_MASK       (1<<0)  // 已访问标志
#define CODE_READ_MASK         (1<<1)  // 可读标志
#define CODE_CONFORMING_MASK   (1<<2)  // 一致段标志（允许低特权级代码调用）
#define CODE_FLAG              (1<<3)  // 识别代码段的标志

// 门类型（IDT 门描述符）
#define TASK_GATE      5   // 任务门
#define INTERRUPT_GATE 6   // 中断门（自动关闭 IF 标志）
#define TRAP_GATE      7   // 降阱门（保留 IF 标志不变）

// IDT（中断描述符表）项结构体，同时也用于降阱门描述符
typedef struct _IDT_ENTRY
{
   USHORT LowOffset;   // 处理函数地址的低 16 位
   USHORT Selector;    // 代码段选择子
   UCHAR Ignored : 5;  // 保留字段
   UCHAR Zero : 3;     // 必须为 0
   UCHAR Type : 3;     // 门类型（TASK_GATE / INTERRUPT_GATE / TRAP_GATE）
   UCHAR Is32Bit : 1;  // 1 表示 32 位处理程序
   UCHAR Ignored2 : 1; // 保留
   UCHAR DPL : 2;      // 描述符特权级
   UCHAR Present : 1;  // 存在标志
   USHORT HighOffset;  // 处理函数地址的高 16 位
#ifdef _WIN64
   ULONG HighOffset64; // x64 下处理函数地址的最高 32 位
   ULONG Reserved;     // 保留
#endif
} IDT_ENTRY, TRAP_GATE_ENTRY;

// 调用门（Call Gate）描述符结构体，用于受控特权级过渡
typedef struct _CALL_GATE_ENTRY
{
   USHORT LowOffset;          // 目标函数地址低 16 位
   USHORT Selector;           // 目标代码段选择子
   UCHAR ParameterCount: 4;   // 需要从调用者栈复制到被调用者栈的参数个数
   UCHAR Ignored : 3;         // 保留
   UCHAR Type : 5;            // 门类型
   UCHAR DPL : 2;             // 描述符特权级（控制谁可调用此门）
   UCHAR Present : 1;         // 存在标志
   USHORT HighOffset;         // 目标函数地址高 16 位
#ifdef _WIN64
   ULONG HighOffset64;        // x64 下目标地址的高 32 位
   ULONG Reserved;            // 保留
#endif
} CALL_GATE_ENTRY;

// 任务门（Task Gate）描述符结构体，用于硬件任务切换
typedef struct _TASK_GATE_ENTRY
{
   USHORT Ignored;     // 保留
   USHORT Selector;    // TSS 的段选择子
   UCHAR Ignored2 : 5; // 保留
   UCHAR Zero : 3;     // 必须为 0
   UCHAR Type : 5;     // 门类型（= TASK_GATE = 5）
   UCHAR DPL : 2;      // 描述符特权级
   UCHAR Present : 1;  // 存在标志
   USHORT Ignored3;    // 保留
} TASK_GATE_ENTRY;

// 段描述符（Descriptor Entry）结构体，对应 GDT/LDT 中的一个 8 字节项
typedef struct _DESCRIPTOR_ENTRY
{
    USHORT  LimitLow;          // 段界限低 16 位
    USHORT  BaseLow;           // 段基地址低 16 位
    UCHAR   BaseMid;           // 段基地址中间 8 位
    UCHAR   Type : 4;          // 段类型
                               // 代码段：10EWA（E=向下扩展, W=可写, A=已访问）
                               // 数据段：11CRA（C=一致, R=可读, A=已访问）
    UCHAR   System : 1;        // 为 1 时表示这是门描述符或 LDT
    UCHAR   DPL : 2;           // 描述符特权级 (Descriptor Privilege Level)
                               // 数据段：MAX(CPL, RPL) 必须 <= DPL 才可访问（否则 #GP 异常）
                               // 非一致代码段无调用门：MAX(CPL, RPL) 必须 <= DPL
                               // 一致代码段：MAX(CPL, RPL) 必须 >= DPL（即 CPL 0-2 无法访问 DPL 3 的一致段）
                               // 非一致代码段有调用门：DPL 表示可访问门的最低特权级
    UCHAR   Present : 1;       // 存在标志：为 1 时段在内存中
    UCHAR   LimitHigh : 4;     // 段界限高 4 位
    UCHAR   Available: 1;      // 可由操作系统自由使用（AVL 位）
    UCHAR   Reserved : 1;      // 保留，必须为 0
    UCHAR   Is32Bit : 1;       // D/B 标志：为 1 表示 32 位操作符尺寸
    UCHAR   Granularity : 1;   // 粒度标志 G：为 1 时段界限单位为 4KB
    UCHAR   BaseHi : 8;        // 段基地址高 8 位
#ifdef _WIN64
   ULONG HighOffset64;         // x64 下段基地址高 32 位
   ULONG Reserved2;            // 保留
#endif
} DESCRIPTOR_ENTRY;

// 通用门（Gate Entry）描述符结构体
typedef struct _GATE_ENTRY
{
   USHORT LowOffset;   // 处理函数地址低 16 位
   UCHAR Skip;         // 保留字节
   UCHAR Type : 5;     // 门类型
   UCHAR DPL : 2;      // 描述符特权级
   UCHAR Present : 1;  // 存在标志
   USHORT HighOffset;  // 处理函数地址高 16 位
#ifdef _WIN64
   ULONG HighOffset64; // x64 下地址高 32 位
   ULONG Reserved;     // 保留
#endif
} GATE_ENTRY;

// 页表项（PTE）结构体，描述一个 4KB 物理内存页面的映射信息
// TODO: 需要更新以支持 X64
typedef struct _PTE_ENTRY
{
    ULONG Present : 1;        // 页面存在标志：为 1 时表示页面在物理内存中
    ULONG Write : 1;          // 可写标志：为 0 时仅可读
    ULONG Owner : 1;          // 用户/内核标志：为 1 时用户态可访问
    ULONG WriteThrough : 1;   // 写直通缓存模式
    ULONG CacheDisable : 1;   // 禁用缓存标志
    ULONG Accessed : 1;       // 已访问标志（硬件自动置位）
    ULONG Dirty : 1;          // 脔页标志（已写入）
    ULONG PAT : 1;            // 页属性表字段
    ULONG Global : 1;         // 全局页面标志（不被 TLB 刷新）
    ULONG CopyOnWrite : 1;    // 写时复制标志
    ULONG Prototype : 1;      // 原型页标志
    ULONG Transition : 1;     // 过渡页标志
    ULONG Address : 20;       // 页面框编号（物理地址 >> 12）
} PTE_ENTRY;

// 页目录项（PDE）结构体，描述一个 4MB 内存页面目录的映射信息
// TODO: 需要更新以支持 X64
typedef struct _PDE_ENTRY
{
	ULONG Present : 1;       // 存在标志
	ULONG Write : 1;         // 可写标志
	ULONG Owner : 1;         // 用户/内核标志
	ULONG WriteThrough : 1;  // 写直通缓存模式
	ULONG CacheDisable : 1;  // 禁用缓存标志
	ULONG Accessed : 1;      // 已访问标志
	ULONG Reserved1 : 1;     // 保留
	ULONG PageSize : 1;      // 大页面标志：为 1 时该项指向 4MB 页面
	ULONG Global : 1;        // 全局标志
	ULONG Reserved : 3;      // 保留
	ULONG Address : 20;      // 页表基地址（对应的页表地址 >> 12）
} PDE_ENTRY;

// I/O 访问许可映射结构体，存在于 TSS 中，用于对特定端口进行访问控制
// TODO: 需要更新以支持 X64
typedef struct _IO_ACCESS_MAP
{
    UCHAR DirectionMap[32];  // IN/OUT 指令方向映射
    UCHAR IoMap[8196];       // I/O 端口访问位图（每位对应一个端口，0=允许）
} IO_ACCESS_MAP;

// TSS 实体将1 页的大小
#define MIN_TSS_SIZE FIELD_OFFSET(TSS_ENTRY, IoMaps)
// 任务状态段 (TSS) 32 位版结构体，用于任务切换和内核栈存储
// TODO: 需要更新以支持 X64
typedef struct _TSS_ENTRY
{
    USHORT  Backlink;            // 上一个 TSS 的段选择子（任务嵌套时使用）
    USHORT  Reserved0;
    ULONG   Esp0;                // 特权级 0 的堆栈指针
    USHORT  Ss0;                 // 特权级 0 的堆栈段选择子
    USHORT  Reserved1;
    ULONG   NotUsed1[4];         // 特权级 1/2 的堆栈信息（Windows 不使用）
    ULONG   CR3;                 // 页目录基址寄存器
    ULONG   Eip;                 // 任务切换时保存的 EIP
    ULONG   NotUsed2[9];         // 其他通用寄存器保存区
    USHORT  Es;                  // ES 段选择子
    USHORT  Reserved2;
    USHORT  Cs;                  // CS 段选择子
    USHORT  Reserved3;
    USHORT  Ss;                  // SS 段选择子
    USHORT  Reserved4;
    USHORT  Ds;                  // DS 段选择子
    USHORT  Reserved5;
    USHORT  Fs;                  // FS 段选择子
    USHORT  Reserved6;
    USHORT  Gs;                  // GS 段选择子
    USHORT  Reserved7;
    USHORT  LDT;                 // LDT 段选择子
    USHORT  Reserved8;
    USHORT  Flags;               // 调试相关标志
    USHORT  IoMapBase;           // I/O 位图在 TSS 内的偏移量
    IO_ACCESS_MAP IoMaps[1];     // I/O 访问许可映射
    UCHAR IntDirectionMap[32];   // 中断方向映射
} TSS_ENTRY;

// TODO: update for X64
typedef struct _TSS16_ENTRY
{
    USHORT  Backlink;
    USHORT  Sp0;
    USHORT  Ss0;
    USHORT  Sp1;
    USHORT  Ss1;
    USHORT  Sp2;
    USHORT  Ss3;
    USHORT  Ip;
    USHORT  Flags;
    USHORT  Ax;
    USHORT  Cx;
    USHORT  Dx;
    USHORT  Bx;
    USHORT  Sp;
    USHORT  Bp;
    USHORT  Si;
    USHORT  Di;
    USHORT  Es;
    USHORT  Cs;
    USHORT  Ss;
    USHORT  Ds;
    USHORT  LDT;
} TSS16_ENTRY;

// TODO: update for X64
typedef struct _GDT_ENTRY
{
    USHORT  LimitLow;
    USHORT  BaseLow;
    union {
        struct {
            UCHAR   BaseMid;
            UCHAR   Flags1;
            UCHAR   Flags2;
            UCHAR   BaseHi;
        } Bytes;
        struct {
            ULONG   BaseMid : 8;
            ULONG   Type : 5;
            ULONG   Dpl : 2;
            ULONG   Pres : 1;
            ULONG   LimitHi : 4;
            ULONG   Sys : 1;
            ULONG   Reserved_0 : 1;
            ULONG   Default_Big : 1;
            ULONG   Granularity : 1;
            ULONG   BaseHi : 8;
        } Bits;
    } HighWord;
} GDT_ENTRY;

BYTE *GetAbsoluteAddressFromSegment(BYTE Segment, DWORD Offset);
BYTE *GetAbsoluteAddressFromSelector(WORD Selector, DWORD Offset);

#pragma pack(pop)
#ifdef __cplusplus
}
#endif
#endif // CPU_H