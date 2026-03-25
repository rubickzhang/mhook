// Copyright (C) 2004, Matt Conover (mconover@gmail.com)
//
// disasm.h - 通用反汇编器接口头文件
// 定义了反汇编指令、操作数、指令类型、体系结构等核心数据结构。
//
// 警告：
// 不建议修改任何 OP_*、ITYPE_*、*_MASK 等标志（标注为 UNUSED 的除外）。
// 这些标志有一部分是体系无关的，另一部分由具体体系定义，
// 在没有充分了解其相互关系之前请勿擅自修改。

#ifndef DISASM_H
#define DISASM_H
#ifdef __cplusplus
extern "C" {
#endif
#include <windows.h>
#include <stdio.h>
#include "misc.h"

// 基本整数类型的类型别名
typedef signed char S8;
typedef unsigned char U8;
typedef signed short S16;
typedef unsigned short U16;
typedef signed long S32;
typedef unsigned long U32;
typedef LONG64 S64;
typedef ULONG64 U64;

#ifdef SPEEDY
// 在 Visual Studio 6 下将内部函数设为 inline 会导致编译极慢，此处封装相关宏
#define INTERNAL static _inline 
#define INLINE _inline
#else
#define INTERNAL static
#define INLINE
#endif

// 判断一条指令是否有效（非 NULL 且未发生错误）
#define VALID_INSTRUCTION(i) ((i) && !((i)->ErrorOccurred))
// 获取下一条指令的地址（当前地址 + 当前指令长度）
#define NEXT_INSTRUCTION(i) ((i)->Address + (i)->Length)
// 获取反汇编器的体系类型
#define DISASM_ARCH_TYPE(dis) ((dis)->ArchType)
// 获取指令所属反汇编器的体系类型
#define INS_ARCH_TYPE(ins) DISASM_ARCH_TYPE((ins)->Disassembler)

// 各项最大长度常量（应设为所支持体系的最大値）
#define MAX_PREFIX_LENGTH 15          // 指令前缀最大数量
#define MAX_OPERAND_COUNT 3           // 操作数最多个数
#define MAX_INSTRUCTION_LENGTH 25     // 指令最大字节数
#define MAX_OPCODE_LENGTH 3           // 操作码最大字节数
#define MAX_OPCODE_DESCRIPTION 256    // 指令文字描述的最大长度

/////////////////////////////////////////////////////////////////////
// 代码分支信息结构体
/////////////////////////////////////////////////////////////////////

// 代码分支目标地址的最大数量
#define MAX_CODE_REFERENCE_COUNT 3

// 代码分支信息：存储指令的跳转目标
// 对于条件跳转 / 调用指令，Addresses 包含可能的目标地址
typedef struct _CODE_BRANCH
{
	U64 Addresses[MAX_CODE_REFERENCE_COUNT]; // 跳转目标地址列表（多目标时为 NULL）
	U32 Count;                               // 目标地址的数量
	U8 IsLoop : 1;                           // 是否是循环指令（LOOP/LOOPE/LOOPNE）
	U8 IsCall : 1;                           // 为 1 表示调用指令，为 0 表示跳转指令
	U8 IsIndirect : 1;                       // 是否是间接调用/跳转（call/jmp [Address] 形式）
	U8 AddressOffset: 5;                     // 地址在指令中的偏移量
	struct _INSTRUCTION_OPERAND *Operand;    // 包含目标地址的操作数
} CODE_BRANCH;

/////////////////////////////////////////////////////////////////////
// 数据引用信息结构体
/////////////////////////////////////////////////////////////////////

// 数据引用目标地址的最大数量
#define MAX_DATA_REFERENCE_COUNT 3

// 数据引用信息：存储指令访问的数据地址
typedef struct _DATA_REFERENCE
{
	U64 Addresses[MAX_DATA_REFERENCE_COUNT]; // 引用的数据地址列表（多地址时为 NULL）
	U32 Count;                               // 引用地址数量
	ULONG_PTR DataSize;                      // 被引用数据的大小（字节数）
	struct _INSTRUCTION_OPERAND *Operand;    // 包含引用地址的操作数
} DATA_REFERENCE;

////////////////////////////////////////////////////////////////////
// 指令分类定义
/////////////////////////////////////////////////////////////////////

// 指令组偏移量（bits 8-26）：每个组占一个 bit 位，可组合使用
// 指令类型（bits 0-7）：标识指令在组内的具体类型，互斥
#define ITYPE_EXEC_OFFSET     (1<<8)   // 执行控制类（分支、调用、返回）
#define ITYPE_ARITH_OFFSET    (1<<9)   // 算术运算类
#define ITYPE_LOGIC_OFFSET    (1<<10)  // 逻辑运算类
#define ITYPE_STACK_OFFSET    (1<<11)  // 堆栈操作类
#define ITYPE_TESTCOND_OFFSET (1<<12)  // 条件测试类
#define ITYPE_LOAD_OFFSET     (1<<13)  // 数据加载/传送类
#define ITYPE_ARRAY_OFFSET    (1<<14)  // 字符串/数组操作类
#define ITYPE_BIT_OFFSET      (1<<15)  // 位操作类
#define ITYPE_FLAG_OFFSET     (1<<16)  // 标志位操作类
#define ITYPE_FPU_OFFSET      (1<<17)  // 浮点运算类
#define ITYPE_TRAPS_OFFSET    (1<<18)  // 陷阱/中断类
#define ITYPE_SYSTEM_OFFSET   (1<<19)  // 系统指令类
#define ITYPE_OTHER_OFFSET    (1<<20)  // 其他指令类
#define ITYPE_UNUSED1_OFFSET  (1<<21)  // 未使用（可由架构自定义）
#define ITYPE_UNUSED2_OFFSET  (1<<22)
#define ITYPE_UNUSED3_OFFSET  (1<<23)
#define ITYPE_UNUSED4_OFFSET  (1<<24)
#define ITYPE_UNUSED5_OFFSET  (1<<25)
#define ITYPE_UNUSED6_OFFSET  (1<<26)
#define ITYPE_EXT_UNUSED1     (1<<27)
#define ITYPE_EXT_UNUSED2     (1<<28)
#define ITYPE_EXT_UNUSED3     (1<<29)
#define ITYPE_EXT_UNUSED4     (1<<30)
#define ITYPE_EXT_UNUSED5     (1<<31)

// x86 指令组扩展标志（bits 27-31）
#define ITYPE_EXT_64     ITYPE_EXT_UNUSED1 // 64 位模式下使用索引 1，否则用索引 0
#define ITYPE_EXT_MODRM  ITYPE_EXT_UNUSED2 // ModRM 字节可能延伸操作码
#define ITYPE_EXT_SUFFIX ITYPE_EXT_UNUSED3 // ModRM/SIB/位移后的字节是第三操作码字节
#define ITYPE_EXT_PREFIX ITYPE_EXT_UNUSED4 // 该条目是前缀
#define ITYPE_EXT_FPU    ITYPE_EXT_UNUSED5 // FPU 指令需要特殊处理

// SIMD 指令集组偏移量定义
#define ITYPE_3DNOW_OFFSET ITYPE_UNUSED1_OFFSET  // AMD 3DNow! 指令
#define ITYPE_MMX_OFFSET   ITYPE_UNUSED2_OFFSET  // MMX 指令
#define ITYPE_SSE_OFFSET   ITYPE_UNUSED3_OFFSET  // SSE 指令
#define ITYPE_SSE2_OFFSET  ITYPE_UNUSED4_OFFSET  // SSE2 指令
#define ITYPE_SSE3_OFFSET  ITYPE_UNUSED5_OFFSET  // SSE3 指令

// 指令类型掌码
#define ITYPE_TYPE_MASK  0x7FFFFFFF  // 提取指令类型字段
#define ITYPE_GROUP_MASK 0x7FFFFF00  // 提取指令组字段

// 指令类型枚举定义
typedef enum _INSTRUCTION_TYPE
{
	// ITYPE_EXEC 组：执行流程控制
	ITYPE_EXEC = ITYPE_EXEC_OFFSET,  // 直接跳转/分支
	ITYPE_BRANCH,                    // 无条件跳转
	ITYPE_BRANCHCC, // 条件跳转（不仅限于标志位条件）
	ITYPE_CALL,                      // 调用指令
	ITYPE_CALLCC, // 条件调用（不仅限于标志位条件）
	ITYPE_RET,                       // 返回指令
	ITYPE_LOOPCC,                    // 循环指令（LOOP/LOOPE/LOOPNE）

	// ITYPE_ARITH 组：算术运算
	ITYPE_ARITH = ITYPE_ARITH_OFFSET,
	ITYPE_XCHGADD,  // 交换名并加
	ITYPE_ADD,
	ITYPE_SUB,
	ITYPE_MUL,
	ITYPE_DIV,
	ITYPE_INC,       // 自增
	ITYPE_DEC,       // 自减
	ITYPE_SHL,       // 左移
	ITYPE_SHR,
	ITYPE_ROL,
	ITYPE_ROR,

	// ITYPE_LOGIC group
	ITYPE_LOGIC=ITYPE_LOGIC_OFFSET,
	ITYPE_AND,
	ITYPE_OR,
	ITYPE_XOR,
	ITYPE_NOT,
	ITYPE_NEG,

	// ITYPE_STACK group
	ITYPE_STACK=ITYPE_STACK_OFFSET,
	ITYPE_PUSH,
	ITYPE_POP,
	ITYPE_PUSHA,
	ITYPE_POPA,
	ITYPE_PUSHF,
	ITYPE_POPF,
	ITYPE_ENTER,
	ITYPE_LEAVE,

	// ITYPE_TESTCOND group
	ITYPE_TESTCOND=ITYPE_TESTCOND_OFFSET,
		ITYPE_TEST,
		ITYPE_CMP,

	// ITYPE_LOAD group
	ITYPE_LOAD=ITYPE_LOAD_OFFSET,
		ITYPE_MOV,
		ITYPE_MOVCC, // conditional
		ITYPE_LEA,
		ITYPE_XCHG,
		ITYPE_XCHGCC, // conditional

	// ITYPE_ARRAY group
	ITYPE_ARRAY=ITYPE_ARRAY_OFFSET,
		ITYPE_STRCMP,
		ITYPE_STRLOAD,
		ITYPE_STRMOV,
		ITYPE_STRSTOR,
		ITYPE_XLAT,

	// ITYPE_BIT group
	ITYPE_BIT=ITYPE_BIT_OFFSET,
		ITYPE_BITTEST,
		ITYPE_BITSET,
		ITYPE_BITCLR,

	// ITYPE_FLAG group
	// PF = parify flag
	// ZF = zero flag
	// OF = overflow flag
	// DF = direction flag
	// SF = sign flag
	ITYPE_FLAG=ITYPE_FLAG_OFFSET,
		// clear
		ITYPE_CLEARCF, 
		ITYPE_CLEARZF,
		ITYPE_CLEAROF,
		ITYPE_CLEARDF,
		ITYPE_CLEARSF,
		ITYPE_CLEARPF,
		// set
		ITYPE_SETCF, 
		ITYPE_SETZF,
		ITYPE_SETOF,
		ITYPE_SETDF,
		ITYPE_SETSF,
		ITYPE_SETPF,
		// toggle
		ITYPE_TOGCF, 
		ITYPE_TOGZF,
		ITYPE_TOGOF,
		ITYPE_TOGDF,
		ITYPE_TOGSF,
		ITYPE_TOGPF,

	// ITYPE_FPU group
	ITYPE_FPU=ITYPE_FPU_OFFSET,
		ITYPE_FADD,
		ITYPE_FSUB,
		ITYPE_FMUL,
		ITYPE_FDIV,
		ITYPE_FCOMP,
		ITYPE_FEXCH,
		ITYPE_FLOAD,
		ITYPE_FLOADENV,
		ITYPE_FSTORE,
		ITYPE_FSTOREENV,
		ITYPE_FSAVE,
		ITYPE_FRESTORE,
		ITYPE_FMOVCC,

	ITYPE_UNUSED1=ITYPE_UNUSED1_OFFSET,
	ITYPE_UNUSED2=ITYPE_UNUSED2_OFFSET,
	ITYPE_UNUSED3=ITYPE_UNUSED3_OFFSET,

	// ITYPE_MMX group
	ITYPE_MMX=ITYPE_MMX_OFFSET,
		ITYPE_MMX_MOV,
		ITYPE_MMX_ADD,
		ITYPE_MMX_SUB,
		ITYPE_MMX_MUL,
		ITYPE_MMX_DIV,
		ITYPE_MMX_AND,
		ITYPE_MMX_OR,
		ITYPE_MMX_XOR,
		ITYPE_MMX_CMP,

	// ITYPE_SSE group
	ITYPE_SSE=ITYPE_SSE_OFFSET,
		ITYPE_SSE_MOV,
		ITYPE_SSE_ADD,
		ITYPE_SSE_SUB,
		ITYPE_SSE_MUL,
		ITYPE_SSE_DIV,
		ITYPE_SSE_AND,
		ITYPE_SSE_OR,
		ITYPE_SSE_XOR,
		ITYPE_SSE_CMP,
		
		// ITYPE_SSE2 group
	ITYPE_SSE2=ITYPE_SSE2_OFFSET,
		ITYPE_SSE2_MOV,
		ITYPE_SSE2_ADD,
		ITYPE_SSE2_SUB,
		ITYPE_SSE2_MUL,
		ITYPE_SSE2_DIV,
		ITYPE_SSE2_AND,
		ITYPE_SSE2_OR,
		ITYPE_SSE2_XOR,
		ITYPE_SSE2_CMP,

	// ITYPE_SSE3 group
	ITYPE_SSE3=ITYPE_SSE3_OFFSET,
		ITYPE_SSE3_MOV,
		ITYPE_SSE3_ADD,
		ITYPE_SSE3_SUB,
		ITYPE_SSE3_MUL,
		ITYPE_SSE3_DIV,
		ITYPE_SSE3_AND,
		ITYPE_SSE3_OR,
		ITYPE_SSE3_XOR,
		ITYPE_SSE3_CMP,

	// ITYPE_3DNOW group
	ITYPE_3DNOW=ITYPE_3DNOW_OFFSET,
		ITYPE_3DNOW_ADD,
		ITYPE_3DNOW_SUB,
		ITYPE_3DNOW_MUL,
		ITYPE_3DNOW_DIV,
		ITYPE_3DNOW_CMP,
		ITYPE_3DNOW_XCHG,

	// ITYPE_TRAP
	ITYPE_TRAPS=ITYPE_TRAPS_OFFSET, 
		ITYPE_TRAP, // generate trap
		ITYPE_TRAPCC,  // conditional trap gen
		ITYPE_TRAPRET,    // return from trap
		ITYPE_BOUNDS,  // gen bounds trap
		ITYPE_DEBUG,   // gen breakpoint trap
		ITYPE_TRACE,   // gen single step trap
		ITYPE_INVALID, // gen invalid instruction
		ITYPE_OFLOW,   // gen overflow trap

	// ITYPE_SYSTEM group
	ITYPE_SYSTEM=ITYPE_SYSTEM_OFFSET,
		ITYPE_HALT,    // halt machine
		ITYPE_IN,      // input form port
		ITYPE_OUT,     // output to port
		ITYPE_CPUID,   // identify cpu
		ITYPE_SETIF,   // allow interrupts
		ITYPE_CLEARIF, // block interrupts
		ITYPE_SYSCALL,
		ITYPE_SYSCALLRET,

	// ITYPE_OTHER group
	ITYPE_OTHER = ITYPE_OTHER_OFFSET,
		ITYPE_NOP,
		ITYPE_BCDCONV, // convert to/from BCD
		ITYPE_SZCONV   // convert size of operand
} INSTRUCTION_TYPE;

// 操作数标志定义

// 操作数类型（Type = bits 0-6），互斥，始终是 2 的幂
#define OPTYPE_NONE    0x00  // 无操作数
#define OPTYPE_IMM    0x01   // 立即数就被编码在指令中
#define OPTYPE_OFFSET 0x02   // 相对地址偏移量
#define OPTYPE_FLOAT  0x03   // 浮点小数
#define OPTYPE_BCD    0x04   // BCD 码
#define OPTYPE_STRING 0x05   // 字符串操作数
#define OPTYPE_SPECIAL 0x06  // 特殊操作数
#define OPTYPE_MASK   0x7F   // 操作数类型掉码

// 操作数标志（Flags = bits 7-23），可组合使用，在 x86 操作码表中使用
#define OP_REG      (1<<7)   // 操作数是寄存器
#define OP_SIGNED   (1<<8)   // 有符号操作数
#define OP_SYS      (1<<9)   // 操作数是某系统结构的索引
#define OP_CONDR    (1<<10)  // 有条件读操作
#define OP_CONDW    (1<<11)  // 有条件写操作
#define OP_UNUSED   (1<<12)  // 未使用
#define OP_SRC      (1<<13)  // 操作数是源操作数
#define OP_DST      (1<<14)  // 操作数是目标操作数
#define OP_EXEC     (1<<15)  // 操作数中存的是可执行地址

#define OP_CONDE     OP_CONDR
#define OP_COND_EXEC (OP_CONDE|OP_EXEC)  // 条件成立时才执行
#define OP_COND_SRC  (OP_CONDR|OP_SRC)   // 条件成立时才读回
#define OP_COND_DST  (OP_CONDW|OP_DST)   // 条件成立时才写入
#define OP_COND      (OP_CONDR|OP_CONDW)

// bits 16-31 可在操作码表外使用，但只限于 INSTRUCTION_OPERAND.Flags
// 警告：这些位可能与具体体系的 AMODE_* / OPTYPE_* 冲突
#define OP_ADDRESS    (1<<16)  // 操作数是内存地址
#define OP_LOCAL      (1<<17)  // 操作数是局部变量
#define OP_PARAM      (1<<18)  // 操作数是函数参数
#define OP_GLOBAL     (1<<19)  // 操作数是全局变量
#define OP_FAR        (1<<20)  // 远调用/远跳转（跨段）
#define OP_IPREL      (1<<21)  // IP 相对寻址（x64 下的 RIP 相对指令）

// x86 扩展操作数标志（bits 27-31）
#define OP_MSR      (OP_SYS|OP_UNUSED)  // 模型特定寄存器（MSR）操作数

// 其他体系标志
#define OP_DELAY  OP_UNUSED // 延迟执行指令（例如 MIPS 延迟分支）

/////////////////////////////////////////////////////////////////////
// 支持的处理器体系类型
/////////////////////////////////////////////////////////////////////

typedef enum _ARCHITECTURE_TYPE
{
	ARCH_UNKNOWN=0,   // 未知体系
	
	// x86 系列
	ARCH_X86,    // 32 位 x86
	ARCH_X86_16, // 16 位 x86
	ARCH_X64,    // AMD64 和 Intel EM64T
	
	// 其他体系
	ARCH_ALPHA,
	ARCH_ARM,
	ARCH_DOTNET,
	ARCH_EFI,
	ARCH_IA64,
	ARCH_M68K,
	ARCH_MIPS,
	ARCH_PPC,
	ARCH_SH3,
	ARCH_SH4,
	ARCH_SPARC,
	ARCH_THUMB

} ARCHITECTURE_TYPE;

typedef BOOL (*INIT_INSTRUCTION)(struct _INSTRUCTION *Instruction);
typedef void (*DUMP_INSTRUCTION)(struct _INSTRUCTION *Instruction, BOOL ShowBytes, BOOL Verbose);
typedef BOOL (*GET_INSTRUCTION)(struct _INSTRUCTION *Instruction, U8 *Address, U32 Flags);
typedef U8 *(*FIND_FUNCTION_BY_PROLOGUE)(struct _INSTRUCTION *Instruction, U8 *StartAddress, U8 *EndAddress, U32 Flags);

typedef struct _ARCHITECTURE_FORMAT_FUNCTIONS
{
	INIT_INSTRUCTION InitInstruction;
	DUMP_INSTRUCTION DumpInstruction;
	GET_INSTRUCTION GetInstruction;
	FIND_FUNCTION_BY_PROLOGUE FindFunctionByPrologue;
} ARCHITECTURE_FORMAT_FUNCTIONS;

// 体系结构函数表（每个体系对应一组回调函数）
typedef struct _ARCHITECTURE_FORMAT
{
	ARCHITECTURE_TYPE Type;                    // 体系类型
	ARCHITECTURE_FORMAT_FUNCTIONS *Functions;  // 该体系对应的函数指针表
} ARCHITECTURE_FORMAT;

// 反汇编器 / 指令结构体已初始化标志
#define DISASSEMBLER_INITIALIZED 0x1234566F
#define INSTRUCTION_INITIALIZED 0x1234567F

#include "disasm_x86.h"

// 128 位有符号 / 无符号整數类型（SSE 汇编指令操作数需要 16 字节对齐）
typedef struct DECLSPEC_ALIGN(16) _S128
{
    U64 Low;
    S64 High;
} S128;
typedef struct DECLSPEC_ALIGN(16) _U128
{
    U64 Low;
    U64 High;
} U128;

// 指令操作数结构体——描述一条指令的单个操作数
typedef struct _INSTRUCTION_OPERAND
{
	U32 Flags;       // 操作数标志（OP_REG、OP_SRC、OP_DST 等组合）
	U8 Type : 6;     // 操作数类型（OPTYPE_IMM、OPTYPE_OFFSET 等）
	U8 Unused : 2;   // 保留位
	U16 Length;      // 操作数长度（字节）
	
	// 若非 NULL，表示指令的目标地址（分支目标或无基寻址的位移）。
	// 该地址仅在镜像正确映射时可靠（即可执行文件已按镜像映射且已应用重定位）。
	//
	// 对于 16 位 DOS 应用程序，TargetAddress 基于 X86Instruction->Segment：
	//   - 索引为代码跳转时在 CS 段中（除非有段覆盖前缀）
	//   - 索引为数据指针时在 DS 段中（除非有段覆盖前缀）
	U64 TargetAddress;  // 目标地址
	U32 Register;       // 操作数对应的寄存器编号

	union
	{
		// 所有 8/16/32 位操作数均自动扩展到 64 位
		// 若需取小位值，请先检查 Flags & OP_SIGNED 是否置位：
		//   if (Operand->Flags & OP_SIGNED) return (S32)Operand->Value_S64;
		//   else return (U32)Operand->Value_U64;
		U64 Value_U64;    // 无符号整数值
		S64 Value_S64;    // 有符号整数值
		U128 Value_U128;  // 128 位整数值
		U128 Float128;    // 128 位浮点数
		U8 Float80[80];   // 80 位扩展精度浮点数
		U8 BCD[10];       // BCD 编码数
	};
} INSTRUCTION_OPERAND;

/*
[`INSTRUCTION`]结构体的各个字段用于存储反汇编过程中解析出的指令信息。以下是各个字段的意义：

- `U32 Initialized`: 指示该结构体是否已初始化。
- [`struct _DISASSEMBLER *Disassembler`]: 指向反汇编器实例的指针。
- `char String[MAX_OPCODE_DESCRIPTION]`: 存储指令的字符串描述。
- `U8 StringIndex`: 字符串描述的索引。
- `U64 VirtualAddressDelta`: 虚拟地址增量。
- `U32 Groups`: 指令组（如 ITYPE_EXEC, ITYPE_ARITH 等），可以是多个组的组合。
- `INSTRUCTION_TYPE Type`: 指令类型（如 ITYPE_ADD, ITYPE_RET 等），每条指令只有一个类型。
- [`U8 *Address`]: 指令在内存中的地址。
- [`U8 *OpcodeAddress`]: 操作码的地址。
- `U32 Length`: 指令的长度。
- `U8 Prefixes[MAX_PREFIX_LENGTH]`: 存储指令前缀。
- `U32 PrefixCount`: 前缀的数量。
- `U8 LastOpcode`: 操作码的最后一个字节。
- `U8 OpcodeBytes[MAX_OPCODE_LENGTH]`: 存储操作码字节。
- `U32 OpcodeLength`: 操作码的长度，不包括操作数和前缀。
- `INSTRUCTION_OPERAND Operands[MAX_OPERAND_COUNT]`: 存储指令的操作数。
- `U32 OperandCount`: 操作数的数量。
- `X86_INSTRUCTION X86`: 存储x86指令的特定信息。
- `DATA_REFERENCE DataSrc`: 数据源引用。
- `DATA_REFERENCE DataDst`: 数据目标引用。
- `CODE_BRANCH CodeBranch`: 代码分支信息。
- `LONG StackChange`: 堆栈变化量，指示指令对堆栈的影响。
- `U8 StringAligned : 1`: 内部使用，指示字符串是否对齐。
- `U8 NeedsEmulation : 1`: 指示指令是否需要仿真。
- `U8 Repeat : 1`: 指示指令是否重复执行（如 REP 前缀）。
- `U8 ErrorOccurred : 1`: 指示指令是否无效。
- `U8 AnomalyOccurred : 1`: 指示指令是否异常。
- `U8 LastInstruction : 1`: 指示这是最后一条指令。
- `U8 CodeBlockFirst: 1`: 指示这是代码块的第一条指令。
- `U8 CodeBlockLast : 1`: 指示这是代码块的最后一条指令。

这些字段共同作用，帮助反汇编器解析和存储指令的详细信息。
*/
typedef struct _INSTRUCTION
{
	U32 Initialized;
	struct _DISASSEMBLER *Disassembler;

	char String[MAX_OPCODE_DESCRIPTION];
	U8 StringIndex;
	U64 VirtualAddressDelta;

	U32 Groups; // ITYPE_EXEC, ITYPE_ARITH, etc. -- NOTE groups can be OR'd together
	INSTRUCTION_TYPE Type; // ITYPE_ADD, ITYPE_RET, etc. -- NOTE there is only one possible type

	U8 *Address;
	U8 *OpcodeAddress;
	U32 Length;

	U8 Prefixes[MAX_PREFIX_LENGTH];
	U32 PrefixCount;

	U8 LastOpcode; // last byte of opcode
	U8 OpcodeBytes[MAX_OPCODE_LENGTH];
	U32 OpcodeLength; // excludes any operands and prefixes

	INSTRUCTION_OPERAND Operands[MAX_OPERAND_COUNT];
	U32 OperandCount;

	X86_INSTRUCTION X86;

	DATA_REFERENCE DataSrc;
	DATA_REFERENCE DataDst;
	CODE_BRANCH CodeBranch;

	// Direction depends on which direction the stack grows
	// For example, on x86 a push results in StackChange < 0 since the stack grows down
	// This is only relevant if (Group & ITYPE_STACK) is true
	//
	// If Groups & ITYPE_STACK is set but StackChange = 0, it means that the change
	// couldn't be determined (non-constant)
	LONG StackChange;

	// 调试辅助标志——如果置位，表示当前指令需要特殊处理
	// 例如 popf 可导致单步跟踪被禁用

	U8 StringAligned : 1;     // 仅内部使用：字符串是否对齐
	U8 NeedsEmulation : 1;    // 该指令需要仓真运行（不能直接执行）
	U8 Repeat : 1;            // 含有重复前缀（如 x86 的 REP 前缀）
	U8 ErrorOccurred : 1;     // 指令无效 / 解码失败
	U8 AnomalyOccurred : 1;   // 指令异常（例如未定义行为）
	U8 LastInstruction : 1;   // 迭代回调中用来通知这是最后一条指令
	U8 CodeBlockFirst: 1;     // 是否是代码块中的第一条指令
	U8 CodeBlockLast : 1;     // 是否是代码块中的最后一条指令
} INSTRUCTION;

// 反汇编器实例结构体，封装了对某一体系进行反汇编所需的全部状态
typedef struct _DISASSEMBLER
{
	U32 Initialized;                         // 初始化标志（DISASSEMBLER_INITIALIZED）
	ARCHITECTURE_TYPE ArchType;              // 体系类型
	ARCHITECTURE_FORMAT_FUNCTIONS *Functions; // 指向该体系函数表的指针
	INSTRUCTION Instruction;                 // 当前正在解码的指令
	U32 Stage1Count;         // GetInstruction 被调用次数
	U32 Stage2Count;         // 操作码完全解码的次数
	U32 Stage3CountNoDecode;   // 未设置 DISASM_DECODE 时通过所有检查的次数
	U32 Stage3CountWithDecode; // 设置 DISASM_DECODE 时通过所有检查的次数
} DISASSEMBLER;

// GetInstruction() 的调用标志
#define DISASM_DISASSEMBLE         (1<<1)  // 生成反汇编字符串表示
#define DISASM_DECODE              (1<<2)  // 解码指令字段（填充 INSTRUCTION 结构体）
#define DISASM_SUPPRESSERRORS      (1<<3)  // 错误不输出日志
#define DISASM_SHOWFLAGS           (1<<4)  // 在反汇编字符串中显示标志信息
#define DISASM_ALIGNOUTPUT         (1<<5)  // 对齐输出字符串
#define DISASM_DISASSEMBLE_MASK (DISASM_ALIGNOUTPUT|DISASM_SHOWBYTES|DISASM_DISASSEMBLE)

// 初始化反汇编器实例，指定目标体系类型
BOOL InitDisassembler(DISASSEMBLER *Disassembler, ARCHITECTURE_TYPE Architecture);
// 释放反汇编器占用的资源
void CloseDisassembler(DISASSEMBLER *Disassembler);
// 获取下一条指令，将解码结果填充到 Disassembler->Instruction 中
// 参数：VirtualAddress —— 如果不同于内存映射地址，可将虚拟地址传入供展示
INSTRUCTION *GetInstruction(DISASSEMBLER *Disassembler, U64 VirtualAddress, U8 *Address, U32 Flags);

#ifdef __cplusplus
}
#endif
#endif // DISASM_H
