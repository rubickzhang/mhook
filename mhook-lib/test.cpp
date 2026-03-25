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
	__asm {
		mov eax, pFunc
		jmp eax
	}

	return 0;
}