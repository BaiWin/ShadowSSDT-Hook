#pragma once

#include "KernelIncludes.h"

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * 在指定内存区间查找字节模式
	 * @param base: 起始地址
	 * @param size: 区间大小
	 * @param pattern: 字节模式（支持通配符）
	 * @param mask: 掩码字符串，'x'表示必须匹配，'?'表示任意字节
	 * @return 匹配地址，没找到返回NULL
	 */
	unsigned char* FindPattern(unsigned char* base, size_t size, const unsigned char* pattern, const char* mask);

#ifdef __cplusplus
}
#endif