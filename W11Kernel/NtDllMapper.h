#pragma once
#include "KernelIncludes.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ViewUnmap
#define ViewUnmap 2
#endif

	// 映射用户态 ntdll.dll，查找导出函数地址
	PVOID MapUserNtdllAndFindExport(PCWSTR dllPath, PCSTR exportName);

#ifdef __cplusplus
}
#endif