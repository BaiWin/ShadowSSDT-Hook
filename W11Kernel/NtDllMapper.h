#pragma once
#include "KernelIncludes.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ViewUnmap
#define ViewUnmap 2
#endif

	// ӳ���û�̬ ntdll.dll�����ҵ���������ַ
	PVOID MapUserNtdllAndFindExport(PCWSTR dllPath, PCSTR exportName);

#ifdef __cplusplus
}
#endif