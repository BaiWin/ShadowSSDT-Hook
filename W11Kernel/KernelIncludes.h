#pragma once

#include <ntdef.h>     // �Ȱ����������Ͷ���
#include <ntimage.h>   // PE�ṹ����������

#ifdef _KERNEL_MODE
#include <ntifs.h>
#else
#include <windows.h>
#include <string.h>
#endif

// ��Ŀ��ͷ�ļ�
#include "Comm.h"
#include "Util.h"
#include "HookFunction.h"
#include "ModuleBase.h"
#include "PatternScan.h"
#include "ShadowSSDT.h"
#include "NtDllMapper.h"

