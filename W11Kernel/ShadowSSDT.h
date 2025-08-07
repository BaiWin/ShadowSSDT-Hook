#pragma once
#include "KernelIncludes.h"

void EnableWP(KIRQL irql);
KIRQL DisableWP();

NTSTATUS InitShadowSSDT(void);
void UnhookShadowSSDT(void);
