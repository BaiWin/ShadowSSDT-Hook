#include "KernelIncludes.h"

// �ֽڶԱȺ���
static int DataCompare(const unsigned char* data, const unsigned char* pattern, const char* mask)
{
    while (*mask)
    {
        if (*mask == 'x' && *data != *pattern)
            return 0;
        data++;
        pattern++;
        mask++;
    }
    return 1;
}

// ���Һ���ʵ��
unsigned char* FindPattern(unsigned char* base, size_t size, const unsigned char* pattern, const char* mask)
{
    size_t patternLen = strlen(mask);
    size_t maxScan = size - patternLen;

    for (size_t i = 0; i <= maxScan; i++)
    {
        if (DataCompare(base + i, pattern, mask))
            return base + i;
    }
    return NULL;
}