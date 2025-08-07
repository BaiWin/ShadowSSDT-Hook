#pragma once

#include "KernelIncludes.h"

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * ��ָ���ڴ���������ֽ�ģʽ
	 * @param base: ��ʼ��ַ
	 * @param size: �����С
	 * @param pattern: �ֽ�ģʽ��֧��ͨ�����
	 * @param mask: �����ַ�����'x'��ʾ����ƥ�䣬'?'��ʾ�����ֽ�
	 * @return ƥ���ַ��û�ҵ�����NULL
	 */
	unsigned char* FindPattern(unsigned char* base, size_t size, const unsigned char* pattern, const char* mask);

#ifdef __cplusplus
}
#endif