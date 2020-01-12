#include "stdafx.h"
#include <Windows.h>

//将文件读取到内存中
char* ReadFileToMemory(char* pFilePath)
{
	FILE* pFile;
	fopen_s(&pFile, pFilePath, "rb");
	if (!pFile)
	{
		printf("文件打开失败\n");
		return 0;
	}
	//获取文件大小
	fseek(pFile, 0, SEEK_END);
	int nSize = ftell(pFile);
	char* pBuf = new char[nSize] {};
	//读文件到内存中
	fseek(pFile, 0, SEEK_SET);
	fread(pBuf, nSize, 1, pFile);
	//关闭文件
	fclose(pFile);
	return pBuf;
}

//判断是否是PE文件
bool IsPeFile(char* pBuf)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuf;
	if (pDos->e_magic != IMAGE_DOS_SIGNATURE)//0x5A4D
	{
		return false;
	}
	//NT头
	PIMAGE_NT_HEADERS pNt =
		(PIMAGE_NT_HEADERS)
		(pDos->e_lfanew + pBuf);
	if (pNt->Signature != IMAGE_NT_SIGNATURE) //0x00004550
	{
		return false;
	}
	return true;
}

DWORD RVAtoFOA(DWORD dwRVA, char* pBuf)
{
	//找到导出位置，数据目录表的第一项（下标0）
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuf;
	//NT头
	PIMAGE_NT_HEADERS pNt =
		(PIMAGE_NT_HEADERS)
		(pDos->e_lfanew + pBuf);
	//区段表首地址
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
	//区段表中的个数
	DWORD dwCount = pNt->FileHeader.NumberOfSections;
	for (int i = 0; i < dwCount; i++)
	{
		if (dwRVA >= pSec->VirtualAddress &&
			dwRVA < (pSec->VirtualAddress + pSec->SizeOfRawData))
		{
			return dwRVA -
				pSec->VirtualAddress + pSec->PointerToRawData;
		}
		//下一个区段
		pSec++;
	}
	return 0;
}

