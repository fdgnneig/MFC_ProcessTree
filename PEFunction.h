#pragma once

char* ReadFileToMemory(char* pFilePath);

bool IsPeFile(char* pBuf);

DWORD RVAtoFOA(DWORD dwRVA, char* pBuf);