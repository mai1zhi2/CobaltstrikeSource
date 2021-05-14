#include <stdio.h>
#pragma once
#include <Windows.h>

PIMAGE_NT_HEADERS 		m_pntHeaders = 0;		// PE结构指针
PCHAR					m_pImageBase = 0;		// 映象基址

UINT g_pResource;
PVOID g_hVector;
DWORD g_dwSize;
BOOL bRsrcExe;


PCHAR RVAToPtr(DWORD dwRVA)
{
	return (PCHAR)((DWORD)m_pImageBase + dwRVA);
}



BOOL InstallVEHHook(PVECTORED_EXCEPTION_HANDLER Handler)
{
	printf("Current Handler Address = 0x%p\n", Handler);
	g_hVector = AddVectoredExceptionHandler(1, Handler);
	return g_hVector != NULL;
}

IMAGE_DOS_HEADER* GetDosHeader(void* pFileData)
{
	return (IMAGE_DOS_HEADER*)pFileData;
}

IMAGE_NT_HEADERS* GetNtHeader(void* pFileData)
{
	return (IMAGE_NT_HEADERS*)(GetDosHeader(pFileData)->e_lfanew + (SIZE_T)pFileData);
}



//解析资源
UINT FindFirstResADDR()
{
	UINT							FirstResAddr = NULL;

	PIMAGE_DATA_DIRECTORY			pResourceDir = NULL;
	PIMAGE_RESOURCE_DIRECTORY		pResource = NULL;

	PIMAGE_RESOURCE_DIRECTORY		pTypeRes = NULL;
	PIMAGE_RESOURCE_DIRECTORY		pNameIdRes = NULL;
	PIMAGE_RESOURCE_DIRECTORY		pLanguageRes = NULL;

	PIMAGE_RESOURCE_DIRECTORY_ENTRY	pTypeEntry = NULL;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY	pNameIdEntry = NULL;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY	pLanguageEntry = NULL;

	PIMAGE_RESOURCE_DATA_ENTRY		pResData = NULL;

	UINT							nTypeNum = 0;
	UINT							nTypeIndex = 0;
	UINT							nNameIdNum = 0;
	UINT							nNameIdIndex = 0;
	UINT							nLanguageNum = 0;
	UINT							nLanguageIndex = 0;

	try
	{
		HMODULE hCurProcess = NULL;
		hCurProcess = GetModuleHandle(NULL);
		if (hCurProcess == NULL)
		{
			return -1;
		}

		m_pntHeaders = GetNtHeader(hCurProcess);
		m_pImageBase = (PCHAR)hCurProcess;
		FirstResAddr = m_pntHeaders->OptionalHeader.SizeOfImage;

		pResourceDir = &m_pntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
		if (pResourceDir->VirtualAddress == NULL)
		{
			return FALSE;
		}

		//设置权限
		g_dwSize = pResourceDir->Size;
		pResource = (PIMAGE_RESOURCE_DIRECTORY)RVAToPtr(pResourceDir->VirtualAddress);//资源起点地址
		

		pTypeRes = pResource;
		nTypeNum = pTypeRes->NumberOfIdEntries + pTypeRes->NumberOfNamedEntries;//该类型中有几类资源
		pTypeEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pTypeRes + sizeof(IMAGE_RESOURCE_DIRECTORY));

		for (nTypeIndex = 0; nTypeIndex < nTypeNum; nTypeIndex++, pTypeEntry++)
		{
			//该类型目录地址
			pNameIdRes = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pResource + (DWORD)pTypeEntry->OffsetToDirectory);
			//该类型中有几个项目
			nNameIdNum = pNameIdRes->NumberOfIdEntries + pNameIdRes->NumberOfNamedEntries;
			pNameIdEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pNameIdRes + sizeof(IMAGE_RESOURCE_DIRECTORY));

			for (nNameIdIndex = 0; nNameIdIndex < nNameIdNum; nNameIdIndex++, pNameIdEntry++)
			{
				//该项目目录地址
				pLanguageRes = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pResource + (DWORD)pNameIdEntry->OffsetToDirectory);
				nLanguageNum = pLanguageRes->NumberOfIdEntries + pLanguageRes->NumberOfNamedEntries;
				pLanguageEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pLanguageRes + sizeof(IMAGE_RESOURCE_DIRECTORY));

				for (nLanguageIndex = 0; nLanguageIndex < nLanguageNum; nLanguageIndex++, pLanguageEntry++)
				{
					pResData = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD)pResource + (DWORD)pLanguageEntry->OffsetToData);
					if ((pResData->OffsetToData < FirstResAddr) && (pResData->OffsetToData > pResourceDir->VirtualAddress))
					{
						FirstResAddr = pResData->OffsetToData;
					}
				}
			}
		}


	}
	catch (...)
	{
		return FALSE;
	}
	return (UINT)m_pImageBase+FirstResAddr;

}



LONG WINAPI
VectoredHandler(
	struct _EXCEPTION_POINTERS* ExceptionInfo
)
{
	LONG lResult = EXCEPTION_CONTINUE_SEARCH;
	PEXCEPTION_RECORD pExceptionRecord;
	PCONTEXT pContextRecord;
	int ret = 0;
	NTSTATUS stat;
	DWORD dwOldProtect;

	pExceptionRecord = ExceptionInfo->ExceptionRecord;
	pContextRecord = ExceptionInfo->ContextRecord;
	ULONG_PTR* uESP = 0;

	UINT uPoint = g_pResource + 0x42a1;

	UINT uBase;
	DWORD dwsize = 0x3D000;

	printf("ExceptionAddress = 0x%p\n", pExceptionRecord->ExceptionAddress);

	if (pExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT
		&& LOWORD(pContextRecord->Eip) == 0x42a1)//判断后面四位
	{

		printf("ESP = 0x%p\n", pContextRecord->Esp);
		printf("EIP = 0x%p\n", pContextRecord->Eip);

		uBase = pContextRecord->Eip - 0x42a1;

		uESP = (ULONG_PTR*)pContextRecord->Esp;
		//ret = g_OriginalMessageBoxA((HWND)uESP[1], szNewMsg, (LPCTSTR)uESP[3], (int)uESP[4]);

		stat = VirtualProtect((PVOID*)uBase, dwsize, PAGE_READONLY, &dwOldProtect);
		printf("stat = %d\n", stat);
		//Sleep(uESP[1]);
		Sleep(10000);

		stat = VirtualProtect((PVOID*)uBase, dwsize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
		printf("stat = %d\n", stat);
		pContextRecord->Eip = (pContextRecord->Eip + 6);
		pContextRecord->Esp +=  sizeof(ULONG_PTR);

		lResult = EXCEPTION_CONTINUE_EXECUTION;
	}
	return lResult;
}



int main() {

	//选择安装一个进行测试
	InstallVEHHook(VectoredHandler);

	g_pResource = FindFirstResADDR();

	DWORD dwOldProtect;
	NTSTATUS stat;
	stat = VirtualProtect((PVOID*)g_pResource, g_dwSize, PAGE_EXECUTE_READ, &dwOldProtect);
	bRsrcExe = TRUE;

	printf("g_pResource = 0x%p\n", g_pResource);
	printf("size = %d\n", g_dwSize);
	printf("stat = %d\n", stat);
	_asm {
		call g_pResource;
	}

}