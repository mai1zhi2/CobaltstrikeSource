#include <stdio.h>
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
		FirstResAddr = m_pntHeaders->OptionalHeader.SizeOfImage;//现放置一个最大值（这里取映像尺寸），然后根据比较逐渐减小

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
	return (UINT)m_pImageBase + FirstResAddr;

}



DWORD dwCurAddr;
DWORD dwsize = 0x3D000;
NTSTATUS stat;
DWORD dwOldProtect;


VOID __stdcall MySleep(DWORD dwSecond) {
	printf("MySleep,%d", dwSecond);

	_asm {
		mov eax, [esp+8];
		push eax;
		pop dwCurAddr;
	}


	DWORD dwMZ = dwCurAddr - 0x42a7;
	if (*(PCHAR)dwMZ == 'M')
	{
		printf("found tou %p", dwMZ);
		//找到，修改属性
		stat = VirtualProtect((PVOID*)dwMZ, dwsize, PAGE_READONLY, &dwOldProtect);
		Sleep(dwSecond);
		stat = VirtualProtect((PVOID*)dwMZ, dwsize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	}
	else
	{
		Sleep(5000);
	}


}



int main() {

	g_pResource = FindFirstResADDR();

	DWORD dwOldProtect;
	NTSTATUS stat;
	stat = VirtualProtect((PVOID*)g_pResource, g_dwSize, PAGE_READWRITE, &dwOldProtect);
	bRsrcExe = TRUE;
	printf("%p", MySleep);
	printf("%p", &MySleep);
	//在资源的内存中不用捞到相应的位置，直接加上对应位置即可，再把自定义的函数指针补上去
	//*(PDWORD)(g_pResource + 0x36a3) = (DWORD)&MySleep;

	DWORD dwMySleepAddr = (DWORD)&MySleep;
	printf("%p", dwMySleepAddr);
	*(PDWORD)(g_pResource + 0x36a3) = (DWORD)&dwMySleepAddr;
	//还要修改重定位表

	stat = VirtualProtect((PVOID*)g_pResource, g_dwSize, PAGE_EXECUTE_READ, &dwOldProtect);
	printf("g_pResource = 0x%p\n", g_pResource);
	printf("size = %d\n", g_dwSize);
	printf("stat = %d\n", stat);
	_asm {
		call g_pResource;
	}

}

