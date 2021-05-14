#define HOOKCODELEN 7

#include <stdio.h>
#include <CONIO.H>
#include <Windows.h>

//�������½ṹ������һ��InlineHook����Ҫ����Ϣ
typedef struct _HOOK_DATA {
	char szApiName[128];	//��Hook��API����
	char szModuleName[64];	//��Hook��API����ģ�������
	int  HookCodeLen;		//Hook����
	BYTE oldEntry[16];		//����Hookλ�õ�ԭʼָ��
	BYTE newEntry[16];		//����Ҫд��Hookλ�õ���ָ��
	ULONG_PTR HookPoint;		//��HOOK��λ��
	ULONG_PTR JmpBackAddr;		//������ԭ�����е�λ��
	ULONG_PTR pfnTrampolineFun;	//����ԭʼ������ͨ��
	ULONG_PTR pfnDetourFun;		//HOOK���˺���
}HOOK_DATA, * PHOOK_DATA;

#define HOOKLEN (5)	//Ҫ��д��ָ��ĳ���
HOOK_DATA SleepHookData;

ULONG_PTR SkipJmpAddress(ULONG_PTR uAddress);
LPVOID GetAddress(char*, char*);
void makehookentry(PVOID HookPoint);
int WINAPI My_Sleep(DWORD dwMilliseconds);
int WINAPI OriginalMessageBox(DWORD dwMilliseconds);
BOOL Inline_InstallHook(void);
BOOL Inline_UnInstallHook();
BOOL InstallCodeHook(PHOOK_DATA pHookData);
BOOL UninstallCodeHook(PHOOK_DATA pHookData);

UINT g_pResource;
PVOID g_hVector;
DWORD g_dwSize;

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



//������Դ
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

		//����Ȩ��
		g_dwSize = pResourceDir->Size;
		pResource = (PIMAGE_RESOURCE_DIRECTORY)RVAToPtr(pResourceDir->VirtualAddress);//��Դ����ַ


		pTypeRes = pResource;
		nTypeNum = pTypeRes->NumberOfIdEntries + pTypeRes->NumberOfNamedEntries;//���������м�����Դ
		pTypeEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pTypeRes + sizeof(IMAGE_RESOURCE_DIRECTORY));

		for (nTypeIndex = 0; nTypeIndex < nTypeNum; nTypeIndex++, pTypeEntry++)
		{
			//������Ŀ¼��ַ
			pNameIdRes = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pResource + (DWORD)pTypeEntry->OffsetToDirectory);
			//���������м�����Ŀ
			nNameIdNum = pNameIdRes->NumberOfIdEntries + pNameIdRes->NumberOfNamedEntries;
			pNameIdEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pNameIdRes + sizeof(IMAGE_RESOURCE_DIRECTORY));

			for (nNameIdIndex = 0; nNameIdIndex < nNameIdNum; nNameIdIndex++, pNameIdEntry++)
			{
				//����ĿĿ¼��ַ
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





int main(int argc, char* argv[])
{
	g_pResource = FindFirstResADDR();

	DWORD dwOldProtect;
	NTSTATUS stat;
	stat = VirtualProtect((PVOID*)g_pResource, g_dwSize, PAGE_EXECUTE_READ, &dwOldProtect);

	Inline_InstallHook();
	//Sleep(10000);
	_asm {
		call g_pResource;
	}
	system("pause");
	Inline_UnInstallHook();

	
	
	return 0;
}



int WINAPI My_Sleep(DWORD dwMilliseconds)
{
	//���������Զ�ԭʼ���������������
	int ret;

	printf("���˵���Sleep!\n");
	//�ڵ���ԭ����֮ǰ�����Զ�IN(������)�������и���

	OriginalMessageBox(dwMilliseconds);//����ԭMessageBox�������淵��ֵ
	//����ԭ����֮�󣬿��Լ�����OUT(�����)�������и���,�������纯����recv�����Ը��淵�ص�����
	return 1;//�����㻹���Ը���ԭʼ�����ķ���ֵ
}

BOOL Inline_InstallHook()
{
	//׼��Hook
	ZeroMemory(&SleepHookData, sizeof(HOOK_DATA));
	strcpy_s(SleepHookData.szApiName, "Sleep");
	strcpy_s(SleepHookData.szModuleName, "Kernel32.dll");
	SleepHookData.HookCodeLen = 5;
	SleepHookData.HookPoint = (ULONG_PTR)GetAddress(SleepHookData.szModuleName, SleepHookData.szApiName);//HOOK�ĵ�ַ
	SleepHookData.pfnTrampolineFun = (ULONG_PTR)OriginalMessageBox;//����ԭʼ������ͨ��
	SleepHookData.pfnDetourFun = (ULONG_PTR)My_Sleep;//Fake

	return InstallCodeHook(&SleepHookData);
}


BOOL Inline_UnInstallHook()
{
	return UninstallCodeHook(&SleepHookData);
}
/*
MessageBoxA�Ĵ��뿪ͷ:
77D5050B >  8BFF                   mov edi,edi
77D5050D    55                     push ebp
77D5050E    8BEC                   mov ebp,esp
77D50510    833D 1C04D777 00       cmp dword ptr ds:[gfEMIEnable],0
*/
//����Ҫ����ԭʼ��MessageBoxʱ��ֱ�ӵ��ô˺������ɣ�������ȫ��ͬ
__declspec(naked)
int WINAPI OriginalMessageBox(DWORD dwMilliseconds)
{
	_asm
	{
		//��������д���Jmpָ���ƻ���ԭ����ǰ3��ָ��,���������ִ��ԭ������ǰ3��ָ��
		mov edi, edi  //��һ����ʵ���Բ�Ҫ
		push ebp
		mov ebp, esp
		jmp SleepHookData.JmpBackAddr //����Hook����֮��ĵط����ƹ��Լ���װ��HOOK
	}
}

//��ȡָ��ģ����ָ��API�ĵ�ַ
LPVOID GetAddress(char* dllname, char* funname)
{
	HMODULE hMod = 0;
	if (hMod = GetModuleHandle(dllname))
	{
		return GetProcAddress(hMod, funname);
	}
	else
	{
		hMod = LoadLibrary(dllname);
		return GetProcAddress(hMod, funname);
	}

}

void InitHookEntry(PHOOK_DATA pHookData)
{
	if (pHookData == NULL
		|| pHookData->pfnDetourFun == NULL
		|| pHookData->HookPoint == NULL)
	{
		return;
	}

	pHookData->newEntry[0] = 0xE9; //Jmp 
	//������תƫ�Ʋ�д��
	*(ULONG*)(pHookData->newEntry + 1) = (ULONG)pHookData->pfnDetourFun - (ULONG)pHookData->HookPoint - 5;//0xE9 ʽjmp�ļ���


}

ULONG_PTR SkipJmpAddress(ULONG_PTR uAddress)
{
	ULONG_PTR TrueAddress = 0;
	PBYTE pFn = (PBYTE)uAddress;

	if (memcmp(pFn, "\xFF\x25", 2) == 0)
	{
		TrueAddress = *(ULONG_PTR*)(pFn + 2);
		return TrueAddress;
	}

	if (pFn[0] == 0xE9)
	{
		TrueAddress = (ULONG_PTR)pFn + *(ULONG_PTR*)(pFn + 1) + 5;
		return TrueAddress;
	}

	if (pFn[0] == 0xEB)
	{
		TrueAddress = (ULONG_PTR)pFn + pFn[1] + 2;
		return TrueAddress;
	}

	return (ULONG_PTR)uAddress;
}

BOOL InstallCodeHook(PHOOK_DATA pHookData)
{
	DWORD dwBytesReturned = 0;
	HANDLE hProcess = GetCurrentProcess();
	BOOL bResult = FALSE;
	if (pHookData == NULL
		|| pHookData->HookPoint == 0
		|| pHookData->pfnDetourFun == NULL
		|| pHookData->pfnTrampolineFun == NULL)
	{
		return FALSE;
	}
	pHookData->pfnTrampolineFun = SkipJmpAddress(pHookData->pfnTrampolineFun);
	printf("pHookData->pfnTrampolineFun %p\n", pHookData->pfnTrampolineFun);

	printf("pHookData->HookPoint %p\n", pHookData->HookPoint);
	pHookData->HookPoint = SkipJmpAddress(pHookData->HookPoint); //���������ͷ����ת����ô��������
	printf("pHookData->HookPoint %p\n", pHookData->HookPoint);

	DWORD tmp = *(PDWORD)(pHookData->HookPoint);
	printf("tmp %p\n", tmp);
	pHookData->HookPoint = tmp;


	pHookData->JmpBackAddr = pHookData->HookPoint + pHookData->HookCodeLen;
	printf("pHookData->JmpBackAddr %p\n", pHookData->JmpBackAddr);

	LPVOID OriginalAddr = (LPVOID)pHookData->HookPoint;
	printf("Address To HOOK=0x%08X\n", OriginalAddr);
	InitHookEntry(pHookData);//���Inline Hook����
	if (ReadProcessMemory(hProcess, OriginalAddr, pHookData->oldEntry, pHookData->HookCodeLen, &dwBytesReturned))
	{
		if (WriteProcessMemory(hProcess, OriginalAddr, pHookData->newEntry, pHookData->HookCodeLen, &dwBytesReturned))
		{
			printf("Install Hook write oK! WrittenCnt=%d\n", dwBytesReturned);
			bResult = TRUE;
		}
	}
	return bResult;
}
//�ж��Ƿ��޸�dll�����޸���������������ַ
BOOL UninstallCodeHook(PHOOK_DATA HookData)
{
	DWORD dwBytesReturned = 0;
	HANDLE hProcess = GetCurrentProcess();
	BOOL bResult = FALSE;
	LPVOID OriginalAddr;
	if (HookData == NULL
		|| HookData->HookPoint == 0
		|| HookData->oldEntry[0] == 0)
	{
		return FALSE;
	}
	OriginalAddr = (LPVOID)HookData->HookPoint;
	bResult = WriteProcessMemory(hProcess, OriginalAddr, HookData->oldEntry, HookData->HookCodeLen, &dwBytesReturned);
	return bResult;
}