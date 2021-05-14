#define HOOKCODELEN 7

#include <stdio.h>
#include <CONIO.H>
#include <Windows.h>

//定义如下结构，保存一次InlineHook所需要的信息
typedef struct _HOOK_DATA {
	char szApiName[128];	//待Hook的API名字
	char szModuleName[64];	//待Hook的API所属模块的名字
	int  HookCodeLen;		//Hook长度
	BYTE oldEntry[16];		//保存Hook位置的原始指令
	BYTE newEntry[16];		//保存要写入Hook位置的新指令
	ULONG_PTR HookPoint;		//待HOOK的位置
	ULONG_PTR JmpBackAddr;		//回跳到原函数中的位置
	ULONG_PTR pfnTrampolineFun;	//调用原始函数的通道
	ULONG_PTR pfnDetourFun;		//HOOK过滤函数
}HOOK_DATA, * PHOOK_DATA;

#define HOOKLEN (5)	//要改写的指令的长度
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
	//在这里，你可以对原始参数进行任意操作
	int ret;

	printf("有人调用Sleep!\n");
	//在调用原函数之前，可以对IN(输入类)参数进行干涉

	OriginalMessageBox(dwMilliseconds);//调用原MessageBox，并保存返回值
	//调用原函数之后，可以继续对OUT(输出类)参数进行干涉,比如网络函数的recv，可以干涉返回的内容
	return 1;//这里你还可以干涉原始函数的返回值
}

BOOL Inline_InstallHook()
{
	//准备Hook
	ZeroMemory(&SleepHookData, sizeof(HOOK_DATA));
	strcpy_s(SleepHookData.szApiName, "Sleep");
	strcpy_s(SleepHookData.szModuleName, "Kernel32.dll");
	SleepHookData.HookCodeLen = 5;
	SleepHookData.HookPoint = (ULONG_PTR)GetAddress(SleepHookData.szModuleName, SleepHookData.szApiName);//HOOK的地址
	SleepHookData.pfnTrampolineFun = (ULONG_PTR)OriginalMessageBox;//调用原始函数的通道
	SleepHookData.pfnDetourFun = (ULONG_PTR)My_Sleep;//Fake

	return InstallCodeHook(&SleepHookData);
}


BOOL Inline_UnInstallHook()
{
	return UninstallCodeHook(&SleepHookData);
}
/*
MessageBoxA的代码开头:
77D5050B >  8BFF                   mov edi,edi
77D5050D    55                     push ebp
77D5050E    8BEC                   mov ebp,esp
77D50510    833D 1C04D777 00       cmp dword ptr ds:[gfEMIEnable],0
*/
//当需要调用原始的MessageBox时，直接调用此函数即可，参数完全相同
__declspec(naked)
int WINAPI OriginalMessageBox(DWORD dwMilliseconds)
{
	_asm
	{
		//由于我们写入的Jmp指令破坏了原来的前3条指令,因此在这里执行原函数的前3条指令
		mov edi, edi  //这一句其实可以不要
		push ebp
		mov ebp, esp
		jmp SleepHookData.JmpBackAddr //跳到Hook代码之后的地方，绕过自己安装的HOOK
	}
}

//获取指定模块中指定API的地址
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
	//计算跳转偏移并写入
	*(ULONG*)(pHookData->newEntry + 1) = (ULONG)pHookData->pfnDetourFun - (ULONG)pHookData->HookPoint - 5;//0xE9 式jmp的计算


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
	pHookData->HookPoint = SkipJmpAddress(pHookData->HookPoint); //如果函数开头是跳转，那么将其跳过
	printf("pHookData->HookPoint %p\n", pHookData->HookPoint);

	DWORD tmp = *(PDWORD)(pHookData->HookPoint);
	printf("tmp %p\n", tmp);
	pHookData->HookPoint = tmp;


	pHookData->JmpBackAddr = pHookData->HookPoint + pHookData->HookCodeLen;
	printf("pHookData->JmpBackAddr %p\n", pHookData->JmpBackAddr);

	LPVOID OriginalAddr = (LPVOID)pHookData->HookPoint;
	printf("Address To HOOK=0x%08X\n", OriginalAddr);
	InitHookEntry(pHookData);//填充Inline Hook代码
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
//判断是否修改dll还是修改自身，搞清三个地址
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