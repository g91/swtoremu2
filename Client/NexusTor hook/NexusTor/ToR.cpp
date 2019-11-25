// ==========================================================
// Nexus - ToR Project
// 
// Usage: Rename 'MemoryMan.dll' (located in the SWToR
//   directory) to 'Nexus.dll', build this project and place
//   the built 'MemoryMan.dll' in your SWToR directory
//
// Notes: Should work with any version of the game
//   No need for manual patching
//
// Author: NoFaTe
// ==========================================================

#include <WinSock2.h>
#include <WS2tcpip.h>
#include "StdAfx.h"
#include "ToR.h"
#include "wininet.h"

#pragma comment(lib, "ws2_32.lib")

ToR* ToR::gInstance = NULL;

ToR* ToR::GetInstance()
{
	if(gInstance == NULL)
		gInstance = new ToR;
	return gInstance;
}

//--------------------------------------------------------------------------------
typedef int (WSAAPI *getaddrinfo_t)(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA *pHints, PADDRINFOA *ppResult);
getaddrinfo_t getaddrinfo_r = (getaddrinfo_t)getaddrinfo;

char* serverName = NULL;
char* webName = NULL;

int WSAAPI getaddrinfo_c(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA *pHints, PADDRINFOA *ppResult) 
{
	printf("GetAddrInfo (%s)", (char*)pNodeName);

	unsigned int RandomHost = Utils::oneAtATimeHash("crash.swtor.com");

	unsigned int current = Utils::oneAtATimeHash((char*)pNodeName);

	if (current == RandomHost) 
	{
		serverName = "crash.emulatornexus.com";
		pNodeName = serverName;

		printf("Redirecting to '%s'", serverName);
	}

	return getaddrinfo_r(pNodeName, pServiceName, pHints, ppResult);
}

//--------------------------------------------------------------------------------
void crash(static TCHAR frmdata[])
{
	static TCHAR hdrs[] = "Content-Type: application/x-www-form-urlencoded";

	HINTERNET hSession = InternetOpen("MyAgent", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	HINTERNET hConnect = InternetConnect(hSession, "emulatornexus.com", INTERNET_DEFAULT_HTTP_PORT, NULL, NULL,INTERNET_SERVICE_HTTP, 0, 1);
	HINTERNET hRequest = HttpOpenRequest(hConnect, "POST", "/sso/swtor/crash.php", NULL, NULL, (LPCSTR*)"*/*", 0, 1);
	HttpSendRequest(hRequest, hdrs, strlen(hdrs), frmdata, strlen(frmdata));
}

//--------------------------------------------------------------------------------
void http(char* post_to, static TCHAR frmdata[])
{
	static TCHAR hdrs[] = "Content-Type: application/x-www-form-urlencoded";

	HINTERNET hSession = InternetOpen("MyAgent", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	HINTERNET hConnect = InternetConnect(hSession, "emulatornexus.com", INTERNET_DEFAULT_HTTP_PORT, NULL, NULL,INTERNET_SERVICE_HTTP, 0, 1);
	HINTERNET hRequest = HttpOpenRequest(hConnect, "POST", post_to, NULL, NULL, (LPCSTR*)"*/*", 0, 1);
	HttpSendRequest(hRequest, hdrs, strlen(hdrs), frmdata, strlen(frmdata));
}

void ToR::InitHooks()
{
	http("/sso/swtor/log.php", "v=4.0");

	// Hook GetHostByName - just in case
	PBYTE offset = (PBYTE)GetProcAddress(GetModuleHandleA("ws2_32.dll"), "getaddrinfo");
	getaddrinfo_r = (getaddrinfo_t)DetourFunction(offset, (PBYTE)&getaddrinfo_c);
}

ToR::ToR()
{
	HANDLE hModule = GetModuleHandle(NULL);

	dwCodeSize = Utils::GetSizeOfCode( hModule );
	dwCodeOffset = Utils::OffsetToCode( hModule );
	dwEntryPoint = (DWORD)hModule + dwCodeOffset;

	InitHooks();
}