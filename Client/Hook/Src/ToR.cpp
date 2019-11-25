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
#include <stdint.h>
#include "StdAfx.h"
#include "acpdump2.h"
#include "ToR.h"

#pragma comment(lib, "ws2_32.lib")

typedef wchar_t* (__stdcall * getValByName_t)(char* name);
getValByName_t getValByName = (getValByName_t)0x00;

//--------------------------------------------------------------------------------
int (__stdcall* RSAFunc_r)(int a2, int pRSAKey, int a4);

int __stdcall RSAFunc(int a2, int pRSAKey, int a4)
{
	// Function is a __thiscall
	void* th; 
	__asm mov [th], ecx 

	Log::Write("RSAHook", "Called");

	//printf("RSA:\n%s\n", (char*)pRSAKey);

	// Replace with our custom RSA Key
	/*pRSAKey = "30820120300D06092A864886F70D01010105000382010D00308201080282010100B23B14D060C30DDB90532994FD63F3570D"
			  "025541CD086A6FFF0D44E519A804E63C31281C717440AD7BAB8FE33E06F7BD10F53D8E0FA900B8B6A08FE4CBE4133D84BCE9"
			  "19916ECE588450DC7915D316EE6B36ECDF811E8F039B20B18E564E5166EDC7FC7E03C4CCD2CD311CAC1C173EB3F65FB8AA05"
			  "5AAEB5B1503EE890691FBA840EDB6258644A4B64E7B65A2DA36C8E6C2602F608F67A0320C06863B119EF189A60B3DD8921F6"
			  "9A011E3D518F030E5DD89622067C472166F129BC283E8DBEEE4B6B7D57E135186A87B51FCC17AEC74673796EF8A6D9E59852"
			  "E9E61D8A6D0EEEBC6B93F5F87F7D3069B621503DA1277299C8220051B595B941207EFA93553A31020111";*/

	__asm mov ecx, [th]

	return RSAFunc_r(a2, pRSAKey, a4);
}
//--------------------------------------------------------------------------------
int (__cdecl* SSL_CTX_set_verify_r)(int ctx, int mode, int cb);

int __cdecl SSL_CTX_set_verify(int ctx, int mode, int cb)
{
	// Accept any SSL Certificate
	if (mode == 1)
		mode = 0;

	return SSL_CTX_set_verify_r(ctx, mode, cb);
}
//--------------------------------------------------------------------------------

char (__stdcall* GenRSAHandshake_r)(int a1, int a2, char *uUsername, char *uPassword);

char __stdcall GenRSAHandshake_stub(int a1, int a2, char *uUsername, char *uPassword)
{
	
	return GenRSAHandshake_r(a1, a2, uUsername, uPassword);
}

char __stdcall GenRSAHandshake(int a1, int a2, char *uUsername, char *uPassword)
{
	__asm pushad

	Log::Write("PassHook", "Called; Username: %s | Password: %s", (const char*)uUsername, (const char*)uPassword);

	__asm popad
	/*__asm
	{
		push ebp
		mov ebp, esp
		push dword ptr[ebp + 0x0C] // uPassword
		push dword ptr[ebp + 0x08] // uUsername
		//push uPassword
		//push uUsername
		push ecx // a2
		push eax // a1
		call GenRSAHandshake_stub
		
		mov esp, ebp
		pop ebp

		retn 8//n 8
	}*/

	return GenRSAHandshake_r(a1, a2, uUsername, uPassword);
}

//--------------------------------------------------------------------------------
typedef int (WSAAPI *getaddrinfo_t)(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA *pHints, PADDRINFOA *ppResult);
getaddrinfo_t getaddrinfo_r = (getaddrinfo_t)getaddrinfo;

char* serverName = NULL;
char* webName = NULL;

int WSAAPI getaddrinfo_c(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA *pHints, PADDRINFOA *ppResult) 
{
	Log::Write("WS2_32", "GetAddrInfo (%s)", (char*)pNodeName);

	/*unsigned int RandomHost = Utils::oneAtATimeHash("something.com");

	unsigned int current = Utils::oneAtATimeHash((char*)name);

	if (current == RandomHost) 
	{
		serverName = "localhost";
		hostname = serverName;

		Log::Write("WS2_32", "Redirecting to '%s'", serverName);
	}*/

	return getaddrinfo_r(pNodeName, pServiceName, pHints, ppResult);
}


typedef int (WINAPI *recv_t)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
recv_t recv_r = (recv_t)WSARecv;

int WINAPI recv_c(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	_asm pushad;

	if( lpBuffers && lpBuffers->buf && lpBuffers->len > 0 )
	{
		sockaddr_in addr;
		int len = sizeof(sockaddr_in);
		getpeername(s, (sockaddr*)&addr, &len);

		Log::Write("MainHook", "WSARecv Called [%s:%d]", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
	}
	
	_asm popad;

	return recv_r(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
}

//--------------------------------------------------------------------------------

typedef int (WINAPI *send_t)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
send_t send_r = (send_t)WSASend;

int WINAPI send_c(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	sockaddr_in addr;
	int len = sizeof(sockaddr_in);
	getpeername(s, (sockaddr*)&addr, &len);

	Log::Write("MainHook", "WSASend Called [%s:%d]", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

	return send_r(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
}

//--------------------------------------------------------------------------------

typedef int (WINAPI *sendTo_t)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const struct sockaddr *lpTo, int iTolen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
sendTo_t sendTo_r = (sendTo_t)WSASendTo;

int WINAPI sendTo_c(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const struct sockaddr *lpTo, int iTolen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	Log::Write("MainHook", "WSASendTo Called [%s:%d]", inet_ntoa(((sockaddr_in*)lpTo)->sin_addr), ntohs(((sockaddr_in*)lpTo)->sin_port));
	return sendTo_r(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine);
}

//--------------------------------------------------------------------------------

typedef int (WINAPI *recvFrom_t)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, struct sockaddr *lpFrom, LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
recvFrom_t recvFrom_r = (recvFrom_t)WSARecvFrom;

int WINAPI recvFrom_c(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, struct sockaddr *lpFrom, LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	Log::Write("MainHook", "WSARecvFrom Called [%s:%d]", inet_ntoa(((sockaddr_in*)lpFrom)->sin_addr), ntohs(((sockaddr_in*)lpFrom)->sin_port));
	return recvFrom_r(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine);
}

//--------------------------------------------------------------------------------

ToR* ToR::gInstance = NULL;

ToR* ToR::GetInstance()
{
	if(gInstance == NULL)
		gInstance = new ToR;
	return gInstance;
}

void ToR::InitHooks()
{
	// Hook GetHostByName - just in case
	PBYTE offset = (PBYTE)GetProcAddress(GetModuleHandleA("ws2_32.dll"), "getaddrinfo");
	getaddrinfo_r = (getaddrinfo_t)DetourFunction(offset, (PBYTE)&getaddrinfo_c);

	// Send/Recv Hooks
	offset = (PBYTE)GetProcAddress(GetModuleHandleA("ws2_32.dll"), "WSARecv");
	recv_r = (recv_t)DetourFunction(offset, (PBYTE)&recv_c);

	offset = (PBYTE)GetProcAddress(GetModuleHandleA("ws2_32.dll"), "WSASend");
	send_r = (send_t)DetourFunction(offset, (PBYTE)&send_c);
	
	// These two are rarely used but whatever
	offset = (PBYTE)GetProcAddress(GetModuleHandleA("ws2_32.dll"), "WSASendTo");
	sendTo_r = (sendTo_t)DetourFunction(offset, (PBYTE)&sendTo_c);

	offset = (PBYTE)GetProcAddress(GetModuleHandleA("ws2_32.dll"), "WSARecvFrom");
	recvFrom_r = (recvFrom_t)DetourFunction(offset, (PBYTE)&recvFrom_c);
	
	// Password setting hook
	// char __userpurge Generate_RSA_Handshake<al>(int a1<eax>, int a2<ecx>, char *uUsername, char *uPassword)
	//DWORD GenRSAHandshake_addr = Utils::FindPattern(dwEntryPoint, dwCodeSize, (BYTE*)"\x55\x8B\xEC\x64\xA1\x00\x00\x00\x00\x6A\xFF\x00\x00\x00\x00\x00\x50\x64\x89\x25\x00\x00\x00\x00\x81\xEC\x70\x08\x00\x00\x53\x56", "xxxxxxxxxxx?????xxxxxxxxxxxxxxxx");
	//GenRSAHandshake_r = (char (__stdcall*)(int a1, int a2, char *uUsername, char *uPassword))DetourFunction((PBYTE)GenRSAHandshake_addr, (PBYTE)GenRSAHandshake);

	// RSA/SSL Hooks
	DWORD RSAFuncAddr = Utils::FindPattern(dwEntryPoint, dwCodeSize, (BYTE*)"\x50\x64\x89\x25\x00\x00\x00\x00\x51\x53\x56\x8B\xF1\x8B\x46\x5C", "xxxxxxxxxxxxxxxx");
	RSAFuncAddr -= 16;
	//RSAFunc_r = (int (__stdcall*)(int a2, int pRSAKey, int a4))DetourFunction((PBYTE)RSAFuncAddr, (PBYTE)RSAFunc);

	DWORD SSL_CTX_set_verify_addr = Utils::FindPattern(dwEntryPoint, dwCodeSize, (BYTE*)"\x8B\x44\x24\x04\x8B\x4C\x24\x08\x8B\x54\x24\x0C\x89\x88\xC0\x00", "xxxxxxxxxxxxxxxx");
	SSL_CTX_set_verify_r = (int (__cdecl*)(int ctx, int mode, int cb))DetourFunction((PBYTE)SSL_CTX_set_verify_addr, (PBYTE)SSL_CTX_set_verify);

	Log::Write("NexusToR", "Hooked Send/SendTo and Recv/RecvFrom functions");

	Log::Write("NexusToR", "Hooked RSA Key certification and SSL Validation");
}

ToR::ToR()
{
	// Initialize the Logging module
	Log::Init();

	HANDLE hModule = GetModuleHandle(NULL);

	dwCodeSize = Utils::GetSizeOfCode( hModule );
	dwCodeOffset = Utils::OffsetToCode( hModule );
	dwEntryPoint = (DWORD)hModule + dwCodeOffset;

	// Allocate a console for game output
	Utils::AllocateConsole("Star Wars: The Old Republic");
	Log::Write("NexusToR", "Initializing NexusToR Client");

	// Initialize our Hooks
	InitHooks();
}
