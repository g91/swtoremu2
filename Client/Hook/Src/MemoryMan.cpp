// ==========================================================
// Nexus - ToR Project
// 
// Author: NoFaTe
// ==========================================================

#pragma comment(linker, "/export:mm_aligned_alloc=Nexus.mm_aligned_alloc")
#pragma comment(linker, "/export:mm_aligned_free=Nexus.mm_aligned_free")
#pragma comment(linker, "/export:mm_aligned_offset_alloc=Nexus.mm_aligned_offset_alloc")
#pragma comment(linker, "/export:mm_alloc=Nexus.mm_alloc")
#pragma comment(linker, "/export:mm_check_memory=Nexus.mm_check_memory")
#pragma comment(linker, "/export:mm_create_private_heap=Nexus.mm_create_private_heap")
#pragma comment(linker, "/export:mm_destory_private_heap=Nexus.mm_destory_private_heap")
#pragma comment(linker, "/export:mm_free=Nexus.mm_free")
#pragma comment(linker, "/export:mm_get_heap_stats=Nexus.mm_get_heap_stats")
#pragma comment(linker, "/export:mm_heap_aligned_alloc=Nexus.mm_heap_aligned_alloc")
#pragma comment(linker, "/export:mm_heap_aligned_free=Nexus.mm_heap_aligned_free")
#pragma comment(linker, "/export:mm_heap_aligned_offset_alloc=Nexus.mm_heap_aligned_offset_alloc")
#pragma comment(linker, "/export:mm_heap_alloc=Nexus.mm_heap_alloc")
#pragma comment(linker, "/export:mm_heap_free=Nexus.mm_heap_free")
#pragma comment(linker, "/export:mm_heap_realloc=Nexus.mm_heap_realloc")
#pragma comment(linker, "/export:mm_realloc=Nexus.mm_realloc")

#include "StdAfx.h"
#include "ToR.h"

extern "C" 
{
	static BYTE originalCode[5];
	static PBYTE originalEP = 0;
	static HANDLE gModule = NULL;

	#pragma unmanaged
	void Main_UnprotectModule(HMODULE hModule)
	{
		PIMAGE_DOS_HEADER header = (PIMAGE_DOS_HEADER)hModule;
		PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD)hModule + header->e_lfanew);

		SIZE_T size = ntHeader->OptionalHeader.SizeOfImage;
		DWORD oldProtect;
		VirtualProtect((LPVOID)hModule, size, PAGE_EXECUTE_READWRITE, &oldProtect);
	}

	void Main_DoInit()
	{
		HMODULE hModule;
		if (SUCCEEDED(GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)Main_DoInit, &hModule)))
		{
			Main_UnprotectModule(hModule);
		}

		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)ToR::GetInstance, NULL, NULL, NULL);

		memcpy(originalEP, &originalCode, sizeof(originalCode));
		__asm jmp originalEP
	}

	void Main_SetSafeInit()
	{
		HMODULE hModule = GetModuleHandle(NULL);

		if (hModule)
		{
			PIMAGE_DOS_HEADER header = (PIMAGE_DOS_HEADER)hModule;
			PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD)hModule + header->e_lfanew);

			Main_UnprotectModule(hModule);

			PBYTE ep = (PBYTE)((DWORD)hModule + ntHeader->OptionalHeader.AddressOfEntryPoint);
			memcpy(originalCode, ep, sizeof(originalCode));

			int newEP = (int)Main_DoInit - ((int)ep + 5);
			ep[0] = 0xE9;
			memcpy(&ep[1], &newEP, 4);

			originalEP = ep;
		}
	}

	int IdentifyClient(void)
	{
		// TODO: Add a check to see if we want to launch the retail client (without hooking anything)
		int nArgs;
		bool isSWTORclient = false;

		LPWSTR *szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
		if( szArglist == NULL )
		{
			Log::Write("CommandLine", "CommandLineToArgvW failed");
		}
		else
		{
			for( int i = 0; i < nArgs; i++)
				if (!wcscmp(L"@swtor_dual.icb", szArglist[i])) 
					isSWTORclient = true;
		}

		LocalFree(szArglist);

		// Only initialize our hooks if this is the main SWToR client
		if (isSWTORclient)
			Main_SetSafeInit();

		return 0;
	}

	BOOL WINAPI DllMain( HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved ) 
	{
		switch( ul_reason_for_call ) 
		{
			case DLL_PROCESS_ATTACH:
				gModule = hModule;
				IdentifyClient();
				break;
			case DLL_PROCESS_DETACH:
				break;
		}

		return TRUE;
	}
}