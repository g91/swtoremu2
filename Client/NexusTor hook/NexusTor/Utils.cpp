// ==========================================================
// Nexus - ToR Project
// 
// Author: NoFaTe
// ==========================================================

#include "StdAfx.h"
#include "Utils.h"

void Utils::AllocateConsole(const char* pTitle)
{
	// Allocate Console Window
	AllocConsole() ;
	AttachConsole( GetCurrentProcessId() );
	freopen( "CON", "w", stdout ) ;
	SetConsoleTitle( pTitle );

	// Resize console (max length)
	COORD cordinates = {80, 32766};
	HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleScreenBufferSize(handle, cordinates);
}

unsigned int Utils::oneAtATimeHash(const char *inpStr)
{
	unsigned int value = 0, temp = 0;
	for(size_t i = 0; inpStr[i] != 0; ++i)
	{
		char ctext = tolower(inpStr[i]);
		temp = ctext + value;
		value = temp << 10;
		temp = temp + value;
		value = temp >> 6;
		value = value ^ temp;
	}
	temp = value << 3;
	temp = temp + value;
	unsigned int temp2 = temp >> 11;
	temp = temp2 ^ temp;
	temp2 = temp << 15;
	value = temp2 + temp;
	if(value < 2)
		return value + 2;
	return value;
}

DWORD Utils::FindPattern( DWORD dwStart, DWORD dwLen, BYTE* pszPatt, char pszMask[] )
{
	unsigned int i = NULL;
	int iLen = strlen( pszMask ) - 1;

	for( DWORD dwRet = dwStart; dwRet < dwStart + dwLen; dwRet++ )
	{
		if( *(BYTE*)dwRet == pszPatt[i] || pszMask[i] == '?' )
		{
			if( pszMask[i+1] == '\0' )
				return( dwRet - iLen );
			i++;
		} 
		else 
			i = NULL;
	}
	return NULL;
}

DWORD Utils::GetSizeOfCode( HANDLE hHandle )
{
	HMODULE hModule = (HMODULE)hHandle;

	if ( !hModule )
		return NULL;

	PIMAGE_DOS_HEADER pDosHeader = PIMAGE_DOS_HEADER( hModule );

	if( !pDosHeader )
		return NULL;

	PIMAGE_NT_HEADERS pNTHeader = PIMAGE_NT_HEADERS( (LONG)hModule + pDosHeader->e_lfanew );

	if( !pNTHeader )
		return NULL;

	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNTHeader->OptionalHeader;

	if( !pOptionalHeader )
		return NULL;

	return pOptionalHeader->SizeOfCode;
}

DWORD Utils::OffsetToCode( HANDLE hHandle )
{
	HMODULE hModule = (HMODULE)hHandle;

	if ( !hModule )
		return NULL;

	PIMAGE_DOS_HEADER pDosHeader = PIMAGE_DOS_HEADER( hModule );

	if( !pDosHeader )
		return NULL;

	PIMAGE_NT_HEADERS pNTHeader = PIMAGE_NT_HEADERS( (LONG)hModule + pDosHeader->e_lfanew );

	if( !pNTHeader )
		return NULL;

	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNTHeader->OptionalHeader;

	if( !pOptionalHeader )
		return NULL;

	return pOptionalHeader->BaseOfCode;
}
