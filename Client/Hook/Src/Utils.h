// ==========================================================
// Nexus - ToR Project
//
// Author: NoFaTe
// ==========================================================

#ifndef UTILS_H
#define UTILS_H

class Utils
{
public:
	static DWORD FindPattern( DWORD dwStart, DWORD dwLen, BYTE* pszPatt, char pszMask[] );
	static unsigned int oneAtATimeHash( const char* inpStr );
	static DWORD OffsetToCode( HANDLE hHandle );
	static DWORD GetSizeOfCode( HANDLE hHandle );
	static void AllocateConsole(const char* pTitle);
	static void HexDump(void *ptr, int buflen);
};

#endif