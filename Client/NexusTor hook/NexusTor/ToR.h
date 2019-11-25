// ==========================================================
// Nexus - ToR Project
// 
// Author: NoFaTe
// ==========================================================

#include "detours.h"

#ifndef TOR_H
#define TOR_H

class ToR
{
public:
	static ToR* GetInstance();
	void InitHooks();
	static ToR* gInstance;

private:
	ToR();
	~ToR();

	DWORD dwCodeSize;
	DWORD dwCodeOffset;
	DWORD dwEntryPoint;
};

#endif