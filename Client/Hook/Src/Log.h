// ==========================================================
// Nexus - ToR Project
// 
// Author: NoFaTe
// ==========================================================

#include <iostream>
#include <vector>

#ifndef LOG_H
#define LOG_H

class Log
{
public:
	static void Init();
	static HWND WindowHandle;
	static HWND ListBoxHandle;
	static void Write(char* pCaller, char* pText, ...);

private:
	static std::vector<std::string> LogQueue;
	static void LogWriter();
	static bool IsInit;
	static void ILogWindow();
	static void CreateListBox();
	static HWND CreateLogWindow(LPCTSTR pTitle, int pXPos, int pYPos, int pWidth, int pHeight);
	static LRESULT CALLBACK WindowProc( HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam );
};

#endif