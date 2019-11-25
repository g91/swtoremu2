// ==========================================================
// Nexus - ToR Project
// 
// Author: NoFaTe
// ==========================================================

#include "StdAfx.h"
#include "Log.h"

HWND Log::WindowHandle = NULL;
HWND Log::ListBoxHandle = NULL;
bool Log::IsInit = false;
std::vector<std::string> Log::LogQueue;

LRESULT CALLBACK Log::WindowProc( HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam )
{
    switch ( msg )
    {
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
		default:
			return DefWindowProc(hwnd, msg, wParam, lParam);
			break;
    }
    return 0;
}
HWND Log::CreateLogWindow(LPCTSTR pTitle, int pXPos, int pYPos, int pWidth, int pHeight)
{
	// Create a new window which will be used for logging
	WNDCLASSEX wc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = (LPCSTR)"NexusToRConsole";
    wc.lpfnWndProc = WindowProc;
    wc.style = CS_DBLCLKS;
    wc.cbSize = sizeof (WNDCLASSEX);
    wc.hIcon = LoadIcon (NULL, IDI_APPLICATION);
    wc.hIconSm = LoadIcon (NULL, IDI_APPLICATION);
    wc.hCursor = LoadCursor (NULL, IDC_ARROW);
    wc.lpszMenuName = NULL;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hbrBackground = (HBRUSH)GetStockObject(LTGRAY_BRUSH);

	RegisterClassEx( &wc );

	return CreateWindowEx(WS_EX_CONTROLPARENT, "NexusToRConsole", pTitle, WS_CAPTION | WS_POPUPWINDOW | WS_VISIBLE, pXPos, pYPos, pWidth, pHeight, NULL, NULL, GetModuleHandle(NULL), NULL );
}

void Log::CreateListBox()
{
	// Add a listbox to that window
	ListBoxHandle = CreateWindow("LISTBOX", "", WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_DISABLENOSCROLL, 10, 10, 774, 358, WindowHandle, NULL, GetModuleHandle(NULL), NULL);

	LOGFONT pLogFont;
	pLogFont.lfHeight = 15;
	pLogFont.lfWidth = 0;
	pLogFont.lfEscapement = 0;
	pLogFont.lfOrientation = 0;
	pLogFont.lfWeight = 400;
	pLogFont.lfItalic = FALSE;
	pLogFont.lfUnderline = FALSE;
	pLogFont.lfStrikeOut = FALSE;
	pLogFont.lfCharSet = DEFAULT_CHARSET;
	pLogFont.lfOutPrecision = OUT_DEFAULT_PRECIS;
	pLogFont.lfClipPrecision = CLIP_DEFAULT_PRECIS;
	pLogFont.lfQuality = DEFAULT_QUALITY;
	pLogFont.lfPitchAndFamily = DEFAULT_PITCH | FF_DONTCARE;
	strcpy(pLogFont.lfFaceName, "Arial");

	HFONT hFont = CreateFontIndirect(&pLogFont);
	SendMessage(ListBoxHandle, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
}

void Log::ILogWindow()
{
	MSG messages;

	WindowHandle = CreateLogWindow("Nexus: The Old Republic | 0.1-alpha | Debug Console", 100, 100, 800, 400);

	CreateListBox();

	ShowWindow(WindowHandle, SW_SHOW);

	IsInit = true;

	while (GetMessage (&messages, NULL, 0, 0))
	{
		TranslateMessage(&messages);
        DispatchMessage(&messages);
	}
}

void Log::Init()
{
	CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)ILogWindow, NULL, NULL, NULL);
	
	// Start the log queue
	CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)LogWriter, NULL, NULL, NULL);

	while(!IsInit)
		Sleep(5);
}

void Log::LogWriter()
{
	while(true)
	{
		if (LogQueue.size() > 0)
		{
			// Add a new log item to the listbox
			SendMessage(ListBoxHandle, LB_ADDSTRING, 0, (LPARAM)LogQueue.front().c_str());
			SendMessage(ListBoxHandle, LB_SELECTSTRING, 0, (LPARAM)LogQueue.front().c_str());
			LogQueue.erase(LogQueue.begin());
			Sleep(75);
		}
		Sleep(5);
	}
}

void Log::Write(char* pCaller, char* pText, ...)
{
	char timeStr[9];
	char logOut[1024];

	_strtime( timeStr );

	va_list argList;
	va_start(argList, pText);
	vsnprintf(logOut, sizeof(logOut), pText, argList);
	va_end(argList);

	char logBuff[1024];

	_snprintf(logBuff, sizeof(logBuff), "[%s] %s: %s\n", timeStr, pCaller, logOut);

	LogQueue.push_back(std::string(logBuff));

	// TODO: Write to file
}