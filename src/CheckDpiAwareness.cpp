
/*
Copyright (c) 2014 Maximus5
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. The name of the authors may not be used to endorse or promote products
   derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <Windows.h>
#include <TlHelp32.h>
#include <algorithm>
#include <map>
#include <vector>

UINT CP = CP_OEMCP;

enum Awareness
{
	Aware_Unknown                  = -1,
	Aware_AccessDenied             = -2,
	Process_DPI_Unaware            =  0,
	Process_System_DPI_Aware       =  1,
	Process_Per_Monitor_DPI_Aware  =  2,
};

typedef HRESULT (WINAPI* GetProcessDPIAwareness_t)(HANDLE hprocess, Awareness *value);
GetProcessDPIAwareness_t getProcessDPIAwareness = NULL;

struct WndInfo
{
	HWND       Wnd;
	DWORD      PID;
	Awareness  Aware;
	HRESULT    hrc;
	char       Name[MAX_PATH+1];
	char       Title[MAX_PATH];
};

std::map<DWORD,WndInfo> wList;

void PrintInfo(const WndInfo& w)
{
	char szAware[32];

	switch (w.Aware)
	{
	case Process_DPI_Unaware:
		strcpy_s(szAware, "Unaware"); break;
	case Process_System_DPI_Aware:
		strcpy_s(szAware, "SystemAware"); break;
	case Process_Per_Monitor_DPI_Aware:
		strcpy_s(szAware, "!PerMonitor"); break;
	case Aware_Unknown:
		strcpy_s(szAware, "Unknown"); break;
	case Aware_AccessDenied:
		strcpy_s(szAware, "AccessDenied"); break;
	default:
		strcpy_s(szAware, "Failed");
	}

	printf("%-6u  %-15s %-20s  %s\n", w.PID, szAware, w.Name, w.Title);
}

BOOL CALLBACK CheckWindow(HWND hWnd, LPARAM)
{
	if (IsWindowVisible(hWnd))
	{
		DWORD nPID = 0;
		if (GetWindowThreadProcessId(hWnd, &nPID) && nPID && (nPID != GetCurrentProcessId()))
		{
			std::map<DWORD,WndInfo>::const_iterator i;
			i = wList.find(nPID);
			if (i == wList.end())
			{
				WndInfo w = {hWnd, nPID, Aware_Unknown};
				wchar_t szText[MAX_PATH] = L"";
				if ((GetWindowText(hWnd, szText, ARRAYSIZE(szText)-2) <= 0) || (szText[0] == 0))
				{
					szText[0] = L'<';
					GetClassName(hWnd, szText+1, ARRAYSIZE(szText)-2);
					wcscat_s(szText, L">");
				}
				if (szText[0])
				{
					int iLen = lstrlen(szText);
					if (iLen > 32) wcscpy_s(szText+30, 4, L"...");
					WideCharToMultiByte(CP, 0, szText, -1, w.Title, ARRAYSIZE(w.Title), NULL, NULL);
				}
				HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, nPID);
				if (h && (h != INVALID_HANDLE_VALUE))
				{
					w.hrc = getProcessDPIAwareness(h, &w.Aware);
					if (FAILED(w.hrc))
						w.Aware = Aware_AccessDenied;
					CloseHandle(h);
				}
				else
				{
					w.Aware = Aware_AccessDenied;
				}
				wList[nPID] = w;
			}
		}
	}
	return TRUE;
}

void EnumProcesses()
{
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (!h || h ==  INVALID_HANDLE_VALUE)
		return;
	PROCESSENTRY32W pi = {sizeof(pi)};
	if (Process32FirstW(h, &pi)) do
	{
		std::map<DWORD,WndInfo>::iterator i;
		i = wList.find(pi.th32ProcessID);
		if (i != wList.end())
		{
			//wchar_t* p1 = wcsrchr(pi.szExeFile, L'\\');
			//wchar_t* p2 = wcsrchr(pi.szExeFile, L'/');
			//wchar_t* pszName = pi.szExeFile;
			//if (p1 && p2)
			//{
			//	if (p1 > p2)
			//		pszName = p1 + 1;
			//	else
			//		pszName = p2 + 1;
			//}
			//else if (p1)
			//	pszName = p1 + 1;
			//else if (p2)
			//	pszName = p2 + 1;
			LPCWSTR pszName = pi.szExeFile;
			WideCharToMultiByte(CP, 0, pszName, -1, i->second.Name, 20/*ARRAYSIZE(i->second.Name)*/, NULL, NULL);
		}
	} while (Process32Next(h, &pi));
}

bool myfunction (WndInfo& i, WndInfo& j)
{
	if (i.Aware == Process_Per_Monitor_DPI_Aware && j.Aware != Process_Per_Monitor_DPI_Aware)
		return true;
	else if (i.Aware != Process_Per_Monitor_DPI_Aware && j.Aware == Process_Per_Monitor_DPI_Aware)
		return false;
	return (lstrcmpA(i.Name, j.Name)<0);
}

void PrintResults()
{
	printf("\n");
	printf("%-6s  %-15s %s\n", "PID", "Awareness", "Process name");
	printf("%-6s  %-15s %s\n", "---", "---------", "------------");

	std::vector<WndInfo> vSort;
	for (std::map<DWORD,WndInfo>::iterator j = wList.begin(); j != wList.end(); ++j)
		vSort.push_back(j->second);
	std::sort(vSort.begin(), vSort.end(), myfunction);

	std::vector<WndInfo>::iterator i = vSort.begin();
	while (i != vSort.end())
	{
		PrintInfo(*i);
		++i;
	}
}

int main(int argc, char* argv[])
{
	printf("Process DPI-Awareness checker. (C) 2014 Maximus5\n");

	HMODULE hdll = LoadLibraryW(L"SHCore.dll");
	getProcessDPIAwareness = hdll ? (GetProcessDPIAwareness_t)GetProcAddress(hdll, "GetProcessDpiAwareness") : NULL;
	if (getProcessDPIAwareness == NULL)
	{
		printf("Your system does not have GetProcessDpiAwareness function\n");
		return 100;
	}

	CP = GetConsoleOutputCP();
	if (!CP) CP = CP_OEMCP;

	EnumWindows(CheckWindow, 0);

	EnumProcesses();

	PrintResults();

	return 0;
}

