/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2014 Cuckoo Sandbox Developers

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include "ntapi.h"
#include "hooking.h"
#include "misc.h"
#include "pipe.h"
#include "log.h"

HOOKDEF(HWND, WINAPI, FindWindowA,
    __in_opt  LPCTSTR lpClassName,
    __in_opt  LPCTSTR lpWindowName
) {
    // The atom must be in the low-order word of lpClassName;
    // the high-order word must be zero (from MSDN documentation.)
    HWND ret = Old_FindWindowA(lpClassName, lpWindowName);
    if(((DWORD_PTR) lpClassName & 0xffff) == (DWORD_PTR) lpClassName) {
        LOQ_nonnull("windows", "is", "ClassName", lpClassName, "WindowName", lpWindowName);
    }
    else {
        LOQ_nonnull("windows", "ss", "ClassName", lpClassName, "WindowName", lpWindowName);
    }
    return ret;
}

HOOKDEF(HWND, WINAPI, FindWindowW,
    __in_opt  LPWSTR lpClassName,
    __in_opt  LPWSTR lpWindowName
) {
    HWND ret = Old_FindWindowW(lpClassName, lpWindowName);
    if(((DWORD_PTR) lpClassName & 0xffff) == (DWORD_PTR) lpClassName) {
        LOQ_nonnull("windows", "iu", "ClassName", lpClassName, "WindowName", lpWindowName);
    }
    else {
        LOQ_nonnull("windows", "uu", "ClassName", lpClassName, "WindowName", lpWindowName);
    }
    return ret;
}

HOOKDEF(HWND, WINAPI, FindWindowExA,
    __in_opt  HWND hwndParent,
    __in_opt  HWND hwndChildAfter,
    __in_opt  LPCTSTR lpszClass,
    __in_opt  LPCTSTR lpszWindow
) {
    HWND ret = Old_FindWindowExA(hwndParent, hwndChildAfter, lpszClass,
        lpszWindow);

    // lpszClass can be one of the predefined window controls.. which lay in
    // the 0..ffff range
    if(((DWORD_PTR) lpszClass & 0xffff) == (DWORD_PTR) lpszClass) {
        LOQ_nonnull("windows", "is", "ClassName", lpszClass, "WindowName", lpszWindow);
    }
    else {
        LOQ_nonnull("windows", "ss", "ClassName", lpszClass, "WindowName", lpszWindow);
    }
    return ret;
}

HOOKDEF(HWND, WINAPI, FindWindowExW,
    __in_opt  HWND hwndParent,
    __in_opt  HWND hwndChildAfter,
    __in_opt  LPWSTR lpszClass,
    __in_opt  LPWSTR lpszWindow
) {
    HWND ret = Old_FindWindowExW(hwndParent, hwndChildAfter, lpszClass,
        lpszWindow);
    // lpszClass can be one of the predefined window controls.. which lay in
    // the 0..ffff range
    if(((DWORD_PTR) lpszClass & 0xffff) == (DWORD_PTR) lpszClass) {
        LOQ_nonnull("windows", "iu", "ClassName", lpszClass, "WindowName", lpszWindow);
    }
    else {
        LOQ_nonnull("windows", "uu", "ClassName", lpszClass, "WindowName", lpszWindow);
    }
    return ret;
}

HOOKDEF(BOOL, WINAPI, SendNotifyMessageA,
	_In_  HWND hWnd,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
) {
	DWORD pid;
	lasterror_t lasterror;
	BOOL ret;

	get_lasterrors(&lasterror);
	GetWindowThreadProcessId(hWnd, &pid);
	if (pid != GetCurrentProcessId())
		pipe("PROCESS:%d:%d", is_suspended(pid, 0), pid);
	set_lasterrors(&lasterror);

	ret = Old_SendNotifyMessageA(hWnd, Msg, wParam, lParam);

	LOQ_bool("windows", "ph", "WindowHandle", hWnd, "Message", Msg);

	return ret;
}

HOOKDEF(BOOL, WINAPI, SendNotifyMessageW,
	_In_  HWND hWnd,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
	) {
	DWORD pid;
	lasterror_t lasterror;
	BOOL ret;

	get_lasterrors(&lasterror);
	GetWindowThreadProcessId(hWnd, &pid);
	if (pid != GetCurrentProcessId())
		pipe("PROCESS:%d:%d", is_suspended(pid, 0), pid);
	set_lasterrors(&lasterror);

	ret = Old_SendNotifyMessageW(hWnd, Msg, wParam, lParam);

	LOQ_bool("windows", "ph", "WindowHandle", hWnd, "Message", Msg);

	return ret;
}


HOOKDEF(BOOL, WINAPI, EnumWindows,
    _In_  WNDENUMPROC lpEnumFunc,
    _In_  LPARAM lParam
) {

    BOOL ret = Old_EnumWindows(lpEnumFunc, lParam);
    LOQ_bool("windows", "");
    return ret;
}

HOOKDEF(HWND, WINAPI, CreateWindowExA,
	__in DWORD dwExStyle,
	__in_opt LPCSTR lpClassName,
	__in_opt LPCSTR lpWindowName,
	__in DWORD dwStyle,
	__in int x,
	__in int y,
	__in int nWidth,
	__in int nHeight,
	__in_opt HWND hWndParent,
	__in_opt HMENU hMenu,
	__in_opt HINSTANCE hInstance,
	__in_opt LPVOID lpParam
) {
	HWND ret = (HWND)1;
	// We have to log first as this function may not return, this unfortunately means
	// faking the return value as well

	// lpClassName can be one of the predefined window controls.. which lay in
	// the 0..ffff range
	if (((DWORD_PTR)lpClassName & 0xffff) == (DWORD_PTR)lpClassName) {
		LOQ_nonnull("windows", "is", "ClassName", lpClassName, "WindowName", lpWindowName);
	}
	else {
		LOQ_nonnull("windows", "ss", "ClassName", lpClassName, "WindowName", lpWindowName);
	}

	ret = Old_CreateWindowExA(dwExStyle, lpClassName,
		lpWindowName, dwStyle, x, y, nWidth, nHeight,
		hWndParent, hMenu, hInstance, lpParam);

	return ret;
}

HOOKDEF(HWND, WINAPI, CreateWindowExW,
	__in DWORD dwExStyle,
	__in_opt LPWSTR lpClassName,
	__in_opt LPWSTR lpWindowName,
	__in DWORD dwStyle,
	__in int x,
	__in int y,
	__in int nWidth,
	__in int nHeight,
	__in_opt HWND hWndParent,
	__in_opt HMENU hMenu,
	__in_opt HINSTANCE hInstance,
	__in_opt LPVOID lpParam
) {
	HWND ret = (HWND)1;
	// We have to log first as this function may not return, this unfortunately means
	// faking the return value as well

	// lpClassName can be one of the predefined window controls.. which lay in
	// the 0..ffff range
	if (((DWORD_PTR)lpClassName & 0xffff) == (DWORD_PTR)lpClassName) {
		LOQ_nonnull("windows", "iu", "ClassName", lpClassName, "WindowName", lpWindowName);
	}
	else {
		LOQ_nonnull("windows", "uu", "ClassName", lpClassName, "WindowName", lpWindowName);
	}

	ret = Old_CreateWindowExW(dwExStyle, lpClassName,
		lpWindowName, dwStyle, x, y, nWidth, nHeight,
		hWndParent, hMenu, hInstance, lpParam);

	return ret;
}
