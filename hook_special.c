/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2015 Cuckoo Sandbox Developers, Optiv, Inc. (brad.spengler@optiv.com

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
#include "log.h"
#include "pipe.h"
#include "hook_sleep.h"
#include "misc.h"
#include "config.h"

HOOKDEF_NOTAIL(WINAPI, LdrLoadDll,
    __in_opt    PWCHAR PathToFile,
    __in_opt    PULONG Flags,
    __in        PUNICODE_STRING ModuleFileName,
    __out       PHANDLE ModuleHandle
) {

    //
    // In the event that loading this dll results in loading another dll as
    // well, then the unicode string (which is located in the TEB) will be
    // overwritten, therefore we make a copy of it for our own use.
    //
	lasterror_t lasterror;
	NTSTATUS ret = 0;

	COPY_UNICODE_STRING(library, ModuleFileName);

	get_lasterrors(&lasterror);

	/* Workaround for the case where we're being loaded twice in the same process
	Logging the load could confuse a novice analyst into thinking there's unusual
	activity when there's not, so hide it
	*/
	if (!called_by_hook() && wcsncmp(library.Buffer, g_config.dllpath, wcslen(g_config.dllpath))) {
		if (g_config.file_of_interest && g_config.suspend_logging) {
			wchar_t *absolutename = malloc(32768 * sizeof(wchar_t));
			ensure_absolute_unicode_path(absolutename, library.Buffer);
			if (!wcsicmp(absolutename, g_config.file_of_interest))
				g_config.suspend_logging = FALSE;
			free(absolutename);
		}

		if (!wcsncmp(library.Buffer, L"\\??\\", 4) || library.Buffer[1] == L':')
			LOQ_ntstatus("system", "HFP", "Flags", Flags, "FileName", library.Buffer,
			"BaseAddress", ModuleHandle);
		else
			LOQ_ntstatus("system", "HoP", "Flags", Flags, "FileName", &library,
			"BaseAddress", ModuleHandle);

		if (library.Buffer[1] == L':' && (!wcsnicmp(library.Buffer, L"c:\\windows\\system32\\", 20) ||
										  !wcsnicmp(library.Buffer, L"c:\\windows\\syswow64\\", 20) ||
										  !wcsnicmp(library.Buffer, L"c:\\windows\\sysnative\\", 21))) {
			ret = 1;
		}
		else if (library.Buffer[1] != L':') {
			WCHAR newlib[MAX_PATH] = { 0 };
			DWORD concatlen = MIN((DWORD)wcslen(library.Buffer), MAX_PATH - 21);
			wcscpy(newlib, L"c:\\windows\\system32\\");
			wcsncat(newlib, library.Buffer, concatlen);
			if (GetFileAttributesW(newlib) != INVALID_FILE_ATTRIBUTES)
				ret = 1;
		}

	}
	else {
		ret = 1;
	}

	set_lasterrors(&lasterror);

	return ret;
}

HOOKDEF_ALT(NTSTATUS, WINAPI, LdrLoadDll,
	__in_opt    PWCHAR PathToFile,
	__in_opt    PULONG Flags,
	__in        PUNICODE_STRING ModuleFileName,
	__out       PHANDLE ModuleHandle
) {
	NTSTATUS ret;
	ret = Old_LdrLoadDll(PathToFile, Flags, ModuleFileName, ModuleHandle);
	disable_tail_call_optimization();
	return ret;
}


extern void revalidate_all_hooks(void);

HOOKDEF_NOTAIL(WINAPI, LdrUnloadDll,
	PVOID DllImageBase
) {
	return 0;
}


HOOKDEF(BOOL, WINAPI, CreateProcessInternalW,
    __in_opt    LPVOID lpUnknown1,
    __in_opt    LPWSTR lpApplicationName,
    __inout_opt LPWSTR lpCommandLine,
    __in_opt    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    __in_opt    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    __in        BOOL bInheritHandles,
    __in        DWORD dwCreationFlags,
    __in_opt    LPVOID lpEnvironment,
    __in_opt    LPWSTR lpCurrentDirectory,
    __in        LPSTARTUPINFOW lpStartupInfo,
    __out       LPPROCESS_INFORMATION lpProcessInformation,
    __in_opt    LPVOID lpUnknown2
) {
    BOOL ret = Old_CreateProcessInternalW(lpUnknown1, lpApplicationName,
        lpCommandLine, lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, dwCreationFlags | CREATE_SUSPENDED, lpEnvironment,
        lpCurrentDirectory, lpStartupInfo, lpProcessInformation, lpUnknown2);

    if(ret != FALSE) {
		pipe("PROCESS:%d:%d,%d", (dwCreationFlags & CREATE_SUSPENDED) ? 1 : 0, lpProcessInformation->dwProcessId,
            lpProcessInformation->dwThreadId);

        // if the CREATE_SUSPENDED flag was not set, then we have to resume
        // the main thread ourself
        if((dwCreationFlags & CREATE_SUSPENDED) == 0) {
            ResumeThread(lpProcessInformation->hThread);
        }

        disable_sleep_skip();
    }
	
    if (!called_by_hook()) {
		if (dwCreationFlags & EXTENDED_STARTUPINFO_PRESENT && lpStartupInfo->cb == sizeof(STARTUPINFOEXW)) {
			HANDLE ParentHandle = (HANDLE)-1;
			unsigned int i;
			LPSTARTUPINFOEXW lpExtStartupInfo = (LPSTARTUPINFOEXW)lpStartupInfo;
			if (lpExtStartupInfo->lpAttributeList) {
				for (i = 0; i < lpExtStartupInfo->lpAttributeList->Count; i++)
					if (lpExtStartupInfo->lpAttributeList->Entries[i].Attribute == PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)
						ParentHandle = *(HANDLE *)lpExtStartupInfo->lpAttributeList->Entries[i].lpValue;
			}
			LOQ_bool("process", "uuhiippps", "ApplicationName", lpApplicationName,
				"CommandLine", lpCommandLine, "CreationFlags", dwCreationFlags,
				"ProcessId", lpProcessInformation->dwProcessId,
				"ThreadId", lpProcessInformation->dwThreadId,
				"ParentHandle", ParentHandle,
				"ProcessHandle", lpProcessInformation->hProcess,
				"ThreadHandle", lpProcessInformation->hThread, "StackPivoted", is_stack_pivoted() ? "yes" : "no");
		}
		else {
			LOQ_bool("process", "uuhiipps", "ApplicationName", lpApplicationName,
				"CommandLine", lpCommandLine, "CreationFlags", dwCreationFlags,
				"ProcessId", lpProcessInformation->dwProcessId,
				"ThreadId", lpProcessInformation->dwThreadId,
				"ProcessHandle", lpProcessInformation->hProcess,
				"ThreadHandle", lpProcessInformation->hThread, "StackPivoted", is_stack_pivoted() ? "yes" : "no");
		}
    }

    return ret;
}

static GUID _CLSID_CUrlHistory =	  { 0x3C374A40L, 0xBAE4, 0x11CF, 0xBF, 0x7D, 0x00, 0xAA, 0x00, 0x69, 0x46, 0xEE };
static GUID _CLSID_InternetExplorer = { 0x0002DF01L, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 };
static GUID _CLSID_InternetSecurityManager = { 0x79EAC9EE, 0xBAF9, 0x11CE, 0x8C, 0x82, 0x00, 0xAA, 0x00, 0x4B, 0xA9, 0x0B };
static GUID _CLSID_CTaskScheduler = { 0x148BD52A, 0xA2AB, 0x11CE, 0xB1, 0x1F, 0x00, 0xAA, 0x00, 0x53, 0x05, 0x03 };

static char *known_object(IID *app, IID *iface)
{
	if (!memcmp(app, &_CLSID_CUrlHistory, sizeof(*app)))
		return "CUrlHistory";
	else if (!memcmp(app, &_CLSID_InternetExplorer, sizeof(*app)))
		return "InternetExplorer";
	else if (!memcmp(app, &_CLSID_InternetSecurityManager, sizeof(*app)))
		return "InternetSecurityManager";
	else if (!memcmp(app, &_CLSID_CTaskScheduler, sizeof(*app)))
		return "CTaskScheduler";

	return NULL;
}

HOOKDEF(HRESULT, WINAPI, CoCreateInstance,
	__in    REFCLSID rclsid,
	__in	LPUNKNOWN pUnkOuter,
	__in	DWORD dwClsContext,
	__in	REFIID riid,
	__out	LPVOID *ppv
) {
	IID id1;
	IID id2;
	char idbuf1[40];
	char idbuf2[40];
	char *known;
	lasterror_t lasterror;
	HRESULT ret = Old_CoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv);

	get_lasterrors(&lasterror);

	memcpy(&id1, rclsid, sizeof(id1));
	memcpy(&id2, riid, sizeof(id2));
	sprintf(idbuf1, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X", id1.Data1, id1.Data2, id1.Data3,
		id1.Data4[0], id1.Data4[1], id1.Data4[2], id1.Data4[3], id1.Data4[4], id1.Data4[5], id1.Data4[6], id1.Data4[7]);
	sprintf(idbuf2, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X", id2.Data1, id2.Data2, id2.Data3,
		id2.Data4[0], id2.Data4[1], id2.Data4[2], id2.Data4[3], id2.Data4[4], id2.Data4[5], id2.Data4[6], id2.Data4[7]);

	set_lasterrors(&lasterror);

	if ((known = known_object(&id1, &id2)))
		LOQ_hresult("com", "shss", "rclsid", idbuf1, "ClsContext", dwClsContext, "riid", idbuf2, "KnownObject", known);
	else
		LOQ_hresult("com", "shs", "rclsid", idbuf1, "ClsContext", dwClsContext, "riid", idbuf2);

	return ret;
}

HOOKDEF(int, WINAPI, JsEval,
	PVOID Arg1,
	PVOID Arg2,
	PVOID Arg3,
	int Index,
	DWORD *scriptobj
) {
#ifndef _WIN64
	PWCHAR jsbuf;
	PUCHAR p;
#endif
	int ret = Old_JsEval(Arg1, Arg2, Arg3, Index, scriptobj);

	/* TODO: 64-bit support*/
#ifdef _WIN64
	return ret;
#else

	p = (PUCHAR)scriptobj[4 * Index - 2];
	jsbuf = *(PWCHAR *)(p + 8);
	if (jsbuf)
		LOQ_ntstatus("browser", "u", "Javascript", jsbuf);

	return ret;
#endif
}

HOOKDEF(int, WINAPI, COleScript_ParseScriptText,
	PVOID Arg1,
	PWCHAR ScriptBuf,
	PVOID Arg3,
	PVOID Arg4,
	PVOID Arg5,
	PVOID Arg6,
	PVOID Arg7,
	PVOID Arg8,
	PVOID Arg9,
	PVOID Arg10
) {
	int ret = Old_COleScript_ParseScriptText(Arg1, ScriptBuf, Arg3, Arg4, Arg5, Arg6, Arg7, Arg8, Arg9, Arg10);
	LOQ_ntstatus("browser", "u", "Script", ScriptBuf);
	return ret;
}

HOOKDEF(PVOID, WINAPI, JsParseScript,
	const wchar_t *script,
	PVOID SourceContext,
	const wchar_t *sourceUrl,
	PVOID *result
) {
	PVOID ret = Old_JsParseScript(script, SourceContext, sourceUrl, result);

	LOQ_zero("browser", "uu", "Script", script, "Source", sourceUrl);

	return ret;
}

HOOKDEF(PVOID, WINAPI, JsRunScript,
	const wchar_t *script,
	PVOID SourceContext,
	const wchar_t *sourceUrl,
	PVOID *result
) {
	PVOID ret = Old_JsRunScript(script, SourceContext, sourceUrl, result);

	LOQ_zero("browser", "uu", "Script", script, "Source", sourceUrl);

	return ret;
}

// based on code by Stephan Chenette and Moti Joseph of Websense, Inc. released under the GPLv3
// http://securitylabs.websense.com/content/Blogs/3198.aspx

HOOKDEF(int, WINAPI, CDocument_write,
	PVOID this,
	SAFEARRAY *psa
) {
	DWORD i;
	PWCHAR buf;
	int ret = Old_CDocument_write(this, psa);
	VARIANT *pvars = (VARIANT *)psa->pvData;
	unsigned int buflen = 0;
	unsigned int offset = 0;
	for (i = 0; i < psa->rgsabound[0].cElements; i++) {
		if (pvars[i].vt == VT_BSTR)
			buflen += (unsigned int)wcslen((const wchar_t *)pvars[i].pbstrVal) + 8;
	}
	buf = calloc(1, (buflen + 1) * sizeof(wchar_t));
	if (buf == NULL)
		return ret;

	for (i = 0; i < psa->rgsabound[0].cElements; i++) {
		if (pvars[i].vt == VT_BSTR) {
			wcscpy(buf + offset, (const wchar_t *)pvars[i].pbstrVal);
			offset += (unsigned int)wcslen((const wchar_t *)pvars[i].pbstrVal);
			wcscpy(buf + offset, L"\r\n||||\r\n");
			offset += 8;
		}
	}

	LOQ_ntstatus("browser", "u", "Buffer", buf);

	return ret;
}
