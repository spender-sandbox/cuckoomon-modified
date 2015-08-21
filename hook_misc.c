/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2015 Cuckoo Sandbox Developers, Optiv, Inc. (brad.spengler@optiv.com)

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
#include "misc.h"
#include "hook_file.h"
#include "hook_sleep.h"
#include "config.h"
#include "ignore.h"

HOOKDEF(HHOOK, WINAPI, SetWindowsHookExA,
    __in  int idHook,
    __in  HOOKPROC lpfn,
    __in  HINSTANCE hMod,
    __in  DWORD dwThreadId
) {

    HHOOK ret = Old_SetWindowsHookExA(idHook, lpfn, hMod, dwThreadId);
    LOQ_nonnull("system", "ippi", "HookIdentifier", idHook, "ProcedureAddress", lpfn,
        "ModuleAddress", hMod, "ThreadId", dwThreadId);
    return ret;
}

HOOKDEF(HHOOK, WINAPI, SetWindowsHookExW,
    __in  int idHook,
    __in  HOOKPROC lpfn,
    __in  HINSTANCE hMod,
    __in  DWORD dwThreadId
) {

    HHOOK ret = Old_SetWindowsHookExW(idHook, lpfn, hMod, dwThreadId);
    LOQ_nonnull("system", "ippi", "HookIdentifier", idHook, "ProcedureAddress", lpfn,
        "ModuleAddress", hMod, "ThreadId", dwThreadId);
    return ret;
}

HOOKDEF(BOOL, WINAPI, UnhookWindowsHookEx,
    __in  HHOOK hhk
) {

    BOOL ret = Old_UnhookWindowsHookEx(hhk);
    LOQ_bool("hooking", "p", "HookHandle", hhk);
    return ret;
}

HOOKDEF(LPTOP_LEVEL_EXCEPTION_FILTER, WINAPI, SetUnhandledExceptionFilter,
    _In_  LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter
) {
    BOOL ret = 1;
    LPTOP_LEVEL_EXCEPTION_FILTER res;

#if REPORT_EXCEPTIONS
	res = NULL;
#else
	res = Old_SetUnhandledExceptionFilter(lpTopLevelExceptionFilter);
#endif
	LOQ_bool("hooking", "");
    return res;
}

HOOKDEF(UINT, WINAPI, SetErrorMode,
	_In_ UINT uMode
) {
	UINT ret = 0;
#if REPORT_EXCEPTIONS
#else
	ret = Old_SetErrorMode(uMode);
#endif
	//LOQ_void("system", "h", "Mode", uMode);
	disable_tail_call_optimization();
	return ret;
}

// Called with the loader lock held
HOOKDEF(NTSTATUS, WINAPI, LdrGetDllHandle,
    __in_opt    PWORD pwPath,
    __in_opt    PVOID Unused,
    __in        PUNICODE_STRING ModuleFileName,
    __out       PHANDLE pHModule
) {
    NTSTATUS ret = Old_LdrGetDllHandle(pwPath, Unused, ModuleFileName,
        pHModule);
    LOQ_ntstatus("system", "oP", "FileName", ModuleFileName, "ModuleHandle", pHModule);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, LdrGetProcedureAddress,
    __in        HMODULE ModuleHandle,
    __in_opt    PANSI_STRING FunctionName,
    __in_opt    WORD Ordinal,
    __out       PVOID *FunctionAddress
) {
    NTSTATUS ret = Old_LdrGetProcedureAddress(ModuleHandle, FunctionName,
        Ordinal, FunctionAddress);
    LOQ_ntstatus("system", "opSiP", "ModuleName", get_basename_of_module(ModuleHandle), "ModuleHandle", ModuleHandle,
        "FunctionName", FunctionName != NULL ? FunctionName->Length : 0,
            FunctionName != NULL ? FunctionName->Buffer : NULL,
        "Ordinal", Ordinal, "FunctionAddress", FunctionAddress);
    return ret;
}

HOOKDEF(BOOL, WINAPI, DeviceIoControl,
    __in         HANDLE hDevice,
    __in         DWORD dwIoControlCode,
    __in_opt     LPVOID lpInBuffer,
    __in         DWORD nInBufferSize,
    __out_opt    LPVOID lpOutBuffer,
    __in         DWORD nOutBufferSize,
    __out_opt    LPDWORD lpBytesReturned,
    __inout_opt  LPOVERLAPPED lpOverlapped
) {
	BOOL ret = Old_DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer,
		nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned,
		lpOverlapped);
    LOQ_bool("device", "phbb", "DeviceHandle", hDevice, "IoControlCode", dwIoControlCode,
        "InBuffer", nInBufferSize, lpInBuffer,
        "OutBuffer", lpBytesReturned ? *lpBytesReturned : nOutBufferSize,
            lpOutBuffer);

	if (!g_config.no_stealth && ret && lpOutBuffer)
		perform_device_fakery(lpOutBuffer, nOutBufferSize, dwIoControlCode);

	return ret;
}

HOOKDEF_NOTAIL(WINAPI, ExitWindowsEx,
    __in  UINT uFlags,
    __in  DWORD dwReason
) {
    DWORD ret = 0;
    LOQ_zero("system", "hi", "Flags", uFlags, "Reason", dwReason);
	pipe("SHUTDOWN:");
	return ret;
}

HOOKDEF_NOTAIL(WINAPI, InitiateShutdownW,
	_In_opt_ LPWSTR lpMachineName,
	_In_opt_ LPWSTR lpMessage,
	_In_     DWORD  dwGracePeriod,
	_In_     DWORD  dwShutdownFlags,
	_In_     DWORD  dwReason
) {
	DWORD ret = 0;
	LOQ_zero("system", "uuihh", "MachineName", lpMachineName, "Message", lpMessage, "GracePeriod", dwGracePeriod, "ShutdownFlags", dwShutdownFlags, "Reason", dwReason);
	pipe("SHUTDOWN:");
	return ret;
}

HOOKDEF_NOTAIL(WINAPI, InitiateSystemShutdownW,
	_In_opt_ LPWSTR lpMachineName,
	_In_opt_ LPWSTR lpMessage,
	_In_     DWORD  dwTimeout,
	_In_     BOOL	bForceAppsClosed,
	_In_     BOOL	bRebootAfterShutdown
) {
	DWORD ret = 0;
	LOQ_zero("system", "uuiii", "MachineName", lpMachineName, "Message", lpMessage, "Timeout", dwTimeout, "ForceAppsClosed", bForceAppsClosed, "RebootAfterShutdown", bRebootAfterShutdown);
	pipe("SHUTDOWN:");
	return ret;
}

HOOKDEF_NOTAIL(WINAPI, InitiateSystemShutdownExW,
	_In_opt_ LPWSTR lpMachineName,
	_In_opt_ LPWSTR lpMessage,
	_In_     DWORD  dwTimeout,
	_In_     BOOL	bForceAppsClosed,
	_In_     BOOL	bRebootAfterShutdown,
	_In_	 DWORD	dwReason
) {
	DWORD ret = 0;
	LOQ_zero("system", "uuiiih", "MachineName", lpMachineName, "Message", lpMessage, "Timeout", dwTimeout, "ForceAppsClosed", bForceAppsClosed, "RebootAfterShutdown", bRebootAfterShutdown, "Reason", dwReason);
	pipe("SHUTDOWN:");
	return ret;
}

static int num_isdebuggerpresent;

HOOKDEF(BOOL, WINAPI, IsDebuggerPresent,
	void
) {

	BOOL ret = Old_IsDebuggerPresent();
	num_isdebuggerpresent++;
	if (num_isdebuggerpresent < 20)
		LOQ_bool("system", "");
	else if (num_isdebuggerpresent == 20)
		LOQ_bool("system", "s", "Status", "Log limit reached");
#ifndef _WIN64
	else if (num_isdebuggerpresent == 1000) {
		lasterror_t lasterror;

		get_lasterrors(&lasterror);
		__try {
			hook_info_t *hookinfo = hook_info();
			PUCHAR p = (PUCHAR)hookinfo->main_caller_retaddr - 6;
			if (p[0] == 0xff && p[1] == 0x15 && p[6] == 0x49) {
				DWORD oldprot;
				VirtualProtect(p, 6, PAGE_EXECUTE_READWRITE, &oldprot);
				memcpy(p, "\x31\xc0\x31\xc9\x41\x90", 6);
				VirtualProtect(p, 6, oldprot, &oldprot);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			;
		}
		set_lasterrors(&lasterror);
	}
#endif

	return ret;
}

HOOKDEF(BOOL, WINAPI, LookupPrivilegeValueW,
    __in_opt  LPWSTR lpSystemName,
    __in      LPWSTR lpName,
    __out     PLUID lpLuid
) {

    BOOL ret = Old_LookupPrivilegeValueW(lpSystemName, lpName, lpLuid);
    LOQ_bool("system", "uu", "SystemName", lpSystemName, "PrivilegeName", lpName);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtClose,
    __in    HANDLE Handle
) {
	NTSTATUS ret;
	if (Handle == g_log_handle) {
		ret = STATUS_INVALID_HANDLE;
		LOQ_ntstatus("system", "ps", "Handle", Handle, "Alert", "Tried to close Cuckoo's log handle");
		return ret;
	}
	ret = Old_NtClose(Handle);
    LOQ_ntstatus("system", "p", "Handle", Handle);
    if(NT_SUCCESS(ret)) {
		remove_file_from_log_tracking(Handle);
        file_close(Handle);
    }
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtDuplicateObject,
	__in       HANDLE SourceProcessHandle,
	__in       HANDLE SourceHandle,
	__in_opt   HANDLE TargetProcessHandle,
	__out_opt  PHANDLE TargetHandle,
	__in       ACCESS_MASK DesiredAccess,
	__in       ULONG HandleAttributes,
	__in       ULONG Options
	) {
	NTSTATUS ret = Old_NtDuplicateObject(SourceProcessHandle, SourceHandle, TargetProcessHandle,
		TargetHandle, DesiredAccess, HandleAttributes, Options);
	if (TargetHandle)
		LOQ_ntstatus("system", "pP", "SourceHandle", SourceHandle, "TargetHandle", TargetHandle);
	else
		LOQ_ntstatus("system", "p", "SourceHandle", SourceHandle);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtMakeTemporaryObject,
	__in     HANDLE ObjectHandle
	) {
	NTSTATUS ret = Old_NtMakeTemporaryObject(ObjectHandle);
	LOQ_ntstatus("system", "p", "ObjectHandle", ObjectHandle);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtMakePermanentObject,
	__in     HANDLE ObjectHandle
	) {
	NTSTATUS ret = Old_NtMakePermanentObject(ObjectHandle);
	LOQ_ntstatus("system", "p", "ObjectHandle", ObjectHandle);
	return ret;
}

HOOKDEF(BOOL, WINAPI, WriteConsoleA,
    _In_        HANDLE hConsoleOutput,
    _In_        const VOID *lpBuffer,
    _In_        DWORD nNumberOfCharsToWrite,
    _Out_       LPDWORD lpNumberOfCharsWritten,
    _Reserved_  LPVOID lpReseverd
) {
    BOOL ret = Old_WriteConsoleA(hConsoleOutput, lpBuffer,
        nNumberOfCharsToWrite, lpNumberOfCharsWritten, lpReseverd);
    LOQ_bool("system", "pS", "ConsoleHandle", hConsoleOutput,
        "Buffer", nNumberOfCharsToWrite, lpBuffer);
    return ret;
}

HOOKDEF(BOOL, WINAPI, WriteConsoleW,
    _In_        HANDLE hConsoleOutput,
    _In_        const VOID *lpBuffer,
    _In_        DWORD nNumberOfCharsToWrite,
    _Out_       LPDWORD lpNumberOfCharsWritten,
    _Reserved_  LPVOID lpReseverd
) {
    BOOL ret = Old_WriteConsoleW(hConsoleOutput, lpBuffer,
        nNumberOfCharsToWrite, lpNumberOfCharsWritten, lpReseverd);
    LOQ_bool("system", "pU", "ConsoleHandle", hConsoleOutput,
        "Buffer", nNumberOfCharsToWrite, lpBuffer);
    return ret;
}

HOOKDEF(int, WINAPI, GetSystemMetrics,
    _In_  int nIndex
) {
    int ret = Old_GetSystemMetrics(nIndex);

	if (nIndex == SM_CXSCREEN || nIndex == SM_CXVIRTUALSCREEN || nIndex == SM_CYSCREEN ||
		nIndex == SM_CYVIRTUALSCREEN || nIndex == SM_REMOTECONTROL || nIndex == SM_REMOTESESSION ||
		nIndex == SM_SHUTTINGDOWN || nIndex == SM_SWAPBUTTON)
	    LOQ_nonzero("misc", "i", "SystemMetricIndex", nIndex);
    return ret;
}

typedef int (WINAPI * __GetSystemMetrics)(__in int nIndex);

__GetSystemMetrics _GetSystemMetrics;

DWORD WINAPI our_GetSystemMetrics(
	__in int nIndex
	) {
	if (!_GetSystemMetrics) {
		_GetSystemMetrics = (__GetSystemMetrics)GetProcAddress(LoadLibraryA("user32"), "GetSystemMetrics");
	}
	return _GetSystemMetrics(nIndex);
}

static LARGE_INTEGER last_skipped;
static int num_to_spoof;
static int num_spoofed;
static int lastx;
static int lasty;

HOOKDEF(BOOL, WINAPI, GetCursorPos,
    _Out_ LPPOINT lpPoint
) {
    BOOL ret = Old_GetCursorPos(lpPoint);

	/* work around the fact that skipping sleeps prevents the human module from making the system look active */
	if (lpPoint && time_skipped.QuadPart != last_skipped.QuadPart) {
		int xres, yres;
		xres = our_GetSystemMetrics(0);
		yres = our_GetSystemMetrics(1);
		if (!num_to_spoof)
			num_to_spoof = (random() % 20) + 10;
		if (num_spoofed < num_to_spoof) {
			lpPoint->x = random() % xres;
			lpPoint->y = random() % yres;
			num_spoofed++;
		}
		else {
			lpPoint->x = lastx;
			lpPoint->y = lasty;
			lastx = lpPoint->x;
			lasty = lpPoint->y;
		}
		last_skipped.QuadPart = time_skipped.QuadPart;
	}
	else if (last_skipped.QuadPart == 0) {
		last_skipped.QuadPart = time_skipped.QuadPart;
	}

	LOQ_bool("misc", "ii", "x", lpPoint != NULL ? lpPoint->x : 0,
        "y", lpPoint != NULL ? lpPoint->y : 0);
	
	return ret;
}

HOOKDEF(DWORD, WINAPI, GetLastError,
	void
)
{
	DWORD ret = Old_GetLastError();
	LOQ_void("misc", "");
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetComputerNameA,
    _Out_    LPSTR lpBuffer,
    _Inout_  LPDWORD lpnSize
) {
    BOOL ret = Old_GetComputerNameA(lpBuffer, lpnSize);
    LOQ_bool("misc", "s", "ComputerName", lpBuffer);
    return ret;
}

HOOKDEF(BOOL, WINAPI, GetComputerNameW,
    _Out_    LPWSTR lpBuffer,
    _Inout_  LPDWORD lpnSize
) {
    BOOL ret = Old_GetComputerNameW(lpBuffer, lpnSize);
    LOQ_bool("misc", "u", "ComputerName", lpBuffer);
    return ret;
}

HOOKDEF(BOOL, WINAPI, GetUserNameA,
	_Out_    LPSTR lpBuffer,
    _Inout_  LPDWORD lpnSize
) {
    BOOL ret = Old_GetUserNameA(lpBuffer, lpnSize);
    LOQ_bool("misc", "s", "Name", lpBuffer);
    return ret;
}

HOOKDEF(BOOL, WINAPI, GetUserNameW,
	_Out_    LPWSTR lpBuffer,
    _Inout_  LPDWORD lpnSize
) {
    BOOL ret = Old_GetUserNameW(lpBuffer, lpnSize);
    LOQ_bool("misc", "u", "Name", lpBuffer);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtLoadDriver,
	__in PUNICODE_STRING DriverServiceName
) {
	NTSTATUS ret = Old_NtLoadDriver(DriverServiceName);
	LOQ_ntstatus("misc", "o", "DriverServiceName", DriverServiceName);
	return ret;
}

static unsigned int asynckeystate_logcount;

HOOKDEF(SHORT, WINAPI, GetAsyncKeyState,
	__in int vKey
) {
	SHORT ret = Old_GetAsyncKeyState(vKey);
	if (asynckeystate_logcount < 50 && ((vKey >= 0x30 && vKey <= 0x39) || (vKey >= 0x41 && vKey <= 0x5a))) {
		asynckeystate_logcount++;
		LOQ_nonzero("windows", "i", "KeyCode", vKey);
	}
	else if (asynckeystate_logcount == 50) {
		asynckeystate_logcount++;
		LOQ_nonzero("windows", "is", "KeyCode", vKey, "Status", "Log limit reached");
	}
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, RtlDecompressBuffer,
	__in USHORT CompressionFormat,
	__out PUCHAR UncompressedBuffer,
	__in ULONG UncompressedBufferSize,
	__in PUCHAR CompressedBuffer,
	__in ULONG CompressedBufferSize,
	__out PULONG FinalUncompressedSize
) {
	NTSTATUS ret = Old_RtlDecompressBuffer(CompressionFormat, UncompressedBuffer, UncompressedBufferSize,
		CompressedBuffer, CompressedBufferSize, FinalUncompressedSize);

	LOQ_ntstatus("misc", "pbh", "UncompressedBufferAddress", UncompressedBuffer, "UncompressedBuffer", ret ? 0 : *FinalUncompressedSize, UncompressedBuffer, "UncompressedBufferLength", ret ? 0 : *FinalUncompressedSize);

	return ret;
}

HOOKDEF(void, WINAPI, GetSystemInfo,
	__out LPSYSTEM_INFO lpSystemInfo
) {
	int ret = 0;

	Old_GetSystemInfo(lpSystemInfo);

	if (!g_config.no_stealth && lpSystemInfo->dwNumberOfProcessors == 1)
		lpSystemInfo->dwNumberOfProcessors = 2;

	LOQ_void("misc", "");

	return;
}

HOOKDEF(NTSTATUS, WINAPI, NtQuerySystemInformation,
	_In_ ULONG SystemInformationClass,
	_Inout_ PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
) {
	NTSTATUS ret;
	char *buf;
	lasterror_t lasterror;
	ENSURE_ULONG(ReturnLength);

	if (SystemInformationClass != SystemProcessInformation || SystemInformation == NULL) {
normal_call:
		ret = Old_NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
		LOQ_ntstatus("misc", "i", "SystemInformationClass", SystemInformationClass);

		if (!g_config.no_stealth && SystemInformationClass == SystemBasicInformation && SystemInformationLength >= sizeof(SYSTEM_BASIC_INFORMATION) && NT_SUCCESS(ret)) {
			PSYSTEM_BASIC_INFORMATION p = (PSYSTEM_BASIC_INFORMATION)SystemInformation;
			p->NumberOfProcessors = 2;
		}
		return ret;
	}

	get_lasterrors(&lasterror);
	buf = calloc(1, SystemInformationLength);
	set_lasterrors(&lasterror);
	if (buf == NULL)
		goto normal_call;

	ret = Old_NtQuerySystemInformation(SystemInformationClass, buf, SystemInformationLength, ReturnLength);
	LOQ_ntstatus("misc", "i", "SystemInformationClass", SystemInformationClass);

	if (SystemInformationLength >= sizeof(SYSTEM_PROCESS_INFORMATION) && NT_SUCCESS(ret)) {
		PSYSTEM_PROCESS_INFORMATION our_p = (PSYSTEM_PROCESS_INFORMATION)buf;
		char *their_last_p = NULL;
		char *their_p = (char *)SystemInformation;
		ULONG lastlen = 0;
		while (1) {
			if (!is_protected_pid((DWORD)our_p->UniqueProcessId)) {
				PSYSTEM_PROCESS_INFORMATION tmp;
				if (our_p->NextEntryOffset)
					lastlen = our_p->NextEntryOffset;
				else
					lastlen = *ReturnLength - (ULONG)((char *)our_p - buf);
				// make sure we copy all data associated with the entry
				memcpy(their_p, our_p, lastlen);
				tmp = (PSYSTEM_PROCESS_INFORMATION)their_p;
				tmp->NextEntryOffset = lastlen;
				// adjust the only pointer field in the struct so that it points into the user's buffer,
				// but only if the pointer exists, otherwise we'd rewrite a NULL pointer to something not NULL
				if (tmp->ImageName.Buffer)
					tmp->ImageName.Buffer = (PWSTR)(((ULONG_PTR)tmp->ImageName.Buffer - (ULONG_PTR)our_p) + (ULONG_PTR)their_p);
				their_last_p = their_p;
				their_p += lastlen;
			}
			if (!our_p->NextEntryOffset)
				break;
			our_p = (PSYSTEM_PROCESS_INFORMATION)((PCHAR)our_p + our_p->NextEntryOffset);
		}
		if (their_last_p) {
			PSYSTEM_PROCESS_INFORMATION tmp;
			tmp = (PSYSTEM_PROCESS_INFORMATION)their_last_p;
			*ReturnLength = (ULONG)(their_last_p + tmp->NextEntryOffset - (char *)SystemInformation);
			tmp->NextEntryOffset = 0;
		}
	}

	free(buf);

	return ret;
}

static GUID _CLSID_DiskDrive = { 0x4d36e967, 0xe325, 0x11ce, 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 };
static GUID _CLSID_CDROM = { 0x4d36e965, 0xe325, 0x11ce, 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 };
static GUID _CLSID_Display = { 0x4d36e968, 0xe325, 0x11ce, 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 };
static GUID _CLSID_FDC = { 0x4d36e969, 0xe325, 0x11ce, 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 };
static GUID _CLSID_HDC = { 0x4d36e96a, 0xe325, 0x11ce, 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 };
static GUID _CLSID_FloppyDisk = { 0x4d36e980, 0xe325, 0x11ce, 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 };

static char *known_object(IID *cls)
{
	if (!memcmp(cls, &_CLSID_DiskDrive, sizeof(*cls)))
		return "DiskDrive";
	else if (!memcmp(cls, &_CLSID_CDROM, sizeof(*cls)))
		return "CDROM";
	else if (!memcmp(cls, &_CLSID_Display, sizeof(*cls)))
		return "Display";
	else if (!memcmp(cls, &_CLSID_FDC, sizeof(*cls)))
		return "FDC";
	else if (!memcmp(cls, &_CLSID_HDC, sizeof(*cls)))
		return "HDC";
	else if (!memcmp(cls, &_CLSID_FloppyDisk, sizeof(*cls)))
		return "FloppyDisk";

	return NULL;
}

HOOKDEF(HDEVINFO, WINAPI, SetupDiGetClassDevsA,
	_In_opt_ const GUID   *ClassGuid,
	_In_opt_       PCSTR Enumerator,
	_In_opt_       HWND   hwndParent,
	_In_           DWORD  Flags
) {
	IID id1;
	char idbuf[40];
	char *known;
	lasterror_t lasterror;
	HDEVINFO ret = Old_SetupDiGetClassDevsA(ClassGuid, Enumerator, hwndParent, Flags);

	get_lasterrors(&lasterror);

	if (ClassGuid) {
		memcpy(&id1, ClassGuid, sizeof(id1));
		sprintf(idbuf, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X", id1.Data1, id1.Data2, id1.Data3,
			id1.Data4[0], id1.Data4[1], id1.Data4[2], id1.Data4[3], id1.Data4[4], id1.Data4[5], id1.Data4[6], id1.Data4[7]);
		set_lasterrors(&lasterror);

		if ((known = known_object(&id1)))
			LOQ_handle("misc", "ss", "ClassGuid", idbuf, "Known", known);
		else
			LOQ_handle("misc", "s", "ClassGuid", idbuf);
	}
	return ret;
}

HOOKDEF(HDEVINFO, WINAPI, SetupDiGetClassDevsW,
	_In_opt_ const GUID   *ClassGuid,
	_In_opt_       PCWSTR Enumerator,
	_In_opt_       HWND   hwndParent,
	_In_           DWORD  Flags
) {
	IID id1;
	char idbuf[40];
	char *known;
	lasterror_t lasterror;
	HDEVINFO ret = Old_SetupDiGetClassDevsW(ClassGuid, Enumerator, hwndParent, Flags);
	if (ClassGuid) {
		memcpy(&id1, ClassGuid, sizeof(id1));
		sprintf(idbuf, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X", id1.Data1, id1.Data2, id1.Data3,
			id1.Data4[0], id1.Data4[1], id1.Data4[2], id1.Data4[3], id1.Data4[4], id1.Data4[5], id1.Data4[6], id1.Data4[7]);
		set_lasterrors(&lasterror);

		if ((known = known_object(&id1)))
			LOQ_handle("misc", "ss", "ClassGuid", idbuf, "Known", known);
		else
			LOQ_handle("misc", "s", "ClassGuid", idbuf);
	}
	return ret;
}

HOOKDEF(BOOL, WINAPI, SetupDiGetDeviceRegistryPropertyA,
	_In_      HDEVINFO         DeviceInfoSet,
	_In_      PSP_DEVINFO_DATA DeviceInfoData,
	_In_      DWORD            Property,
	_Out_opt_ PDWORD           PropertyRegDataType,
	_Out_opt_ PBYTE            PropertyBuffer,
	_In_      DWORD            PropertyBufferSize,
	_Out_opt_ PDWORD           RequiredSize
) {
	BOOL ret = Old_SetupDiGetDeviceRegistryPropertyA(DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize, RequiredSize);

	if (PropertyBuffer)
		LOQ_bool("misc", "ir", "Property", Property, "PropertyBuffer", PropertyRegDataType, PropertyBufferSize, PropertyBuffer);

	if (!g_config.no_stealth && ret && PropertyBuffer) {
		replace_ci_string_in_buf(PropertyBuffer, PropertyBufferSize, "VBOX", "DELL_");
		replace_ci_string_in_buf(PropertyBuffer, PropertyBufferSize, "QEMU", "DELL");
		replace_ci_string_in_buf(PropertyBuffer, PropertyBufferSize, "VMWARE", "DELL__");
	}

	return ret;
}


HOOKDEF(BOOL, WINAPI, SetupDiGetDeviceRegistryPropertyW,
	_In_      HDEVINFO         DeviceInfoSet,
	_In_      PSP_DEVINFO_DATA DeviceInfoData,
	_In_      DWORD            Property,
	_Out_opt_ PDWORD           PropertyRegDataType,
	_Out_opt_ PBYTE            PropertyBuffer,
	_In_      DWORD            PropertyBufferSize,
	_Out_opt_ PDWORD           RequiredSize
) {
	BOOL ret;
	ENSURE_DWORD(PropertyRegDataType);
	ret = Old_SetupDiGetDeviceRegistryPropertyW(DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize, RequiredSize);

	if (PropertyBuffer)
		LOQ_bool("misc", "iR", "Property", Property, "PropertyBuffer", PropertyRegDataType, PropertyBufferSize, PropertyBuffer);

	if (!g_config.no_stealth && ret && PropertyBuffer) {
		replace_ci_wstring_in_buf((PWCHAR)PropertyBuffer, PropertyBufferSize, L"VBOX", L"DELL_");
		replace_ci_wstring_in_buf((PWCHAR)PropertyBuffer, PropertyBufferSize, L"QEMU", L"DELL");
		replace_ci_wstring_in_buf((PWCHAR)PropertyBuffer, PropertyBufferSize, L"VMWARE", L"DELL__");
	}

	return ret;
}

HOOKDEF(HRESULT, WINAPI, DecodeImageEx,
	__in PVOID pStream, // IStream *
	__in PVOID pMap, // IMapMIMEToCLSID *
	__in PVOID pEventSink, // IUnknown *
	__in_opt LPCWSTR pszMIMETypeParam
) {
	HRESULT ret = Old_DecodeImageEx(pStream, pMap, pEventSink, pszMIMETypeParam);
	LOQ_hresult("misc", "");
	return ret;
}

HOOKDEF(HRESULT, WINAPI, DecodeImage,
	__in PVOID pStream, // IStream *
	__in PVOID pMap, // IMapMIMEToCLSID *
	__in PVOID pEventSink // IUnknown *
) {
	HRESULT ret = Old_DecodeImage(pStream, pMap, pEventSink);
	LOQ_hresult("misc", "");
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, LsaOpenPolicy,
	PLSA_UNICODE_STRING SystemName,
	PVOID ObjectAttributes,
	ACCESS_MASK DesiredAccess,
	PVOID PolicyHandle
) {
	NTSTATUS ret = Old_LsaOpenPolicy(SystemName, ObjectAttributes, DesiredAccess, PolicyHandle);
	LOQ_ntstatus("misc", "");
	return ret;
}

HOOKDEF(DWORD, WINAPI, WNetGetProviderNameW,
	__in DWORD dwNetType,
	__out LPWSTR lpProviderName,
	__inout LPDWORD lpBufferSize
) {
	DWORD ret;
	WCHAR *tmp = calloc(1, (*lpBufferSize + 1) * sizeof(wchar_t));

	if (tmp == NULL)
		return Old_WNetGetProviderNameW(dwNetType, lpProviderName, lpBufferSize);

	ret = Old_WNetGetProviderNameW(dwNetType, tmp, lpBufferSize);

	LOQ_zero("misc", "iu", "NetType", dwNetType, "ProviderName", ret == NO_ERROR ? tmp : L"");

	// WNNC_NET_RDR2SAMPLE, used for vbox detection
	if (!g_config.no_stealth && ret && dwNetType == 0x250000) {
		lasterror_t lasterrors;

		ret = ERROR_NO_NETWORK;
		lasterrors.Win32Error = ERROR_NO_NETWORK;
		lasterrors.NtstatusError = STATUS_ENTRYPOINT_NOT_FOUND;
	}
	else if (ret == NO_ERROR && lpProviderName) {
		wcscpy(lpProviderName, tmp);
	}

	free(tmp);

	return ret;
}
