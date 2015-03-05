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
#include <tlhelp32.h>
#include "hooking.h"
#include "log.h"
#include "pipe.h"
#include "misc.h"
#include "ignore.h"
#include "hook_sleep.h"
#include "unhook.h"

HOOKDEF(HANDLE, WINAPI, CreateToolhelp32Snapshot,
	__in DWORD dwFlags,
	__in DWORD th32ProcessID
) {
	HANDLE ret = Old_CreateToolhelp32Snapshot(dwFlags, th32ProcessID);

	LOQ_handle("process", "hi", "Flags", dwFlags, "ProcessId", th32ProcessID);

	return ret;
}

HOOKDEF(BOOL, WINAPI, Process32NextW,
	__in HANDLE hSnapshot,
	__out LPPROCESSENTRY32W lppe
	) {
	BOOL ret = Old_Process32NextW(hSnapshot, lppe);

	/* skip returning protected processes */
	while (ret && lppe && is_protected_pid(lppe->th32ProcessID))
		ret = Old_Process32NextW(hSnapshot, lppe);

	if (ret)
		LOQ_bool("process", "ui", "ProcessName", lppe->szExeFile, "ProcessId", lppe->th32ProcessID);
	else
		LOQ_bool("process", "");

	return ret;
}

HOOKDEF(BOOL, WINAPI, Process32FirstW,
	__in HANDLE hSnapshot,
	__out LPPROCESSENTRY32W lppe
	) {
	BOOL ret = Old_Process32FirstW(hSnapshot, lppe);

	/* skip returning protected processes */
	while (ret && lppe && is_protected_pid(lppe->th32ProcessID))
		ret = Old_Process32NextW(hSnapshot, lppe);

	if (ret)
		LOQ_bool("process", "ui", "ProcessName", lppe->szExeFile, "ProcessId", lppe->th32ProcessID);
	else
		LOQ_bool("process", "");

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtCreateProcess,
    __out       PHANDLE ProcessHandle,
    __in        ACCESS_MASK DesiredAccess,
    __in_opt    POBJECT_ATTRIBUTES ObjectAttributes,
    __in        HANDLE ParentProcess,
    __in        BOOLEAN InheritObjectTable,
    __in_opt    HANDLE SectionHandle,
    __in_opt    HANDLE DebugPort,
    __in_opt    HANDLE ExceptionPort
) {
    NTSTATUS ret = Old_NtCreateProcess(ProcessHandle, DesiredAccess,
        ObjectAttributes, ParentProcess, InheritObjectTable, SectionHandle,
        DebugPort, ExceptionPort);
    LOQ_ntstatus("process", "PphO", "ProcessHandle", ProcessHandle, "ParentHandle", ParentProcess, "DesiredAccess", DesiredAccess,
        "FileName", ObjectAttributes);
    if(NT_SUCCESS(ret)) {
		DWORD pid = pid_from_process_handle(*ProcessHandle);
        pipe("PROCESS:%d:%d", is_suspended(pid, 0), pid);
        disable_sleep_skip();
    }
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtCreateProcessEx,
    __out       PHANDLE ProcessHandle,
    __in        ACCESS_MASK DesiredAccess,
    __in_opt    POBJECT_ATTRIBUTES ObjectAttributes,
    __in        HANDLE ParentProcess,
    __in        ULONG Flags,
    __in_opt    HANDLE SectionHandle,
    __in_opt    HANDLE DebugPort,
    __in_opt    HANDLE ExceptionPort,
    __in        BOOLEAN InJob
) {
    NTSTATUS ret = Old_NtCreateProcessEx(ProcessHandle, DesiredAccess,
        ObjectAttributes, ParentProcess, Flags, SectionHandle, DebugPort,
        ExceptionPort, InJob);
	LOQ_ntstatus("process", "PphO", "ProcessHandle", ProcessHandle, "ParentHandle", ParentProcess, "DesiredAccess", DesiredAccess,
        "FileName", ObjectAttributes);
    if(NT_SUCCESS(ret)) {
		DWORD pid = pid_from_process_handle(*ProcessHandle);
        pipe("PROCESS:%d:%d", is_suspended(pid, 0), pid);
        disable_sleep_skip();
    }
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtCreateUserProcess,
    __out       PHANDLE ProcessHandle,
    __out       PHANDLE ThreadHandle,
    __in        ACCESS_MASK ProcessDesiredAccess,
    __in        ACCESS_MASK ThreadDesiredAccess,
    __in_opt    POBJECT_ATTRIBUTES ProcessObjectAttributes,
    __in_opt    POBJECT_ATTRIBUTES ThreadObjectAttributes,
    __in        ULONG ProcessFlags,
    __in        ULONG ThreadFlags,
    __in_opt    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    __inout     PPS_CREATE_INFO CreateInfo,
    __in_opt    PPS_ATTRIBUTE_LIST AttributeList
) {
    RTL_USER_PROCESS_PARAMETERS _ProcessParameters;
	NTSTATUS ret;

	memset(&_ProcessParameters, 0, sizeof(_ProcessParameters));

	if(ProcessParameters == NULL)
		ProcessParameters = &_ProcessParameters;

    ret = Old_NtCreateUserProcess(ProcessHandle, ThreadHandle,
        ProcessDesiredAccess, ThreadDesiredAccess,
        ProcessObjectAttributes, ThreadObjectAttributes,
        ProcessFlags, ThreadFlags, ProcessParameters,
        CreateInfo, AttributeList);
    LOQ_ntstatus("process", "PPhhOOoo", "ProcessHandle", ProcessHandle,
        "ThreadHandle", ThreadHandle,
        "ProcessDesiredAccess", ProcessDesiredAccess,
        "ThreadDesiredAccess", ThreadDesiredAccess,
        "ProcessFileName", ProcessObjectAttributes,
        "ThreadName", ThreadObjectAttributes,
        "ImagePathName", &ProcessParameters->ImagePathName,
        "CommandLine", &ProcessParameters->CommandLine);
    if(NT_SUCCESS(ret)) {
		DWORD pid = pid_from_process_handle(*ProcessHandle);
		DWORD tid = tid_from_thread_handle(*ThreadHandle);
		pipe("PROCESS:%d:%d,%d", is_suspended(pid, tid), pid, tid);
        disable_sleep_skip();
    }
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, RtlCreateUserProcess,
    IN      PUNICODE_STRING ImagePath,
    IN      ULONG ObjectAttributes,
    IN OUT  PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    IN      PSECURITY_DESCRIPTOR ProcessSecurityDescriptor OPTIONAL,
    IN      PSECURITY_DESCRIPTOR ThreadSecurityDescriptor OPTIONAL,
    IN      HANDLE ParentProcess,
    IN      BOOLEAN InheritHandles,
    IN      HANDLE DebugPort OPTIONAL,
    IN      HANDLE ExceptionPort OPTIONAL,
    OUT     PRTL_USER_PROCESS_INFORMATION ProcessInformation
) {
    NTSTATUS ret = Old_RtlCreateUserProcess(ImagePath, ObjectAttributes,
        ProcessParameters, ProcessSecurityDescriptor,
        ThreadSecurityDescriptor, ParentProcess, InheritHandles, DebugPort,
        ExceptionPort, ProcessInformation);
    LOQ_ntstatus("process", "ohp", "ImagePath", ImagePath, "ObjectAttributes", ObjectAttributes,
        "ParentHandle", ParentProcess);
    if(NT_SUCCESS(ret)) {
		DWORD pid = pid_from_process_handle(ProcessInformation->ProcessHandle);
		DWORD tid = tid_from_thread_handle(ProcessInformation->ThreadHandle);
		pipe("PROCESS:%d:%d,%d", is_suspended(pid, tid), pid, tid);
        disable_sleep_skip();
    }
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtOpenProcess,
    __out     PHANDLE ProcessHandle,
    __in      ACCESS_MASK DesiredAccess,
    __in      POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt  PCLIENT_ID ClientId
) {
    // although the documentation on msdn is a bit vague, this seems correct
    // for both XP and Vista (the ClientId->UniqueProcess part, that is)

    int pid = 0;
	NTSTATUS ret;

    if(ClientId != NULL) {
        pid = (int) ClientId->UniqueProcess;
    }

    if(is_protected_pid(pid)) {
        ret = STATUS_ACCESS_DENIED;
        LOQ_ntstatus("process", "ppl", "ProcessHandle", NULL, "DesiredAccess", DesiredAccess,
            "ProcessIdentifier", pid);
        return ret;
    }

    ret = Old_NtOpenProcess(ProcessHandle, DesiredAccess,
        ObjectAttributes, ClientId);
    LOQ_ntstatus("process", "Phi", "ProcessHandle", ProcessHandle,
        "DesiredAccess", DesiredAccess,
        "ProcessIdentifier", pid);

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtResumeProcess,
	__in  HANDLE ProcessHandle
) {
	NTSTATUS ret;
	DWORD pid = pid_from_process_handle(ProcessHandle);
	pipe("RESUME:%d", pid);

	ret = Old_NtResumeProcess(ProcessHandle);
	LOQ_ntstatus("process", "p", "ProcessHandle", ProcessHandle);
	return ret;
}


int process_shutting_down;

HOOKDEF(NTSTATUS, WINAPI, NtTerminateProcess,
    __in_opt  HANDLE ProcessHandle,
    __in      NTSTATUS ExitStatus
) {
	// Process will terminate. Default logging will not work. Be aware: return value not valid
    NTSTATUS ret = 0;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);
    LOQ_ntstatus("process", "ph", "ProcessHandle", ProcessHandle, "ExitCode", ExitStatus);
	if (ProcessHandle == NULL || GetCurrentProcessId() == GetProcessId(ProcessHandle)) {
		pipe("KILL:%d", GetCurrentProcessId());
		log_free();
		process_shutting_down = 1;
	}
	else {
		DWORD PID = pid_from_process_handle(ProcessHandle);
		if (is_protected_pid(PID)) {
			ret = STATUS_ACCESS_DENIED;
			LOQ_ntstatus("process", "ph", "ProcessHandle", ProcessHandle, "ExitCode", ExitStatus);
			return ret;
		}
		pipe("KILL:%d", PID);
	}
	set_lasterrors(&lasterror);

	ret = Old_NtTerminateProcess(ProcessHandle, ExitStatus);
    return ret;
}

extern void file_write(HANDLE file_handle);

HOOKDEF(NTSTATUS, WINAPI, NtCreateSection,
    __out     PHANDLE SectionHandle,
    __in      ACCESS_MASK DesiredAccess,
    __in_opt  POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt  PLARGE_INTEGER MaximumSize,
    __in      ULONG SectionPageProtection,
    __in      ULONG AllocationAttributes,
    __in_opt  HANDLE FileHandle
) {
    NTSTATUS ret = Old_NtCreateSection(SectionHandle, DesiredAccess,
        ObjectAttributes, MaximumSize, SectionPageProtection,
        AllocationAttributes, FileHandle);
    LOQ_ntstatus("process", "Phop", "SectionHandle", SectionHandle,
        "DesiredAccess", DesiredAccess, "ObjectAttributes", ObjectAttributes ? ObjectAttributes->ObjectName : NULL,
        "FileHandle", FileHandle);

	if (NT_SUCCESS(ret) && FileHandle && (DesiredAccess & SECTION_MAP_WRITE)) {
		file_write(FileHandle);
	}

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtOpenSection,
    __out  PHANDLE SectionHandle,
    __in   ACCESS_MASK DesiredAccess,
    __in   POBJECT_ATTRIBUTES ObjectAttributes
) {
    NTSTATUS ret = Old_NtOpenSection(SectionHandle, DesiredAccess,
        ObjectAttributes);
    LOQ_ntstatus("process", "Ppo", "SectionHandle", SectionHandle, "DesiredAccess", DesiredAccess,
        "ObjectAttributes", ObjectAttributes ? ObjectAttributes->ObjectName : NULL);
    return ret;
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
        bInheritHandles, dwCreationFlags, lpEnvironment,
        lpCurrentDirectory, lpStartupInfo, lpProcessInformation, lpUnknown2);
    LOQ_bool("process", "uuhiipp", "ApplicationName", lpApplicationName,
        "CommandLine", lpCommandLine, "CreationFlags", dwCreationFlags,
        "ProcessId", lpProcessInformation->dwProcessId,
        "ThreadId", lpProcessInformation->dwThreadId,
        "ProcessHandle", lpProcessInformation->hProcess,
        "ThreadHandle", lpProcessInformation->hThread);
    return ret;
}

HOOKDEF(BOOL, WINAPI, ShellExecuteExW,
    __inout  SHELLEXECUTEINFOW *pExecInfo
) {
    BOOL ret = Old_ShellExecuteExW(pExecInfo);
	if (pExecInfo->lpFile && lstrlenW(pExecInfo->lpFile) > 2 &&
		pExecInfo->lpFile[1] == L':' && pExecInfo->lpFile[2] == L'\\') {
		LOQ_bool("process", "Fui", "FilePath", pExecInfo->lpFile,
			"Parameters", pExecInfo->lpParameters, "Show", pExecInfo->nShow);
	} else {
		LOQ_bool("process", "uui", "FilePath", pExecInfo->lpFile,
			"Parameters", pExecInfo->lpParameters, "Show", pExecInfo->nShow);
	}

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtUnmapViewOfSection,
    _In_      HANDLE ProcessHandle,
    _In_opt_  PVOID BaseAddress
) {
    SIZE_T map_size = 0; MEMORY_BASIC_INFORMATION mbi;
	DWORD pid = pid_from_process_handle(ProcessHandle);
	DWORD protect = PAGE_READWRITE;
	NTSTATUS ret;

	if (VirtualQueryEx(ProcessHandle, BaseAddress, &mbi,
            sizeof(mbi)) == sizeof(mbi)) {
        map_size = mbi.RegionSize;
		protect = mbi.Protect;
    }
    ret = Old_NtUnmapViewOfSection(ProcessHandle, BaseAddress);
	
	if (pid != GetCurrentProcessId() || protect != PAGE_READWRITE) {
		LOQ_ntstatus("process", "ppp", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
			"RegionSize", map_size);
	}

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtMapViewOfSection,
	_In_     HANDLE SectionHandle,
	_In_     HANDLE ProcessHandle,
	__inout  PVOID *BaseAddress,
	_In_     ULONG_PTR ZeroBits,
	_In_     SIZE_T CommitSize,
	__inout  PLARGE_INTEGER SectionOffset,
	__inout  PSIZE_T ViewSize,
	__in     UINT InheritDisposition,
	__in     ULONG AllocationType,
	__in     ULONG Win32Protect
	) {
	NTSTATUS ret = Old_NtMapViewOfSection(SectionHandle, ProcessHandle,
		BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize,
		InheritDisposition, AllocationType, Win32Protect);
	DWORD pid = pid_from_process_handle(ProcessHandle);

	if ((pid != GetCurrentProcessId()) || Win32Protect != PAGE_READWRITE)
		LOQ_ntstatus("process", "ppPpPh", "SectionHandle", SectionHandle,
		"ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
		"SectionOffset", SectionOffset, "ViewSize", ViewSize, "Win32Protect", Win32Protect);

	if (NT_SUCCESS(ret)) {
		if (pid != GetCurrentProcessId()) {
			pipe("PROCESS:%d:%d", is_suspended(pid, 0), pid);
			disable_sleep_skip();
		}
	}
	return ret;
}

// it's not safe to call pipe() in this hook until we replace all uses of snprintf in pipe()
HOOKDEF(NTSTATUS, WINAPI, NtAllocateVirtualMemory,
    __in     HANDLE ProcessHandle,
    __inout  PVOID *BaseAddress,
    __in     ULONG_PTR ZeroBits,
    __inout  PSIZE_T RegionSize,
    __in     ULONG AllocationType,
    __in     ULONG Protect
) {
	lasterror_t lasterror;
    NTSTATUS ret = Old_NtAllocateVirtualMemory(ProcessHandle, BaseAddress,
        ZeroBits, RegionSize, AllocationType, Protect);

	get_lasterrors(&lasterror);
	if (Protect != PAGE_READWRITE || GetCurrentProcessId() != GetProcessId(ProcessHandle)) {
		LOQ_ntstatus("process", "pPPh", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
			"RegionSize", RegionSize, "Protection", Protect);
	}
	set_lasterrors(&lasterror);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtReadVirtualMemory,
    __in        HANDLE ProcessHandle,
    __in        LPCVOID BaseAddress,
    __out       LPVOID Buffer,
    __in        ULONG NumberOfBytesToRead,
    __out_opt   PULONG NumberOfBytesReaded
) {
	NTSTATUS ret;
    ENSURE_ULONG(NumberOfBytesReaded);

    ret = Old_NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer,
        NumberOfBytesToRead, NumberOfBytesReaded);

	if (pid_from_process_handle(ProcessHandle) != GetCurrentProcessId()) {
		LOQ_ntstatus("process", "ppB", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
			"Buffer", NumberOfBytesReaded, Buffer);
	}

	return ret;
}

HOOKDEF(BOOL, WINAPI, ReadProcessMemory,
    _In_    HANDLE hProcess,
    _In_    LPCVOID lpBaseAddress,
    _Out_   LPVOID lpBuffer,
    _In_    SIZE_T nSize,
    _Out_   SIZE_T *lpNumberOfBytesRead
) {
	BOOL ret;
    ENSURE_SIZET(lpNumberOfBytesRead);

    ret = Old_ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer,
        nSize, lpNumberOfBytesRead);

	if (pid_from_process_handle(hProcess) != GetCurrentProcessId()) {
		LOQ_bool("process", "ppB", "ProcessHandle", hProcess, "BaseAddress", lpBaseAddress,
			"Buffer", lpNumberOfBytesRead, lpBuffer);
	}

    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtWriteVirtualMemory,
    __in        HANDLE ProcessHandle,
    __in        LPVOID BaseAddress,
    __in        LPCVOID Buffer,
    __in        ULONG NumberOfBytesToWrite,
    __out_opt   ULONG *NumberOfBytesWritten
) {
	NTSTATUS ret;
	DWORD pid;
    ENSURE_ULONG(NumberOfBytesWritten);

    ret = Old_NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer,
        NumberOfBytesToWrite, NumberOfBytesWritten);

	pid = pid_from_process_handle(ProcessHandle);

	if (pid != GetCurrentProcessId()) {
		LOQ_ntstatus("process", "ppB", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
			"Buffer", NumberOfBytesWritten, Buffer);

		if (NT_SUCCESS(ret)) {
			pipe("PROCESS:%d:%d", is_suspended(pid, 0), pid);
			disable_sleep_skip();
		}
	}


	return ret;
}

HOOKDEF(BOOL, WINAPI, WriteProcessMemory,
    _In_    HANDLE hProcess,
    _In_    LPVOID lpBaseAddress,
    _In_    LPCVOID lpBuffer,
    _In_    SIZE_T nSize,
    _Out_   SIZE_T *lpNumberOfBytesWritten
) {
	BOOL ret;
	DWORD pid;
    ENSURE_SIZET(lpNumberOfBytesWritten);

    ret = Old_WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer,
        nSize, lpNumberOfBytesWritten);

	pid = pid_from_process_handle(hProcess);

	if (pid != GetCurrentProcessId()) {
		LOQ_bool("process", "ppB", "ProcessHandle", hProcess, "BaseAddress", lpBaseAddress,
			"Buffer", lpNumberOfBytesWritten, lpBuffer);

		if (ret) {
			pipe("PROCESS:%d:%d", is_suspended(pid, 0), pid);
			disable_sleep_skip();
		}
	}

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtProtectVirtualMemory,
    IN      HANDLE ProcessHandle,
    IN OUT  PVOID *BaseAddress,
    IN OUT  PULONG NumberOfBytesToProtect,
    IN      ULONG NewAccessProtection,
    OUT     PULONG OldAccessProtection
) {
	NTSTATUS ret;

	if (NewAccessProtection == PAGE_EXECUTE_READ && BaseAddress && NumberOfBytesToProtect &&
		GetCurrentProcessId() == GetProcessId(ProcessHandle) && is_in_dll_range((ULONG_PTR)*BaseAddress))
		restore_hooks_on_range((ULONG_PTR)*BaseAddress, (ULONG_PTR)*BaseAddress + *NumberOfBytesToProtect);
	
	ret = Old_NtProtectVirtualMemory(ProcessHandle, BaseAddress,
        NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
    LOQ_ntstatus("process", "pPHhH", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
        "NumberOfBytesProtected", NumberOfBytesToProtect,
        "NewAccessProtection", NewAccessProtection,
        "OldAccessProtection", OldAccessProtection);
    return ret;
}

HOOKDEF(BOOL, WINAPI, VirtualProtectEx,
    __in   HANDLE hProcess,
    __in   LPVOID lpAddress,
    __in   SIZE_T dwSize,
    __in   DWORD flNewProtect,
    __out  PDWORD lpflOldProtect
) {
	BOOL ret;

	if (flNewProtect == PAGE_EXECUTE_READ && GetCurrentProcessId() == GetProcessId(hProcess) &&
		is_in_dll_range((ULONG_PTR)lpAddress))
		restore_hooks_on_range((ULONG_PTR)lpAddress, (ULONG_PTR)lpAddress + dwSize);

	ret = Old_VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect,
        lpflOldProtect);
    LOQ_bool("process", "ppph", "ProcessHandle", hProcess, "Address", lpAddress,
        "Size", dwSize, "Protection", flNewProtect);
    return ret;
}

// it's not safe to call pipe() in this hook until we replace all uses of snprintf in pipe()
HOOKDEF(NTSTATUS, WINAPI, NtFreeVirtualMemory,
    IN      HANDLE ProcessHandle,
    IN      PVOID *BaseAddress,
    IN OUT  PSIZE_T RegionSize,
    IN      ULONG FreeType
) {
	lasterror_t lasterror;
    NTSTATUS ret = Old_NtFreeVirtualMemory(ProcessHandle, BaseAddress,
        RegionSize, FreeType);

	get_lasterrors(&lasterror);
	if (GetCurrentProcessId() != GetProcessId(ProcessHandle)) {
		LOQ_ntstatus("process", "pPPh", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
			"RegionSize", RegionSize, "FreeType", FreeType);
	}
	set_lasterrors(&lasterror);
    return ret;
}

HOOKDEF(BOOL, WINAPI, VirtualFreeEx,
    __in  HANDLE hProcess,
    __in  LPVOID lpAddress,
    __in  SIZE_T dwSize,
    __in  DWORD dwFreeType
) {
    BOOL ret = Old_VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType);
    LOQ_bool("process", "ppph", "ProcessHandle", hProcess, "Address", lpAddress,
        "Size", dwSize, "FreeType", dwFreeType);
    return ret;
}

HOOKDEF(int, CDECL, system,
    const char *command
) {
    int ret = Old_system(command);
    LOQ_nonnegone("process", "s", "Command", command);
    return ret;
}

HOOKDEF(BOOL, WINAPI, WaitForDebugEvent,
	__out LPDEBUG_EVENT lpDebugEvent,
	__in DWORD dwMilliseconds
) {
	BOOL ret = Old_WaitForDebugEvent(lpDebugEvent, dwMilliseconds);

	if (!ret)
		return ret;

	switch (lpDebugEvent->dwDebugEventCode) {
	case CREATE_THREAD_DEBUG_EVENT:
		LOQ_bool("process", "iiip", "EventCode", lpDebugEvent->dwDebugEventCode, "ProcessId", lpDebugEvent->dwProcessId, "ThreadId", lpDebugEvent->dwThreadId, "StartAddress", lpDebugEvent->u.CreateThread.lpStartAddress);
		break;
	case LOAD_DLL_DEBUG_EVENT:
		// we could continue ourselves here and skip notification to the malware of cuckoomon loading
		if (lpDebugEvent->u.LoadDll.fUnicode)
			LOQ_bool("process", "iiiu", "EventCode", lpDebugEvent->dwDebugEventCode, "ProcessId", lpDebugEvent->dwProcessId, "ThreadId", lpDebugEvent->dwThreadId, "DllPath", lpDebugEvent->u.LoadDll.lpImageName);
		else
			LOQ_bool("process", "iiis", "EventCode", lpDebugEvent->dwDebugEventCode, "ProcessId", lpDebugEvent->dwProcessId, "ThreadId", lpDebugEvent->dwThreadId, "DllPath", lpDebugEvent->u.LoadDll.lpImageName);
		break;
	default:
		LOQ_bool("process", "iii", "EventCode", lpDebugEvent->dwDebugEventCode, "ProcessId", lpDebugEvent->dwProcessId, "ThreadId", lpDebugEvent->dwThreadId);
	}

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, DbgUiWaitStateChange,
	__out PDBGUI_WAIT_STATE_CHANGE StateChange,
	__in_opt PLARGE_INTEGER Timeout)
{
	NTSTATUS ret = Old_DbgUiWaitStateChange(StateChange, Timeout);

	if (NT_SUCCESS(ret)) {
		switch (StateChange->NewState) {
		case DbgCreateThreadStateChange:
			LOQ_ntstatus("process", "iiip", "NewState", StateChange->NewState, "ProcessId", pid_from_process_handle(StateChange->AppClientId.UniqueProcess), "ThreadId", tid_from_thread_handle(StateChange->AppClientId.UniqueThread), "StartAddress", StateChange->StateInfo.CreateThread.NewThread.StartAddress);
			break;
		case DbgLoadDllStateChange:
			{
				wchar_t *fname = calloc(32768, sizeof(wchar_t));

				path_from_handle(StateChange->StateInfo.LoadDll.FileHandle, fname, 32768);
				// we could continue ourselves here and skip notification to the malware of cuckoomon loading
				LOQ_ntstatus("process", "iiiF", "NewState", StateChange->NewState, "ProcessId", pid_from_process_handle(StateChange->AppClientId.UniqueProcess), "ThreadId", tid_from_thread_handle(StateChange->AppClientId.UniqueThread), "DllPath", fname);
				free(fname);
			}
			break;
		default:
			LOQ_ntstatus("process", "iii", "NewState", StateChange->NewState, "ProcessId", pid_from_process_handle(StateChange->AppClientId.UniqueProcess), "ThreadId", tid_from_thread_handle(StateChange->AppClientId.UniqueThread));
		}
	}

	return ret;
}

HOOKDEF(BOOLEAN, WINAPI, RtlDispatchException,
	__in PEXCEPTION_RECORD ExceptionRecord,
	__in PCONTEXT Context)
{
	// flush logs prior to handling of an exception without having to register a vectored exception handler
	log_flush();

	return Old_RtlDispatchException(ExceptionRecord, Context);
}