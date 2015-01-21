// Copyright 2014-2015 Accuvant, Inc. (bspengler@accuvant.com)
// This file is published under the GNU GPL v3
// http://www.gnu.org/licenses/gpl.html

#include "Loader.h"

static int grant_debug_privileges(void)
{
	HANDLE token = NULL;
	TOKEN_PRIVILEGES priv;
	LUID privval;
	int ret;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token))
		return 0;

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &privval)) {
		CloseHandle(token);
		return 0;
	}
	priv.PrivilegeCount = 1;
	priv.Privileges[0].Luid = privval;
	priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	ret = AdjustTokenPrivileges(token, FALSE, &priv, sizeof(priv), NULL, NULL);
	CloseHandle(token);

	return ret;
}

static BOOLEAN is_suspended(int pid, int tid)
{
	ULONG length;
	PSYSTEM_PROCESS_INFORMATION pspi, proc;
	ULONG requestedlen = 16384;
	_NtQuerySystemInformation pNtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");

	pspi = malloc(requestedlen);
	if (pspi == NULL)
		return FALSE;

	while (pNtQuerySystemInformation(SystemProcessInformation, pspi, requestedlen, &length) == STATUS_INFO_LENGTH_MISMATCH) {
		free(pspi);
		requestedlen <<= 1;
		pspi = malloc(requestedlen);
		if (pspi == NULL)
			return FALSE;
	}
	// now we have a valid list of process information
	for (proc = pspi; proc->NextEntryOffset; proc = (PSYSTEM_PROCESS_INFORMATION)((PCHAR)proc + proc->NextEntryOffset)) {
		ULONG i;
		if (proc->UniqueProcessId != (HANDLE)pid)
			continue;
		for (i = 0; i < proc->NumberOfThreads; i++) {
			PSYSTEM_THREAD thread = &proc->Threads[i];
			if (tid && thread->ClientId.UniqueThread != (HANDLE)tid)
				continue;
			if (thread->WaitReason != Suspended)
				return FALSE;
		}
	}
	free(pspi);

	return TRUE;
}

// returns -1 if injection failed, 0 if injection succeeded and process is alive, and 1 if we injected but the process is suspended, so we shouldn't wait for it
static int inject(int pid, int tid, const char *dllpath, BOOLEAN suspended)
{
	unsigned int injectmode = INJECT_QUEUEUSERAPC;
	HANDLE prochandle = NULL;
	HANDLE threadhandle = NULL;
	LPVOID dllpathbuf;
	LPVOID loadlibraryaddr;
	SIZE_T byteswritten = 0;
	int ret = -1;

	if (pid <= 0 || tid < 0 || (tid == 0 && suspended))
		goto out;

	if (tid == 0)
		injectmode = INJECT_CREATEREMOTETHREAD;

	prochandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (prochandle == NULL)
		goto out;

	if (tid > 0) {
		threadhandle = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
		if (threadhandle == NULL)
			goto out;
	}

	dllpathbuf = VirtualAllocEx(prochandle, NULL, strlen(dllpath) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (dllpathbuf == NULL)
		goto out;

	if (!WriteProcessMemory(prochandle, dllpathbuf, dllpath, strlen(dllpath) + 1, &byteswritten))
		goto out;

	loadlibraryaddr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

	if (injectmode == INJECT_QUEUEUSERAPC) {
		if (!QueueUserAPC(loadlibraryaddr, threadhandle, (ULONG_PTR)dllpathbuf))
			goto out;
	}
	else if (injectmode == INJECT_CREATEREMOTETHREAD) {
		DWORD threadid;
		HANDLE newhandle;
		newhandle = CreateRemoteThread(prochandle, NULL, 0, loadlibraryaddr, dllpathbuf, 0, &threadid);
		if (newhandle)
			CloseHandle(newhandle);
		else {
			if (GetLastError() == ERROR_NOT_ENOUGH_MEMORY) {
				/* Bypass Vista+ userland session restrictions on thread injection */
				PVOID pCsrClientCallServer = (PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "CsrClientCallServer");
				DWORD oldprot;
				unsigned char origbuf[16];
				// we hardcode the offsets obtained from reversing because all the definitions of 
				// PORT_MESSAGE/CSRSS_MESSAGE/etc available online are incorrect for x64, assuming ULONG size of various fields 
				// due to copy+pasting from Gary Nebbet's Windows 2000 Native API Reference book

#ifdef _WIN64
				const unsigned char payload[] = { 0x33, 0xc0, 0x89, 0x41, 0x34, 0xc3 }; // xor eax, eax / mov dword ptr [rcx+<offset of status>], eax / ret
#else
				const unsigned char payload[] = { 0x33, 0xc0, 0x8b, 0x4c, 0x24, 0x04, 0x89, 0x41, 0x20, 0xc2, 0x10, 0x00 }; // xor eax, eax, / mov ecx, [esp+4] / mov [ecx+<offset of status>], eax / retn 0x10
#endif
				VirtualProtect(pCsrClientCallServer, sizeof(payload), PAGE_EXECUTE_READWRITE, &oldprot);

				memcpy(origbuf, pCsrClientCallServer, sizeof(payload));
				memcpy(pCsrClientCallServer, payload, sizeof(payload));

				newhandle = CreateRemoteThread(prochandle, NULL, 0, loadlibraryaddr, dllpathbuf, 0, &threadid);

				memcpy(pCsrClientCallServer, origbuf, sizeof(payload));

				if (newhandle)
					CloseHandle(newhandle);

				VirtualProtect(pCsrClientCallServer, sizeof(payload), oldprot, &oldprot);
				if (newhandle)
					goto success;
			}
			goto out;
		}
	}
	else
		goto out;

success:
	if (suspended)
		ret = 1;
	else
		ret = 0;
out:
	if (prochandle)
		CloseHandle(prochandle);
	if (threadhandle)
		CloseHandle(threadhandle);
	return ret;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	if (__argc < 2)
		return -1;
	
	if (!grant_debug_privileges())
		return -1;

	if (!strcmp(__argv[1], "inject")) {
		int pid, tid;
		if (__argc != 5)
			return -1;
		pid = atoi(__argv[2]);
		tid = atoi(__argv[3]);
		return inject(pid, tid, __argv[4], is_suspended(pid, tid));
	}

	return -1;
}