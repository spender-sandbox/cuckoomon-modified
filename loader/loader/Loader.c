#include <Windows.h>

enum {
	INJECT_CREATEREMOTETHREAD,
	INJECT_QUEUEUSERAPC
};

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

static int inject(int pid, int tid, const char *dllpath, unsigned int injectmode)
{
	HANDLE prochandle = NULL;
	HANDLE threadhandle = NULL;
	LPVOID dllpathbuf;
	LPVOID loadlibraryaddr;
	SIZE_T byteswritten = 0;
	int ret = -1;

	if (pid <= 0 || tid < 0)
		goto out;

	if (injectmode == INJECT_QUEUEUSERAPC && tid == 0)
		goto out;

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
		else
			goto out;
	}
	else
		goto out;

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
		unsigned int injectmode;
		if (__argc != 6)
			return -1;
		if (!strcmp(__argv[5], "createremotethread"))
			injectmode = INJECT_CREATEREMOTETHREAD;
		else if (!strcmp(__argv[5], "queueuserapc"))
			injectmode = INJECT_QUEUEUSERAPC;
		else
			return -1;
		return inject(atoi(__argv[2]), atoi(__argv[3]), __argv[4], injectmode);
	}

	return -1;
}