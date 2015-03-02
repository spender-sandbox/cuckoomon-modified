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
#include "pipe.h"
#include "log.h"
#include "misc.h"
#include "config.h"
#include <Sddl.h>

#define UNHOOK_MAXCOUNT 2048
#define UNHOOK_BUFSIZE 256

static HANDLE g_unhook_thread_handle, g_watcher_thread_handle;

// Index for adding new hooks and iterating all existing hooks.
static uint32_t g_index = 0;

// Length of this region.
static uint32_t g_length[UNHOOK_MAXCOUNT];

// Address of the region.
static uint8_t *g_addr[UNHOOK_MAXCOUNT];

// Function name of the region.
static char g_funcname[UNHOOK_MAXCOUNT][64];

// The original contents of this region, before we modified it.
static uint8_t g_orig[UNHOOK_MAXCOUNT][UNHOOK_BUFSIZE];

// The contents of this region after we modified it.
static uint8_t g_our[UNHOOK_BUFSIZE][UNHOOK_BUFSIZE];

// If the region has been modified, did we report this already?
static uint8_t g_hook_reported[UNHOOK_MAXCOUNT];

void unhook_detect_add_region(const char *funcname, uint8_t *addr,
    const uint8_t *orig, const uint8_t *our, uint32_t length)
{
    if(g_index == UNHOOK_MAXCOUNT) {
        pipe("CRITICAL:Reached maximum number of unhook detection entries!");
        return;
    }

    g_length[g_index] = length;
    g_addr[g_index] = addr;

    if(funcname != NULL) {
        strcpy(g_funcname[g_index], funcname);
    }

    memcpy(g_orig[g_index], orig, MIN(length, UNHOOK_BUFSIZE));
    memcpy(g_our[g_index], our, MIN(length, UNHOOK_BUFSIZE));
    g_index++;
}

void restore_hooks_on_range(ULONG_PTR start, ULONG_PTR end)
{
	lasterror_t lasterror;
	uint32_t idx;

	get_lasterrors(&lasterror);

	__try {
		for (idx = 0; idx < g_index; idx++) {
			if ((ULONG_PTR)g_addr[idx] < start || ((ULONG_PTR)g_addr[idx] + g_length[idx]) > end)
				continue;
			if (!memcmp(g_orig[idx], g_addr[idx], g_length[idx])) {
				memcpy(g_addr[idx], g_our[idx], g_length[idx]);
				log_hook_restoration(g_funcname[idx]);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		;
	}

	set_lasterrors(&lasterror);
}


static DWORD WINAPI _unhook_detect_thread(LPVOID param)
{
    static int watcher_first = 1;
	uint32_t idx;

    hook_disable();

    while (1) {
        if(WaitForSingleObject(g_watcher_thread_handle,
                500) != WAIT_TIMEOUT) {
            if(watcher_first != 0) {
                if(is_shutting_down() == 0) {
                    log_anomaly("unhook", 1, NULL,
                        "Unhook watcher thread has been corrupted!");
                }
                watcher_first = 0;
            }
            raw_sleep(100);
        }

		for (idx = 0; idx < g_index; idx++) {
			if (g_hook_reported[idx] == 0) {
				char *tmpbuf = NULL;
				if (!is_valid_address_range((ULONG_PTR)g_addr[idx], g_length[idx])) {
					continue;
				}
				__try {
					int is_modification = 1;
					// Check whether this memory region still equals what we made it.
					if (!memcmp(g_addr[idx], g_our[idx], g_length[idx])) {
						continue;
					}

					// If the memory region matches the original contents, then it
					// has been restored to its original state.
					if (!memcmp(g_orig[idx], g_addr[idx], g_length[idx]))
						is_modification = 0;

					if (is_shutting_down() == 0) {
						if (is_modification) {
							char *tmpbuf2;
							tmpbuf2 = tmpbuf = malloc(g_length[idx]);
							memcpy(tmpbuf, g_addr[idx], g_length[idx]);
							log_hook_modification(g_funcname[idx], g_our[idx], tmpbuf, g_length[idx]);
							tmpbuf = NULL;
							free(tmpbuf2);
						} 
						else
							log_hook_removal(g_funcname[idx]);
					}
					g_hook_reported[idx] = 1;
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					// cuckoo currently has no handling for FreeLibrary, so if a hooked DLL ends up
					// being unloaded we would crash in the code above
					if (tmpbuf)
						free(tmpbuf);
				}
			}
		}
	}

    return 0;
}

static DWORD WINAPI _unhook_watch_thread(LPVOID param)
{
    hook_disable();

    while (WaitForSingleObject(g_unhook_thread_handle, 1000) == WAIT_TIMEOUT);

    if(is_shutting_down() == 0) {
        log_anomaly("unhook", 1, NULL,
            "Unhook detection thread has been corrupted!");
    }
    return 0;
}

int unhook_init_detection()
{
    g_unhook_thread_handle =
        CreateThread(NULL, 0, &_unhook_detect_thread, NULL, 0, NULL);

    g_watcher_thread_handle =
        CreateThread(NULL, 0, &_unhook_watch_thread, NULL, 0, NULL);

    if(g_unhook_thread_handle != NULL && g_watcher_thread_handle != NULL) {
        return 0;
    }

    pipe("CRITICAL:Error initializing unhook detection threads!");
    return -1;
}

static HANDLE g_terminate_event_thread_handle;
static HANDLE g_terminate_event_handle;

static DWORD WINAPI _terminate_event_thread(LPVOID param)
{
	hook_disable();

	while (1) {
		WaitForSingleObject(g_terminate_event_handle, INFINITE);
		log_flush();
	}

	return 0;
}


int terminate_event_init()
{
	SECURITY_DESCRIPTOR sd;
	SECURITY_ATTRIBUTES sa;
	InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = FALSE;
	sa.lpSecurityDescriptor = &sd;
	g_terminate_event_handle = CreateEventA(&sa, FALSE, FALSE, g_config.terminate_event_name);

	g_terminate_event_thread_handle =
		CreateThread(NULL, 0, &_terminate_event_thread, NULL, 0, NULL);

	if (g_terminate_event_handle != NULL && g_terminate_event_thread_handle != NULL)
		return 0;

	pipe("CRITICAL:Error initializing terminate event thread!");
	return -1;
}

#ifndef _WIN64
static ULONG_PTR cuckoomonaddrs[20];
static int cuckoomonaddrs_num;

static int find_cuckoomon_addrs(ULONG_PTR addr)
{
	if (cuckoomonaddrs_num < 20)
		cuckoomonaddrs[cuckoomonaddrs_num++] = addr;
	return 0;
}

static int _operate_on_backtrace(ULONG_PTR retaddr, ULONG_PTR _ebp, int(*func)(ULONG_PTR))
{
	int ret;

	while (_ebp)
	{
		// obtain the return address and the next value of ebp
		ULONG_PTR addr = *(ULONG_PTR *)(_ebp + sizeof(ULONG_PTR));
		_ebp = *(ULONG_PTR *)_ebp;

		ret = func(addr);
		if (ret)
			return ret;
	}

	return ret;
}

static DWORD WINAPI _watchdog_thread(LPVOID param)
{
	while (1) {
		char msg[1024];
		char *dllname;
		unsigned int off = 0;
		int i;

		CONTEXT ctx;
		raw_sleep(1000);
		memset(&cuckoomonaddrs, 0, sizeof(cuckoomonaddrs));
		cuckoomonaddrs_num = 0;
		memset(&ctx, 0, sizeof(ctx));
		SuspendThread((HANDLE)param);
		ctx.ContextFlags = CONTEXT_FULL;
		GetThreadContext((HANDLE)param, &ctx);
		dllname = convert_address_to_dll_name_and_offset(ctx.Eip, &off);
		sprintf(msg, "INFO: PID %u thread: %p EIP: %s+%x(%p) EAX: %p EBX: %p ECX: %p EDX: %p ESI: %p EDI: %p EBP: %p ESP: %p\n", GetCurrentProcessId(), param, dllname ? dllname : "", off, ctx.Eip, ctx.Eax, ctx.Ebx, ctx.Ecx, ctx.Edx, ctx.Esi, ctx.Edi, ctx.Ebp, ctx.Esp);

		_operate_on_backtrace(ctx.Eip, ctx.Ebp, find_cuckoomon_addrs);

		for (i = 0; i < cuckoomonaddrs_num; i++) {
			char *dllname2 = convert_address_to_dll_name_and_offset(cuckoomonaddrs[i], &off);
			sprintf(msg + strlen(msg), " %s+%x(%p)", dllname2 ? dllname2 : "", off, cuckoomonaddrs[i]);
			if (dllname2)
				free(dllname2);
		}

		if (dllname)
			free(dllname);
		ResumeThread((HANDLE)param);
		pipe(msg);
	}
}

int init_watchdog()
{
	HANDLE mainthreadhandle;

	DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &mainthreadhandle, THREAD_ALL_ACCESS, FALSE, 0);

	CreateThread(NULL, 0, &_watchdog_thread, mainthreadhandle, 0, NULL);

	return 0;
}
#endif
