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
#include "log.h"
#include "pipe.h"
#include "config.h"
#include "misc.h"

// only skip Sleep()'s the first five seconds
#define MAX_SLEEP_SKIP_DIFF 5000


// skipping sleep calls is done while this variable is set to true
static int sleep_skip_active = 1;

// the amount of time skipped, in 100-nanosecond
LARGE_INTEGER time_skipped;
static LARGE_INTEGER time_start;

static int num_skipped = 0;
static int num_small = 0;
static int num_wait_skipped = 0;
static int num_wait_small = 0;

void disable_sleep_skip()
{
	if (sleep_skip_active && g_config.force_sleepskip < 1) {
		pipe("INFO:Disabling sleep skipping.");
		sleep_skip_active = 0;
	}
}

HOOKDEF(NTSTATUS, WINAPI, NtWaitForSingleObject,
	__in	HANDLE Handle,
	__in    BOOLEAN Alertable,
	__in_opt    PLARGE_INTEGER Timeout
) {
	NTSTATUS ret = STATUS_TIMEOUT;
	LONGLONG interval;
	LARGE_INTEGER newint;
	LARGE_INTEGER li;
	unsigned long milli;
	FILETIME ft;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	// handle INFINITE wait
	if (Timeout == NULL || Timeout->QuadPart == 0x8000000000000000ULL) {
		// only log potentially interesting cases
		if (hook_info()->main_caller_retaddr)
			LOQ_ntstatus("system", "pis", "Handle", Handle, "Milliseconds", -1, "Status", "Infinite");
		set_lasterrors(&lasterror);
		return Old_NtWaitForSingleObject(Handle, Alertable, Timeout);
	}

	newint.QuadPart = Timeout->QuadPart;

	if (newint.QuadPart > 0LL) {
		/* convert absolute time to relative time */
		FILETIME ft;
		GetSystemTimeAsFileTime(&ft);

		newint.HighPart = ft.dwHighDateTime;
		newint.LowPart = ft.dwLowDateTime;
		newint.QuadPart += time_skipped.QuadPart;
		newint.QuadPart -= Timeout->QuadPart;
		if (newint.QuadPart > 0LL)
			newint.QuadPart = 0LL;
	}
	interval = -newint.QuadPart;
	milli = (unsigned long)(interval / 10000);

	// only handle lame cases
	if (Handle != GetCurrentProcess()) {
		LOQ_ntstatus("system", "pi", "Handle", Handle, "Milliseconds", milli);
		goto docall;
	}

	GetSystemTimeAsFileTime(&ft);
	li.HighPart = ft.dwHighDateTime;
	li.LowPart = ft.dwLowDateTime;

	// check if we're still within the hardcoded limit
	if (sleep_skip_active && (li.QuadPart < time_start.QuadPart + MAX_SLEEP_SKIP_DIFF * 10000)) {
		time_skipped.QuadPart += interval;

		if (num_wait_skipped < 20) {
			// notify how much we've skipped
			LOQ_ntstatus("system", "pis", "Handle", Handle, "Milliseconds", milli, "Status", "Skipped");
			num_wait_skipped++;
		}
		else if (num_wait_skipped == 20) {
			LOQ_ntstatus("system", "s", "Status", "Skipped log limit reached");
			num_wait_skipped++;
		}
		goto skipcall;
	}
	/* clamp sleeps between 30 seconds and 1 hour down to 10 seconds  as long as we didn't force off sleep skipping */
	else if (milli >= 30000 && milli <= 3600000 && g_config.force_sleepskip != 0) {
		LARGE_INTEGER newint;
		newint.QuadPart = -(10000 * 10000);
		time_skipped.QuadPart += interval - (10000 * 10000);
		LOQ_ntstatus("system", "pis", "Handle", Handle, "Milliseconds", milli, "Status", "Skipped");
		goto docall;
	}
	else if (g_config.force_sleepskip > 0) {
		time_skipped.QuadPart += interval;
		LOQ_ntstatus("system", "pis", "Handle", Handle, "Milliseconds", milli, "Status", "Skipped");
		newint.QuadPart = 0;
		goto docall;
	}
	else {
		disable_sleep_skip();
	}
	if (milli <= 10) {
		if (num_wait_small < 20) {
			LOQ_ntstatus("system", "pi", "Handle", Handle, "Milliseconds", milli);
			num_wait_small++;
		}
		else if (num_wait_small == 20) {
			LOQ_ntstatus("system", "s", "Status", "Small log limit reached");
			num_wait_small++;
		}
		else if (num_wait_small > 20) {
			// likely using a bunch of tiny sleeps to delay execution, so let's suddenly mimic high load and give our
			// fake passage of time the impression of longer delays to return from sleep
			time_skipped.QuadPart += (randint(500, 1000) * 10000);
		}
	}
	else {
		LOQ_ntstatus("system", "pi", "Handle", Handle, "Milliseconds", milli);
	}

docall:
	set_lasterrors(&lasterror);
	return Old_NtWaitForSingleObject(Handle, Alertable, &newint);
skipcall:
	set_lasterrors(&lasterror);
	return ret;
}
HOOKDEF(NTSTATUS, WINAPI, NtDelayExecution,
    __in    BOOLEAN Alertable,
    __in    PLARGE_INTEGER DelayInterval
) {
    NTSTATUS ret = 0;
	LONGLONG interval;
	FILETIME ft;
	LARGE_INTEGER li;
	LARGE_INTEGER newint;
	unsigned long milli;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	newint.QuadPart = DelayInterval->QuadPart;
	// handle INFINITE sleep
	if (newint.QuadPart == 0x8000000000000000ULL) {
		LOQ_ntstatus("system", "is", "Milliseconds", -1, "Status", "Infinite");
		goto docall;
	}

	if (newint.QuadPart > 0LL) {
		/* convert absolute time to relative time */
		FILETIME ft;
		GetSystemTimeAsFileTime(&ft);

		newint.HighPart = ft.dwHighDateTime;
		newint.LowPart = ft.dwLowDateTime;
		newint.QuadPart += time_skipped.QuadPart;
		newint.QuadPart -= DelayInterval->QuadPart;
		if (newint.QuadPart > 0LL)
			newint.QuadPart = 0LL;
	}
	interval = -newint.QuadPart;
	milli = (unsigned long)(interval / 10000);

	GetSystemTimeAsFileTime(&ft);
    li.HighPart = ft.dwHighDateTime;
    li.LowPart = ft.dwLowDateTime;

    // check if we're still within the hardcoded limit
    if(sleep_skip_active && (li.QuadPart < time_start.QuadPart + MAX_SLEEP_SKIP_DIFF * 10000)) {
        time_skipped.QuadPart += interval;

		if (num_skipped < 20) {
			// notify how much we've skipped
			LOQ_ntstatus("system", "is", "Milliseconds", milli, "Status", "Skipped");
			num_skipped++;
		}
		else if (num_skipped == 20) {
			LOQ_ntstatus("system", "s", "Status", "Skipped log limit reached");
			num_skipped++;
		}
        goto skipcall;
	}
	/* clamp sleeps between 30 seconds and 1 hour down to 10 seconds  as long as we didn't force off sleep skipping */
	else if (milli >= 30000 && milli <= 3600000 && g_config.force_sleepskip != 0) {
		LARGE_INTEGER newint;
		newint.QuadPart = -(10000 * 10000);
		time_skipped.QuadPart += interval - (10000 * 10000);
		LOQ_ntstatus("system", "is", "Milliseconds", milli, "Status", "Skipped");
		goto docall;
	}
	else if (g_config.force_sleepskip > 0) {
		time_skipped.QuadPart += interval;
		LOQ_ntstatus("system", "is", "Milliseconds", milli, "Status", "Skipped");
		newint.QuadPart = 0;
		goto docall;
	}
    else {
        disable_sleep_skip();
    }
	if (milli <= 10) {
		if (num_small < 20) {
			LOQ_ntstatus("system", "i", "Milliseconds", milli);
			num_small++;
		}
		else if (num_small == 20) {
			LOQ_ntstatus("system", "s", "Status", "Small log limit reached");
			num_small++;
		}
		else if (num_small > 20) {
			// likely using a bunch of tiny sleeps to delay execution, so let's suddenly mimic high load and give our
			// fake passage of time the impression of longer delays to return from sleep
			time_skipped.QuadPart += (randint(500, 1000) * 10000);
		}
	}
	else {
		LOQ_ntstatus("system", "i", "Milliseconds", milli);
	}
docall:
	set_lasterrors(&lasterror);
	return Old_NtDelayExecution(Alertable, &newint);
skipcall:
	set_lasterrors(&lasterror);
	return ret;
}

HOOKDEF(void, WINAPI, GetLocalTime,
    __out  LPSYSTEMTIME lpSystemTime
) {
	lasterror_t lasterror;
	LARGE_INTEGER li; FILETIME ft;
	DWORD ret = 0;

	Old_GetLocalTime(lpSystemTime);


	get_lasterrors(&lasterror);

	SystemTimeToFileTime(lpSystemTime, &ft);
    li.HighPart = ft.dwHighDateTime;
    li.LowPart = ft.dwLowDateTime;
    li.QuadPart += time_skipped.QuadPart;
    ft.dwHighDateTime = li.HighPart;
    ft.dwLowDateTime = li.LowPart;
    FileTimeToSystemTime(&ft, lpSystemTime);

	set_lasterrors(&lasterror);

	LOQ_void("system", "");
}

HOOKDEF(void, WINAPI, GetSystemTime,
    __out  LPSYSTEMTIME lpSystemTime
) {
	lasterror_t lasterror;
	LARGE_INTEGER li; FILETIME ft;
	DWORD ret = 0;

    Old_GetSystemTime(lpSystemTime);

	get_lasterrors(&lasterror);

    SystemTimeToFileTime(lpSystemTime, &ft);
    li.HighPart = ft.dwHighDateTime;
    li.LowPart = ft.dwLowDateTime;
    li.QuadPart += time_skipped.QuadPart;
    ft.dwHighDateTime = li.HighPart;
    ft.dwLowDateTime = li.LowPart;
    FileTimeToSystemTime(&ft, lpSystemTime);

	set_lasterrors(&lasterror);

	LOQ_void("system", "");
}

HOOKDEF(DWORD, WINAPI, GetTickCount,
    void
) {
    DWORD ret = Old_GetTickCount();

    // add the time we've skipped
    ret += (DWORD)(time_skipped.QuadPart / 10000);

    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQuerySystemTime,
    _Out_  PLARGE_INTEGER SystemTime
) {
    NTSTATUS ret = Old_NtQuerySystemTime(SystemTime);
	LOQ_ntstatus("system", "");
    if(NT_SUCCESS(ret)) {
        SystemTime->QuadPart += time_skipped.QuadPart;
    }
    return 0;
}

HOOKDEF(DWORD, WINAPI, timeGetTime,
	void
) {
	DWORD ret = Old_timeGetTime();

	// add the time we've skipped
	ret += (DWORD)(time_skipped.QuadPart / 10000);

	return ret;
}

HOOKDEF(void, WINAPI, GetSystemTimeAsFileTime,
	_Out_ LPFILETIME lpSystemTimeAsFileTime
) {
	LARGE_INTEGER li;
	FILETIME ft;
	DWORD ret = 0;

	Old_GetSystemTimeAsFileTime(&ft);

	li.HighPart = ft.dwHighDateTime;
	li.LowPart = ft.dwLowDateTime;
	li.QuadPart += time_skipped.QuadPart;
	ft.dwHighDateTime = li.HighPart;
	ft.dwLowDateTime = li.LowPart;

	memcpy(lpSystemTimeAsFileTime, &ft, sizeof(ft));

	LOQ_void("system", "");

	return;
}

static int lastinput_called;

HOOKDEF(BOOL, WINAPI, GetLastInputInfo,
	_Out_ PLASTINPUTINFO plii
) {
	BOOL ret = Old_GetLastInputInfo(plii);

	LOQ_bool("system", "");

	lastinput_called++;

	/* fake recent user activity */
	if (lastinput_called > 2 && plii && plii->cbSize == 8)
		plii->dwTime = GetTickCount() + (DWORD)(time_skipped.QuadPart / 10000);

	return ret;
}

void init_sleep_skip(int first_process)
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    time_start.HighPart = ft.dwHighDateTime;
    time_start.LowPart = ft.dwLowDateTime;

    // we don't want to skip sleep calls in child processes
    if(first_process == 0) {
        disable_sleep_skip();
    }
}

void init_startup_time(unsigned int startup_time)
{
    time_skipped.QuadPart += (unsigned __int64) startup_time * 10000;
}
