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
#include <ctype.h>
#include "ntapi.h"
#include <shlwapi.h>
#include <sddl.h>
#include "misc.h"
#include "hooking.h"
#include "log.h"
#include "pipe.h"
#include "config.h"

static _NtQueryInformationProcess pNtQueryInformationProcess;
static _NtQueryInformationThread pNtQueryInformationThread;
static _RtlGenRandom pRtlGenRandom;
static _NtQueryAttributesFile pNtQueryAttributesFile;
static _NtQueryObject pNtQueryObject;
static _NtQueryKey pNtQueryKey;
static _NtDelayExecution pNtDelayExecution;
static _NtQuerySystemInformation pNtQuerySystemInformation;
_NtAllocateVirtualMemory pNtAllocateVirtualMemory;
_NtFreeVirtualMemory pNtFreeVirtualMemory;

void resolve_runtime_apis(void)
{
	HMODULE ntdllbase = GetModuleHandle("ntdll");

	*(FARPROC *)&pNtDelayExecution = GetProcAddress(ntdllbase, "NtDelayExecution");
	*(FARPROC *)&pNtQuerySystemInformation = GetProcAddress(ntdllbase, "NtQuerySystemInformation");
	*(FARPROC *)&pNtQueryInformationProcess = GetProcAddress(ntdllbase, "NtQueryInformationProcess");
	*(FARPROC *)&pNtQueryInformationThread = GetProcAddress(ntdllbase, "NtQueryInformationThread");
	*(FARPROC *)&pNtQueryObject = GetProcAddress(ntdllbase, "NtQueryObject");
	*(FARPROC *)&pNtQueryKey = GetProcAddress(ntdllbase, "NtQueryKey");
	*(FARPROC *)&pNtQueryAttributesFile = GetProcAddress(ntdllbase, "NtQueryAttributesFile");
	*(FARPROC *)&pNtAllocateVirtualMemory = GetProcAddress(ntdllbase, "NtAllocateVirtualMemory");
	*(FARPROC *)&pNtFreeVirtualMemory = GetProcAddress(ntdllbase, "NtFreeVirtualMemory");
	*(FARPROC *)&pRtlGenRandom = GetProcAddress(GetModuleHandle("advapi32"), "SystemFunction036");
}

ULONG_PTR g_our_dll_base;
DWORD g_our_dll_size;

void raw_sleep(int msecs)
{
	LARGE_INTEGER interval;
	interval.QuadPart = -(msecs * 10000);

	pNtDelayExecution(FALSE, &interval);

}

// snprintf can end up acquiring the process' heap lock which will be unsafe in the context of a hooked
// NtAllocate/FreeVirtualMemory
void num_to_string(char *buf, unsigned int buflen, unsigned int num)
{
	unsigned int dec = 1000000000;
	unsigned int i = 0;

	if (!buflen)
		return;

	while (dec) {
		if (!i && ((num / dec) || dec == 1))
			buf[i++] = '0' + (num / dec);
		else if (i)
			buf[i++] = '0' + (num / dec);
		if (i == buflen - 1)
			break;
		num = num % dec;
		dec /= 10;
	}
	buf[i] = '\0';
}

DWORD get_image_size(ULONG_PTR base)
{
	PIMAGE_DOS_HEADER doshdr = (PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS nthdr = (PIMAGE_NT_HEADERS)(base + doshdr->e_lfanew);
	return nthdr->OptionalHeader.SizeOfImage;
}

BOOLEAN is_valid_address_range(ULONG_PTR start, DWORD len)
{
	MEMORY_BASIC_INFORMATION meminfo;

	if (!VirtualQuery((LPCVOID)start, &meminfo, sizeof(meminfo)))
		return FALSE;

	if (start < (ULONG_PTR)meminfo.BaseAddress || (start + len) > ((ULONG_PTR)meminfo.BaseAddress + meminfo.RegionSize))
		return FALSE;

	if (!(meminfo.State & MEM_COMMIT))
		return FALSE;

	if (meminfo.Protect & (PAGE_NOACCESS | PAGE_GUARD))
		return FALSE;

	return TRUE;
}

ULONG_PTR parent_process_id() // By Napalm @ NetCore2K (rohitab.com)
{
    ULONG_PTR pbi[6]; ULONG ulSize = 0;

    if(pNtQueryInformationProcess(GetCurrentProcess(), 0, &pbi, sizeof(pbi), &ulSize) >= 0 && ulSize == sizeof(pbi))
        return pbi[5];

	return 0;
}

DWORD pid_from_process_handle(HANDLE process_handle)
{
	PROCESS_BASIC_INFORMATION pbi;
	ULONG ulSize;
	HANDLE dup_handle = process_handle;
	DWORD PID = 0;
	BOOL duped;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	if (process_handle == GetCurrentProcess()) {
		PID = GetCurrentProcessId();
		goto out;
	}

	memset(&pbi, 0, sizeof(pbi));
	
	duped = DuplicateHandle(GetCurrentProcess(), process_handle, GetCurrentProcess(), &dup_handle, PROCESS_QUERY_INFORMATION, FALSE, 0);

    if(pNtQueryInformationProcess(dup_handle, 0, &pbi, sizeof(pbi), &ulSize) >= 0 && ulSize == sizeof(pbi))
        PID = (DWORD)pbi.UniqueProcessId;

	if (duped)
		CloseHandle(dup_handle);

out:
	set_lasterrors(&lasterror);

	return PID;
}

static BOOL cid_from_thread_handle(HANDLE thread_handle, PCLIENT_ID cid)
{
	THREAD_BASIC_INFORMATION tbi;
	ULONG ulSize;
	HANDLE dup_handle = thread_handle;
	BOOL duped;
	BOOL ret = FALSE;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	memset(&tbi, 0, sizeof(tbi));

	duped = DuplicateHandle(GetCurrentProcess(), thread_handle, GetCurrentProcess(), &dup_handle, THREAD_QUERY_INFORMATION, FALSE, 0);
	
	if(pNtQueryInformationThread(dup_handle, 0, &tbi, sizeof(tbi), &ulSize) >= 0 && ulSize == sizeof(tbi)) {
		memcpy(cid, &tbi.ClientId, sizeof(CLIENT_ID));
		ret = TRUE;
    }

	if (duped)
		CloseHandle(dup_handle);

	set_lasterrors(&lasterror);

	return ret;
}

DWORD pid_from_thread_handle(HANDLE thread_handle)
{
	CLIENT_ID cid;
	BOOL ret;

	memset(&cid, 0, sizeof(cid));

	ret = cid_from_thread_handle(thread_handle, &cid);
	return (DWORD)cid.UniqueProcess;
}

DWORD tid_from_thread_handle(HANDLE thread_handle)
{
	CLIENT_ID cid;
	BOOL ret;

	memset(&cid, 0, sizeof(cid));

	ret = cid_from_thread_handle(thread_handle, &cid);
	return (DWORD)cid.UniqueThread;
}


DWORD random()
{
    DWORD ret, realret;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);

    realret = pRtlGenRandom(&ret, sizeof(ret)) ? ret : rand();

	set_lasterrors(&lasterror);

	return realret;
}

DWORD randint(DWORD min, DWORD max)
{
    return min + (random() % (max - min + 1));
}

BOOL is_directory_objattr(const OBJECT_ATTRIBUTES *obj)
{
    FILE_BASIC_INFORMATION basic_information;
    if(NT_SUCCESS(pNtQueryAttributesFile(obj, &basic_information))) {
        return basic_information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY;
    }
    return FALSE;
}

DWORD loaded_dlls;
struct dll_range dll_ranges[MAX_DLLS];

static void add_dll_range(ULONG_PTR start, ULONG_PTR end)
{
	DWORD tmp_loaded_dlls = loaded_dlls;
	if (tmp_loaded_dlls >= MAX_DLLS)
		return;
	if (is_in_dll_range(start))
		return;
	dll_ranges[tmp_loaded_dlls].start = start;
	dll_ranges[tmp_loaded_dlls].end = end;

	loaded_dlls++;
}

BOOL is_in_dll_range(ULONG_PTR addr)
{
	DWORD i;
	for (i = 0; i < loaded_dlls; i++)
		if (addr >= dll_ranges[i].start && addr < dll_ranges[i].end)
			return TRUE;
	return FALSE;
}

static ULONG_PTR base_of_dll_of_interest;

void set_dll_of_interest(ULONG_PTR BaseAddress)
{
	base_of_dll_of_interest = BaseAddress;
}

void add_all_dlls_to_dll_ranges(void)
{
	LDR_MODULE *mod; PEB *peb = (PEB *)get_peb();

	/* skip the base image */
	mod = (LDR_MODULE *)peb->LoaderData->InLoadOrderModuleList.Flink;
	if (mod->BaseAddress == NULL)
		return;
	for (mod = (LDR_MODULE *)mod->InLoadOrderModuleList.Flink;
		mod->BaseAddress != NULL;
		mod = (LDR_MODULE *)mod->InLoadOrderModuleList.Flink) {
		if ((ULONG_PTR)mod->BaseAddress != base_of_dll_of_interest)
			add_dll_range((ULONG_PTR)mod->BaseAddress, (ULONG_PTR)mod->BaseAddress + mod->SizeOfImage);
	}

}

char *convert_address_to_dll_name_and_offset(ULONG_PTR addr, unsigned int *offset)
{
	LDR_MODULE *mod; PEB *peb = (PEB *)get_peb();

	if (addr >= g_our_dll_base && addr < (g_our_dll_base + g_our_dll_size))
	{
		char *buf = calloc(1, strlen("cuckoomon.dll") + 1);
		if (buf == NULL)
			return NULL;
		strcpy(buf, "cuckoomon.dll");
		*offset = (unsigned int)(addr - g_our_dll_base);
		return buf;
	}

	for (mod = (LDR_MODULE *)peb->LoaderData->InLoadOrderModuleList.Flink;
		mod->BaseAddress != NULL;
		mod = (LDR_MODULE *)mod->InLoadOrderModuleList.Flink) {
		char *buf;
		unsigned int i;

		if (addr < (ULONG_PTR)mod->BaseAddress || addr >= ((ULONG_PTR)mod->BaseAddress + mod->SizeOfImage))
			continue;
		buf = calloc(1, (mod->BaseDllName.Length / sizeof(wchar_t)) + 1);
		if (buf == NULL)
			return NULL;
		for (i = 0; i < (mod->BaseDllName.Length / sizeof(wchar_t)); i++)
			buf[i] = (char)mod->BaseDllName.Buffer[i];
		*offset = (unsigned int)(addr - (ULONG_PTR)mod->BaseAddress);
		return buf;
	}
	return NULL;
}


// hide our module from PEB
// http://www.openrce.org/blog/view/844/How_to_hide_dll

#define CUT_LIST(item) \
    item.Blink->Flink = item.Flink; \
    item.Flink->Blink = item.Blink

void hide_module_from_peb(HMODULE module_handle)
{
    LDR_MODULE *mod; PEB *peb = (PEB *)get_peb();

    for (mod = (LDR_MODULE *) peb->LoaderData->InLoadOrderModuleList.Flink;
         mod->BaseAddress != NULL;
         mod = (LDR_MODULE *) mod->InLoadOrderModuleList.Flink) {

        if(mod->BaseAddress == module_handle) {
            CUT_LIST(mod->InLoadOrderModuleList);
            CUT_LIST(mod->InInitializationOrderModuleList);
            CUT_LIST(mod->InMemoryOrderModuleList);

            // TODO test whether this list is really used as a linked list
            // like InLoadOrderModuleList etc
            CUT_LIST(mod->HashTableEntry);

            memset(mod, 0, sizeof(LDR_MODULE));
            break;
        }
    }
}

uint32_t path_from_handle(HANDLE handle,
    wchar_t *path, uint32_t path_buffer_len)
{
	POBJECT_NAME_INFORMATION resolvedName;
	ULONG returnLength;
	NTSTATUS status;
	uint32_t length = 0;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	resolvedName = (POBJECT_NAME_INFORMATION)calloc(1, OBJECT_NAME_INFORMATION_REQUIRED_SIZE);

	status = pNtQueryObject(handle, ObjectNameInformation,
		resolvedName, OBJECT_NAME_INFORMATION_REQUIRED_SIZE, &returnLength);

	if (NT_SUCCESS(status)) {
		length = min(resolvedName->Name.Length / sizeof(wchar_t), path_buffer_len - 1);
		// NtQueryInformationFile omits the "C:" part in a
		// filename, apparently
		memcpy(path, resolvedName->NameBuffer, length * sizeof(wchar_t));
	}
	if (path_buffer_len)
		path[length] = L'\0';

	free(resolvedName);

	set_lasterrors(&lasterror);

	return length;
}

uint32_t path_from_object_attributes(const OBJECT_ATTRIBUTES *obj,
    wchar_t *path, uint32_t buffer_length)
{
	uint32_t copylen, obj_length, length;

    if (obj->ObjectName == NULL || obj->ObjectName->Buffer == NULL) {
		return path_from_handle(obj->RootDirectory, path, buffer_length);;
    }

    // ObjectName->Length is actually the size in bytes.
    obj_length = obj->ObjectName->Length / sizeof(wchar_t);

	copylen = min(obj_length, buffer_length - 1);

    if(obj->RootDirectory == NULL) {
        memcpy(path, obj->ObjectName->Buffer, copylen * sizeof(wchar_t));
		path[copylen] = L'\0';
        return copylen;
    }

    length = path_from_handle(obj->RootDirectory,
        path, buffer_length);

	
	path[length++] = L'\\';
	if (length >= (buffer_length - 1))
		copylen = 0;
	else
		copylen = buffer_length - 1 - length;
	copylen = min(copylen, obj_length);
	memcpy(&path[length], obj->ObjectName->Buffer, copylen * sizeof(wchar_t));
	path[length + copylen] = L'\0';
    return length + copylen;
}

static char *system32dir_a;
static char *sysnativedir_a;
static wchar_t *system32dir_w;
static wchar_t *sysnativedir_w;
static unsigned int system32dir_len;
static unsigned int sysnativedir_len;

char *ensure_absolute_ascii_path(char *out, const char *in)
{
	char tmpout[MAX_PATH];
	char nonexistent[MAX_PATH];
	char *pathcomponent;
	unsigned int nonexistentidx;
	unsigned int pathcomponentlen;
	unsigned int lenchars;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	if (!GetFullPathNameA(in, MAX_PATH, tmpout, NULL))
		goto normal_copy;

	lenchars = 0;
	nonexistentidx = MAX_PATH - 1;
	nonexistent[nonexistentidx] = '\0';
	while (lenchars == 0) {
		lenchars = GetLongPathNameA(tmpout, out, MAX_PATH);
		if (lenchars)
			break;
		if (GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_PATH_NOT_FOUND && GetLastError() != ERROR_INVALID_NAME)
			goto normal_copy;
		pathcomponent = strrchr(tmpout, '\\');
		if (pathcomponent == NULL)
			goto normal_copy;
		pathcomponentlen = (unsigned int)strlen(pathcomponent);
		nonexistentidx -= pathcomponentlen;
		memcpy(nonexistent + nonexistentidx, pathcomponent, pathcomponentlen * sizeof(char));
		*pathcomponent = '\0';
	}
	strncat(out, nonexistent + nonexistentidx, MAX_PATH - strlen(out));
	goto out;

normal_copy:
	strncpy(out, in, MAX_PATH);
out:
	if (is_wow64_fs_redirection_disabled() && !strnicmp(out, system32dir_a, system32dir_len)) {
		memmove(out + system32dir_len + 1, out + system32dir_len, strlen(out + system32dir_len) + 1);
		memcpy(out, sysnativedir_a, sysnativedir_len);
	}
	out[MAX_PATH - 1] = '\0';
	if (out[1] == ':' && out[2] == '\\')
		out[0] = toupper(out[0]);

	set_lasterrors(&lasterror);

	return out;
}

wchar_t *ensure_absolute_unicode_path(wchar_t *out, const wchar_t *in)
{
	wchar_t *tmpout;
	wchar_t *nonexistent;
	unsigned int lenchars;
	unsigned int nonexistentidx;
	wchar_t *pathcomponent;
	unsigned int pathcomponentlen;
	const wchar_t *inadj;
	unsigned int inlen;
	int is_globalroot = 0;

	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	if (!wcsncmp(in, L"\\??\\", 4)) {
		inadj = in + 4;
		is_globalroot = 1;
	}
	else if (!wcsnicmp(in, L"\\\\?\\globalroot", 14)) {
		inadj = in + 14;
		is_globalroot = 1;
	}
	else
		inadj = in;

	inlen = lstrlenW(inadj);

	tmpout = malloc(32768 * sizeof(wchar_t));
	nonexistent = malloc(32768 * sizeof(wchar_t));

	if (tmpout == NULL || nonexistent == NULL)
		goto normal_copy;

	if (!wcsnicmp(inadj, L"\\device\\", 8) || !wcsnicmp(inadj, L"\\systemroot", 11)) {
		// handle \\Device\\* and \\systemroot\\*
		unsigned int matchlen;
		wchar_t *tmpout2;
		wchar_t *retstr = get_matching_unicode_specialname(inadj, &matchlen);
		if (retstr == NULL)
			goto normal_copy;
		// rewrite \\Device\\HarddiskVolumeX etc to the appropriate drive letter
		tmpout2 = malloc(32768 * sizeof(wchar_t));
		if (tmpout2 == NULL)
			goto normal_copy;

		wcscpy(tmpout2, L"\\\\?\\");
		wcscat(tmpout2, retstr);
		wcsncat(tmpout2, inadj + matchlen, 32768 - 4 - 3);
		if (!GetFullPathNameW(tmpout2, 32768, tmpout, NULL)) {
			free(tmpout2);
			goto normal_copy;
		}
		free(tmpout2);
	}
	else if (inlen > 1 && inadj[1] == L':') {
		wchar_t *tmpout2;

		tmpout2 = malloc(32768 * sizeof(wchar_t));
		if (tmpout2 == NULL)
			goto normal_copy;

		wcscpy(tmpout2, L"\\\\?\\");
		wcsncat(tmpout2, inadj, 32768 - 4);
		if (!GetFullPathNameW(tmpout2, 32768, tmpout, NULL)) {
			free(tmpout2);
			goto normal_copy;
		}
		free(tmpout2);
	}
	else if (is_globalroot) {
		// handle \\??\\*\\*
		goto globalroot_copy;
	}
	else {
		if (!GetFullPathNameW(inadj, 32768, tmpout, NULL))
			goto normal_copy;
	}

	lenchars = 0;
	nonexistentidx = 32767;
	nonexistent[nonexistentidx] = L'\0';
	while (lenchars == 0) {
		lenchars = GetLongPathNameW(tmpout, out, 32768);
		if (lenchars)
			break;
		if (GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_PATH_NOT_FOUND && GetLastError() != ERROR_INVALID_NAME)
			goto normal_copy;
		pathcomponent = wcsrchr(tmpout, L'\\');
		if (pathcomponent == NULL)
			goto normal_copy;
		pathcomponentlen = lstrlenW(pathcomponent);
		nonexistentidx -= pathcomponentlen;
		memcpy(nonexistent + nonexistentidx, pathcomponent, pathcomponentlen * sizeof(wchar_t));
		*pathcomponent = L'\0';
	}
	wcsncat(out, nonexistent + nonexistentidx, 32768 - lstrlenW(out));

	if (!wcsncmp(out, L"\\\\?\\", 4))
		memmove(out, out + 4, (lstrlenW(out) + 1 - 4) * sizeof(wchar_t));

	if (is_wow64_fs_redirection_disabled() && !wcsnicmp(out, system32dir_w, system32dir_len)) {
		memmove(out + system32dir_len + 1, out + system32dir_len, (lstrlenW(out + system32dir_len) + 1) * sizeof(wchar_t));
		memcpy(out, sysnativedir_w, sysnativedir_len * sizeof(wchar_t));
	}

	goto out;

globalroot_copy:
	wcscpy(out, L"\\??\\");
	wcsncat(out, inadj, 32768 - 4);
	goto out;

normal_copy:
	wcsncpy(out, inadj, 32768);
	if (!wcsncmp(out, L"\\\\?\\", 4))
		memmove(out, out + 4, (lstrlenW(out) + 1 - 4) * sizeof(wchar_t));
out:
	out[32767] = L'\0';
	if (tmpout)
		free(tmpout);
	if (nonexistent)
		free(nonexistent);
	if (out[1] == L':' && out[2] == L'\\')
		out[0] = toupper(out[0]);

	set_lasterrors(&lasterror);

	return out;
}

static unsigned int get_encoded_unicode_string_len(const wchar_t *buf, USHORT len)
{
	unsigned int numnulls = 0;
	unsigned int i;

	for (i = 0; i < len / sizeof(wchar_t); i++) {
		if (buf[i] == L'\0')
			numnulls++;
	}

	return len + (numnulls * 4 * sizeof(wchar_t));
}

static void copy_encoded_unicode_string(wchar_t *out, const wchar_t *in, unsigned int origlen, unsigned int newlen)
{
	unsigned int i, x;

	for (i = 0, x = 0; i < origlen / sizeof(wchar_t); i++) {
		if (in[i] == L'\0') {
			out[x++] = L'\\';
			out[x++] = L'x';
			out[x++] = L'0';
			out[x++] = L'0';
		}
		else
			out[x++] = in[i];
	}
	out[newlen / sizeof(wchar_t)] = L'\0';
}

wchar_t *get_full_keyvalue_pathA(HKEY registry, const char *in, PKEY_NAME_INFORMATION keybuf, unsigned int len)
{
	if (in && in[0] != '\0')
		return get_full_key_pathA(registry, in, keybuf, len);
	else
		return get_full_key_pathA(registry, "(Default)", keybuf, len);
}
wchar_t *get_full_keyvalue_pathW(HKEY registry, const wchar_t *in, PKEY_NAME_INFORMATION keybuf, unsigned int len)
{
	if (in && in[0] != L'\0')
		return get_full_key_pathW(registry, in, keybuf, len);
	else
		return get_full_key_pathW(registry, L"(Default)", keybuf, len);
}
wchar_t *get_full_keyvalue_pathUS(HKEY registry, const PUNICODE_STRING in, PKEY_NAME_INFORMATION keybuf, unsigned int len)
{
	wchar_t *ret;
	if (in && in->Length) {
		unsigned int newlen = get_encoded_unicode_string_len(in->Buffer, in->Length);
		wchar_t *incpy = malloc(newlen + (1 * sizeof(wchar_t)));
		copy_encoded_unicode_string(incpy, in->Buffer, in->Length, newlen);
		ret = get_full_key_pathW(registry, incpy, keybuf, len);
		free(incpy);
	}
	else {
		ret = get_full_key_pathW(registry, L"(Default)", keybuf, len);
	}
	return ret;
}

wchar_t *get_full_key_pathA(HKEY registry, const char *in, PKEY_NAME_INFORMATION keybuf, unsigned int len)
{
	wchar_t *widein = NULL;
	const char *p;
	wchar_t *u;
	unsigned int widelen = 0;
	wchar_t *ret;

	if (in) {
		widelen = (unsigned int)((strlen(in) + 1) * sizeof(wchar_t));
		widein = calloc(1, widelen);
		for (u = widein, p = in; *p; p++, u++)
			*u = (wchar_t)(unsigned short)*p;
	}

	ret = get_full_key_pathW(registry, widein, keybuf, len);

	if (widein)
		free(widein);

	return ret;
}

wchar_t *get_full_key_pathW(HKEY registry, const wchar_t *in, PKEY_NAME_INFORMATION keybuf, unsigned int len)
{
	OBJECT_ATTRIBUTES objattr;
	UNICODE_STRING keystr;
	const wchar_t *p;
	wchar_t *u;
	wchar_t *ret;
	unsigned short idx = 0;

	memset(&objattr, 0, sizeof(objattr));

	keystr.Buffer = calloc(1, MAX_KEY_BUFLEN);
	keystr.MaximumLength = MAX_KEY_BUFLEN;
	objattr.ObjectName = &keystr;

	if (in) {
		for (p = in, u = keystr.Buffer; *p && idx < (MAX_KEY_BUFLEN / sizeof(wchar_t) - 1); p++, u++, idx++) {
			*u = *p;
			// normalize duplicate backslashes in the user-provided string as the registry APIs will use them without error
			if (*p == L'\\') {
				while (*(p + 1) == L'\\')
					p++;
			}
		}
		keystr.Length = idx * sizeof(wchar_t);
	}
	else {
		keystr.Buffer[0] = L'\0';
		keystr.Length = 0;
	}

	objattr.RootDirectory = registry;

	ret = get_key_path(&objattr, keybuf, len);
	free(keystr.Buffer);
	return ret;
}

wchar_t *get_key_path(POBJECT_ATTRIBUTES ObjectAttributes, PKEY_NAME_INFORMATION keybuf, unsigned int len)
{
	NTSTATUS status;
	ULONG reslen;
	unsigned int maxlen = len - sizeof(KEY_NAME_INFORMATION);
	unsigned int maxlen_chars = maxlen / sizeof(WCHAR);
	unsigned int remaining;
	unsigned int curlen;
	HKEY rootkey;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	if (ObjectAttributes == NULL || ObjectAttributes->ObjectName == NULL)
		goto error;
	if (ObjectAttributes->RootDirectory == NULL) {
		unsigned int copylen = min(maxlen, ObjectAttributes->ObjectName->Length);
		unsigned int newlen = get_encoded_unicode_string_len(ObjectAttributes->ObjectName->Buffer, copylen);
		copy_encoded_unicode_string(keybuf->KeyName, ObjectAttributes->ObjectName->Buffer, copylen, newlen);
		keybuf->KeyNameLength = newlen;
		goto normal;
	}

	keybuf->KeyName[0] = L'\0';
	keybuf->KeyNameLength = 0;

	/* mingw doesn't like case statements with pointer values */
	rootkey = (HKEY)ObjectAttributes->RootDirectory;
	if (rootkey == HKEY_CLASSES_ROOT)
		wcscpy(keybuf->KeyName, L"HKEY_CLASSES_ROOT");
	else if (rootkey == HKEY_CURRENT_USER)
		wcscpy(keybuf->KeyName, L"HKEY_CURRENT_USER");
	else if (rootkey == HKEY_LOCAL_MACHINE)
		wcscpy(keybuf->KeyName, L"HKEY_LOCAL_MACHINE");
	else if (rootkey == HKEY_USERS)
		wcscpy(keybuf->KeyName, L"HKEY_USERS");
	else if (rootkey == HKEY_PERFORMANCE_DATA)
		wcscpy(keybuf->KeyName, L"HKEY_PERFORMANCE_DATA");
	else if (rootkey == HKEY_PERFORMANCE_TEXT)
		wcscpy(keybuf->KeyName, L"HKEY_PERFORMANCE_TEXT");
	else if (rootkey == HKEY_PERFORMANCE_NLSTEXT)
		wcscpy(keybuf->KeyName, L"HKEY_PERFORMANCE_NLSTEXT");
	else if (rootkey == HKEY_CURRENT_CONFIG)
		wcscpy(keybuf->KeyName, L"HKEY_CURRENT_CONFIG");
	else if (rootkey == HKEY_DYN_DATA)
		wcscpy(keybuf->KeyName, L"HKEY_DYN_DATA");
	else if (rootkey == HKEY_CURRENT_USER_LOCAL_SETTINGS)
		wcscpy(keybuf->KeyName, L"HKEY_CURRENT_USER_LOCAL_SETTINGS");

	keybuf->KeyNameLength = lstrlenW(keybuf->KeyName) * sizeof(wchar_t);
	if (!keybuf->KeyNameLength) {
		status = pNtQueryKey(ObjectAttributes->RootDirectory, KeyNameInformation, keybuf, len, &reslen);
		if (status < 0)
			goto error;
	}

	keybuf->KeyName[keybuf->KeyNameLength / sizeof(WCHAR)] = 0;

	curlen = (unsigned int)wcslen(keybuf->KeyName);
	remaining = maxlen_chars - (unsigned int)wcslen(keybuf->KeyName) - 1;

	if (ObjectAttributes->ObjectName == NULL) {
		if (remaining < 10)
			goto error;
		wcscat(keybuf->KeyName, L"(Default)");
		keybuf->KeyNameLength = (curlen + 9) * sizeof(WCHAR);
	}
	else {
		unsigned int newlen = get_encoded_unicode_string_len(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);

		if ((remaining * sizeof(WCHAR)) < newlen + (1 * sizeof(WCHAR)))
			goto error;

		keybuf->KeyName[curlen++] = L'\\';
		copy_encoded_unicode_string(keybuf->KeyName + curlen, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, newlen);
		keybuf->KeyNameLength = curlen * sizeof(WCHAR) + newlen;
	}

normal:
	if (!wcsnicmp(keybuf->KeyName, g_hkcu.hkcu_string, g_hkcu.len) && (keybuf->KeyName[g_hkcu.len] == L'\\' || keybuf->KeyName[g_hkcu.len] == L'\0')) {
		unsigned int ourlen = lstrlenW(L"HKEY_CURRENT_USER");
		memcpy(keybuf->KeyName, L"HKEY_CURRENT_USER", ourlen * sizeof(WCHAR));
		memmove(keybuf->KeyName + ourlen, keybuf->KeyName + g_hkcu.len, keybuf->KeyNameLength + (1 * sizeof(WCHAR)) - ((g_hkcu.len) * sizeof(WCHAR)));
		keybuf->KeyNameLength -= (g_hkcu.len - ourlen) * sizeof(WCHAR);
	}
	else if (!wcsnicmp(keybuf->KeyName, g_hkcu.hkcu_string, g_hkcu.len) && !wcsnicmp(&keybuf->KeyName[g_hkcu.len], L"_Classes", 8)) {
		unsigned int ourlen = lstrlenW(L"HKEY_CURRENT_USER\\Software\\Classes");
		unsigned int existlen = g_hkcu.len + 8;
		memmove(keybuf->KeyName + ourlen, keybuf->KeyName + existlen, keybuf->KeyNameLength + (1 * sizeof(WCHAR)) - (existlen * sizeof(WCHAR)));
		memcpy(keybuf->KeyName, L"HKEY_CURRENT_USER\\Software\\Classes", ourlen * sizeof(WCHAR));
		keybuf->KeyNameLength -= (existlen - ourlen) * sizeof(WCHAR);
	}
	else if (!wcsnicmp(keybuf->KeyName, L"\\REGISTRY\\MACHINE", 17) && (keybuf->KeyName[17] == L'\\' || keybuf->KeyName[17] == L'\0')) {
		unsigned int ourlen = 18;
		memmove(keybuf->KeyName + ourlen, keybuf->KeyName + 17, keybuf->KeyNameLength + (1 * sizeof(WCHAR)) - (17 * sizeof(WCHAR)));
		memcpy(keybuf->KeyName, L"HKEY_LOCAL_MACHINE", ourlen * sizeof(WCHAR));
		keybuf->KeyNameLength += (ourlen - 17) * sizeof(WCHAR);
	}
	else if (!wcsnicmp(keybuf->KeyName, L"\\REGISTRY\\USER", 14) && (keybuf->KeyName[14] == L'\\' || keybuf->KeyName[14] == L'\0')) {
		unsigned int ourlen = 10;
		memmove(keybuf->KeyName + ourlen, keybuf->KeyName + 14, keybuf->KeyNameLength + (1 * sizeof(WCHAR)) - (14 * sizeof(WCHAR)));
		memcpy(keybuf->KeyName, L"HKEY_USERS", ourlen * sizeof(WCHAR));
		keybuf->KeyNameLength -= (14 - ourlen) * sizeof(WCHAR);
	}

	goto out;

error:
	keybuf->KeyName[0] = 0;
	keybuf->KeyNameLength = 0;
out:
	set_lasterrors(&lasterror);

	return keybuf->KeyName;
}

static PSID GetSID(void)
{
	HANDLE token;
	DWORD retlen;
	PTOKEN_USER userinfo = NULL;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_QUERY_SOURCE, &token))
		return NULL;
	if (GetTokenInformation(token, TokenUser, 0, 0, &retlen) || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		CloseHandle(token);
		return NULL;
	}
	userinfo = malloc(retlen);
	if (userinfo) {
		if (!GetTokenInformation(token, TokenUser, userinfo, retlen, &retlen)) {
			free(userinfo);
			CloseHandle(token);
			return NULL;
		}
	}
	CloseHandle(token);
	return userinfo->User.Sid;
}

void hkcu_init(void)
{
	PSID sid = GetSID();
	LPWSTR sidstr;

	ConvertSidToStringSidW(sid, &sidstr);

	g_hkcu.len = lstrlenW(sidstr) + lstrlenW(L"\\REGISTRY\\USER\\");
	g_hkcu.hkcu_string = malloc((g_hkcu.len + 1) * sizeof(wchar_t));
	wcscpy(g_hkcu.hkcu_string, L"\\REGISTRY\\USER\\");
	wcscat(g_hkcu.hkcu_string, sidstr);
	LocalFree(sidstr);
}

extern int process_shutting_down;

int is_shutting_down()
{
	lasterror_t lasterror;
	int ret = 0;
	HANDLE mutex_handle;

	if (process_shutting_down)
		return 1;

	get_lasterrors(&lasterror);

	mutex_handle = OpenMutex(SYNCHRONIZE, FALSE, g_config.shutdown_mutex);
    if(mutex_handle != NULL) {
		log_flush();
        CloseHandle(mutex_handle);
        ret = 1;
    }

	set_lasterrors(&lasterror);

    return ret;
}

static char *g_specialnames_a[27];
static char *g_targetnames_a[27];

static wchar_t *g_specialnames_w[27];
static wchar_t *g_targetnames_w[27];
static unsigned int g_num_specialnames;

wchar_t *get_matching_unicode_specialname(const wchar_t *path, unsigned int *matchlen)
{
	unsigned int i;
	for (i = 0; i < g_num_specialnames; i++) {
		if (!wcsnicmp(path, g_targetnames_w[i], wcslen(g_targetnames_w[i]))) {
			*matchlen = lstrlenW(g_targetnames_w[i]);
			return g_specialnames_w[i];
		}
	}
	return NULL;
}

void specialname_map_init(void)
{
	char letter[3];
	char buf[MAX_PATH];
	char c;
	unsigned int idx = 0;
	unsigned int i, x;
	size_t len;
	letter[1] = ':';
	letter[2] = '\0';
	for (c = 'A'; c <= 'Z'; c++) {
		letter[0] = c;
		if (QueryDosDeviceA(letter, buf, MAX_PATH)) {
			g_specialnames_a[idx] = strdup(letter);
			g_targetnames_a[idx] = strdup(buf);
			idx++;
		}
	}

	GetWindowsDirectoryA(buf, MAX_PATH);
	g_targetnames_a[idx] = strdup("\\systemroot");
	g_specialnames_a[idx] = strdup(buf);
	idx++;

	len = strlen(buf) + strlen("\\system32");
	system32dir_a = calloc(1, len + 1);
	system32dir_w = calloc(1, (len + 1) * sizeof(wchar_t));
	strcpy(system32dir_a, buf);
	strcat(system32dir_a, "\\system32");
	for (x = 0; x < len - strlen("\\system32"); x++)
		system32dir_w[x] = (wchar_t)buf[x];
	wcscat(system32dir_w, L"\\system32");
	system32dir_len = (unsigned int)len;

	len = strlen(buf) + strlen("\\sysnative");
	sysnativedir_a = calloc(1, len + 1);
	sysnativedir_w = calloc(1, (len + 1) * sizeof(wchar_t));
	strcpy(sysnativedir_a, buf);
	strcat(sysnativedir_a, "\\sysnative");
	for (x = 0; x < len - strlen("\\sysnative"); x++)
		sysnativedir_w[x] = (wchar_t)buf[x];
	wcscat(sysnativedir_w, L"\\sysnative");
	sysnativedir_len = (unsigned int)len;

	for (i = 0; i < idx; i++) {
		len = strlen(g_specialnames_a[i]) + 1;
		g_specialnames_w[i] = (wchar_t *)malloc(len * sizeof(wchar_t));
		for (x = 0; x < len; x++)
			g_specialnames_w[i][x] = (wchar_t)g_specialnames_a[i][x];
		len = strlen(g_targetnames_a[i]) + 1;
		g_targetnames_w[i] = (wchar_t *)malloc(len * sizeof(wchar_t));
		for (x = 0; x < len; x++)
			g_targetnames_w[i][x] = (wchar_t)g_targetnames_a[i][x];
	}

	g_num_specialnames = idx;

}

int is_wow64_fs_redirection_disabled(void)
{
#ifdef _WIN64
	return 1;
#else
	if (is_64bit_os) {
		__try {
			PCHAR teb = (PCHAR)NtCurrentTeb();
			PCHAR ptr1 = (PCHAR)(ULONG_PTR)*(DWORD *)(teb + 0xf70);
			if (ptr1 == NULL)
				return 0;
			if (*(DWORD *)(ptr1 + 0x14c0) == 1 && *(DWORD *)(ptr1 + 0x14c4) == 0)
				return 1;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			;
		}
	}
	return 0;
#endif
}

BOOLEAN is_suspended(DWORD pid, DWORD tid)
{
	ULONG length;
	PSYSTEM_PROCESS_INFORMATION pspi, proc;
	ULONG requestedlen = 16384;
	lasterror_t lasterror;
	BOOLEAN ret = FALSE;

	get_lasterrors(&lasterror);

	pspi = malloc(requestedlen);
	if (pspi == NULL)
		goto out;

	while (pNtQuerySystemInformation(SystemProcessInformation, pspi, requestedlen, &length) == STATUS_INFO_LENGTH_MISMATCH) {
		free(pspi);
		requestedlen <<= 1;
		pspi = malloc(requestedlen);
		if (pspi == NULL)
			goto out;
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
				goto out;
		}
	}
	free(pspi);
	ret = TRUE;
out:
	set_lasterrors(&lasterror);

	return ret;
}
