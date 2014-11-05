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

ULONG_PTR parent_process_id(); // By Napalm @ NetCore2K (rohitab.com)
DWORD pid_from_process_handle(HANDLE process_handle);
DWORD pid_from_thread_handle(HANDLE thread_handle);
DWORD tid_from_thread_handle(HANDLE thread_handle);
DWORD random();
DWORD randint(DWORD min, DWORD max);
BOOL is_directory_objattr(const OBJECT_ATTRIBUTES *obj);
void hide_module_from_peb(HMODULE module_handle);

uint32_t path_from_handle(HANDLE handle,
    wchar_t *path, uint32_t path_buffer_len);

uint32_t path_from_object_attributes(const OBJECT_ATTRIBUTES *obj,
    wchar_t *path, uint32_t buffer_length);

struct {
	wchar_t *hkcu_string;
	unsigned int len;
} g_hkcu;

void hkcu_init(void);

char *ensure_absolute_ascii_path(char *out, const char *in);
wchar_t *ensure_absolute_unicode_path(wchar_t *out, const wchar_t *in);

wchar_t *get_key_path(POBJECT_ATTRIBUTES ObjectAttributes, PKEY_NAME_INFORMATION keybuf, unsigned int len);
wchar_t *get_full_key_pathA(HKEY registry, const char *in, PKEY_NAME_INFORMATION keybuf, unsigned int len);
wchar_t *get_full_key_pathW(HKEY registry, const wchar_t *in, PKEY_NAME_INFORMATION keybuf, unsigned int len);
wchar_t *get_full_keyvalue_pathA(HKEY registry, const char *in, PKEY_NAME_INFORMATION keybuf, unsigned int len);
wchar_t *get_full_keyvalue_pathW(HKEY registry, const wchar_t *in, PKEY_NAME_INFORMATION keybuf, unsigned int len);
wchar_t *get_full_keyvalue_pathUS(HKEY registry, const PUNICODE_STRING in, PKEY_NAME_INFORMATION keybuf, unsigned int len);

// imported but for some doesn't show up when #including string.h etc
int wcsnicmp(const wchar_t *a, const wchar_t *b, size_t len);
int wcsicmp(const wchar_t *a, const wchar_t *b);

int is_shutting_down();

// Define MAX_PATH plus tolerance for windows "tolerance"
#define MAX_PATH_PLUS_TOLERANCE MAX_PATH + 64

#define MAX_KEY_BUFLEN ((16384 + 256) * sizeof(WCHAR))

struct dll_range {
	ULONG_PTR start;
	ULONG_PTR end;
};
#define MAX_DLLS 100

BOOL is_in_dll_range(ULONG_PTR addr);
void add_all_dlls_to_dll_ranges(void);

wchar_t *get_matching_unicode_specialname(const wchar_t *path, unsigned int *matchlen);
void specialname_map_init(void);

char *convert_address_to_dll_name_and_offset(ULONG_PTR addr, unsigned int *offset);
int is_wow64_fs_redirection_disabled(void);
