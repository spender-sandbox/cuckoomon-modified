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

#include "ntapi.h"
#include <Windows.h>

enum {
	UWOP_PUSH_NONVOL = 0,
	UWOP_ALLOC_LARGE,
	UWOP_ALLOC_SMALL,
	UWOP_SET_FPREG,
	UWOP_SAVE_NONVOL,
	UWOP_SAVE_NONVOL_FAR,
	UWOP_SAVE_XMM,
	UWOP_SAVE_XMM_FAR,
	UWOP_SAVE_XMM128,
	UWOP_SAVE_XMM128_FAR,
	UWOP_PUSH_MACHFRAME
};

#ifndef UNW_FLAG_NHANDLER
#define UNW_FLAG_NHANDLER 0
#endif

typedef union _UNWIND_CODE {
	struct {
		BYTE CodeOffset;
		BYTE UnwindOp : 4;
		BYTE OpInfo : 4;
	};
	USHORT FrameOffset;
} UNWIND_CODE;

typedef struct _UNWIND_INFO {
	BYTE Version : 3;
	BYTE Flags : 5;
	BYTE SizeOfProlog;
	BYTE CountOfCodes;
	BYTE FrameRegister : 4;
	BYTE FrameOffset : 4;
	UNWIND_CODE UnwindCode[10];
} UNWIND_INFO;

typedef struct _hook_info_t {
	int disable_count;
	ULONG_PTR return_address;
	ULONG_PTR frame_pointer;
	ULONG_PTR main_caller_retaddr;
	ULONG_PTR parent_caller_retaddr;
} hook_info_t;

typedef struct _hook_data_t {
	unsigned char tramp[128];
	unsigned char pre_tramp[148];
	//unsigned char our_handler[128];
	unsigned char hook_data[32];

	UNWIND_INFO unwind_info;
} hook_data_t;

typedef struct _addr_map_t {
	ULONG_PTR map[32][2];
} addr_map_t;

typedef struct _hook_t {
    const wchar_t *library;
    const char *funcname;

    // instead of a library/funcname combination, an address can be given
    // as well (this address has more priority than library/funcname)
    void *addr;

    // pointer to the new function
    void *new_func;

    // "function" which jumps over the trampoline and executes the original
    // function call
    void **old_func;

    // allow hook recursion on this hook?
    // (see comments @ hook_create_pre_trampoline)
    int allow_hook_recursion;

    // this hook has been performed
    int is_hooked;

	hook_data_t *hookdata;
} hook_t;

typedef struct _lasterror_t {
	DWORD Win32Error;
	DWORD NtstatusError;
} lasterror_t;

int lde(void *addr);

hook_data_t *alloc_hookdata_near(void *addr);

int hook_api(hook_t *h, int type);

hook_info_t* hook_info();
void hook_enable();
void hook_disable();
int called_by_hook(void);
int addr_in_our_dll_range(ULONG_PTR addr);
void get_lasterrors(lasterror_t *errors);
void set_lasterrors(lasterror_t *errors);
int WINAPI enter_hook(uint8_t is_special_hook, ULONG_PTR _ebp, ULONG_PTR retaddr);
void emit_rel(unsigned char *buf, unsigned char *source, unsigned char *target);
int operate_on_backtrace(ULONG_PTR retaddr, ULONG_PTR _ebp, int(*func)(ULONG_PTR));

extern LARGE_INTEGER time_skipped;

#define HOOK_BACKTRACE_DEPTH 40

#define HOOK_ENABLE_FPU 0

#ifndef _WIN64
enum {
    HOOK_JMP_DIRECT,
    HOOK_NOP_JMP_DIRECT,
    HOOK_HOTPATCH_JMP_DIRECT,
    HOOK_PUSH_RETN,
    HOOK_NOP_PUSH_RETN,
    HOOK_JMP_INDIRECT,
    HOOK_MOV_EAX_JMP_EAX,
    HOOK_MOV_EAX_PUSH_RETN,
    HOOK_MOV_EAX_INDIRECT_JMP_EAX,
    HOOK_MOV_EAX_INDIRECT_PUSH_RETN,
#if HOOK_ENABLE_FPU
    HOOK_PUSH_FPU_RETN,
#endif
    HOOK_SPECIAL_JMP,
	HOOK_NATIVE_JMP_INDIRECT,
	HOOK_HOTPATCH_JMP_INDIRECT,
    HOOK_TECHNIQUE_MAXTYPE,
};
#else
enum {
	HOOK_NATIVE_JMP_INDIRECT,
	HOOK_JMP_INDIRECT
};
#endif

static __inline PVOID get_peb(void)
{
#ifndef _WIN64
	return (PVOID)__readfsdword(0x30);
#else
	return (PVOID)__readgsqword(0x60);
#endif
}

static __inline ULONG_PTR get_stack_top(void)
{
#ifndef _WIN64
	return __readfsdword(0x04);
#else
	return __readgsqword(0x08);
#endif
}

static __inline ULONG_PTR get_stack_bottom(void)
{
#ifndef _WIN64
	return __readfsdword(0x08);
#else
	return __readgsqword(0x10);
#endif
}

#define HOOKDEF(return_value, calling_convention, apiname, ...) \
    return_value (calling_convention *Old_##apiname)(__VA_ARGS__); \
    return_value calling_convention New_##apiname(__VA_ARGS__)

#define HOOKDEF2(return_value, calling_convention, apiname, ...) \
    return_value (calling_convention *Old2_##apiname)(__VA_ARGS__); \
    return_value calling_convention New2_##apiname(__VA_ARGS__)

// each thread has a special 260-wchar counting unicode_string buffer in its
// thread information block, this is likely to be overwritten in certain
// functions, therefore we have this macro which copies it to the stack.
// (so we can use the unicode_string after executing the original function)
#define COPY_UNICODE_STRING(local_name, param_name) \
    UNICODE_STRING local_name = {0}; wchar_t local_name##_buf[260] = {0}; \
    local_name.Buffer = local_name##_buf; \
    if (param_name != NULL && param_name->Length < 520) { \
        local_name.Length = param_name->Length; \
        local_name.MaximumLength = param_name->Length; \
        memcpy(local_name.Buffer, param_name->Buffer, \
            local_name.Length); \
    }
