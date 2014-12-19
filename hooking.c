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
#include <stddef.h>
#include "ntapi.h"
#include "capstone/include/capstone.h"
#include "capstone/include/x86.h"
#include "hooking.h"
#include "ignore.h"
#include "unhook.h"
#include "misc.h"
#include "pipe.h"

extern DWORD g_tls_hook_index;

// do not change this number
#define TLS_LAST_ERROR 0x34


// length disassembler engine
int lde(void *addr)
{
    static int capstone_init = 0; static csh capstone;

    if(capstone_init == 0) {
        cs_open(CS_ARCH_X86, CS_MODE_32, &capstone);
        capstone_init = 1;
    }

    cs_insn *insn;

    size_t ret = cs_disasm_ex(capstone, addr, 16, (uintptr_t) addr, 1, &insn);
    if(ret == 0) return 0;

    ret = insn->size;

    cs_free(insn, 1);
    return ret;
}

static void emit_rel(unsigned char *buf, unsigned char *source, unsigned char *target)
{
	*(DWORD *)buf = (DWORD)(target - (source + 4));
}

// need to be very careful about what we call in here, as it can be called in the context of any hook
// including those that hold the loader lock

static int set_caller_info(unsigned int addr)
{
	hook_info_t *hookinfo = hook_info();

	if (!is_in_dll_range(addr)) {
		if (hookinfo->main_caller_retaddr == 0)
			hookinfo->main_caller_retaddr = addr;
		else {
			hookinfo->parent_caller_retaddr = addr;
			return 1;
		}
	}
	return 0;
}

static int addr_in_our_dll_range(unsigned int addr)
{
	if (addr >= g_our_dll_base && addr < (g_our_dll_base + g_our_dll_size))
		return 1;
	return 0;
}

static int operate_on_backtrace(unsigned int retaddr, unsigned int _ebp, int (*func)(unsigned int))
{
	hook_info_t *hookinfo = hook_info();
	int ret;

    unsigned int top = __readfsdword(0x04);
    unsigned int bottom = __readfsdword(0x08);

    unsigned int count = HOOK_BACKTRACE_DEPTH;

	ret = func(retaddr);
	if (ret)
		return ret;

	while (_ebp >= bottom && _ebp <= (top - 8) && count-- != 0)
	{
        // obtain the return address and the next value of ebp
		ULONG_PTR addr = *(unsigned int *)(_ebp + 4);
		_ebp = *(unsigned int *)_ebp;

		ret = func(addr);
		if (ret)
			return ret;
    }

	return ret;
}

// create a trampoline at the given address, that is, we are going to replace
// the original instructions at this particular address. So, in order to
// call the original function from our hook, we have to execute the original
// instructions *before* jumping into addr+offset, where offset is the length
// which totals the size of the instructions which we place in the `tramp'.
// returns 0 on failure, or a positive integer defining the size of the tramp
// NOTE: tramp represents the memory address where the trampoline will be
// placed, copying it to another memory address will result into failure
static int hook_create_trampoline(unsigned char *addr, int len,
    unsigned char *tramp)
{
    const unsigned char *base = tramp;

    // our trampoline should contain at least enough bytes to fit the given
    // length
    while (len > 0) {

        // obtain the length of this instruction
        int length = lde(addr);

        // error?
        if(length == 0) {
            return 0;
        }

        // how many bytes left?
        len -= length;

        // check the type of instruction at this particular address, if it's
        // a jump or a call instruction, then we have to calculate some fancy
        // addresses, otherwise we can simply copy the instruction to our
        // trampoline

        // it's a (conditional) jump or call with 32bit relative offset
        if(*addr == 0xe9 || *addr == 0xe8 || (*addr == 0x0f &&
                addr[1] >= 0x80 && addr[1] < 0x90)) {

            // copy the jmp or call instruction (conditional jumps are two
            // bytes, the rest is one byte)
            *tramp++ = *addr++;
            if(addr[-1] != 0xe9 && addr[-1] != 0xe8) {
                *tramp++ = *addr++;
            }

            // when a jmp/call is performed, then the relative offset +
            // the instruction pointer + the size of the instruction is the
            // calculated address, so that's our target address as well.
            // (note that `addr' is already increased by one or two, so the
            // 4 represents the 32bit offset of this particular instruction)
            unsigned long jmp_addr = *(int *) addr + 4 +
                (unsigned long) addr;
            addr += 4;

            // trampoline is already filled with the opcode itself (the jump
            // instruction), now we will actually jump to the location by
            // calculating the relative offset which points to the real
            // address (this is the reverse operation of the one to calculate
            // the absolute address of a jump)
            *(unsigned long *) tramp = jmp_addr - (unsigned long) tramp - 4;
            tramp += 4;

            // because an unconditional jump denotes the end of a basic block
            // we will return failure if we have not yet processed enough room
            // to store our hook code
            if(tramp[-5] == 0xe9 && len > 0) return 0;
        }
        // (conditional) jump with 8bit relative offset
        else if(*addr == 0xeb || (*addr >= 0x70 && *addr < 0x80)) {

            // same rules apply as with the 32bit relative offsets, except
            // for the fact that both conditional and unconditional 8bit
            // relative jumps take only one byte for the opcode

            // 8bit relative offset, we have to sign-extend it (by casting it
            // as signed char) in order to calculate the correct address
            unsigned long jmp_addr = (unsigned long) addr + 2 +
                *(signed char *)(addr + 1);

            // the chance is *fairly* high that we will not be able to perform
            // a jump from the trampoline to the original function, so instead
            // we will use 32bit relative offset jumps
            if(*addr == 0xeb) {
                *tramp++ = 0xe9;
            }
            else {
                // hex representation of the two types of 32bit jumps
                // 8bit relative conditional jumps:     70..80
                // 32bit relative conditional jumps: 0f 80..90
                // so we will simply add 0x10 to the opcode of 8bit relative
                // offset jump to obtain the 32bit relative offset jump opcode
                *tramp++ = 0x0f;
                *tramp++ = *addr + 0x10;
            }

            // calculate the correct relative offset address
            *(unsigned long *) tramp = jmp_addr - (unsigned long) tramp - 4;
            tramp += 4;

            // again, end of basic block, check for length
            if(*addr == 0xeb && len > 0) {
                return 0;
            }

            // add the instruction length
            addr += 2;
        }
        // return instruction, indicates end of basic block as well, so we
        // have to check if we already have enough space for our hook..
        else if((*addr == 0xc3 || *addr == 0xc2) && len > 0) {
            return 0;
        }
        else {
            // copy the instruction directly to the trampoline
            while (length-- != 0) {
                *tramp++ = *addr++;
            }
        }
    }

    // append a jump from the trampoline to the original function
    *tramp++ = 0xe9;
	emit_rel(tramp, tramp, addr);
    tramp += 4;

	// return the length of this trampoline
    return tramp - base;
}

int called_by_hook(void)
{
	hook_info_t *hookinfo = hook_info();

	return operate_on_backtrace(hookinfo->return_address, hookinfo->frame_pointer, addr_in_our_dll_range);
}

// returns 1 if we should call our hook, 0 if we should call the original function instead
static int WINAPI enter_hook(uint8_t is_special_hook, unsigned int _ebp, unsigned int retaddr)
{
	hook_info_t *hookinfo = hook_info();

	hookinfo->return_address = retaddr;
	hookinfo->frame_pointer = _ebp;

	/* set caller information */
	hookinfo->main_caller_retaddr = 0;
	hookinfo->parent_caller_retaddr = 0;
	operate_on_backtrace(retaddr, _ebp, set_caller_info);

	if ((!called_by_hook() || is_special_hook) && (hookinfo->disable_count < 1))
		return 1;
	return 0;
}

// this function constructs the so-called pre-trampoline, this pre-trampoline
// determines if a hook should really be executed. An example will be the
// easiest; imagine we have a hook on CreateProcessInternalW() and on
// NtCreateProcessEx() (this is actually the case currently), now, if all goes
// well, a call to CreateProcess() will call CreateProcessInternalW() followed
// by a call to NtCreateProcessEx(). Because we already hook the higher-level
// API CreateProcessInternalW() it is not really useful to us to log the
// information retrieved in the NtCreateProcessEx() function as well,
// therefore, because one is called by the other, we can tell the hooking
// engine "once inside a hook, don't hook further API calls" by setting the
// allow_hook_recursion flag to false. The example above is what happens when
// the hook recursion is not allowed.
static void hook_create_pre_tramp(hook_t *h)
{
	unsigned char *p;
	unsigned int off;

	unsigned char pre_tramp1[] = {
#if DISABLE_HOOK_CONTENT
		0xe9, 0x00, 0x00, 0x00, 0x00,
#endif
		// pushf
		0x9c,
		// pusha
		0x60,
		// cld
		0xfc,
		// push dword ptr [esp+36]
		0xff, 0x74, 0x24, 0x24,
		// push ebp
		0x55,
		// push h->allow_hook_recursion
		0x6a, h->allow_hook_recursion,
		// call enter_hook, returns 0 if we should call the original func, otherwise 1 if we should call our New_ version
		0xe8, 0x00, 0x00, 0x00, 0x00
	};
	unsigned char pre_tramp2[] = {
		// test eax, eax
		0x85, 0xc0,
		// popad
		0x61,
		// jnz 0x6
		0x75, 0x06,
			// popf
			0x9d,
			// jmp h->tramp (original function)
			0xe9, 0x00, 0x00, 0x00, 0x00
	};
	unsigned char pre_tramp3[] = {
		// popf
		0x9d,
		// jmp h->new_func (New_ func)
		0xe9, 0x00, 0x00, 0x00, 0x00
	};

#if DISABLE_HOOK_CONTENT
	emit_rel(pre_tramp1 + 1, h->pre_tramp + 1, h->tramp);
#endif

	p = h->pre_tramp;
	off = sizeof(pre_tramp1) - sizeof(unsigned int);
	emit_rel(pre_tramp1 + off, p + off, (unsigned char *)&enter_hook);
	memcpy(p, pre_tramp1, sizeof(pre_tramp1));
	p += sizeof(pre_tramp1);

	off = sizeof(pre_tramp2) - sizeof(unsigned int);
	emit_rel(pre_tramp2 + off, p + off, h->tramp);
	memcpy(p, pre_tramp2, sizeof(pre_tramp2));
	p += sizeof(pre_tramp2);

	off = sizeof(pre_tramp3) - sizeof(unsigned int);
	emit_rel(pre_tramp3 + off, p + off, h->new_func);
	memcpy(p, pre_tramp3, sizeof(pre_tramp3));
}

static int hook_api_jmp_direct(hook_t *h, unsigned char *from,
    unsigned char *to)
{
    // unconditional jump opcode
    *from = 0xe9;

    // store the relative address from this opcode to our hook function
    *(unsigned long *)(from + 1) = (unsigned char *) to - from - 5;
    return 0;
}

static int hook_api_nop_jmp_direct(hook_t *h, unsigned char *from,
    unsigned char *to)
{
    // nop
    *from++ = 0x90;

    return hook_api_jmp_direct(h, from, to);
}

static int hook_api_hotpatch_jmp_direct(hook_t *h, unsigned char *from,
    unsigned char *to)
{
    // mov edi, edi
    *from++ = 0x8b;
    *from++ = 0xff;

    return hook_api_jmp_direct(h, from, to);
}

static int hook_api_push_retn(hook_t *h, unsigned char *from,
    unsigned char *to)
{
    // push addr
    *from++ = 0x68;
    *(unsigned char **) from = to;

    // retn
    from[4] = 0xc3;

    return 0;
}

static int hook_api_nop_push_retn(hook_t *h, unsigned char *from,
    unsigned char *to)
{
    // nop
    *from++ = 0x90;

    return hook_api_push_retn(h, from, to);
}

static int hook_api_jmp_indirect(hook_t *h, unsigned char *from,
    unsigned char *to)
{
    // jmp dword [hook_data]
    *from++ = 0xff;
    *from++ = 0x25;

    *(unsigned char **) from = h->hook_data;

    // the real address is stored in hook_data
    memcpy(h->hook_data, &to, sizeof(to));
    return 0;
}

static int hook_api_hotpatch_jmp_indirect(hook_t *h, unsigned char *from,
	unsigned char *to)
{
	// mov edi, edi
	*from++ = 0x8b;
	*from++ = 0xff;

	return hook_api_jmp_indirect(h, from, to);
}

static int hook_api_mov_eax_jmp_eax(hook_t *h, unsigned char *from,
    unsigned char *to)
{
    // mov eax, address
    *from++ = 0xb8;
    *(unsigned char **) from = to;
    from += 4;

    // jmp eax
    *from++ = 0xff;
    *from++ = 0xe0;
    return 0;
}

static int hook_api_mov_eax_push_retn(hook_t *h, unsigned char *from,
    unsigned char *to)
{
    // mov eax, address
    *from++ = 0xb8;
    *(unsigned char **) from = to;
    from += 4;

    // push eax
    *from++ = 0x50;

    // retn
    *from++ = 0xc3;
    return 0;
}

static int hook_api_mov_eax_indirect_jmp_eax(hook_t *h, unsigned char *from,
    unsigned char *to)
{
    // mov eax, [hook_data]
    *from++ = 0xa1;
    *(unsigned char **) from = h->hook_data;
    from += 4;

    // store the address at hook_data
    memcpy(h->hook_data, &to, sizeof(to));

    // jmp eax
    *from++ = 0xff;
    *from++ = 0xe0;
    return 0;
}

static int hook_api_mov_eax_indirect_push_retn(hook_t *h, unsigned char *from,
    unsigned char *to)
{
    // mov eax, [hook_data]
    *from++ = 0xa1;
    *(unsigned char **) from = h->hook_data;
    from += 4;

    // store the address at hook_data
    memcpy(h->hook_data, &to, sizeof(to));

    // push eax
    *from++ = 0x50;

    // retn
    *from++ = 0xc3;
    return 0;
}

#if HOOK_ENABLE_FPU
static int hook_api_push_fpu_retn(hook_t *h, unsigned char *from,
    unsigned char *to)
{
    // push ebp
    *from++ = 0x55;

    // fld qword [hook_data]
    *from++ = 0xdd;
    *from++ = 0x05;

    *(unsigned char **) from = h->hook_data;
    from += 4;

    // fistp dword [esp]
    *from++ = 0xdb;
    *from++ = 0x1c;
    *from++ = 0xe4;

    // retn
    *from++ = 0xc3;

    // store the address as double
    double addr = (double) (unsigned long) to;
    memcpy(h->hook_data, &addr, sizeof(addr));
    return 0;
}
#endif

static int hook_api_special_jmp(hook_t *h, unsigned char *from,
    unsigned char *to)
{
    // our largest hook in use is currently 7 bytes. so we have to make sure
    // that this special hook (a hook that will be patched over again later)
    // is atleast seven bytes.
    *from++ = 0x90;
    *from++ = 0x90;
    return hook_api_jmp_direct(h, from, to);
}

static int hook_api_native_jmp_indirect(hook_t *h, unsigned char *from,
	unsigned char *to)
{
	// hook used for Native API functions where the first instruction specifies the syscall number
	// we'll leave in that mov instruction and repeat it before calling the original function
	from += 5;
	return hook_api_jmp_indirect(h, from, to);
}

int hook_api(hook_t *h, int type)
{
    // table with all possible hooking types
    static struct {
        int(*hook)(hook_t *h, unsigned char *from, unsigned char *to);
        int len;
    } hook_types[] = {
        /* HOOK_JMP_DIRECT */ {&hook_api_jmp_direct, 5},
        /* HOOK_NOP_JMP_DIRECT */ {&hook_api_nop_jmp_direct, 6},
        /* HOOK_HOTPATCH_JMP_DIRECT */ {&hook_api_hotpatch_jmp_direct, 7},
        /* HOOK_PUSH_RETN */ {&hook_api_push_retn, 6},
        /* HOOK_NOP_PUSH_RETN */ {&hook_api_nop_push_retn, 7},
        /* HOOK_JMP_INDIRECT */ {&hook_api_jmp_indirect, 6},
        /* HOOK_MOV_EAX_JMP_EAX */ {&hook_api_mov_eax_jmp_eax, 7},
        /* HOOK_MOV_EAX_PUSH_RETN */ {&hook_api_mov_eax_push_retn, 7},
        /* HOOK_MOV_EAX_INDIRECT_JMP_EAX */
            {&hook_api_mov_eax_indirect_jmp_eax, 7},
        /* HOOK_MOV_EAX_INDIRECT_PUSH_RETN */
            {&hook_api_mov_eax_indirect_push_retn, 7},
#if HOOK_ENABLE_FPU
        /* HOOK_PUSH_FPU_RETN */ {&hook_api_push_fpu_retn, 11},
#endif
        /* HOOK_SPECIAL_JMP */ {&hook_api_special_jmp, 7},
		/* HOOK_NATIVE_JMP_INDIRECT */ {&hook_api_native_jmp_indirect, 11 },
		/* HOOK_HOTPATCH_JMP_INDIRECT */{ &hook_api_hotpatch_jmp_indirect, 8 },
	};

    // is this address already hooked?
    if(h->is_hooked != 0) {
        return 0;
    }

    // resolve the address to hook
    unsigned char *addr = h->addr;

    if(addr == NULL && h->library != NULL && h->funcname != NULL) {
        addr = (unsigned char *) GetProcAddress(GetModuleHandleW(h->library),
            h->funcname);
    }
    if(addr == NULL) {
		// function doesn't exist in this DLL, not a critical error
		return 0;
    }

	int ret = -1;

	// determine whether we're running under win7, if so, we might have to
	// follow a short relative jmp and an indirect jump before reaching
	// the real address
	OSVERSIONINFO os_info = { sizeof(OSVERSIONINFO) };
	if (GetVersionEx(&os_info) && os_info.dwMajorVersion == 6 &&
		os_info.dwMinorVersion == 1) {
		// windows 7 has a DLL called kernelbase.dll which basically acts
		// as a layer between the program and kernel32 (and related?) it
		// allows easy hotpatching of a set of functions which is why
		// there's a short relative jump and an indirect jump. we want to
		// resolve the address of the real function, so we follow these
		// two jumps.
		if (!memcmp(addr, "\xeb\x05", 2) &&
			!memcmp(addr + 7, "\xff\x25", 2)) {

			// Add unhook detection for this region.
			unhook_detect_add_region(h->funcname,
				addr, addr, addr, 7 + 6);

			addr = **(unsigned char ***)(addr + 9);
		}

		// Some functions don't just have the short jump and indirect
		// jump, but also an empty function prolog
		// ("mov edi, edi ; push ebp ; mov ebp, esp ; pop ebp"). Other
		// than that, this edge case is equivalent to the case above.
		else if (!memcmp(addr, "\x8b\xff\x55\x8b\xec\x5d\xeb\x05", 8) &&
			!memcmp(addr + 13, "\xff\x25", 2)) {
			addr = **(unsigned char ***)(addr + 15);
		}

		// the following applies for "inlined" functions on windows 7,
		// some functions are inlined into kernelbase.dll, rather than
		// kernelbase.dll jumping to e.g. kernel32.dll. for these
		// functions there is a short relative jump, followed by the
		// inlined function.
		if (!memcmp(addr, "\xeb\x02", 2) &&
			!memcmp(addr - 5, "\xcc\xcc\xcc\xcc\xcc", 5)) {

			// Add unhook detection for this region.
			unhook_detect_add_region(h->funcname,
				addr - 5, addr - 5, addr - 5, 5 + 2);

			// step over the short jump and the relative offset
			addr += 4;
		}
	}
	if (!wcscmp(h->library, L"ntdll") && addr[0] == 0xb8) {
		// hooking a native API, leave in the mov eax, <syscall nr> instruction
		// as some malware depends on this for direct syscalls
		// missing a few syscalls is better than crashing and getting no information
		// at all
		type = HOOK_NATIVE_JMP_INDIRECT;
	}

	// check if this is a valid hook type
	if (type < 0 && type >= ARRAYSIZE(hook_types)) {
		pipe("WARNING: Provided invalid hook type: %d", type);
		return ret;
	}

	DWORD old_protect;

	// make the address writable
	if (VirtualProtect(addr, hook_types[type].len, PAGE_EXECUTE_READWRITE,
		&old_protect)) {

		if (hook_create_trampoline(addr, hook_types[type].len, h->tramp)) {
			//hook_store_exception_info(h);
			uint8_t orig[16];
			memcpy(orig, addr, 16);

			hook_create_pre_tramp(h);

			// insert the hook (jump from the api to the
			// pre-trampoline)
			ret = hook_types[type].hook(h, addr, h->pre_tramp);

			// Add unhook detection for our newly created hook.
			// Ensure any changes behind our hook are also catched by
			// making the buffersize 16.
			unhook_detect_add_region(h->funcname, addr, orig, addr, 16);

			// if successful, assign the trampoline address to *old_func
			if (ret == 0) {
				*h->old_func = h->tramp;

				// successful hook is successful
				h->is_hooked = 1;
			}
		}
		else {
			pipe("WARNING:Unable to place hook on %z", h->funcname);
		}

		// restore the old protection
		VirtualProtect(addr, hook_types[type].len, old_protect,
			&old_protect);
	}
	else {
		pipe("WARNING:Unable to change protection for hook on %z", h->funcname);
	}

    return ret;
}

static DWORD our_getlasterror(void)
{
	char *teb = (char *)__readfsdword(0x18);

	return *(DWORD *)(teb + TLS_LAST_ERROR);
}

// we do our own version of this function to avoid the potential debug triggers
static void our_setlasterror(DWORD val)
{
	char *teb = (char *)__readfsdword(0x18);

	*(DWORD *)(teb + TLS_LAST_ERROR) = val;
}


hook_info_t *hook_info()
{
	hook_info_t *ptr;

	DWORD lasterror = our_getlasterror();

	ptr = (hook_info_t *)TlsGetValue(g_tls_hook_index);
	if (ptr == NULL) {
		// this wizardry allows us to hook NtAllocateVirtualMemory -- otherwise we'd crash from infinite
		// recursion if NtAllocateVirtualMemory was the first API we saw on a new thread
		char dummybuf[sizeof(hook_info_t)] = { 0 };

		hook_info_t *info = (hook_info_t *)&dummybuf;
		TlsSetValue(g_tls_hook_index, info);

		// now allocate the memory we need for the hook info struct without calling our hooks
		// shouldn't need to do the disable_count thanks to the new call stack inspection, but
		// it doesn't hurt
		info->disable_count++;
		hook_info_t *newinfo = (hook_info_t *)calloc(1, sizeof(hook_info_t));
		info->disable_count--;

		TlsSetValue(g_tls_hook_index, newinfo);
		ptr = newinfo;
	}

	our_setlasterror(lasterror);

	return ptr;
}

void hook_enable()
{
    hook_info()->disable_count--;
}

void hook_disable()
{
    hook_info()->disable_count++;
}
