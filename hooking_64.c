#ifdef _WIN64
/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2014 Accuvant, Inc. (bspengler@accuvant.com), Cuckoo Sandbox Developers

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

static csh capstone;

void init_capstone(void)
{
	cs_open(CS_ARCH_X86, CS_MODE_64, &capstone);
	cs_option(capstone, CS_OPT_DETAIL, CS_OPT_ON);
}

int lde(void *addr)
{
    cs_insn *insn;

    size_t ret = cs_disasm(capstone, addr, 16, (uintptr_t) addr, 1, &insn);
    if(ret == 0) return 0;

    ret = insn->size;

    cs_free(insn, 1);
    return (int)ret;
}

cs_insn *get_insn(void *addr)
{
	cs_insn *insn;
	size_t ret = cs_disasm(capstone, addr, 16, (uintptr_t)addr, 1, &insn);
	if (ret == 0)
		return NULL;
	return insn;
}

put_insn(cs_insn *insn)
{
	cs_free(insn, 1);
}

static unsigned char *emit_indirect_jmp(unsigned char *buf, ULONG_PTR addr)
{
	*buf++ = 0xff;
	*buf++ = 0x25;
	*(DWORD *)buf = 0;
	buf += sizeof(DWORD);
	*(ULONG_PTR *)buf = addr;
	buf += sizeof(ULONG_PTR);
	return buf;
}

static unsigned char *emit_indirect_call(unsigned char *buf, ULONG_PTR addr)
{
	*buf++ = 0xff;
	*buf++ = 0x15;
	*(DWORD *)buf = 2;
	buf += sizeof(DWORD);
	*buf++ = 0xeb;
	*buf++ = 0x08;
	*(ULONG_PTR *)buf = addr;
	buf += sizeof(ULONG_PTR);
	return buf;
}

static unsigned char *emit_indirect_jcc(unsigned char condcode, unsigned char *buf, ULONG_PTR addr)
{
	*buf++ = condcode;
	*buf++ = 2 + 4 + 8;

	*buf++ = 0xff;
	*buf++ = 0x25;
	*(DWORD *)buf = 0;
	buf += sizeof(DWORD);
	*(ULONG_PTR *)buf = (ULONG_PTR)buf + 2 + 4 + 8 + 8;
	buf += sizeof(ULONG_PTR);

	*buf++ = 0xff;
	*buf++ = 0x25;
	*(DWORD *)buf = 0;
	buf += sizeof(DWORD);
	*(ULONG_PTR *)buf = addr;
	buf += sizeof(ULONG_PTR);

	return buf;
}


static ULONG_PTR get_near_rel_target(unsigned char *buf)
{
	if (buf[0] == 0xe9 || buf[0] == 0xe8)
		return (ULONG_PTR)buf + 5 + *(int *)&buf[1];
	else if (buf[0] == 0x0f && buf[1] >= 0x80 && buf[1] < 0x90)
		return (ULONG_PTR)buf + 6 + *(int *)&buf[2];

	assert(false);
	return 0;
}

static ULONG_PTR get_short_rel_target(unsigned char *buf)
{
	if (buf[0] == 0xeb || buf[0] == 0xe3 || (buf[0] >= 0x70 && buf[0] < 0x80))
		return (ULONG_PTR)buf + 2 + *(char *)&buf[1];

	assert(false);
	return 0;
}

static ULONG_PTR get_corresponding_tramp_target(addr_map_t *map, ULONG_PTR addr)
{
	unsigned int i = 0;
	while (map->map[i][1]) {
		if (map->map[i][1] == addr)
			return map->map[i][0];
	}
	return 0;
}

static int addr_is_in_range(ULONG_PTR addr, const unsigned char *buf, DWORD size)
{
	ULONG_PTR start = (ULONG_PTR)buf;
	ULONG_PTR end = start + size;

	if (addr >= start && addr < end)
		return 1;
	return 0;
}

static void retarget_rip_relative_displacement(ULONG_PTR target, unsigned char **tramp, unsigned char **addr, cs_insn *insn)
{
	unsigned short length = insn->size;
	unsigned char offset = (unsigned char)(length - insn->detail->x86.imm_encoded_size - sizeof(int));
	unsigned char *newtramp = *tramp;
	unsigned char *newaddr = *addr;
	int rel = *(int *)(newaddr + offset);
	target = (ULONG_PTR)(newaddr + length + rel);
	// copy the instruction directly to the trampoline
	while (length-- != 0) {
		*newtramp++ = *newaddr++;
	}
	// now replace the displacement
	rel = (int)(target - (ULONG_PTR)newtramp);
	*(int *)(newtramp - insn->detail->x86.imm_encoded_size - sizeof(int)) = rel;

	*tramp = newtramp;
	*addr = newaddr;
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
	addr_map_t addrmap;
	ULONG_PTR target;
    const unsigned char *base = tramp;
	const unsigned char *origaddr = addr;
	unsigned char insnidx = 0;
	int stoleninstrlen = 0;
	cs_insn *insn;

	memset(&addrmap, 0, sizeof(addrmap));
	
	// our trampoline should contain at least enough bytes to fit the given
    // length
    while (len > 0) {
		insn = get_insn(addr);
		if (insn == NULL)
			goto error;
		int length = insn->size;

        // how many bytes left?
        len -= length;
		stoleninstrlen += length;

		addrmap.map[insnidx][0] = (ULONG_PTR)tramp;
		addrmap.map[insnidx][1] = (ULONG_PTR)addr;
		
		// check the type of instruction at this particular address, if it's
        // a jump or a call instruction, then we have to calculate some fancy
        // addresses, otherwise we can simply copy the instruction to our
        // trampoline

		if (addr[0] == 0xe8 || addr[0] == 0xe9 || (addr[0] == 0x0f && addr[1] >= 0x80 && addr[1] < 0x90) ||
			((insn->detail->x86.modrm & 0xc7) == 5)) {
			retarget_rip_relative_displacement(get_near_rel_target(addr), &tramp, &addr, insn);
			if (addr[0] == 0xe9 && len > 0)
				goto error;
		}

		else if (addr[0] == 0xeb) {
			target = get_short_rel_target(addr);
			if (addr_is_in_range(target, origaddr, stoleninstrlen))
				target = get_corresponding_tramp_target(&addrmap, target);
			tramp = emit_indirect_jmp(tramp, target);
			addr += length;
			if (len > 0)
				goto error;
		}
		else if (addr[0] == 0xe3 || ((addr[0] & 0xf0) == 0x70)) {
			target = get_short_rel_target(addr);
			if (addr_is_in_range(target, origaddr, stoleninstrlen))
				target = get_corresponding_tramp_target(&addrmap, target);
			tramp = emit_indirect_jcc(addr[0], tramp, target);
			addr += length;
		}
        // return instruction, indicates end of basic block as well, so we
        // have to check if we already have enough space for our hook..
        else if((addr[0] == 0xc3 || addr[0] == 0xc2) && len > 0) {
			goto error;
		}
        else {
            // copy the instruction directly to the trampoline
            while (length-- != 0) {
                *tramp++ = *addr++;
            }
        }
		put_insn(insn);
    }

	// append a jump from the trampoline to the original function
	*tramp++ = 0xe9;
	emit_rel(tramp, tramp, addr);
	tramp += 4;

	// return the length of this trampoline
    return (int)(tramp - base);
error:
	if (insn)
		put_insn(insn);
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
		0xff, 0x25, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
#endif
		// pushfq
		0x9c,
		// push rax/rcx/rdx/rbx
		0x50, 0x51, 0x52, 0x53,
		// push r8, r9, r10, r11
		0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,
		// cld
		0xfc,
		// mov r8, qword ptr [rsp+0x50]
		0x4c, 0x8b, 0x44, 0x24, 0x50,
		// mov rdx, rbp
		0x48, 0x8b, 0xd5,
		// mov ecx, h->allow_hook_recursion
		0xb9, h->allow_hook_recursion, 0x00, 0x00, 0x00,
		// sub rsp, 0x20
		0x48, 0x83, 0xec, 0x20,
		// call enter_hook, returns 0 if we should call the original func, otherwise 1 if we should call our New_ version
		0xff, 0x15, 0x02, 0x00, 0x00, 0x00,
		// jmp $+8
		0xeb, 0x08,
		// address of enter_hook
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	unsigned char pre_tramp2[] = {
		// test eax, eax
		0x85, 0xc0,
		// jnz 0x1f
		0x75, 0x1f,
			// add rsp, 0x20
			0x48, 0x83, 0xc4, 0x20,
			// pop r11, r10, r9, r8
			0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58,
			// pop rbx/rdx/rcx/rax
			0x5b, 0x5a, 0x59, 0x58,
			// popfq
			0x9d,
			// jmp h->tramp (original function)
			0xff, 0x25, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	unsigned char pre_tramp3[] = {
		// add rsp, 0x20
		0x48, 0x83, 0xc4, 0x20,
		// pop r11, r10, r9, r8
		0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58,
		// pop rbx/rdx/rcx/rax
		0x5b, 0x5a, 0x59, 0x58,
		// popfq
		0x9d,
		// jmp h->new_func (New_ func)
		0xff, 0x25, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

#if DISABLE_HOOK_CONTENT
	*(ULONG_PTR *)(pre_tramp1 + 6) = (ULONG_PTR)h->tramp;
#endif

	p = h->hookdata->pre_tramp;
	off = sizeof(pre_tramp1) - sizeof(ULONG_PTR);
	*(ULONG_PTR *)(pre_tramp1 + off) = (ULONG_PTR)&enter_hook;
	memcpy(p, pre_tramp1, sizeof(pre_tramp1));
	p += sizeof(pre_tramp1);

	off = sizeof(pre_tramp2) - sizeof(ULONG_PTR);
	*(ULONG_PTR *)(pre_tramp2 + off) = (ULONG_PTR)h->hookdata->tramp;
	memcpy(p, pre_tramp2, sizeof(pre_tramp2));
	p += sizeof(pre_tramp2);

	off = sizeof(pre_tramp3) - sizeof(ULONG_PTR);
	*(ULONG_PTR *)(pre_tramp3 + off) = (ULONG_PTR)h->new_func;
	memcpy(p, pre_tramp3, sizeof(pre_tramp3));
}

static int hook_api_jmp_indirect(hook_t *h, unsigned char *from,
    unsigned char *to)
{
    // jmp dword [hook_data]
    *from++ = 0xff;
    *from++ = 0x25;

    *(int *) from = (int)(h->hookdata->hook_data - ((ULONG_PTR)from + 4));

    // the real address is stored in hook_data
	memcpy(h->hookdata->hook_data, &to, sizeof(to));
    return 0;
}

static int hook_api_native_jmp_indirect(hook_t *h, unsigned char *from,
	unsigned char *to)
{
	// hook used for Native API functions where the second instruction specifies the syscall number
	// we'll leave in that mov instruction and repeat it before calling the original function
	from += 8;
	return hook_api_jmp_indirect(h, from, to);
}

hook_data_t *alloc_hookdata_near(void *addr)
{
	PVOID BaseAddress;
	int offset = -(1024 * 1024 * 1024);
	SIZE_T RegionSize = sizeof(hook_data_t);
	LONG status;

	do {
		if (offset < 0 && (ULONG_PTR)addr < (ULONG_PTR)-offset)
			offset = 0x10000;
		BaseAddress = (PCHAR)addr + offset;
		status = pNtAllocateVirtualMemory(GetCurrentProcess(), &BaseAddress, 0, &RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (status >= 0)
			return (hook_data_t *)BaseAddress;
		offset += 0x10000;
	} while (status < 0 && offset <= (1024 * 1024 * 1024));

	return NULL;
}

int hook_api(hook_t *h, int type)
{
    // table with all possible hooking types
    static struct {
        int(*hook)(hook_t *h, unsigned char *from, unsigned char *to);
        int len;
    } hook_types[] = {
		/* HOOK_NATIVE_JMP_INDIRECT */ {&hook_api_native_jmp_indirect, 14 },
		/* HOOK_JMP_INDIRECT */{ &hook_api_jmp_indirect, 6 },
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

	if (!wcscmp(h->library, L"ntdll") && !memcmp(addr, "\x4c\x8b\xd1\xb8", 4)) {
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

		h->hookdata = alloc_hookdata_near(addr);

		if (h->hookdata && hook_create_trampoline(addr, hook_types[type].len, h->hookdata->tramp)) {
			//hook_store_exception_info(h);
			uint8_t orig[16];
			memcpy(orig, addr, 16);

			hook_create_pre_tramp(h);

			// insert the hook (jump from the api to the
			// pre-trampoline)
			ret = hook_types[type].hook(h, addr, h->hookdata->pre_tramp);

			// Add unhook detection for our newly created hook.
			// Ensure any changes behind our hook are also catched by
			// making the buffersize 16.
			unhook_detect_add_region(h->funcname, addr, orig, addr, 16);

			// if successful, assign the trampoline address to *old_func
			if (ret == 0) {
				*h->old_func = h->hookdata->tramp;

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

#endif