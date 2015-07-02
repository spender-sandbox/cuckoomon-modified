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
#include <distorm.h>
#include "hooking.h"
#include "ignore.h"
#include "unhook.h"
#include "misc.h"
#include "pipe.h"

extern DWORD g_tls_hook_index;

// do not change this number
#define TLS_LAST_ERROR 0x34

// length disassembler engine
static int lde(void *addr)
{
	// the length of an instruction is 16 bytes max, but there can also be
	// 16 instructions of length one, so.. we support "decomposing" 16
	// instructions at once, max
	unsigned int used_instruction_count; _DInst instructions[16];
	_CodeInfo code_info = { 0, 0, addr, 16, Decode64Bits };
	_DecodeResult ret = distorm_decompose(&code_info, instructions, 16,
		&used_instruction_count);

	return ret == DECRES_SUCCESS ? instructions[0].size : 0;
}


static _DInst *get_insn(void *addr)
{
	unsigned int used_instruction_count; _DInst instructions[16];
	_CodeInfo code_info = { 0, 0, addr, 16, Decode64Bits };
	_DecodeResult ret = distorm_decompose(&code_info, instructions, 16,
		&used_instruction_count);
	if (ret == DECRES_SUCCESS) {
		_DInst *insn = malloc(sizeof(_DInst));
		memcpy(insn, &instructions[0], sizeof(_DInst));
		return insn;
	}
	return NULL;
}

static void put_insn(_DInst *insn)
{
	free(insn);
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

	assert(0);
	return 0;
}

static ULONG_PTR get_short_rel_target(unsigned char *buf)
{
	if (buf[0] == 0xeb || buf[0] == 0xe3 || (buf[0] >= 0x70 && buf[0] < 0x80))
		return (ULONG_PTR)buf + 2 + *(char *)&buf[1];

	assert(0);
	return 0;
}

static ULONG_PTR get_indirect_target(unsigned char *buf)
{
	return *(ULONG_PTR *)(buf + 6 + *(int *)&buf[2]);
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

static void retarget_rip_relative_displacement(unsigned char **tramp, unsigned char **addr, _DInst *insn)
{
	unsigned short length = insn->size;
	unsigned char offset = (unsigned char)(length - insn->imm_encoded_size - sizeof(int));
	unsigned char *newtramp = *tramp;
	unsigned char *newaddr = *addr;
	ULONG_PTR target;
	int rel = *(int *)(newaddr + offset);
	target = (ULONG_PTR)(newaddr + length + rel);
	// copy the instruction directly to the trampoline
	while (length-- != 0) {
		*newtramp++ = *newaddr++;
	}
	// now replace the displacement
	rel = (int)(target - (ULONG_PTR)newtramp);
	*(int *)(newtramp - insn->imm_encoded_size - sizeof(int)) = rel;

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
	_DInst *insn;

	memset(&addrmap, 0, sizeof(addrmap));

	// our trampoline should contain at least enough bytes to fit the given
	// length
	while (len > 0) {
		int length;

		insn = get_insn(addr);
		if (insn == NULL)
			goto error;
		length = insn->size;

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
			(insn->flags & FLAG_RIP_RELATIVE)) {
			retarget_rip_relative_displacement(&tramp, &addr, insn);
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
		else if ((addr[0] == 0xc3 || addr[0] == 0xc2) && len > 0) {
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
	RUNTIME_FUNCTION *functable;
	UNWIND_INFO *unwindinfo;
	BYTE regs1[] = { 11, 10, 9, 8 };
	BYTE regs2[] = { 3, 2, 1, 0 };
	int i;

	unsigned char pre_tramp1[] = {
#if DISABLE_HOOK_CONTENT
		0xff, 0x25, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
#endif
		// push rax/rcx/rdx/rbx
		0x50, 0x51, 0x52, 0x53,
		// push r8, r9, r10, r11
		0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,
		// call $+0
		0xe8, 0x00, 0x00, 0x00, 0x00,
		// pop r8
		0x41, 0x58,
		// sub r8, 17
		0x49, 0x83, 0xe8, 0x11,
		// mov r8, qword ptr [rsp+0x40]
		// 0x4c, 0x8b, 0x44, 0x24, 0x40,
		// lea rdx, [rsp+0x40]
		0x48, 0x8d, 0x54, 0x24, 0x40,
		// mov ecx, h->allow_hook_recursion
		0xb9, h->allow_hook_recursion, 0x00, 0x00, 0x00,
		// sub rsp, 0x28
		0x48, 0x83, 0xec, 0x28,
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
		// jnz 0x1e
		0x75, 0x1e,
		// add rsp, 0x28
		0x48, 0x83, 0xc4, 0x28,
		// pop r11, r10, r9, r8
		0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58,
		// pop rbx/rdx/rcx/rax
		0x5b, 0x5a, 0x59, 0x58,
		// jmp h->tramp (original function)
		0xff, 0x25, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	unsigned char pre_tramp3[] = {
		// add rsp, 0x28
		0x48, 0x83, 0xc4, 0x28,
		// pop r11, r10, r9, r8
		0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58,
		// pop rbx/rdx/rcx/rax
		0x5b, 0x5a, 0x59, 0x58,
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

	/* now add the necessary unwind information so that stack traces work
	 * properly.  must be modified whenever the assembly above changes
	 */

	/* would be really nice if MSDN had any mention whatsoever that the RUNTIME_FUNCTION needs to have
	   a global allocation -- it doesn't copy the contents of the tiny 12-byte RUNTIME_FUNCTION, it merely
	   stores the same pointer you provide to the API.  If you allocate it on the stack, or call the API multiple
	   times with the same pointer value, you'll end up with completely broken unwind information that fails
	   in spectacular ways.
	 */
	functable = malloc(sizeof(RUNTIME_FUNCTION));
	unwindinfo = &h->hookdata->unwind_info;

	functable->BeginAddress = offsetof(hook_data_t, pre_tramp);
	functable->EndAddress = offsetof(hook_data_t, pre_tramp) + sizeof(h->hookdata->pre_tramp);
	functable->UnwindData = offsetof(hook_data_t, unwind_info);

	unwindinfo->Version = 1;
	unwindinfo->Flags = UNW_FLAG_NHANDLER;
	unwindinfo->SizeOfProlog = 38;
	unwindinfo->CountOfCodes = 9;
	unwindinfo->FrameRegister = 0;
	unwindinfo->FrameOffset = 0;

	unwindinfo->UnwindCode[0].UnwindOp = UWOP_ALLOC_SMALL;
	unwindinfo->UnwindCode[0].CodeOffset = 38;
	unwindinfo->UnwindCode[0].OpInfo = 4; // (4 + 1) * 8 = 0x28

	for (i = 0; i < ARRAYSIZE(regs1); i++) {
		unwindinfo->UnwindCode[1 + i].UnwindOp = UWOP_PUSH_NONVOL;
		unwindinfo->UnwindCode[1 + i].CodeOffset = 12 - (2 * i);
		unwindinfo->UnwindCode[1 + i].OpInfo = regs1[i];
	}

	for (i = 0; i < ARRAYSIZE(regs2); i++) {
		unwindinfo->UnwindCode[5 + i].UnwindOp = UWOP_PUSH_NONVOL;
		unwindinfo->UnwindCode[5 + i].CodeOffset = 4 - i;
		unwindinfo->UnwindCode[5 + i].OpInfo = regs2[i];
	}

	RtlAddFunctionTable(functable, 1, (DWORD64)h->hookdata);
}

static int hook_api_jmp_indirect(hook_t *h, unsigned char *from,
	unsigned char *to)
{
	// jmp dword [hook_data]
	*from++ = 0xff;
	*from++ = 0x25;

	*(int *)from = (int)(h->hookdata->hook_data - ((ULONG_PTR)from + 4));

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
	DWORD old_protect;
	int ret = -1;
	unsigned char *addr;
	OSVERSIONINFO os_info;
	// table with all possible hooking types
	static struct {
		int(*hook)(hook_t *h, unsigned char *from, unsigned char *to);
		int len;
	} hook_types[] = {
		/* HOOK_NATIVE_JMP_INDIRECT */{ &hook_api_native_jmp_indirect, 14 },
		/* HOOK_JMP_INDIRECT */{ &hook_api_jmp_indirect, 6 },
	};

	// is this address already hooked?
	if (h->is_hooked != 0) {
		return 0;
	}

	// resolve the address to hook
	addr = h->addr;

	if (addr == NULL && h->library != NULL && h->funcname != NULL) {
		if (!strcmp(h->funcname, "RtlDispatchException")) {
			// RtlDispatchException is the first relative call in KiUserExceptionDispatcher
			unsigned char *baseaddr = (unsigned char *)GetProcAddress(GetModuleHandleW(h->library), "KiUserExceptionDispatcher");
			int instroff = 0;
			while (baseaddr[instroff] != 0xe8) {
				instroff += lde(&baseaddr[instroff]);
			}
			addr = (unsigned char *)get_near_rel_target(&baseaddr[instroff]);
		}
		else if (!strcmp(h->funcname, "JsEval")) {
			HMODULE hmod = GetModuleHandleW(h->library);
			if (hmod)
				addr = (unsigned char *)get_jseval_addr(hmod);
		}
		else if (!strcmp(h->funcname, "COleScript_ParseScriptText")) {
			HMODULE hmod = GetModuleHandleW(h->library);
			if (hmod)
				addr = (unsigned char *)get_olescript_parsescripttext_addr(hmod);
		}
		else if (!strcmp(h->funcname, "CDocument_write")) {
			HMODULE hmod = GetModuleHandleW(h->library);
			if (hmod)
				addr = (unsigned char *)get_cdocument_write_addr(hmod);
		}
		else {
			addr = (unsigned char *)GetProcAddress(GetModuleHandleW(h->library), h->funcname);
		}
	}
	if (addr == NULL) {
		// function doesn't exist in this DLL, not a critical error
		return 0;
	}

	memset(&os_info, 0, sizeof(os_info));
	os_info.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	if (GetVersionEx(&os_info) && os_info.dwMajorVersion >= 6) {
		if (addr[0] == 0xeb) {
			PUCHAR target = (PUCHAR)get_short_rel_target(addr);
			unhook_detect_add_region(h->funcname, addr, addr, addr, 2);
			if (target[0] == 0xff && target[1] == 0x25) {
				PUCHAR origaddr = addr;
				addr = (PUCHAR)get_indirect_target(target);
				// handle delay-loaded DLL stubs
				if (!memcmp(addr, "\x48\x8d\x05", 3) && addr[7] == 0xe9) {
					// skip this particular hook, we'll hook the delay-loaded DLL at the time
					// is is loaded.  This means we will have duplicate "hook" entries
					// but to avoid any problems, we will check before hooking to see
					// if the final function has already been hooked
					return 0;
				}
				unhook_detect_add_region(h->funcname, target, target, target, 6);
			}
		}
		else if (addr[0] == 0xe9) {
			PUCHAR target = (PUCHAR)get_near_rel_target(addr);
			unhook_detect_add_region(h->funcname, addr, addr, addr, 5);
			if (target[0] == 0xff && target[1] == 0x25) {
				addr = (PUCHAR)get_indirect_target(target);
				// handle delay-loaded DLL stubs
				if (!memcmp(addr, "\x48\x8d\x05", 3) && addr[7] == 0xe9) {
					// skip this particular hook, we'll hook the delay-loaded DLL at the time
					// is is loaded.  This means we will have duplicate "hook" entries
					// but to avoid any problems, we will check before hooking to see
					// if the final function has already been hooked
					return 0;
				}
				unhook_detect_add_region(h->funcname, target, target, target, 6);
			}
			else {
				addr = target;
			}
		}
	}

	/*
	if (!wcscmp(h->library, L"ntdll") && !memcmp(addr, "\x4c\x8b\xd1\xb8", 4)) {
		// hooking a native API, leave in the mov eax, <syscall nr> instruction
		// as some malware depends on this for direct syscalls
		// missing a few syscalls is better than crashing and getting no information
		// at all
		type = HOOK_NATIVE_JMP_INDIRECT;
	}
	*/

	// check if this is a valid hook type
	if (type < 0 && type >= ARRAYSIZE(hook_types)) {
		pipe("WARNING: Provided invalid hook type: %d", type);
		return ret;
	}

	// make sure we aren't trying to hook the same address twice, as could
	// happen due to delay-loaded DLLs
	if (address_already_hooked(addr))
		return 0;
		
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
			unhook_detect_add_region(h->funcname, addr, orig, addr, hook_types[type].len);

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

static unsigned int our_stackwalk(ULONG_PTR retaddr, ULONG_PTR sp, PVOID *backtrace, unsigned int count)
{
	/* derived from http://www.nynaeve.net/Code/StackWalk64.cpp */
	CONTEXT ctx;
	DWORD64 imgbase;
	PRUNTIME_FUNCTION runfunc;
	KNONVOLATILE_CONTEXT_POINTERS nvctx;
	PVOID handlerdata;
	ULONG_PTR establisherframe;
	unsigned int frame;

	RtlCaptureContext(&ctx);

	for (frame = 0; frame < count; frame++) {

		backtrace[frame] = (PVOID)ctx.Rip;
		runfunc = RtlLookupFunctionEntry(ctx.Rip, &imgbase, NULL);
		memset(&nvctx, 0, sizeof(nvctx));
		if (runfunc == NULL) {
			ctx.Rip = (ULONG_PTR)(*(ULONG_PTR *)ctx.Rsp);
			ctx.Rsp += 8;
		}
		else {
			RtlVirtualUnwind(UNW_FLAG_NHANDLER, imgbase, ctx.Rip, runfunc, &ctx, &handlerdata, &establisherframe, &nvctx);
		}
		if (!ctx.Rip)
			break;
	}

	return frame + 1;
}

int operate_on_backtrace(ULONG_PTR retaddr, ULONG_PTR sp, int(*func)(ULONG_PTR))
{
	int ret;
	PVOID backtrace[HOOK_BACKTRACE_DEPTH];
	lasterror_t lasterror;
	WORD frames;
	WORD i;

	get_lasterrors(&lasterror);

	hook_disable();

	frames = our_stackwalk(retaddr, sp, backtrace, HOOK_BACKTRACE_DEPTH);

	for (i = 0; i < frames; i++) {
		if (!addr_in_our_dll_range((ULONG_PTR)backtrace[i]))
			break;
	}

	if (((PUCHAR)backtrace[i])[0] == 0xeb && ((PUCHAR)backtrace[i])[1] == 0x08)
		i++;

	for (; i < frames; i++) {
		ret = func((ULONG_PTR)backtrace[i]);
		if (ret)
			goto out;
	}

out:
	hook_enable();
	set_lasterrors(&lasterror);
	return ret;
}


#endif