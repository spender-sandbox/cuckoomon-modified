#include <Windows.h>
#include "alloc.h"

void *cm_alloc(size_t size)
{
	PVOID BaseAddress = NULL;
	SIZE_T RegionSize = size + CM_ALLOC_METASIZE + 0x1000;
	struct cm_alloc_header *hdr;
	DWORD oldprot;
	LONG status;
	
	status = pNtAllocateVirtualMemory(GetCurrentProcess(), &BaseAddress, 0, &RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (status < 0)
		return NULL;
	hdr = (struct cm_alloc_header *)BaseAddress;
	hdr->Magic = CM_ALLOC_MAGIC;
	hdr->Used = size + CM_ALLOC_METASIZE;
	hdr->Max = RegionSize - 0x1000;

	// add a guard page to the end of every allocation
	assert(VirtualProtect((PCHAR)BaseAddress + RegionSize - 0x1000, 0x1000, PAGE_NOACCESS, &oldprot));

	return (PCHAR)BaseAddress + CM_ALLOC_METASIZE;
}


void cm_free(void *ptr)
{
	PVOID BaseAddress;
	SIZE_T RegionSize;
	LONG status;
	struct cm_alloc_header *hdr;

	hdr = GET_CM_ALLOC_HEADER(ptr);

	assert(hdr->Magic == CM_ALLOC_MAGIC);
	BaseAddress = (PVOID)hdr;
	RegionSize = 0;
	status = pNtFreeVirtualMemory(GetCurrentProcess(), &BaseAddress, &RegionSize, MEM_RELEASE);
	assert(status >= 0);
}

void *cm_realloc(void *ptr, size_t size)
{
	struct cm_alloc_header *hdr;
	char *buf;

	hdr = GET_CM_ALLOC_HEADER(ptr);

	assert(hdr->Magic == CM_ALLOC_MAGIC);

	if (hdr->Max >= size) {
		hdr->Used = size + CM_ALLOC_METASIZE;
		return ptr;
	}
	buf = cm_alloc(size);
	if (buf == NULL)
		return buf;
	memcpy(buf, ptr, hdr->Used - CM_ALLOC_METASIZE);
	cm_free(ptr);
	return buf;
}
