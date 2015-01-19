#ifndef __ALLOC_H
#define __ALLOC_H

#include <assert.h>

typedef NTSTATUS(WINAPI * _NtAllocateVirtualMemory)(
	_In_     HANDLE ProcessHandle,
	_Inout_  PVOID *BaseAddress,
	_In_     ULONG_PTR ZeroBits,
	_Inout_  PSIZE_T RegionSize,
	_In_     ULONG AllocationType,
	_In_     ULONG Protect);
typedef NTSTATUS(WINAPI * _NtFreeVirtualMemory)(
	_In_     HANDLE ProcessHandle,
	_Inout_  PVOID *BaseAddress,
	_Inout_  PSIZE_T RegionSize,
	_In_     ULONG FreeType);

extern _NtAllocateVirtualMemory pNtAllocateVirtualMemory;
extern _NtFreeVirtualMemory pNtFreeVirtualMemory;

#define USE_PRIVATE_HEAP

#ifdef USE_PRIVATE_HEAP
extern HANDLE g_heap;
static __inline void *cm_alloc(size_t size)
{
	return HeapAlloc(g_heap, 0, size);
}

static __inline void *cm_calloc(size_t count, size_t size)
{
	return HeapAlloc(g_heap, HEAP_ZERO_MEMORY, count * size);
}

static __inline void *cm_realloc(void *ptr, size_t size)
{
	return HeapReAlloc(g_heap, 0, ptr, size);
}

static __inline void cm_free(void *ptr)
{
	HeapFree(g_heap, 0, ptr);
}
#else
struct cm_alloc_header {
	DWORD Magic;
	SIZE_T Used;
	SIZE_T Max;
};

#define CM_ALLOC_METASIZE		(sizeof(struct cm_alloc_header))
#define GET_CM_ALLOC_HEADER(x)	(struct cm_alloc_header *)((PCHAR)(x) - CM_ALLOC_METASIZE)
#define CM_ALLOC_MAGIC			0xdeadc01d

extern void *cm_alloc(size_t size);
extern void *cm_realloc(void *ptr, size_t size);
extern void cm_free(void *ptr);

static __inline void *cm_calloc(size_t count, size_t size)
{
	char *buf = cm_alloc(count * size);
	if (buf)
		memset(buf, 0, count * size);
	return buf;
}

#endif

static __inline char *cm_strdup(char *ptr)
{
	char *buf = cm_alloc(strlen(ptr) + 1);
	if (buf)
		strcpy(buf, ptr);
	return buf;
}

#define calloc	cm_calloc
#define malloc	cm_alloc
#define free	cm_free
#define realloc	cm_realloc
#define strdup	cm_strdup

#endif