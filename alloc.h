#ifndef __ALLOC_H
#define __ALLOC_H

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

#define calloc	cm_calloc
#define malloc	cm_alloc
#define free	cm_free
#define realloc	cm_realloc

#endif