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
#include "hooking.h"
#include "log.h"
#include "pipe.h"
#include "misc.h"
#include "ignore.h"
#include "lookup.h"
#include "config.h"

#define DUMP_FILE_MASK (GENERIC_WRITE | FILE_GENERIC_WRITE | \
    FILE_WRITE_DATA | FILE_APPEND_DATA | STANDARD_RIGHTS_WRITE | \
    STANDARD_RIGHTS_ALL)

// length of a hardcoded unicode string
#define UNILEN(x) (sizeof(x) / sizeof(wchar_t) - 1)

typedef struct _file_record_t {
    unsigned int attributes;
    size_t length;
    wchar_t filename[0];
} file_record_t;

static lookup_t g_files;

void file_init()
{
	specialname_map_init();

    lookup_init(&g_files);
}

static void new_file_path_ascii(const char *fname)
{
	char *absolutename = malloc(32768);
	if (absolutename != NULL) {
		unsigned int len;
		ensure_absolute_ascii_path(absolutename, fname);
		len = (unsigned int)strlen(absolutename);
		pipe("FILE_NEW:%s", len, absolutename);
	}
}

static void new_file_path_unicode(const wchar_t *fname)
{
	wchar_t *absolutename = malloc(32768 * sizeof(wchar_t));
	if (absolutename != NULL) {
		unsigned int len;
		ensure_absolute_unicode_path(absolutename, fname);
		len = lstrlenW(absolutename);
		pipe("FILE_NEW:%S", len, absolutename);
	}
}

static void new_file(const UNICODE_STRING *obj)
{
    const wchar_t *str = obj->Buffer;
    unsigned int len = obj->Length / sizeof(wchar_t);

    // maybe it's an absolute path (or a relative path with a harddisk,
    // such as C:abc.txt)
    if(isalpha(str[0]) != 0 && str[1] == ':') {
        pipe("FILE_NEW:%S", len, str);
    }
}

static void cache_file(HANDLE file_handle, const wchar_t *path,
    unsigned int length_in_chars, unsigned int attributes)
{
    file_record_t *r = lookup_add(&g_files, (unsigned int) file_handle,
        sizeof(file_record_t) + length_in_chars * sizeof(wchar_t) + sizeof(wchar_t));

	memset(r, 0, sizeof(*r));
	r->attributes = attributes;
	r->length = length_in_chars;

    wcsncpy(r->filename, path, r->length + 1);
}

void file_write(HANDLE file_handle)
{
	file_record_t *r;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	r = lookup_get(&g_files, (unsigned int)file_handle, NULL);
    if(r != NULL) {
		UNICODE_STRING str;
		str.Length = (USHORT)r->length * sizeof(wchar_t);
		str.MaximumLength = ((USHORT)r->length + 1) * sizeof(wchar_t);
		str.Buffer = r->filename;

        // we do in fact want to dump this file because it was written to
        new_file(&str);

        // delete the file record from the list
        lookup_del(&g_files, (unsigned int) file_handle);
    }

	set_lasterrors(&lasterror);
}

static void check_for_logging_resumption(const OBJECT_ATTRIBUTES *obj)
{
	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	if (g_config.file_of_interest && g_config.suspend_logging) {
		wchar_t *fname = calloc(1, 32768 * sizeof(wchar_t));
		wchar_t *absolutename = malloc(32768 * sizeof(wchar_t));
		BOOLEAN ret = FALSE;

		path_from_object_attributes(obj, fname, 32768);

		ensure_absolute_unicode_path(absolutename, fname);

		if (!wcsicmp(absolutename, g_config.file_of_interest))
			g_config.suspend_logging = FALSE;

		free(absolutename);
		free(fname);
	}

	set_lasterrors(&lasterror);
}

static void handle_new_file(HANDLE file_handle, const OBJECT_ATTRIBUTES *obj)
{
	lasterror_t lasterror;

	get_lasterrors(&lasterror);

    if(is_directory_objattr(obj) == 0) {

        wchar_t *fname = calloc(1, 32768 * sizeof(wchar_t));
		wchar_t *absolutename = calloc(1, 32768 * sizeof(wchar_t));

		path_from_object_attributes(obj, fname, 32768);

		if (absolutename != NULL) {
			unsigned int len;
			ensure_absolute_unicode_path(absolutename, fname);
			len = lstrlenW(absolutename);
			// cache this file
			if (is_ignored_file_unicode(absolutename, len) == 0)
				cache_file(file_handle, absolutename, len, obj->Attributes);
			free(absolutename);
		}
		else {
			if (is_ignored_file_objattr(obj) == 0)
				cache_file(file_handle, fname, lstrlenW(fname), obj->Attributes);
		}
		free(fname);
    }

	set_lasterrors(&lasterror);
}

void file_close(HANDLE file_handle)
{
	lasterror_t lasterror;

	get_lasterrors(&lasterror);
    lookup_del(&g_files, (unsigned int) file_handle);
	set_lasterrors(&lasterror);
}

static BOOLEAN is_protected_objattr(POBJECT_ATTRIBUTES obj)
{
	wchar_t path[MAX_PATH_PLUS_TOLERANCE];
	wchar_t *absolutepath = malloc(32768 * sizeof(wchar_t));
	if (absolutepath) {
		path_from_object_attributes(obj, path, MAX_PATH_PLUS_TOLERANCE);
		ensure_absolute_unicode_path(absolutepath, path);
		if (!wcsnicmp(g_config.w_analyzer, absolutepath, wcslen(g_config.w_analyzer))) {
			lasterror_t lasterror;
			lasterror.NtstatusError = STATUS_ACCESS_DENIED;
			lasterror.Win32Error = ERROR_ACCESS_DENIED;
			set_lasterrors(&lasterror);
			free(absolutepath);
			return TRUE;
		}
		free(absolutepath);
	}
	return FALSE;
}

HOOKDEF(NTSTATUS, WINAPI, NtCreateFile,
    __out     PHANDLE FileHandle,
    __in      ACCESS_MASK DesiredAccess,
    __in      POBJECT_ATTRIBUTES ObjectAttributes,
    __out     PIO_STATUS_BLOCK IoStatusBlock,
    __in_opt  PLARGE_INTEGER AllocationSize,
    __in      ULONG FileAttributes,
    __in      ULONG ShareAccess,
    __in      ULONG CreateDisposition,
    __in      ULONG CreateOptions,
    __in      PVOID EaBuffer,
    __in      ULONG EaLength
) {
	NTSTATUS ret;

	check_for_logging_resumption(ObjectAttributes);

	if (is_protected_objattr(ObjectAttributes))
		return STATUS_ACCESS_DENIED;

    ret = Old_NtCreateFile(FileHandle, DesiredAccess,
        ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes,
        ShareAccess | FILE_SHARE_READ, CreateDisposition, CreateOptions, EaBuffer, EaLength);
    LOQ_ntstatus("filesystem", "PhOiih", "FileHandle", FileHandle, "DesiredAccess", DesiredAccess,
        "FileName", ObjectAttributes, "CreateDisposition", CreateDisposition,
        "ShareAccess", ShareAccess, "FileAttributes", FileAttributes);
    if(NT_SUCCESS(ret) && DesiredAccess & DUMP_FILE_MASK) {
        handle_new_file(*FileHandle, ObjectAttributes);
    }
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtOpenFile,
    __out  PHANDLE FileHandle,
    __in   ACCESS_MASK DesiredAccess,
    __in   POBJECT_ATTRIBUTES ObjectAttributes,
    __out  PIO_STATUS_BLOCK IoStatusBlock,
    __in   ULONG ShareAccess,
    __in   ULONG OpenOptions
) {
	NTSTATUS ret;
	
	check_for_logging_resumption(ObjectAttributes);

	if (is_protected_objattr(ObjectAttributes))
		return STATUS_ACCESS_DENIED;

	ret = Old_NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
		IoStatusBlock, ShareAccess | FILE_SHARE_READ, OpenOptions);
	LOQ_ntstatus("filesystem", "PhOi", "FileHandle", FileHandle, "DesiredAccess", DesiredAccess,
        "FileName", ObjectAttributes, "ShareAccess", ShareAccess);
    if(NT_SUCCESS(ret) && DesiredAccess & DUMP_FILE_MASK) {
        handle_new_file(*FileHandle, ObjectAttributes);
    }
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtReadFile,
    __in      HANDLE FileHandle,
    __in_opt  HANDLE Event,
    __in_opt  PIO_APC_ROUTINE ApcRoutine,
    __in_opt  PVOID ApcContext,
    __out     PIO_STATUS_BLOCK IoStatusBlock,
    __out     PVOID Buffer,
    __in      ULONG Length,
    __in_opt  PLARGE_INTEGER ByteOffset,
    __in_opt  PULONG Key
) {
    NTSTATUS ret = Old_NtReadFile(FileHandle, Event, ApcRoutine, ApcContext,
        IoStatusBlock, Buffer, Length, ByteOffset, Key);
	wchar_t *fname = calloc(32768, sizeof(wchar_t));

	path_from_handle(FileHandle, fname, 32768);

	LOQ_ntstatus("filesystem", "pFbl", "FileHandle", FileHandle,
		"HandleName", fname, "Buffer", IoStatusBlock->Information, Buffer, "Length", IoStatusBlock->Information);

	free(fname);

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtWriteFile,
    __in      HANDLE FileHandle,
    __in_opt  HANDLE Event,
    __in_opt  PIO_APC_ROUTINE ApcRoutine,
    __in_opt  PVOID ApcContext,
    __out     PIO_STATUS_BLOCK IoStatusBlock,
    __in      PVOID Buffer,
    __in      ULONG Length,
    __in_opt  PLARGE_INTEGER ByteOffset,
    __in_opt  PULONG Key
) {
    NTSTATUS ret = Old_NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext,
        IoStatusBlock, Buffer, Length, ByteOffset, Key);
	wchar_t *fname = calloc(32768, sizeof(wchar_t));

	path_from_handle(FileHandle, fname, 32768);

	LOQ_ntstatus("filesystem", "pFbl", "FileHandle", FileHandle,
		"HandleName", fname, "Buffer", IoStatusBlock->Information, Buffer, "Length", IoStatusBlock->Information);

	free(fname);
	
	if(NT_SUCCESS(ret)) {
        file_write(FileHandle);
    }
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtDeleteFile,
    __in  POBJECT_ATTRIBUTES ObjectAttributes
) {
	wchar_t path[MAX_PATH_PLUS_TOLERANCE];
	wchar_t *absolutepath = malloc(32768 * sizeof(wchar_t));
	NTSTATUS ret;

	path_from_object_attributes(ObjectAttributes, path, MAX_PATH_PLUS_TOLERANCE);
	ensure_absolute_unicode_path(absolutepath, path);

	pipe("FILE_DEL:%Z", absolutepath);

    ret = Old_NtDeleteFile(ObjectAttributes);
	LOQ_ntstatus("filesystem", "u", "FileName", absolutepath);

	free(absolutepath);

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtDeviceIoControlFile,
    __in   HANDLE FileHandle,
    __in   HANDLE Event,
    __in   PIO_APC_ROUTINE ApcRoutine,
    __in   PVOID ApcContext,
    __out  PIO_STATUS_BLOCK IoStatusBlock,
    __in   ULONG IoControlCode,
    __in   PVOID InputBuffer,
    __in   ULONG InputBufferLength,
    __out  PVOID OutputBuffer,
    __in   ULONG OutputBufferLength
) {
    NTSTATUS ret = Old_NtDeviceIoControlFile(FileHandle, Event,
        ApcRoutine, ApcContext, IoStatusBlock, IoControlCode,
        InputBuffer, InputBufferLength, OutputBuffer,
        OutputBufferLength);
	LOQ_ntstatus("device", "phbb", "FileHandle", FileHandle,
		"IoControlCode", IoControlCode,
        "InputBuffer", InputBufferLength, InputBuffer,
        "OutputBuffer", IoStatusBlock->Information, OutputBuffer);

	/* Fake harddrive size to 256GB */
	if (NT_SUCCESS(ret) && OutputBuffer && OutputBufferLength >= sizeof(GET_LENGTH_INFORMATION) && IoControlCode == IOCTL_DISK_GET_LENGTH_INFO) {
		((PGET_LENGTH_INFORMATION)OutputBuffer)->Length.QuadPart = 256060514304L;
	}
	/* fake model name */
	if (NT_SUCCESS(ret) && IoControlCode == IOCTL_STORAGE_QUERY_PROPERTY && OutputBuffer && OutputBufferLength > 4) {
		ULONG i;
		for (i = 0; i < OutputBufferLength - 4; i++) {
			if (!memcmp(&((PCHAR)OutputBuffer)[i], "QEMU", 4))
				memcpy(&((PCHAR)OutputBuffer)[i], "DELL", 4);
		}
	}
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQueryDirectoryFile,
    __in      HANDLE FileHandle,
    __in_opt  HANDLE Event,
    __in_opt  PIO_APC_ROUTINE ApcRoutine,
    __in_opt  PVOID ApcContext,
    __out     PIO_STATUS_BLOCK IoStatusBlock,
    __out     PVOID FileInformation,
    __in      ULONG Length,
    __in      FILE_INFORMATION_CLASS FileInformationClass,
    __in      BOOLEAN ReturnSingleEntry,
    __in_opt  PUNICODE_STRING FileName,
    __in      BOOLEAN RestartScan
) {
	OBJECT_ATTRIBUTES objattr;
	NTSTATUS ret;

	memset(&objattr, 0, sizeof(objattr));
	objattr.ObjectName = FileName;
	objattr.RootDirectory = FileHandle;

    ret = Old_NtQueryDirectoryFile(FileHandle, Event,
        ApcRoutine, ApcContext, IoStatusBlock, FileInformation,
        Length, FileInformationClass, ReturnSingleEntry,
        FileName, RestartScan);
	/* don't log the resulting buffer, otherwise we can't turn these calls into simple duplicates */
	if (FileInformationClass == FileNamesInformation) {
		LOQ_ntstatus("filesystem", "pOi", "FileHandle", FileHandle,
			"FileName", &objattr, "FileInformationClass", FileInformationClass);
	}
	else {
		LOQ_ntstatus("filesystem", "pbOi", "FileHandle", FileHandle,
			"FileInformation", IoStatusBlock->Information, FileInformation,
			"FileName", &objattr, "FileInformationClass", FileInformationClass);
	}
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQueryInformationFile,
    __in   HANDLE FileHandle,
    __out  PIO_STATUS_BLOCK IoStatusBlock,
    __out  PVOID FileInformation,
    __in   ULONG Length,
    __in   FILE_INFORMATION_CLASS FileInformationClass
) {
    NTSTATUS ret = Old_NtQueryInformationFile(FileHandle, IoStatusBlock,
        FileInformation, Length, FileInformationClass);
	LOQ_ntstatus("filesystem", "pib", "FileHandle", FileHandle, "FileInformationClass", FileInformationClass,
        "FileInformation", IoStatusBlock->Information, FileInformation);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQueryAttributesFile,
	__in   POBJECT_ATTRIBUTES ObjectAttributes,
	__out  PFILE_BASIC_INFORMATION FileInformation
) {
	NTSTATUS ret = Old_NtQueryAttributesFile(ObjectAttributes, FileInformation);
	LOQ_ntstatus("filesystem", "O", "FileName", ObjectAttributes);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQueryFullAttributesFile,
	__in   POBJECT_ATTRIBUTES ObjectAttributes,
	__out  PFILE_NETWORK_OPEN_INFORMATION FileInformation
) {
	NTSTATUS ret = Old_NtQueryFullAttributesFile(ObjectAttributes, FileInformation);
	LOQ_ntstatus("filesystem", "O", "FileName", ObjectAttributes);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtSetInformationFile,
    __in   HANDLE FileHandle,
    __out  PIO_STATUS_BLOCK IoStatusBlock,
    __in   PVOID FileInformation,
    __in   ULONG Length,
    __in   FILE_INFORMATION_CLASS FileInformationClass
) {
	wchar_t *fname = calloc(32768, sizeof(wchar_t));
	NTSTATUS ret;

	path_from_handle(FileHandle, fname, 32768);
	
	if(FileInformation != NULL && Length == sizeof(BOOLEAN) &&
            FileInformationClass == FileDispositionInformation &&
            *(BOOLEAN *) FileInformation != FALSE) {
		pipe("FILE_DEL:%F", fname);
    }

    ret = Old_NtSetInformationFile(FileHandle, IoStatusBlock,
        FileInformation, Length, FileInformationClass);
	LOQ_ntstatus("filesystem", "pFib", "FileHandle", FileHandle, "HandleName", fname, "FileInformationClass", FileInformationClass,
        "FileInformation", Length, FileInformation);

	free(fname);

    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtOpenDirectoryObject,
    __out  PHANDLE DirectoryHandle,
    __in   ACCESS_MASK DesiredAccess,
    __in   POBJECT_ATTRIBUTES ObjectAttributes
) {
    NTSTATUS ret = Old_NtOpenDirectoryObject(DirectoryHandle, DesiredAccess,
        ObjectAttributes);
	LOQ_ntstatus("filesystem", "PhO", "DirectoryHandle", DirectoryHandle,
        "DesiredAccess", DesiredAccess, "ObjectAttributes", ObjectAttributes);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtCreateDirectoryObject,
    __out  PHANDLE DirectoryHandle,
    __in   ACCESS_MASK DesiredAccess,
    __in   POBJECT_ATTRIBUTES ObjectAttributes
) {
    NTSTATUS ret = Old_NtCreateDirectoryObject(DirectoryHandle, DesiredAccess,
        ObjectAttributes);
	LOQ_ntstatus("filesystem", "PhO", "DirectoryHandle", DirectoryHandle,
        "DesiredAccess", DesiredAccess, "ObjectAttributes", ObjectAttributes);
    return ret;
}

HOOKDEF(BOOL, WINAPI, CreateDirectoryW,
    __in      LPWSTR lpPathName,
    __in_opt  LPSECURITY_ATTRIBUTES lpSecurityAttributes
) {
    BOOL ret = Old_CreateDirectoryW(lpPathName, lpSecurityAttributes);
	LOQ_bool("filesystem", "F", "DirectoryName", lpPathName);
    return ret;
}

HOOKDEF(BOOL, WINAPI, CreateDirectoryExW,
    __in      LPWSTR lpTemplateDirectory,
    __in      LPWSTR lpNewDirectory,
    __in_opt  LPSECURITY_ATTRIBUTES lpSecurityAttributes
) {
    BOOL ret = Old_CreateDirectoryExW(lpTemplateDirectory, lpNewDirectory,
        lpSecurityAttributes);
	LOQ_bool("filesystem", "F", "DirectoryName", lpNewDirectory);
    return ret;
}

HOOKDEF(BOOL, WINAPI, RemoveDirectoryA,
    __in  LPCSTR lpPathName
) {
	char path[MAX_PATH];
	BOOL ret;

	ensure_absolute_ascii_path(path, lpPathName);

    ret = Old_RemoveDirectoryA(lpPathName);
	LOQ_bool("filesystem", "s", "DirectoryName", path);

    return ret;
}

HOOKDEF(BOOL, WINAPI, RemoveDirectoryW,
    __in  LPWSTR lpPathName
) {
	wchar_t *path = malloc(32768 * sizeof(wchar_t));
	BOOL ret;

	ensure_absolute_unicode_path(path, lpPathName);

    ret = Old_RemoveDirectoryW(lpPathName);
	LOQ_bool("filesystem", "u", "DirectoryName", path);

	free(path);

    return ret;
}

HOOKDEF(BOOL, WINAPI, MoveFileWithProgressW,
    __in      LPWSTR lpExistingFileName,
    __in_opt  LPWSTR lpNewFileName,
    __in_opt  LPPROGRESS_ROUTINE lpProgressRoutine,
    __in_opt  LPVOID lpData,
    __in      DWORD dwFlags
) {
	wchar_t *path = malloc(32768 * sizeof(wchar_t));
	BOOL ret;

	ensure_absolute_unicode_path(path, lpExistingFileName);

    ret = Old_MoveFileWithProgressW(lpExistingFileName, lpNewFileName,
        lpProgressRoutine, lpData, dwFlags);
	LOQ_bool("filesystem", "uFh", "ExistingFileName", path,
        "NewFileName", lpNewFileName, "Flags", dwFlags);
    if (ret != FALSE) {
		if (lpNewFileName)
			pipe("FILE_MOVE:%Z::%F", path, lpNewFileName);
		else {
			// we can do this here because it's not scheduled for deletion until reboot
			pipe("FILE_DEL:%Z", path);
		}

    }

	free(path);

	return ret;
}

HOOKDEF(HANDLE, WINAPI, FindFirstFileExA,
    __in        LPCSTR lpFileName,
    __in        FINDEX_INFO_LEVELS fInfoLevelId,
    __out       LPVOID lpFindFileData,
    __in        FINDEX_SEARCH_OPS fSearchOp,
    __reserved  LPVOID lpSearchFilter,
    __in        DWORD dwAdditionalFlags
) {
    HANDLE ret = Old_FindFirstFileExA(lpFileName, fInfoLevelId,
        lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
	LOQ_handle("filesystem", "f", "FileName", lpFileName);
    return ret;
}

HOOKDEF(HANDLE, WINAPI, FindFirstFileExW,
    __in        LPWSTR lpFileName,
    __in        FINDEX_INFO_LEVELS fInfoLevelId,
    __out       LPVOID lpFindFileData,
    __in        FINDEX_SEARCH_OPS fSearchOp,
    __reserved  LPVOID lpSearchFilter,
    __in        DWORD dwAdditionalFlags
) {
    HANDLE ret = Old_FindFirstFileExW(lpFileName, fInfoLevelId,
        lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
	LOQ_handle("filesystem", "F", "FileName", lpFileName);
    return ret;
}

HOOKDEF(BOOL, WINAPI, CopyFileA,
    __in  LPCSTR lpExistingFileName,
    __in  LPCSTR lpNewFileName,
    __in  BOOL bFailIfExists
) {
    BOOL ret = Old_CopyFileA(lpExistingFileName, lpNewFileName,
        bFailIfExists);
	LOQ_bool("filesystem", "ff", "ExistingFileName", lpExistingFileName,
        "NewFileName", lpNewFileName);

	if (ret)
		new_file_path_ascii(lpNewFileName);

    return ret;
}

HOOKDEF(BOOL, WINAPI, CopyFileW,
    __in  LPWSTR lpExistingFileName,
    __in  LPWSTR lpNewFileName,
    __in  BOOL bFailIfExists
) {
    BOOL ret = Old_CopyFileW(lpExistingFileName, lpNewFileName,
        bFailIfExists);
	LOQ_bool("filesystem", "FF", "ExistingFileName", lpExistingFileName,
        "NewFileName", lpNewFileName);

	if (ret)
		new_file_path_unicode(lpNewFileName);

	return ret;
}

HOOKDEF(BOOL, WINAPI, CopyFileExW,
    _In_      LPWSTR lpExistingFileName,
    _In_      LPWSTR lpNewFileName,
    _In_opt_  LPPROGRESS_ROUTINE lpProgressRoutine,
    _In_opt_  LPVOID lpData,
    _In_opt_  LPBOOL pbCancel,
    _In_      DWORD dwCopyFlags
) {
    BOOL ret = Old_CopyFileExW(lpExistingFileName, lpNewFileName,
        lpProgressRoutine, lpData, pbCancel, dwCopyFlags);
	LOQ_bool("filesystem", "FFi", "ExistingFileName", lpExistingFileName,
        "NewFileName", lpNewFileName, "CopyFlags", dwCopyFlags);

	if (ret)
		new_file_path_unicode(lpNewFileName);

	return ret;
}

HOOKDEF(BOOL, WINAPI, DeleteFileA,
    __in  LPCSTR lpFileName
) {
	char path[MAX_PATH];
	BOOL ret;

	ensure_absolute_ascii_path(path, lpFileName);
	
	pipe("FILE_DEL:%z", path);

    ret = Old_DeleteFileA(lpFileName);
	LOQ_bool("filesystem", "s", "FileName", path);

    return ret;
}

HOOKDEF(BOOL, WINAPI, DeleteFileW,
    __in  LPWSTR lpFileName
) {
	wchar_t *path = malloc(32768 * sizeof(wchar_t));
	BOOL ret;

	if (path) {
		ensure_absolute_unicode_path(path, lpFileName);

		pipe("FILE_DEL:%Z", path);
	}

    ret = Old_DeleteFileW(lpFileName);
	if (path) {
		LOQ_bool("filesystem", "u", "FileName", path);
		free(path);
	}
	else {
		LOQ_bool("filesystem", "u", "FileName", lpFileName);
	}
    return ret;
}

HOOKDEF(BOOL, WINAPI, GetDiskFreeSpaceExA,
    _In_opt_   PCSTR lpDirectoryName,
    _Out_opt_  PULARGE_INTEGER lpFreeBytesAvailable,
    _Out_opt_  PULARGE_INTEGER lpTotalNumberOfBytes,
    _Out_opt_  PULARGE_INTEGER lpTotalNumberOfFreeBytes
) {
    BOOL ret = Old_GetDiskFreeSpaceExA(lpDirectoryName, lpFreeBytesAvailable, lpTotalNumberOfBytes, lpTotalNumberOfFreeBytes);
	LOQ_bool("filesystem", "s", "DirectoryName", lpDirectoryName);
    return ret;
}

HOOKDEF(BOOL, WINAPI, GetDiskFreeSpaceExW,
    _In_opt_   PCWSTR lpDirectoryName,
    _Out_opt_  PULARGE_INTEGER lpFreeBytesAvailable,
    _Out_opt_  PULARGE_INTEGER lpTotalNumberOfBytes,
    _Out_opt_  PULARGE_INTEGER lpTotalNumberOfFreeBytes
) {
    BOOL ret = Old_GetDiskFreeSpaceExW(lpDirectoryName, lpFreeBytesAvailable, lpTotalNumberOfBytes, lpTotalNumberOfFreeBytes);
	LOQ_bool("filesystem", "u", "DirectoryName", lpDirectoryName);
    return ret;
}

HOOKDEF(BOOL, WINAPI, GetDiskFreeSpaceA,
    _In_   PCSTR lpRootPathName,
    _Out_  LPDWORD lpSectorsPerCluster,
    _Out_  LPDWORD lpBytesPerSector,
    _Out_  LPDWORD lpNumberOfFreeClusters,
    _Out_  LPDWORD lpTotalNumberOfClusters
) {
    BOOL ret = Old_GetDiskFreeSpaceA(lpRootPathName, lpSectorsPerCluster, lpBytesPerSector, lpNumberOfFreeClusters, lpTotalNumberOfClusters);
	LOQ_bool("filesystem", "s", "RootPathName", lpRootPathName);
    return ret;
}

HOOKDEF(BOOL, WINAPI, GetDiskFreeSpaceW,
    _In_   PCWSTR lpRootPathName,
    _Out_  LPDWORD lpSectorsPerCluster,
    _Out_  LPDWORD lpBytesPerSector,
    _Out_  LPDWORD lpNumberOfFreeClusters,
    _Out_  LPDWORD lpTotalNumberOfClusters
) {
    BOOL ret = Old_GetDiskFreeSpaceW(lpRootPathName, lpSectorsPerCluster, lpBytesPerSector, lpNumberOfFreeClusters, lpTotalNumberOfClusters);
	LOQ_bool("filesystem", "u", "RootPathName", lpRootPathName);
    return ret;
}

HOOKDEF(BOOL, WINAPI, GetVolumeNameForVolumeMountPointW,
	_In_ LPCWSTR lpszVolumeMountPoint,
	_Out_ LPWSTR lpszVolumeName,
	_In_ DWORD cchBufferLength
) {
	BOOL ret = Old_GetVolumeNameForVolumeMountPointW(lpszVolumeMountPoint, lpszVolumeName, cchBufferLength);
	LOQ_bool("filesystem", "uu", "VolumeMountPoint", lpszVolumeMountPoint, "VolumeName", lpszVolumeName);
	if (ret && lpszVolumeName && cchBufferLength > 4) {
		DWORD i;
		for (i = 0; i < cchBufferLength - 4; i++) {
			if (!memcmp(&lpszVolumeName[i], L"QEMU", 8))
				memcpy(&lpszVolumeName[i], L"DELL", 8);
		}
	}
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SHGetFolderPathW,
	_In_ HWND hwndOwner,
	_In_ int nFolder,
	_In_ HANDLE hToken,
	_In_ DWORD dwFlags,
	_Out_ LPWSTR pszPath
) {
	HRESULT ret = Old_SHGetFolderPathW(hwndOwner, nFolder, hToken, dwFlags, pszPath);
	LOQ_hresult("filesystem", "hu", "Folder", nFolder, "Path", pszPath);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetFileVersionInfoW,
	_In_        LPCWSTR lptstrFilename,
	_Reserved_  DWORD dwHandle,
	_In_        DWORD dwLen,
	_Out_       LPVOID lpData
) {
	BOOL ret = Old_GetFileVersionInfoW(lptstrFilename, dwHandle, dwLen, lpData);

	if (lptstrFilename && lstrlenW(lptstrFilename) > 3 && lptstrFilename[1] == L':' && lptstrFilename[2] == L'\\')
		LOQ_bool("filesystem", "F", "PathName", lptstrFilename);
	else
		LOQ_bool("filesystem", "u", "PathName", lptstrFilename);
	return ret;
}

HOOKDEF(DWORD, WINAPI, GetFileVersionInfoSizeW,
	_In_       LPCWSTR lptstrFilename,
	_Out_opt_  LPDWORD lpdwHandle
) {
	DWORD ret = Old_GetFileVersionInfoSizeW(lptstrFilename, lpdwHandle);

	if (lptstrFilename && lstrlenW(lptstrFilename) > 3 && lptstrFilename[1] == L':' && lptstrFilename[2] == L'\\')
		LOQ_nonzero("filesystem", "F", "PathName", lptstrFilename);
	else
		LOQ_nonzero("filesystem", "u", "PathName", lptstrFilename);

	return ret;
}