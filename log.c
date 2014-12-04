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
#include <string.h>
#include <stdarg.h>
#include "ntapi.h"
#include "hooking.h"
#include "misc.h"
#include "utf8.h"
#include "log.h"
#include "bson.h"
#include "config.h"

// the size of the logging buffer
#define BUFFERSIZE 1024 * 1024
#define BUFFER_LOG_MAX 256

static CRITICAL_SECTION g_mutex;
static int g_sock;
static unsigned int g_starttick;

static char g_buffer[BUFFERSIZE];
static int g_idx;

// current to-be-logged API call
static bson g_bson[1];
static char g_istr[4];

static char logtbl_explained[256] = {0};

#define LOG_ID_PROCESS 0
#define LOG_ID_THREAD 1
#define LOG_ID_ANOMALY 2
int g_log_index = 10;  // index must start after the special IDs (see defines)

//
// Log API
//

static void log_raw_direct(const char *buf, size_t length) {
	if (g_sock == INVALID_SOCKET) {
		char filename[64];
		snprintf(filename, sizeof(filename), "c:\\debug%u.log", GetCurrentProcessId());
		// will happen when we're in debug mode
		FILE *f = fopen(filename, "ab");
		if (f) {
			fwrite(buf, length, 1, f);
			fclose(f);
		}
		return;
	}
    size_t sent = 0;
    int r;
    while (sent < length) {
        r = send(g_sock, buf+sent, length-sent, 0);
        if (r == -1) {
            fprintf(stderr, "send returned -1.\n");
            return;
        }
        sent += r;
    }
}

void debug_message(const char *msg) {
    bson b[1];
    bson_init( b );
    bson_append_string( b, "type", "debug" );
    bson_append_string( b, "msg", msg );
    bson_finish( b );
    log_raw_direct(bson_data( b ), bson_size( b ));
    bson_destroy( b );
}

/*
static void log_int8(char value)
{
    bson_append_int( g_bson, g_istr, value );
}

static void log_int16(short value)
{
    bson_append_int( g_bson, g_istr, value );
}
*/

static void log_int32(int value)
{
    bson_append_int( g_bson, g_istr, value );
}

static void log_string(const char *str, int length)
{
    if (str == NULL) {
        bson_append_string_n( g_bson, g_istr, "", 0 );
        return;
    }
    int ret;
    char * utf8s = utf8_string(str, length);
    int utf8len = * (int *) utf8s;
    ret = bson_append_binary( g_bson, g_istr, BSON_BIN_BINARY, utf8s+4, utf8len );
    if (ret == BSON_ERROR) {
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "dbg bson err string %x utf8len %d", g_bson->err, utf8len);
        debug_message(tmp);
    }
    free(utf8s);
}

static void log_wstring(const wchar_t *str, int length)
{
    if (str == NULL) {
        bson_append_string_n( g_bson, g_istr, "", 0 );
        return;
    }
    int ret;
    char * utf8s = utf8_wstring(str, length);
    int utf8len = * (int *) utf8s;
    ret = bson_append_binary( g_bson, g_istr, BSON_BIN_BINARY, utf8s+4, utf8len );
    if (ret == BSON_ERROR) {
        char tmp[64];
        snprintf(tmp, 64, "dbg bson err wstring %x utf8len %d", g_bson->err, utf8len);
        debug_message(tmp);
    }
    free(utf8s);
}

static void log_argv(int argc, const char ** argv) {
    bson_append_start_array( g_bson, g_istr );

    for (int i=0; i<argc; i++) {
        snprintf(g_istr, 4, "%u", i);
        log_string(argv[i], -1);
    }
    bson_append_finish_array( g_bson );
}

static void log_wargv(int argc, const wchar_t ** argv) {
    bson_append_start_array( g_bson, g_istr );

    for (int i=0; i<argc; i++) {
        snprintf(g_istr, 4, "%u", i);
        log_wstring(argv[i], -1);
    }

    bson_append_finish_array( g_bson );
}

static void log_buffer(const char *buf, size_t length) {
    size_t trunclength = min(length, BUFFER_LOG_MAX);

    if (buf == NULL) {
        trunclength = 0;
    }

    bson_append_binary( g_bson, g_istr, BSON_BIN_BINARY, buf, trunclength );
}

void loq(int index, const char *category, const char *name,
    int is_success, int return_value, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    const char * fmtbak = fmt;
    int argnum = 2;
    int count = 1; char key = 0;

	if (index >= LOG_ID_ANOMALY && g_config.suspend_logging)
		return;

	EnterCriticalSection(&g_mutex);

	if(logtbl_explained[index] == 0) {
        logtbl_explained[index] = 1;
        const char * pname;

        bson b[1];
        bson_init( b );
        bson_append_int( b, "I", index );
        bson_append_string( b, "name", name );
        bson_append_string( b, "type", "info" );
        bson_append_string( b, "category", category );

        bson_append_start_array( b, "args" );
        bson_append_string( b, "0", "is_success" );
        bson_append_string( b, "1", "retval" );

        while (--count != 0 || *fmt != 0) {
            // we have to find the next format specifier
            if(count == 0) {
                // end of format
                if(*fmt == 0) break;

                // set the count, possibly with a repeated format specifier
                count = *fmt >= '2' && *fmt <= '9' ? *fmt++ - '0' : 1;

                // the next format specifier
                key = *fmt++;
            }

            pname = va_arg(args, const char *);
            snprintf(g_istr, 4, "%u", argnum);
            argnum++;

            //on certain formats, we need to tell cuckoo about them for nicer display / matching
            if (key == 'p' || key == 'P') {
                bson_append_start_array( b, g_istr );
                bson_append_string( b, "0", pname );
                bson_append_string( b, "1", "p" );
                bson_append_finish_array( b );
            } else {
                bson_append_string( b, g_istr, pname );
            }

            //now ignore the values
            if(key == 's' || key == 'f') {
                (void) va_arg(args, const char *);
            }
            else if(key == 'S') {
                (void) va_arg(args, int);
                (void) va_arg(args, const char *);
            }
            else if(key == 'u' || key == 'F') {
                (void) va_arg(args, const wchar_t *);
            }
            else if(key == 'U') {
                (void) va_arg(args, int);
                (void) va_arg(args, const wchar_t *);
            }
			else if (key == 'e' || key == 'v') {
				(void)va_arg(args, HKEY);
				(void)va_arg(args, const char *);
			}
			else if (key == 'E' || key == 'V') {
				(void)va_arg(args, HKEY);
				(void)va_arg(args, const wchar_t *);
			}
			else if (key == 'k') {
				(void)va_arg(args, HKEY);
				(void)va_arg(args, const PUNICODE_STRING);
			}
			else if (key == 'b') {
                (void) va_arg(args, size_t);
                (void) va_arg(args, const char *);
            }
            else if(key == 'B') {
                (void) va_arg(args, size_t *);
                (void) va_arg(args, const char *);
            }
            else if(key == 'i') {
                (void) va_arg(args, int);
            }
            else if(key == 'l' || key == 'p') {
                (void) va_arg(args, long);
            }
            else if(key == 'L' || key == 'P') {
                (void) va_arg(args, long *);
            }
            else if(key == 'o') {
                (void) va_arg(args, UNICODE_STRING *);
            }
            else if(key == 'O' || key == 'K') {
                (void) va_arg(args, OBJECT_ATTRIBUTES *);
            }
            else if(key == 'a') {
                (void) va_arg(args, int);
                (void) va_arg(args, const char **);
            }
            else if(key == 'A') {
                (void) va_arg(args, int);
                (void) va_arg(args, const wchar_t **);
            }
            else if(key == 'r' || key == 'R') {
                (void) va_arg(args, unsigned long);
                (void) va_arg(args, unsigned long);
                (void) va_arg(args, unsigned char *);
            }

        }
        bson_append_finish_array( b );
        bson_finish( b );
        log_raw_direct(bson_data( b ), bson_size( b ));
        bson_destroy( b );
    }

    va_end(args);
    fmt = fmtbak;
    va_start(args, fmt);
    count = 1; key = 0; argnum = 2;

    bson_init( g_bson );
    bson_append_int( g_bson, "I", index );
	if (hook_info()) {
		hook_info_t *hookinfo = hook_info();
		bson_append_int(g_bson, "C", *(DWORD *)(hookinfo->retaddr_esp));
		// return location of malware callsite
		bson_append_int(g_bson, "R", (int)hookinfo->main_caller_retaddr);
		// return parent location of malware callsite
		bson_append_int(g_bson, "P", (int)hookinfo->parent_caller_retaddr);
	}
	bson_append_int(g_bson, "T", GetCurrentThreadId());
    bson_append_int( g_bson, "t", GetTickCount() - g_starttick );

	bson_append_start_array(g_bson, "args");
    bson_append_int( g_bson, "0", is_success );
    bson_append_int( g_bson, "1", return_value );

    while (--count != 0 || *fmt != 0) {

        // we have to find the next format specifier
        if(count == 0) {
            // end of format
            if(*fmt == 0) break;

            // set the count, possibly with a repeated format specifier
            count = *fmt >= '2' && *fmt <= '9' ? *fmt++ - '0' : 1;

            // the next format specifier
            key = *fmt++;
        }

        // pop the key and omit it
        (void) va_arg(args, const char *);
        snprintf(g_istr, 4, "%u", argnum);
        argnum++;

        // log the value
        if(key == 's') {
            const char *s = va_arg(args, const char *);
            if(s == NULL) s = "";
            log_string(s, -1);
        }
		else if (key == 'f') {
			const char *s = va_arg(args, const char *);
			char absolutepath[MAX_PATH];
			if (s == NULL) s = "";
			ensure_absolute_ascii_path(absolutepath, s);

			log_string(absolutepath, -1);
		}
        else if(key == 'S') {
            int len = va_arg(args, int);
            const char *s = va_arg(args, const char *);
            if(s == NULL) { s = ""; len = 0; }
            log_string(s, len);
        }
        else if(key == 'u') {
            const wchar_t *s = va_arg(args, const wchar_t *);
            if(s == NULL) s = L"";
            log_wstring(s, -1);
        }
		else if (key == 'F') {
			const wchar_t *s = va_arg(args, const wchar_t *);
			wchar_t *absolutepath = malloc(32768 * sizeof(wchar_t));
			if (s == NULL) s = L"";
			if (absolutepath) {
				ensure_absolute_unicode_path(absolutepath, s);
				log_wstring(absolutepath, -1);
				free(absolutepath);
			}
			else {
				log_wstring(L"", -1);
			}
		}
		else if (key == 'U') {
            int len = va_arg(args, int);
            const wchar_t *s = va_arg(args, const wchar_t *);
            if(s == NULL) { s = L""; len = 0; }
            log_wstring(s, len);
        }
        else if(key == 'b') {
            size_t len = va_arg(args, size_t);
            const char *s = va_arg(args, const char *);
            log_buffer(s, len);
        }
        else if(key == 'B') {
            size_t *len = va_arg(args, size_t *);
            const char *s = va_arg(args, const char *);
            log_buffer(s, len == NULL ? 0 : *len);
        }
        else if(key == 'i') {
            int value = va_arg(args, int);
            log_int32(value);
        }
        else if(key == 'l' || key == 'p') {
            long value = va_arg(args, long);
            log_int32(value);
        }
        else if(key == 'L' || key == 'P') {
            long *ptr = va_arg(args, long *);
            log_int32(ptr != NULL ? *ptr : 0);
        }
		else if (key == 'e') {
			HKEY reg = va_arg(args, HKEY);
			const char *s = va_arg(args, const char *);
			unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
			PKEY_NAME_INFORMATION keybuf = malloc(allocsize);

			log_wstring(get_full_key_pathA(reg, s, keybuf, allocsize), -1);
			free(keybuf);
		}
		else if (key == 'E') {
			HKEY reg = va_arg(args, HKEY);
			const wchar_t *s = va_arg(args, const wchar_t *);
			unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
			PKEY_NAME_INFORMATION keybuf = malloc(allocsize);

			log_wstring(get_full_key_pathW(reg, s, keybuf, allocsize), -1);
			free(keybuf);
		}
		else if (key == 'K') {
			OBJECT_ATTRIBUTES *obj = va_arg(args, OBJECT_ATTRIBUTES *);
			unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
			PKEY_NAME_INFORMATION keybuf = malloc(allocsize);

			log_wstring(get_key_path(obj, keybuf, allocsize), -1);
			free(keybuf);
		}
		else if (key == 'k') {
			HKEY reg = va_arg(args, HKEY);
			const PUNICODE_STRING s = va_arg(args, const PUNICODE_STRING);
			unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
			PKEY_NAME_INFORMATION keybuf = malloc(allocsize);

			log_wstring(get_full_keyvalue_pathUS(reg, s, keybuf, allocsize), -1);
			free(keybuf);
		}
		else if (key == 'v') {
			HKEY reg = va_arg(args, HKEY);
			const char *s = va_arg(args, const char *);
			unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
			PKEY_NAME_INFORMATION keybuf = malloc(allocsize);

			log_wstring(get_full_keyvalue_pathA(reg, s, keybuf, allocsize), -1);
			free(keybuf);
		}
		else if (key == 'V') {
			HKEY reg = va_arg(args, HKEY);
			const wchar_t *s = va_arg(args, const wchar_t *);
			unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
			PKEY_NAME_INFORMATION keybuf = malloc(allocsize);

			log_wstring(get_full_keyvalue_pathW(reg, s, keybuf, allocsize), -1);
			free(keybuf);
		}
		else if (key == 'o') {
            UNICODE_STRING *str = va_arg(args, UNICODE_STRING *);
            if(str == NULL) {
                log_string("", 0);
            }
            else {
                log_wstring(str->Buffer, str->Length / sizeof(wchar_t));
            }
        }
        else if(key == 'O') {
            OBJECT_ATTRIBUTES *obj = va_arg(args, OBJECT_ATTRIBUTES *);
            if(obj == NULL || obj->ObjectName == NULL) {
                log_string("", 0);
            }
			else {
				wchar_t path[MAX_PATH_PLUS_TOLERANCE];
				wchar_t *absolutepath = malloc(32768 * sizeof(wchar_t));
				if (absolutepath) {
					path_from_object_attributes(obj, path, MAX_PATH_PLUS_TOLERANCE);

					ensure_absolute_unicode_path(absolutepath, path);
					log_wstring(absolutepath, -1);
					free(absolutepath);
				}
				else {
					log_wstring(L"", -1);
				}
            }
        }
        else if(key == 'a') {
            int argc = va_arg(args, int);
            const char **argv = va_arg(args, const char **);
            log_argv(argc, argv);
        }
        else if(key == 'A') {
            int argc = va_arg(args, int);
            const wchar_t **argv = va_arg(args, const wchar_t **);
            log_wargv(argc, argv);
        }
        else if(key == 'r' || key == 'R') {
            unsigned long type = va_arg(args, unsigned long);
            unsigned long size = va_arg(args, unsigned long);
            unsigned char *data = va_arg(args, unsigned char *);

            // bson_append_start_object( g_bson, g_istr );
            // bson_append_int( g_bson, "type", type );

            // strncpy(g_istr, "val", 4);
            if(type == REG_NONE) {
                log_string("", 0);
            }
            else if(type == REG_DWORD || type == REG_DWORD_LITTLE_ENDIAN) {
                unsigned int value = *(unsigned int *) data;
                log_int32(value);
            }
            else if(type == REG_DWORD_BIG_ENDIAN) {
                unsigned int value = *(unsigned int *) data;
                log_int32(htonl(value));
            }
            else if(type == REG_EXPAND_SZ || type == REG_SZ) {

                if(data == NULL) {
                    bson_append_binary(g_bson, g_istr, BSON_BIN_BINARY,
                        (const char *) data, 0);
                }
                // ascii strings
                else if(key == 'r') {
					if (size >= 1 && data[size - 1] == '\0')
						log_string(data, size - 1);
					else
						log_string(data, size);
                    //bson_append_binary(g_bson, g_istr, BSON_BIN_BINARY,
                    //    (const char *) data, size);
                }
                // unicode strings
                else {
					const wchar_t *wdata = (const wchar_t *)data;
					if (size >= 2 && wdata[(size / sizeof(wchar_t)) - 1] == L'\0')
						log_wstring(wdata, (size / sizeof(wchar_t)) - 1);
					else
						log_wstring(wdata, size / sizeof(wchar_t));
                    //bson_append_binary(g_bson, g_istr, BSON_BIN_BINARY,
                    //    (const char *) data, size);
                }
            } else {
                bson_append_binary(g_bson, g_istr, BSON_BIN_BINARY,
                    (const char *) data, 0);
            }

            // bson_append_finish_object( g_bson );
        }
    }

    va_end(args);

    bson_append_finish_array( g_bson );
    bson_finish( g_bson );
    // if (bson_size( g_bson ) > BUFFERSIZE) {
    //     //DBGWARN, ignoring bson obj
    // } else {
        log_raw_direct(bson_data( g_bson ), bson_size( g_bson ));
    // }

    bson_destroy( g_bson );
    LeaveCriticalSection(&g_mutex);
}

void announce_netlog()
{
    char protoname[32];
    strcpy(protoname, "BSON\n");
    //sprintf(protoname+5, "logs/%lu.bson\n", GetCurrentProcessId());
    log_raw_direct(protoname, strlen(protoname));
}

void log_new_process()
{
    g_starttick = GetTickCount();

    FILETIME st;
    GetSystemTimeAsFileTime(&st);

    loq(LOG_ID_PROCESS, "__notification__", "__process__", 1, 0, "llllu",
        "TimeLow", st.dwLowDateTime,
        "TimeHigh", st.dwHighDateTime,
        "ProcessIdentifier", GetCurrentProcessId(),
        "ParentProcessIdentifier", parent_process_id(),
        "ModulePath", our_process_path);
}

void log_new_thread()
{
    loq(LOG_ID_THREAD, "__notification__", "__thread__", 1, 0, "l",
        "ProcessIdentifier", GetCurrentProcessId());
}

void log_anomaly(const char *subcategory, int success,
    const char *funcname, const char *msg)
{
    loq(LOG_ID_ANOMALY, "__notification__", "__anomaly__", success, 0, "lsss",
        "ThreadIdentifier", GetCurrentThreadId(),
        "Subcategory", subcategory,
        "FunctionName", funcname,
        "Message", msg);
}

void log_init(unsigned int ip, unsigned short port, int debug)
{
    InitializeCriticalSection(&g_mutex);

    if(debug != 0) {
        g_sock = INVALID_SOCKET;
    }
    else {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);

        g_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        struct sockaddr_in addr = {
            .sin_family         = AF_INET,
            .sin_addr.s_addr    = ip,
            .sin_port           = htons(port),
        };

        connect(g_sock, (struct sockaddr *) &addr, sizeof(addr));
    }

	announce_netlog();
    log_new_process();
    log_new_thread();
}

void log_free()
{
    DeleteCriticalSection(&g_mutex);
    if(g_sock != INVALID_SOCKET) {
        closesocket(g_sock);
		g_sock = INVALID_SOCKET;
    }
}
