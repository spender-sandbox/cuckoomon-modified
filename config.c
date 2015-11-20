/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2015 Cuckoo Sandbox Developers, Optiv, Inc. (brad.spengler@optiv.com)

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
#include "ntapi.h"
#include "config.h"
#include "misc.h"
#include "log.h"

int read_config(void)
{
    // TODO unicode support
    char buf[32768], config_fname[MAX_PATH];
	FILE *fp;
	unsigned int i;
	unsigned int vallen;

    sprintf(config_fname, "C:\\%u.ini", GetCurrentProcessId());

    fp = fopen(config_fname, "r");
	if (fp == NULL) {
		// for debugging purposes
		fp = fopen("C:\\config.ini", "r");
		if (fp == NULL)
			return 0;
	}

	g_config.force_sleepskip = -1;
	memset(buf, 0, sizeof(buf));
	while (fgets(buf, sizeof(buf), fp) != NULL)
	{
        // cut off the newline
        char *p = strchr(buf, '\r');
        if(p != NULL) *p = 0;
        p = strchr(buf, '\n');
        if(p != NULL) *p = 0;

        // split key=value
        p = strchr(buf, '=');
        if(p != NULL) {
			const char *key = buf, *value = p + 1;

			*p = 0;
			vallen = (unsigned int)strlen(value);
            if(!strcmp(key, "pipe")) {
				for (i = 0; i < vallen; i++)
					g_config.pipe_name[i] = (wchar_t)(unsigned short)value[i];
            }
			else if (!strcmp(key, "logserver")) {
				strncpy(g_config.logserver, value,
					ARRAYSIZE(g_config.logserver));
			}
			else if (!strcmp(key, "results")) {
                strncpy(g_config.results, value,
                    ARRAYSIZE(g_config.results));
            }
			else if (!strcmp(key, "file-of-interest")) {
				unsigned int len = (unsigned int)strlen(value);
				if (len > 1) {
					if (value[1] == ':') {
						// is a file
						char *tmp = calloc(1, MAX_PATH);
						wchar_t *utmp = calloc(1, MAX_PATH * sizeof(wchar_t));
						unsigned int full_len;

						ensure_absolute_ascii_path(tmp, value);
						full_len = (unsigned int)strlen(tmp);
						for (i = 0; i < full_len; i++)
							utmp[i] = (wchar_t)(unsigned short)tmp[i];
						free(tmp);

						g_config.file_of_interest = utmp;
						// if the file of interest is our own executable, then don't do any special handling
						if (wcsicmp(our_process_path, utmp))
							g_config.suspend_logging = TRUE;
					}
					else {
						// is a URL
						unsigned int url_len = (unsigned int)strlen(value);
						wchar_t *utmp = calloc(1, (url_len + 1) * sizeof(wchar_t));
						for (i = 0; i < url_len; i++)
							utmp[i] = (wchar_t)(unsigned short)value[i];
						g_config.url_of_interest = utmp;
						g_config.suspend_logging = TRUE;
					}
				}
			}
			else if (!strcmp(key, "referrer")) {
				unsigned int ref_len = (unsigned int)strlen(value);
				wchar_t *rtmp = calloc(1, (ref_len + 1) * sizeof(wchar_t));
				for (i = 0; i < ref_len; i++)
					rtmp[i] = (wchar_t)(unsigned short)value[i];
				g_config.w_referrer = rtmp;
				g_config.referrer = strdup(value);
			}
			else if (!strcmp(key, "analyzer")) {
                strncpy(g_config.analyzer, value,
                    ARRAYSIZE(g_config.analyzer)-2);
				strcat(g_config.analyzer, "\\");
				for (i = 0; i < ARRAYSIZE(g_config.analyzer); i++)
					g_config.w_analyzer[i] = (wchar_t)(unsigned short)g_config.analyzer[i];
				wcscpy(g_config.dllpath, g_config.w_analyzer);
				if (wcslen(g_config.dllpath) < ARRAYSIZE(g_config.dllpath) - 4)
					wcscat(g_config.dllpath, L"dll\\");
            }
            else if(!strcmp(key, "shutdown-mutex")) {
                strncpy(g_config.shutdown_mutex, value,
                    ARRAYSIZE(g_config.shutdown_mutex));
            }
            else if(!strcmp(key, "first-process")) {
                g_config.first_process = value[0] == '1';
            }
            else if(!strcmp(key, "startup-time")) {
                g_config.startup_time = atoi(value);
            }
			/*
			else if(!strcmp(key, "host-ip")) {
                g_config.host_ip = inet_addr(value);
            }
            else if(!strcmp(key, "host-port")) {
                g_config.host_port = atoi(value);
            }
			*/
            else if(!strcmp(key, "force-sleepskip")) {
                g_config.force_sleepskip = value[0] == '1';
            }
			else if (!strcmp(key, "serial")) {
				g_config.serial_number = (unsigned int)strtoul(value, NULL, 16);
			}
			else if (!strcmp(key, "sysvol_ctimelow")) {
				g_config.sysvol_ctime.dwLowDateTime = (unsigned int)strtoul(value, NULL, 16);
			}
			else if (!strcmp(key, "sysvol_ctimehigh")) {
				g_config.sysvol_ctime.dwHighDateTime = (unsigned int)strtoul(value, NULL, 16);
			}
			else if (!strcmp(key, "sys32_ctimelow")) {
				g_config.sys32_ctime.dwLowDateTime = (unsigned int)strtoul(value, NULL, 16);
			}
			else if (!strcmp(key, "sys32_ctimehigh")) {
				g_config.sys32_ctime.dwHighDateTime = (unsigned int)strtoul(value, NULL, 16);
			}
			else if (!strcmp(key, "full-logs")) {
				g_config.full_logs = value[0] == '1';
			}
			else if (!strcmp(key, "terminate-event")) {
				strncpy(g_config.terminate_event_name, value,
					ARRAYSIZE(g_config.terminate_event_name));
			}
			else if (!strcmp(key, "no-stealth")) {
				g_config.no_stealth = value[0] == '1';
			}
			else if (!strcmp(key, "buffer-max")) {
				buffer_log_max = (unsigned int)strtoul(value, NULL, 10);
			}
			else if (!strcmp(key, "large-buffer-max")) {
				large_buffer_log_max = (unsigned int)strtoul(value, NULL, 10);
			}
		}
    }

	/* don't suspend logging if this isn't the first process or if we want all the logs */
	if (!g_config.first_process || g_config.full_logs)
		g_config.suspend_logging = FALSE;

	fclose(fp);
    DeleteFileA(config_fname);
	return 1;
}
