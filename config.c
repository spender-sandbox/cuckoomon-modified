/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2012 Cuckoo Sandbox Developers

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

int read_config(void)
{
    // TODO unicode support
    char buf[512], config_fname[MAX_PATH];
	FILE *fp;
	unsigned int i;

    sprintf(config_fname, "C:\\%u.ini", GetCurrentProcessId());

    fp = fopen(config_fname, "r");
	if (fp == NULL)
		return 0;

	g_config.force_sleepskip = -1;
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

            if(!strcmp(key, "pipe")) {
                strncpy(g_config.pipe_name, value,
                    ARRAYSIZE(g_config.pipe_name));
            }
            else if(!strcmp(key, "results")) {
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
						wchar_t *utmp = calloc(1, 512 * sizeof(wchar_t));
						unsigned int url_len = (unsigned int)strlen(value);
						for (i = 0; i < url_len; i++)
							utmp[i] = (wchar_t)(unsigned short)value[i];
						g_config.url_of_interest = utmp;
						g_config.suspend_logging = TRUE;
					}
				}
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
            else if(!strcmp(key, "host-ip")) {
                g_config.host_ip = inet_addr(value);
            }
            else if(!strcmp(key, "host-port")) {
                g_config.host_port = atoi(value);
            }
            else if(!strcmp(key, "force-sleepskip")) {
                g_config.force_sleepskip = value[0] == '1';
            }
			else if (!strcmp(key, "full-logs")) {
				g_config.full_logs = value[0] == '1';
			}
			else if (!strcmp(key, "terminate-event")) {
				strncpy(g_config.terminate_event_name, value,
					ARRAYSIZE(g_config.terminate_event_name));
			}
        }
    }

	/* don't suspend logging if this isn't the first process or if we want all the logs */
	if (!g_config.first_process || g_config.full_logs)
		g_config.suspend_logging = FALSE;

	fclose(fp);
    DeleteFile(config_fname);
	return 1;
}
