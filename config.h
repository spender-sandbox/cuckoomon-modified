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

struct _g_config {
    // name of the pipe to communicate with cuckoo
    char pipe_name[MAX_PATH];

    // results directory, has to be hidden
    char results[MAX_PATH];

    // analyzer directory, has to be hidden
    char analyzer[MAX_PATH];

	// analyzer directory, has to be hidden
	wchar_t w_analyzer[MAX_PATH];

	// cuckoomon DLL directory
	wchar_t dllpath[MAX_PATH];

	// file of interest
	wchar_t *file_of_interest;
	
	// URL of interest
	wchar_t *url_of_interest;

	// if this mutex exists then we're shutting down
    char shutdown_mutex[MAX_PATH];

	// event set by analyzer when our process is potentially going to be terminated
	// cuckoomon itself will flush logs at this point, but the analyzer may take additional
	// actions, like process dumping
	char terminate_event_name[MAX_PATH];

    // is this the first process or not?
    int first_process;

    // how many milliseconds since startup
    unsigned int startup_time;

    // do we force sleep-skipping despite threads?
    int force_sleepskip;

    // server ip and port
    unsigned int host_ip;
    unsigned short host_port;

	BOOLEAN suspend_logging;
};

extern struct _g_config g_config;

int read_config(void);
