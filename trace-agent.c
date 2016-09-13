/*
 * Copyright (C) 2016 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License (not later!)
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not,  see <http://www.gnu.org/licenses>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "trace-local.h"
#include "trace-msg.h"


static bool virt;

static struct tracecmd_msg_handle *setup_network(const char *host)
{
	return NULL;
}

static struct tracecmd_msg_handle *
communicate_with_listener_virt_agent(int fd)
{
	struct tracecmd_msg_handle *msg_handle;

	msg_handle = tracecmd_msg_handle_alloc(fd,
					TRACECMD_MSG_FL_CLIENT |
					TRACECMD_MSG_FL_VIRT |
					TRACECMD_MSG_FL_AGENT);
	if (!msg_handle)
		die("Failed to allocate message handle");

	if (tracecmd_msg_connect_to_server(msg_handle) < 0)
		die("Cannot communicate with server");

	if (tracecmd_msg_agent_connect(msg_handle) < 0)
		die("Cannot connect to server");

	return msg_handle;
}

static struct tracecmd_msg_handle *setup_virtio(void)
{
	int fd;

	fd = open(AGENT_CTL_PATH, O_RDWR);
	if (fd < 0)
		die("Cannot open %s", AGENT_CTL_PATH);

	return communicate_with_listener_virt_agent(fd);
}

enum {
	OPT_virt	= 254,
	OPT_debug	= 255,
};

void trace_agent(int argc, char **argv)
{
	struct tracecmd_msg_handle *msg_handle;
	char *host = NULL;
	int rt_prio = 0;

	int c;

	for (;;) {
		int option_index = 0;
		const char *opts;
		static struct option long_options[] = {
			{"virt", no_argument, NULL, OPT_virt},
			{"debug", no_argument, NULL, OPT_debug},
			{"help", no_argument, NULL, '?'},
			{NULL, 0, NULL, 0}
		};

		opts = "+hae:f:Fp:cC:dDGo:O:s:r:vg:l:n:P:N:tb:R:B:ksSiTm:M:H:";
		c = getopt_long (argc-1, argv+1, opts, long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			usage(argv);
			break;
		case 'r':
			rt_prio = atoi(optarg);
			break;
		case 'N':
			if (virt)
				die("-N can not be used with --virt");
			host = optarg;
			break;
		case OPT_virt:
			if (host)
				die("--virt can not be used with -N");
			virt = true;
			break;
		case OPT_debug:
			debug = 1;
			break;
		default:
			usage(argv);
		}
	}

	if (!host && !virt) {
		printf("must specify --virt or -N\n");
		usage(argv);
	}

	if (host)
		msg_handle = setup_network(host);
	else
		msg_handle = setup_virtio();

	
	return;
}
