/*
 * Copyright (C) 2017 Red Hat Inc, Pratyush Anand <panand@redhat.com>
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
 * There are several scenarios where we land into oom-killer in the early
 * boot process, specially in a memory constrained environment. It becomes
 * very difficult to identify the user space task which required more
 * memory compared to their previous released versions. This interface is
 * an attempt to debug such issues, which will help us to identify peak
 * memory usage of each task. mm_page_alloc() and mm_page_free() are lowest
 * level of kernel APIs which allocates and frees memory from buddy. This
 * tool enables tracepoint of these two functions and then keeps track of
 * peak memory usage of each task.If a task was already running before this
 * tool was started then, it initializes peak memory of that task with
 * corresponding vmRSS component from /proc/$tid/statm
 * If task was insmod/modprobe then it also appends module name (max 16
 * char) in comm.
 *
 * There could still be some cma and memblock allocations which may not be
 * tracked using this tool. Moreover, this may not be the exact peak memory
 * estimation, rather an approximate value.
 *
 * usage:
 * $ trace-cmd top -s "/tmp/socket"
 *	It will start gather statistics of all the process which will be
 *	scheduled after this command execution.
 * $ trace-cmd top -p "/tmp/socket"
 *	It will print peak memory usage(in KB) against each scheduled task.
 * $ trace-cmd top -e "/tmp/socket"
 * It will print peak memory usage(in KB) against each scheduled task and
 * will stop gathering statistics. It will also kill the child process
 * initiated by -s option.
 */

#include <dirent.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "trace-local.h"
#include "trace-msg.h"
#include "kbuffer.h"

static struct pevent *pevent;
static struct kbuffer *kbuf;
static struct pevent_record *record;
static int kmem_mm_page_alloc_id;
static int kmem_mm_page_free_id;

struct top_task_stats {
	pid_t pid;
	long cur_mem;
	long peak_mem;
	char *comm;
};

static struct top_task_stats *top_task_stats;
static int top_task_cnt;

void top_disable_events(void)
{
	char *path;
	char c;
	int fd;
	int ret;

	/*
	 * WARNING: We want only few events related to memory allocation to
	 * be enabled. Disable all events here. Latter, selective events
	 * would be enabled
	 */
	c = '0';
	path = get_instance_file(&top_instance, "events/enable");
	fd = open(path, O_WRONLY);
	if (fd < 0)
		die("failed to open '%s'", path);
	ret = write(fd, &c, 1);
	close(fd);
	tracecmd_put_tracing_file(path);
	if (ret < 1)
		die("failed to write 0 to events/enable");

	path = get_instance_file(&top_instance, "tracing_on");
	fd = open(path, O_WRONLY);
	if (fd < 0)
		die("failed to open '%s'", path);
	ret = write(fd, &c, 1);
	close(fd);
	tracecmd_put_tracing_file(path);
	if (ret < 1)
		die("failed to write 0 to tracing_on\n");

	path = get_instance_file(&top_instance, "set_event");
	fd = open(path, O_WRONLY);
	if (fd < 0)
		die("failed to open '%s'", path);
	close(fd);
	tracecmd_put_tracing_file(path);
}

void top_exit(void)
{
	int i;
	/*
	 * free all the dynamic memories which could have been allocated by
	 * this program
	 */
	if (kbuf)
		kbuffer_free(kbuf);
	if (record)
		free_record(record);
	if (pevent)
		pevent_free(pevent);
	if (top_task_stats) {
		for (i = 0; i < top_task_cnt; i++)
			free(top_task_stats[i].comm);
		free(top_task_stats);
	}

	top_disable_events();
}

void top_initialize_events(void)
{
	char *path;
	int fd;
	char c;
	int ret;
	char *buf;
	int size;
	enum kbuffer_long_size long_size;
	enum kbuffer_endian endian;
	char id_str[8];

	/* trace data is read from the trace_raw_pipe directly */
	if (tracecmd_host_bigendian())
		endian = KBUFFER_ENDIAN_BIG;
	else
		endian = KBUFFER_ENDIAN_LITTLE;

	if (sizeof(long) == 8)
		long_size = KBUFFER_LSIZE_8;
	else
		long_size = KBUFFER_LSIZE_4;

	/* allocate global structures which will be needed during parsing */
	kbuf = kbuffer_alloc(long_size, endian);
	if (!kbuf) {
		warning("failed to allocate kbuf\n");
		goto free_event;
	}
	record = malloc(sizeof(*record));
	if (!record) {
		warning("failed to allocate record\n");
		goto free_event;
	}
	pevent = pevent_alloc();
	if (!pevent) {
		warning("failed to allocate pevent\n");
		goto free_event;
	}
	/* populate pevent structure */
	buf = read_file("events/header_page", &size);
	if (!buf) {
		warning("failed to read header page\n");
		goto free_event;
	}
	/* extract information from header page */
	ret = pevent_parse_header_page(pevent, buf, size,
					sizeof(unsigned long));
	free(buf);
	if (ret < 0) {
		warning("failed to parse header page\n");
		goto free_event;
	}
	/* extract format of events which will be enabled */
	buf = read_file("events/kmem/mm_page_alloc/format", &size);
	if (!buf) {
		warning("failed to read mm_page_alloc format\n");
		goto free_event;
	}
	ret = pevent_parse_event(pevent, buf, size, "kmem");
	free(buf);
	if (ret < 0) {
		warning("failed to parse mm_page_alloc event\n");
		goto free_event;
	}
	buf = read_file("events/kmem/mm_page_free/format", &size);
	if (!buf) {
		warning("failed to read mm_page_free format\n");
		goto free_event;
	}
	ret = pevent_parse_event(pevent, buf, size, "kmem");
	free(buf);
	if (ret < 0) {
		warning("failed to parse mm_page_free event\n");
		goto free_event;
	}
	/* set needed events */
	path = get_instance_file(&top_instance, "set_event");
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		warning("failed to open '%s'\n", path);
		goto free_path;
	}
	ret = write(fd, "kmem:mm_page_alloc", strlen("kmem:mm_page_alloc"));
	if (ret != strlen("kmem:mm_page_alloc")) {
		warning("failed to set kmem:mm_page_alloc event\n");
		goto close_fd;
	}
	ret = write(fd, "kmem:mm_page_free", strlen("kmem:mm_page_free"));
	if (ret != strlen("kmem:mm_page_free")) {
		warning("failed to set kmem:mm_page_free event\n");
		goto close_fd;
	}
	close(fd);
	tracecmd_put_tracing_file(path);
	/* store ID of needed events, will be used to compare*/
	path = get_instance_file(&top_instance, "events/kmem/mm_page_alloc/id");
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		warning("failed to open '%s'\n", path);
		goto free_event;
	}
	ret = read(fd, id_str, 8);
	if (ret < 1) {
		warning("failed to read events/kmem/mm_page_alloc/id\n");
		goto close_fd;
	}
	close(fd);
	tracecmd_put_tracing_file(path);
	kmem_mm_page_alloc_id = atoi(id_str);
	path = get_instance_file(&top_instance, "events/kmem/mm_page_free/id");
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		warning("failed to open '%s'\n", path);
		goto free_event;
	}
	ret = read(fd, id_str, 8);
	if (ret < 1) {
		warning("failed to read events/kmem/mm_page_free/id\n");
		goto close_fd;
	}
	close(fd);
	tracecmd_put_tracing_file(path);
	kmem_mm_page_free_id = atoi(id_str);
	/* enable tracing */
	c = '1';
	path = get_instance_file(&top_instance, "tracing_on");
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		warning("failed to open '%s'\n", path);
		goto free_event;
	}
	ret = write(fd, &c, 1);
	if (ret < 1) {
		warning("failed to write 0 in tracing_on file\n");
		goto close_fd;
	}
	close(fd);
	tracecmd_put_tracing_file(path);

	return;

close_fd:
	close(fd);
free_path:
	tracecmd_put_tracing_file(path);
free_event:
	top_exit();
	die("error with event initialization");
}

int top_pid_cmp(const void *a, const void *b)
{
	const struct top_task_stats *sa = a;
	const struct top_task_stats *sb = b;

	if (sa->pid > sb->pid)
		return 1;
	if (sa->pid < sb->pid)
		return -1;
	return 0;
}

int top_get_pid_comm_rss(char *comm, long *rss, pid_t pid)
{
	char proc_statm[21];
	char rss_str[9];
	char proc_comm[20];
	char proc_cmdline[23];
	char cmdline[24], *cmd;
	int fd, i = 0, len;

	/* read rss from /proc/pid/statm */
	sprintf(proc_statm, "/proc/%d/statm", pid);
	fd = open(proc_statm, O_RDONLY);
	if (fd < 0)
		return -1;
	/* ignore first entry */
	do {
		read(fd, rss_str, 1);
	} while (!isspace(rss_str[0]));
	/* read second entry:rss */
	do {
		read(fd, &rss_str[i], 1);
	} while (!isspace(rss_str[i++]));
	rss_str[i] = '\0';
	*rss = atol(rss_str);
	close(fd);
	/* read comm from /proc/pid/comm */
	sprintf(proc_comm, "/proc/%d/comm", pid);
	fd = open(proc_comm, O_RDONLY);
	if (fd < 0)
		return -1;
	len = read(fd, comm, 16);
	close(fd);
	comm[len - 1] = '\0';
	if (!strcmp(comm, "insmod") || !strcmp(comm, "modprobe")) {
		/* read comm from /proc/pid/cmdline */
		sprintf(proc_cmdline, "/proc/%d/cmdline", pid);
		fd = open(proc_cmdline, O_RDONLY);
		if (fd < 0)
			return -1;
		/*
		 * cmdline would be something like insmodvfat.ko. A module
		 * name could be greater than 16, but copy a max of 16. So
		 * a max of 8 bytes for insmod/modprobe and 16 for module
		 * name
		 */
		cmd = cmdline;
		len = read(fd, cmd, 24);
		close(fd);
		cmd[len - 1] = '\0';
		cmd += strlen(cmd) + 1;
		comm = strcat(comm, "-");
		comm = strcat(comm, cmd);
		/* now comm should look like insmod-vfat.ko */
	}

	return 0;
}

void top_update_pid_stats(pid_t pid, long memory, bool inc)
{
	/* 16 for task name and 16 for module name and 1 for separator */
	char comm[16 + 16 + 1];
	long rss;
	struct top_task_stats *statp, stat;

	/* check, if we have got already an entry for this pid in trace */
	stat.pid = pid;
	statp = bsearch(&stat, top_task_stats, top_task_cnt,
			sizeof(struct top_task_stats), top_pid_cmp);
	if (!statp) {
		/*
		 * if there is no entry in /proc for this pid yet, then no
		 * need to take care of memory consumption of the task. We
		 * will anyway, have those information in statm/rss when
		 * /proc entry will be created
		 */
		if (top_get_pid_comm_rss(comm, &rss, pid))
			return;
		top_task_stats = realloc(top_task_stats, sizeof(*top_task_stats) *
				(top_task_cnt + 1));
		if (!top_task_stats)
			die("Failed to allocate memory for new task");
		statp = top_task_stats + top_task_cnt++;
		statp->pid = pid;
		statp->cur_mem = rss;
		statp->peak_mem = rss;
		statp->comm = strdup(comm);
		qsort(top_task_stats, top_task_cnt, sizeof(struct top_task_stats),
				top_pid_cmp);
	}
	if (inc) {
		statp->cur_mem += memory;
		if (statp->peak_mem < statp->cur_mem)
			statp->peak_mem = statp->cur_mem;
	} else {
		statp->cur_mem -= memory;
	}
}

void top_analyze_event(struct event_format *event, pid_t pid, int id)
{
	struct format_field *field;
	unsigned long long order;

	if (id == kmem_mm_page_alloc_id || id == kmem_mm_page_free_id) {
		field = pevent_find_field(event, "order");
		if (field) {
			pevent_read_number_field(field, record->data, &order);
			top_update_pid_stats(pid, 1 << order,
					 id == kmem_mm_page_alloc_id);
		}
	}
}

void top_update_task_stats(void *page, int size, int cpu)
{
	unsigned long long ts;
	void *ptr;
	int id;
	pid_t pid;
	struct event_format *event;

	/* load page in kbuffer */
	kbuffer_load_subbuffer(kbuf, page);
	if (kbuffer_subbuffer_size(kbuf) > size) {
		warning("%s: page_size > size\n", __func__);
		return;
	}

	do {
		/* process each event in the page */
		ptr = kbuffer_read_event(kbuf, &ts);
		if (!ptr)
			break;
		memset(record, 0, sizeof(*record));
		record->ts = ts;
		record->size = kbuffer_event_size(kbuf);
		record->record_size = kbuffer_curr_size(kbuf);
		record->cpu = cpu;
		record->data = ptr;
		record->ref_count = 1;
		id = pevent_data_type(pevent, record);
		pid = pevent_data_pid(pevent, record);
		event = pevent_data_event_from_type(pevent, id);
		if (event)
			top_analyze_event(event, pid, id);
		ptr = kbuffer_next_event(kbuf, NULL);
		if (!ptr)
			break;
	} while (ptr < page + size);
}

void top_process_events(void)
{
	struct dirent *dent;
	void *page;
	char *path;
	char *file;
	DIR *dir;
	int len;
	int fd;
	int r;

	path = tracecmd_get_tracing_file("per_cpu");
	if (!path)
		die("Failed to allocate per_cpu info");

	dir = opendir(path);
	if (!dir)
		die("Failed to open per_cpu directory");

	len = strlen(path);
	file = malloc(len + strlen("trace_pipe_raw") + 32);
	page = malloc(page_size);
	if (!file || !page)
		die("Failed to allocate trace_pipe_raw info");

	while ((dent = readdir(dir))) {
		const char *name = dent->d_name;

		if (strncmp(name, "cpu", 3) != 0)
			continue;

		sprintf(file, "%s/%s/trace_pipe_raw", path, name);
		fd = open(file, O_RDONLY | O_NONBLOCK);
		if (fd < 0)
			continue;
		do {
			r = read(fd, page, page_size);
			if (r > 0)
				top_update_task_stats(page, r, atoi(&name[3]));
		} while (r > 0);
		close (fd);
	}
	free(file);
	free(page);
	closedir(dir);
	tracecmd_put_tracing_file(path);
}

void top_push_stats(int fd)
{
	int task;
	size_t len;
	char sync = 's';

	for (task = 0; task < top_task_cnt; task++) {
		write(fd, &sync, 1);
		write(fd, &top_task_stats[task].pid,
				sizeof(top_task_stats[task].pid));
		len = strlen(top_task_stats[task].comm);
		write(fd, &len, sizeof(size_t));
		write(fd, top_task_stats[task].comm,
				strlen(top_task_stats[task].comm));
		write(fd, &top_task_stats[task].cur_mem,
				sizeof(top_task_stats[task].cur_mem));
		write(fd, &top_task_stats[task].peak_mem,
				sizeof(top_task_stats[task].peak_mem));
	}
	sync = 'e';
	write(fd, &sync, 1);
}

void top_pop_stats(int fd)
{
	FILE *fp = stdout;
	pid_t pid;
	size_t len;
	char comm[33];
	long peak_mem;
	long cur_mem;
	char sync;

	page_size = getpagesize();

	fprintf(fp, "\npid\t\tcomm\t\tpeak memory(in KB)\t\tcur memory(in KB)\n");
	do {
		if (read(fd, &sync, 1) < 1)
			break;
		if (sync == 'e')
			break;
		if (read(fd, &pid, sizeof(pid)) < (int)sizeof(pid))
			break;
		if (read(fd, &len, sizeof(len)) < (int)sizeof(len))
			break;
		if (read(fd, comm, len) < len)
			break;
		comm[len] = '\0';
		if (read(fd, &cur_mem, sizeof(cur_mem)) < (int)sizeof(cur_mem))
			break;
		if (read(fd, &peak_mem, sizeof(peak_mem)) < (int)sizeof(peak_mem))
			break;
		fprintf(fp, "%d\t\t%-16s\t%ld\t\t%ld\n", pid, comm,
				peak_mem * (page_size >> 10), cur_mem *
				(page_size >> 10));
	} while(sync == 's');

}

void top_print(char *port, char cmd)
{
	int s_fd;
	struct sockaddr_un name;
	int ret;

	s_fd = socket (PF_LOCAL, SOCK_STREAM, 0);
	if (s_fd < 0)
		die("failed to create client socket");
	name.sun_family = AF_LOCAL;
	strcpy (name.sun_path, port);
	ret = connect (s_fd, &name, SUN_LEN(&name));
	if (ret < 0) {
		close(s_fd);
		die("failed to connect to server socket");
	}
	write(s_fd, &cmd, 1);
	top_pop_stats(s_fd);
	close (s_fd);
}

void top_start(char *port)
{
	pid_t pid;
	int s_fd;
	struct sockaddr_un name;
	struct sockaddr_un c_name;
	socklen_t c_name_len = 0;
	int c_s_fd;
	char cmd;
	int ret;

	top_disable_events();
	top_initialize_events();
	page_size = getpagesize();

	pid = fork();
	if (!pid) {
		s_fd = socket(PF_LOCAL, SOCK_STREAM, 0);
		if (s_fd < 0)
			die("failed to create server socket");
		name.sun_family = AF_LOCAL;
		strcpy (name.sun_path, port);
		ret = bind(s_fd, &name, SUN_LEN(&name));
		if (ret < 0) {
			close(s_fd);
			die("failed to bind server socket");
		}
		ret = listen (s_fd, 5);
		if (ret < 0) {
			close(s_fd);
			die("failed to listen on server socket");
		}
		do {
			top_process_events();
			sleep(1);
			c_s_fd = accept (s_fd, &c_name, &c_name_len);
			if (c_s_fd >= 0 && read(c_s_fd, &cmd, 1) == 1){
				if (cmd == 'p') {
					top_push_stats(c_s_fd);
				}else if (cmd == 'e') {
					top_push_stats(c_s_fd);
					top_exit();
					close(c_s_fd);
					break;
				}
			}
			close(c_s_fd);
		} while (1);
		close(s_fd);
		unlink(port);
	}

	return;
}

void trace_top (int argc, char **argv)
{
	int c;
	char *port = NULL;

	for (;;) {
		int option_index = 0;
		static struct option long_options[] = {
			{"start", required_argument, NULL, 's'},
			{"end", required_argument, NULL, 'e'},
			{"print", required_argument, NULL, 'p'},
			{"help", no_argument, NULL, 'h'},
			{NULL, 0, NULL, 0}
		};

		c = getopt_long (argc-1, argv+1, "+hs:e:p:",
			long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			usage(argv);
			break;
		case 's':
			port = optarg;
			top_start(port);
			break;
		case 'e':
		case 'p':
			port = optarg;
			top_print(port, (char)c);
			break;
		default:
			usage(argv);
		}
	}

	if (!port)
		usage(argv);

	exit(0);
}
