/*
 * Copyright (C) 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
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
#define _LARGEFILE64_SOURCE
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <sys/un.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <errno.h>

#include "trace-local.h"
#include "trace-msg.h"

#define MAX_OPTION_SIZE 4096

#define _VAR_DIR_Q(dir)		#dir
#define VAR_DIR_Q(dir)		_VAR_DIR_Q(dir)

#define VAR_RUN_DIR		"/var/run"
#define VAR_LIB_DIR		VAR_DIR_Q(VAR_DIR) "/lib"
#define TRACE_CMD_DIR		VAR_LIB_DIR "/trace-cmd/"
#define TRACE_CMD_RUN_DIR	VAR_RUN_DIR "/trace-cmd/"
#define VIRT_DIR		TRACE_CMD_DIR "virt/"
#define VIRT_TRACE_CTL_SOCK	TRACE_CMD_RUN_DIR "agent-ctl-path"
#define VIRT_DOMAIN_DIR		VIRT_DIR "%s/"
#define TRACE_PATH_DOMAIN_CPU_O	VIRT_DOMAIN_DIR "trace-path-cpu%d.out"
#define TRACE_PATH_DOMAIN_CPU_I	VIRT_DOMAIN_DIR "trace-path-cpu%d.in"

static char *default_output_dir = ".";
static char *output_dir;
static char *default_output_file = "trace";
static char *output_file;

static FILE *logfp;

static int backlog = 5;

static int do_daemon;

static int unlink_sock;

/* Used for signaling INT to finish */
static struct tracecmd_msg_handle *stop_msg_handle;
static bool done;

struct domain_dir {
	struct domain_dir *next;
	char *name;
	char *group;
	mode_t perms;
	int cpu;
};

enum {
	NET	= 1,
	VIRT	= 2,
};

struct domain_dir *dom_dir_list;

#define  TEMP_FILE_STR_NET "%s.%s:%s.cpu%d", output_file, host, port, cpu
#define  TEMP_FILE_STR_VIRT "%s.%s:%d.cpu%d", output_file, domain, virtpid, cpu
static char *get_temp_file(const char *host, const char *port,
			   const char *domain, int virtpid, int cpu, int mode)
{
	char *file = NULL;
	int size;

	if (mode == NET) {
		size = snprintf(file, 0, TEMP_FILE_STR_NET);
		file = malloc(size + 1);
		if (!file)
			return NULL;
		sprintf(file, TEMP_FILE_STR_NET);
	} else if (mode == VIRT) {
		size = snprintf(file, 0, TEMP_FILE_STR_VIRT);
		file = malloc(size + 1);
		if (!file)
			return NULL;
		sprintf(file, TEMP_FILE_STR_VIRT);
	}

	return file;
}

static char *get_temp_file_net(const char *host, const char *port, int cpu)
{
	return  get_temp_file(host, port, NULL, 0, cpu, NET);
}

static char *get_temp_file_virt(const char *domain, int virtpid, int cpu)
{
	return  get_temp_file(NULL, NULL, domain, virtpid, cpu, VIRT);
}

static void put_temp_file(char *file)
{
	free(file);
}

#define MAX_PATH 1024

static void signal_setup(int sig, sighandler_t handle)
{
	struct sigaction action;

	sigaction(sig, NULL, &action);
	/* Make accept return EINTR */
	action.sa_flags &= ~SA_RESTART;
	action.sa_handler = handle;
	sigaction(sig, &action, NULL);
}

static void delete_temp_file(const char *host, const char *port,
			     const char *domain, int virtpid, int cpu, int mode)
{
	char file[MAX_PATH];

	if (mode == NET)
		snprintf(file, MAX_PATH, TEMP_FILE_STR_NET);
	else if (mode == VIRT)
		snprintf(file, MAX_PATH, TEMP_FILE_STR_VIRT);
	unlink(file);
}

static int read_string(int fd, char *buf, size_t size)
{
	size_t i;
	int n;

	for (i = 0; i < size; i++) {
		n = read(fd, buf+i, 1);
		if (!buf[i] || n <= 0)
			break;
	}

	return i;
}

static int process_option(struct tracecmd_msg_handle *msg_handle, char *option)
{
	/* currently the only option we have is to us TCP */
	if (strcmp(option, "TCP") == 0) {
		msg_handle->flags |= TRACECMD_MSG_FL_USE_TCP;
		return 1;
	}
	return 0;
}

static struct tracecmd_recorder *recorder;

static void finish(int sig)
{
	if (recorder)
		tracecmd_stop_recording(recorder);
	if (stop_msg_handle)
		tracecmd_msg_set_done(stop_msg_handle);
	done = true;
}

#define LOG_BUF_SIZE 1024
static void __plog(const char *prefix, const char *fmt, va_list ap,
		   FILE *fp)
{
	static int newline = 1;
	char buf[LOG_BUF_SIZE];
	int r;

	r = vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);

	if (r > LOG_BUF_SIZE)
		r = LOG_BUF_SIZE;

	if (logfp) {
		if (newline)
			fprintf(logfp, "[%d]%s%.*s", getpid(), prefix, r, buf);
		else
			fprintf(logfp, "[%d]%s%.*s", getpid(), prefix, r, buf);
		newline = buf[r - 1] == '\n';
		fflush(logfp);
		return;
	}

	fprintf(fp, "%.*s", r, buf);
}

void plog(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__plog("", fmt, ap, stdout);
	va_end(ap);
	/* Make sure it gets to the screen, in case we crash afterward */
	fflush(stdout);
}

static void make_pid_name(int mode, char *buf)
{
	snprintf(buf, PATH_MAX, VAR_RUN_DIR "/trace-cmd-%s.pid",
		 mode == VIRT ? "virt" : "net");
}

static void remove_pid_file(void)
{
	char buf[PATH_MAX];
	int mode = do_daemon;

	if (!do_daemon)
		return;

	make_pid_name(mode, buf);

	unlink(buf);
}

void pdie(const char *fmt, ...)
{
	va_list ap;
	char *str = "";

	va_start(ap, fmt);
	__plog("Error: ", fmt, ap, stderr);
	va_end(ap);
	if (errno)
		str = strerror(errno);
	if (logfp)
		fprintf(logfp, "\n%s\n", str);
	else
		fprintf(stderr, "\n%s\n", str);

	remove_pid_file();

	exit(-1);
}

static int process_udp_child(int sfd, const char *host, const char *port,
			     int cpu, int page_size, int use_tcp)
{
	struct sockaddr_storage peer_addr;
	socklen_t peer_addr_len;
	char buf[page_size];
	char *tempfile;
	int cfd;
	int fd;
	int n;
	int once = 0;

	signal_setup(SIGUSR1, finish);

	tempfile = get_temp_file_net(host, port, cpu);
	if (!tempfile)
		return -ENOMEM;

	fd = open(tempfile, O_WRONLY | O_TRUNC | O_CREAT, 0644);
	if (fd < 0)
		pdie("creating %s", tempfile);

	if (use_tcp) {
		if (listen(sfd, backlog) < 0)
			pdie("listen");
		peer_addr_len = sizeof(peer_addr);
		cfd = accept(sfd, (struct sockaddr *)&peer_addr, &peer_addr_len);
		if (cfd < 0 && errno == EINTR)
			goto done;
		if (cfd < 0)
			pdie("accept");
		close(sfd);
		sfd = cfd;
	}

	do {
		/* TODO, make this copyless! */
		n = read(sfd, buf, page_size);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			pdie("reading pages from client");
		}
		if (!n)
			break;
		/* UDP requires that we get the full size in one go */
		if (!use_tcp && n < page_size && !once) {
			once = 1;
			warning("read %d bytes, expected %d", n, page_size);
		}
		write(fd, buf, n);
	} while (!done);

 done:
	put_temp_file(tempfile);
	exit(0);
}

#define SLEEP_DEFAULT	1000

static int process_virt_child(int fd, int cpu, int pagesize,
			      const char *domain, int virtpid)
{
	char *tempfile;

	signal_setup(SIGUSR1, finish);
	tempfile = get_temp_file_virt(domain, virtpid, cpu);
	if (!tempfile)
		return -ENOMEM;

	recorder = tracecmd_create_recorder_virt(tempfile, cpu, fd);

	do {
		if (tracecmd_start_recording(recorder, SLEEP_DEFAULT) < 0)
			break;
	} while (!done);

	tracecmd_free_recorder(recorder);
	put_temp_file(tempfile);
	exit(0);
}

#define START_PORT_SEARCH 1500
#define MAX_PORT_SEARCH 6000

static int udp_bind_a_port(int start_port, int *sfd, int use_tcp)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	char buf[BUFSIZ];
	int s;
	int num_port = start_port;

 again:
	snprintf(buf, BUFSIZ, "%d", num_port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = use_tcp ? SOCK_STREAM : SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	s = getaddrinfo(NULL, buf, &hints, &result);
	if (s != 0)
		pdie("getaddrinfo: error opening udp socket");

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		*sfd = socket(rp->ai_family, rp->ai_socktype,
			      rp->ai_protocol);
		if (*sfd < 0)
			continue;

		if (bind(*sfd, rp->ai_addr, rp->ai_addrlen) == 0)
			break;

		close(*sfd);
	}

	if (rp == NULL) {
		freeaddrinfo(result);
		if (++num_port > MAX_PORT_SEARCH)
			pdie("No available ports to bind");
		goto again;
	}

	freeaddrinfo(result);

	return num_port;
}

static void fork_reader(int sfd, const char *node, const char *port,
			int *pid, int cpu, int pagesize, const char *domain,
			int virtpid, int use_tcp, int mode)
{
	int ret;

	*pid = fork();

	if (*pid < 0)
		pdie("creating reader");

	if (!*pid) {
		if (mode == NET)
			ret = process_udp_child(sfd, node, port, cpu, pagesize, use_tcp);
		else if (mode == VIRT)
			ret = process_virt_child(sfd, cpu, pagesize, domain, virtpid);
		if (ret < 0)
			pdie("Problem with udp reader %d", ret);
	}

	close(sfd);
}

static void fork_udp_reader(int sfd, const char *node, const char *port,
			    int *pid, int cpu, int pagesize, int use_tcp)
{
	fork_reader(sfd, node, port, pid, cpu, pagesize, NULL, 0, use_tcp, NET);
}

static void fork_virt_reader(int sfd, int *pid, int cpu, int pagesize,
			     const char *domain, int virtpid)
{
	fork_reader(sfd, NULL, NULL, pid, cpu, pagesize, domain, virtpid, 0, VIRT);
}

static int open_udp(const char *node, const char *port, int *pid,
		    int cpu, int pagesize, int start_port, int use_tcp)
{
	int sfd;
	int num_port;

	/*
	 * udp_bind_a_port() currently does not return an error, but if that
	 * changes in the future, we have a check for it now.
	 */
	num_port = udp_bind_a_port(start_port, &sfd, use_tcp);
	if (num_port < 0)
		return num_port;

	fork_udp_reader(sfd, node, port, pid, cpu, pagesize, use_tcp);

	return num_port;
}

static int open_virtio_serial_pipe(int *pid, int cpu, int pagesize,
				   const char *domain, int virtpid)
{
	char buf[PATH_MAX];
	int fd;

	snprintf(buf, PATH_MAX, TRACE_PATH_DOMAIN_CPU_O, domain, cpu);
	fd = open(buf, O_RDONLY | O_NONBLOCK);
	if (fd < 0) {
		warning("open %s", buf);
		return fd;
	}

	fork_virt_reader(fd, pid, cpu, pagesize, domain, virtpid);

	return fd;
}

static int communicate_with_client_net(struct tracecmd_msg_handle *msg_handle)
{
	char *last_proto = NULL;
	char buf[BUFSIZ];
	char *option;
	int pagesize = 0;
	int options;
	int size;
	int cpus;
	int n, s, t, i;
	int ret = -EINVAL;
	int fd = msg_handle->fd;

	/* Let the client know what we are */
	write(fd, "tracecmd", 8);

 try_again:
	/* read back the CPU count */
	n = read_string(fd, buf, BUFSIZ);
	if (n == BUFSIZ)
		/** ERROR **/
		return -EINVAL;

	cpus = atoi(buf);

	/* Is the client using the new protocol? */
	if (cpus == -1) {
		if (memcmp(buf, V2_CPU, n) != 0) {
			/* If it did not send a version, then bail */
			if (memcmp(buf, "-1V", 3)) {
				plog("Unknown string %s\n", buf);
				goto out;
			}
			/* Skip "-1" */
			plog("Cannot handle the protocol %s\n", buf+2);

			/* If it returned the same command as last time, bail! */
			if (last_proto && strncmp(last_proto, buf, n) == 0) {
				plog("Repeat of version %s sent\n", last_proto);
				goto out;
			}
			free(last_proto);
			last_proto = malloc(n + 1);
			if (last_proto) {
				memcpy(last_proto, buf, n);
				last_proto[n] = 0;
			}
			/* Return the highest protocol we can use */
			write(fd, "V2", 3);
			goto try_again;
		}

		/* Let the client know we use v2 protocol */
		write(fd, "V2", 3);

		/* read the rest of dummy data */
		n = read(fd, buf, sizeof(V2_MAGIC));
		if (memcmp(buf, V2_MAGIC, n) != 0)
			goto out;

		/* We're off! */
		write(fd, "OK", 2);

		msg_handle->version = V2_PROTOCOL;

	} else {
		/* The client is using the v1 protocol */

		plog("cpus=%d\n", cpus);
		if (cpus < 0)
			goto out;

		msg_handle->cpu_count = cpus;

		/* next read the page size */
		n = read_string(fd, buf, BUFSIZ);
		if (n == BUFSIZ)
			/** ERROR **/
			goto out;

		pagesize = atoi(buf);

		plog("pagesize=%d\n", pagesize);
		if (pagesize <= 0)
			goto out;

		/* Now the number of options */
		n = read_string(fd, buf, BUFSIZ);
 		if (n == BUFSIZ)
			/** ERROR **/
			return -EINVAL;

		options = atoi(buf);

		for (i = 0; i < options; i++) {
			/* next is the size of the options */
			n = read_string(fd, buf, BUFSIZ);
			if (n == BUFSIZ)
				/** ERROR **/
				goto out;
			size = atoi(buf);
			/* prevent a client from killing us */
			if (size > MAX_OPTION_SIZE)
				goto out;

			ret = -ENOMEM;
			option = malloc(size);
			if (!option)
				goto out;

			ret = -EIO;
			do {
				t = size;
				s = 0;
				s = read(fd, option+s, t);
				if (s <= 0)
					goto out;
				t -= s;
				s = size - t;
			} while (t);

			s = process_option(msg_handle, option);
			free(option);
			/* do we understand this option? */
			ret = -EINVAL;
			if (!s)
				goto out;
		}
	}

	if (msg_handle->flags & TRACECMD_MSG_FL_USE_TCP)
		plog("Using TCP for live connection\n");

	ret = pagesize;
 out:
	free(last_proto);

	return ret;
}

static int
communicate_with_client_virt(struct tracecmd_msg_handle *msg_handle,
			     const char *domain)
{
	msg_handle->version = V2_PROTOCOL;

	if (tracecmd_msg_set_connection(msg_handle, domain) < 0) {
		plog("Failed connection to domain %s\n", domain);
		return -1;
	}

	return 0;
}

static int create_client_file(const char *node, const char *port,
			      const char *domain, int pid, int mode)
{
	char buf[BUFSIZ];
	int ofd;

	if (mode == NET)
		snprintf(buf, BUFSIZ, "%s.%s:%s.dat", output_file, node, port);
	else if (mode == VIRT)
		snprintf(buf, BUFSIZ, "%s.%s:%d.dat", output_file, domain, pid);
	else
		plog("create_client_file: Unsupported mode %d", mode);

	ofd = open(buf, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (ofd < 0)
		pdie("Can not create file %s", buf);
	return ofd;
}

static void destroy_all_readers(int cpus, int *pid_array, const char *node,
				const char *port, const char *domain,
				int virtpid, int mode)
{
	int cpu;

	for (cpu = 0; cpu < cpus; cpu++) {
		if (pid_array[cpu] > 0) {
			kill(pid_array[cpu], SIGKILL);
			waitpid(pid_array[cpu], NULL, 0);
			delete_temp_file(node, port, domain, virtpid, cpu, mode);
			pid_array[cpu] = 0;
		}
	}

	free(pid_array);
}

static int *create_all_readers(const char *node, const char *port,
			       const char *domain, int virtpid, int pagesize,
			       struct tracecmd_msg_handle *msg_handle, int mode)
{
	int use_tcp = msg_handle->flags & TRACECMD_MSG_FL_USE_TCP;
	char buf[BUFSIZ];
	int *port_array = NULL;
	int *pid_array;
	int start_port;
	int udp_port;
	int cpus = msg_handle->cpu_count;
	int cpu;
	int pid;

	if (!pagesize)
		return NULL;

	if (mode == NET) {
		port_array = malloc(sizeof(int) * cpus);
		if (!port_array)
			return NULL;
		start_port = START_PORT_SEARCH;
	}

	pid_array = malloc(sizeof(int) * cpus);
	if (!pid_array) {
		free(port_array);
		return NULL;
	}

	memset(pid_array, 0, sizeof(int) * cpus);

	/* Now create a reader for each CPU */
	for (cpu = 0; cpu < cpus; cpu++) {
		if (node) {
			udp_port = open_udp(node, port, &pid, cpu,
					    pagesize, start_port, use_tcp);
			if (udp_port < 0)
				goto out_free;
			port_array[cpu] = udp_port;
			/*
			 * Due to some bugging finding ports,
			 * force search after last port
			 */
			start_port = udp_port + 1;
		} else {
			if (open_virtio_serial_pipe(&pid, cpu, pagesize,
						    domain, virtpid) < 0)
				goto out_free;
		}
		pid_array[cpu] = pid;
	}

	if (msg_handle->version == V2_PROTOCOL) {
		/* send set of port numbers to the client */
		if (tracecmd_msg_send_port_array(msg_handle, port_array) < 0) {
			plog("Failed sending port array\n");
			goto out_free;
		}
	} else {
		/* send the client a comma deliminated set of port numbers */
		for (cpu = 0; cpu < cpus; cpu++) {
			snprintf(buf, BUFSIZ, "%s%d",
				 cpu ? "," : "", port_array[cpu]);
			write(msg_handle->fd, buf, strlen(buf));
		}
		/* end with null terminator */
		write(msg_handle->fd, "\0", 1);
	}

	return pid_array;

 out_free:
	destroy_all_readers(cpus, pid_array, node, port, domain, virtpid, mode);
	return NULL;
}

static void
collect_metadata_from_client(struct tracecmd_msg_handle *msg_handle,
			     int ofd)
{
	char buf[BUFSIZ];
	int n, s, t;
	int ifd = msg_handle->fd;

	do {
		n = read(ifd, buf, BUFSIZ);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			pdie("reading client");
		}
		t = n;
		s = 0;
		do {
			s = write(ofd, buf+s, t);
			if (s < 0) {
				if (errno == EINTR)
					break;
				pdie("writing to file");
			}
			t -= s;
			s = n - t;
		} while (t);
	} while (n > 0 && !tracecmd_msg_done(msg_handle));
}

static void stop_all_readers(int cpus, int *pid_array)
{
	int cpu;

	for (cpu = 0; cpu < cpus; cpu++) {
		if (pid_array[cpu] > 0)
			kill(pid_array[cpu], SIGUSR1);
	}
}

static int put_together_file(int cpus, int ofd, const char *node,
			     const char *port, const char *domain, int virtpid,
			     int mode)
{
	char **temp_files;
	int cpu;
	int ret = -ENOMEM;

	/* Now put together the file */
	temp_files = malloc(sizeof(*temp_files) * cpus);
	if (!temp_files)
		return -ENOMEM;

	for (cpu = 0; cpu < cpus; cpu++) {
		temp_files[cpu] = get_temp_file(node, port, domain,
						virtpid, cpu, mode);
		if (!temp_files[cpu])
			goto out;
	}

	tracecmd_attach_cpu_data_fd(ofd, cpus, temp_files);
	ret = 0;
 out:
	for (cpu--; cpu >= 0; cpu--) {
		put_temp_file(temp_files[cpu]);
	}
	free(temp_files);
	return ret;
}

static int process_client(struct tracecmd_msg_handle *msg_handle,
			  const char *node, const char *port,
			   const char *domain, int virtpid, int mode)
{
	int *pid_array;
	int pagesize = 0;
	int cpus;
	int ofd;
	int ret;

	if (mode == NET) {
		pagesize = communicate_with_client_net(msg_handle);
		if (pagesize < 0)
			return pagesize;
	} else if (mode == VIRT) {
		ret = communicate_with_client_virt(msg_handle, domain);
		if (ret < 0)
			return ret;
	} else
		return -EINVAL;

	/* read the CPU count, the page size, and options */
	if ((msg_handle->version == V2_PROTOCOL) &&
	    (pagesize = tracecmd_msg_initial_setting(msg_handle)) < 0) {
		plog("Failed inital settings\n");
		return -EINVAL;
	}

	ofd = create_client_file(node, port, domain, virtpid, mode);
	pid_array = create_all_readers(node, port, domain, virtpid,
				       pagesize, msg_handle, mode);
	if (!pid_array)
		return -ENOMEM;

	/* on signal stop this msg */
	stop_msg_handle = msg_handle;

	/* Now we are ready to start reading data from the client */
	if (msg_handle->version == V2_PROTOCOL)
		tracecmd_msg_collect_metadata(msg_handle, ofd);
	else
		collect_metadata_from_client(msg_handle, ofd);

	/* wait a little to let our readers finish reading */
	sleep(1);

	cpus = msg_handle->cpu_count;

	/* stop our readers */
	stop_all_readers(cpus, pid_array);

	/* wait a little to have the readers clean up */
	sleep(1);

	ret = put_together_file(cpus, ofd, node, port, domain, virtpid, mode);

	destroy_all_readers(cpus, pid_array, node, port, domain, virtpid, mode);

	return ret;
}

static int process_client_net(struct tracecmd_msg_handle *msg_handle,
			      const char *node, const char *port)
{
	return process_client(msg_handle, node, port, NULL, 0, NET);
}

static int process_client_virt(struct tracecmd_msg_handle *msg_handle,
			       const char *domain, int virtpid)
{
	return process_client(msg_handle, NULL, NULL, domain, virtpid, VIRT);
}

static int do_fork(void)
{
	pid_t pid;

	/* in debug mode, we do not fork off children */
	if (debug)
		return 0;

	pid = fork();
	if (pid < 0) {
		warning("failed to create child");
		return -1;
	}

	if (pid > 0)
		return pid;

	unlink_sock = 0;

	signal_setup(SIGINT, finish);

	return 0;
}

static int get_virtpid(int cfd)
{
	struct ucred cr;
	socklen_t cl;
	int ret;

	cl = sizeof(cr);
	ret = getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cr, &cl);
	if (ret < 0)
		return ret;

	return cr.pid;
}

#define LIBVIRT_DOMAIN_PATH     "/var/run/libvirt/qemu/"

/* We can convert pid to domain name of a guest when we use libvirt. */
static char *get_guest_domain_from_pid_libvirt(int pid)
{
	struct dirent *dirent;
	char file_name[NAME_MAX];
	char *file_name_ret, *domain;
	char buf[BUFSIZ];
	DIR *dir;
	size_t doml;
	int fd;

	dir = opendir(LIBVIRT_DOMAIN_PATH);
	if (!dir) {
		if (errno == ENOENT)
			warning("Only support for using libvirt");
		return NULL;
	}

	for (dirent = readdir(dir); dirent != NULL; dirent = readdir(dir)) {
		snprintf(file_name, NAME_MAX, LIBVIRT_DOMAIN_PATH"%s",
			 dirent->d_name);
		file_name_ret = strstr(file_name, ".pid");
		if (file_name_ret) {
			fd = open(file_name, O_RDONLY);
			if (fd < 0)
				return NULL;
			if (read(fd, buf, BUFSIZ) < 0)
				return NULL;

			if (pid == atoi(buf)) {
				/* not include /var/run/libvirt/qemu */
				doml = (size_t)(file_name_ret - file_name)
					- strlen(LIBVIRT_DOMAIN_PATH);
				domain = strndup(file_name +
						 strlen(LIBVIRT_DOMAIN_PATH),
						 doml);
				plog("start %s:%d\n", domain, pid);
				return domain;
			}
		}
	}

	return NULL;
}

static int get_cmd_arg(int fd, char *buf, int size)
{
	static int last_size;
	static int last_r;
	int r;
	int i;

	if (last_size) {
		memmove(buf, buf + last_r, last_size);
		size -= last_size;
	}

	r = read(fd, buf + last_size, size - 1);
	if (r < 0)
		return r;
	r += last_size;
	buf[r] = 0;

	for (i = 0; i < r; i++) {
		if (!buf[i])
			break;
	}
	if (!r)
		return 0;

	if (i < r) {
		i++; /* add the \0 */
		last_size = r - i;
		last_r = i;
		return last_r;
	}

	return 0;
}

/* We can convert pid to domain name of a guest when we use qemu. */
static char *get_guest_domain_from_pid(int pid)
{
	char buf[BUFSIZ];
	char path[PATH_MAX];
	char *domain;
	int fd;
	int r;

	/*
	 * We have the pid, now look at the cmdline to find
	 * the --name option.
	 */
	snprintf(path, PATH_MAX, "/proc/%d/cmdline", pid);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		goto fail;

	do {
		r = get_cmd_arg(fd, buf, BUFSIZ);
		if (r < 0)
			goto fail;
		if (r > 0 && strcmp(buf, "-name") == 0) {
			r = get_cmd_arg(fd, buf, BUFSIZ);
			/* We better have something */
			if (r < 1)
				goto fail;
			domain = strdup(buf);
			close(fd);
			return domain;
		}
	} while (r);

 fail:
	close(fd);
	plog("Failed getting domain from qemu args, try libvirt\n");
	return get_guest_domain_from_pid_libvirt(pid);
}

static int do_connection(int cfd, struct sockaddr *peer_addr,
			 socklen_t peer_addr_len, const char *domain,
			 int virtpid, int mode)
{
	struct tracecmd_msg_handle *msg_handle;
	char host[NI_MAXHOST], service[NI_MAXSERV];
	int s, ret;

	ret = do_fork();
	if (ret) {
		close(cfd);
		return ret;
	}

	msg_handle = tracecmd_msg_handle_alloc(cfd, TRACECMD_MSG_FL_SERVER);

	ret = -EINVAL;

	if (mode == NET) {
		s = getnameinfo(peer_addr, peer_addr_len, host, NI_MAXHOST,
				service, NI_MAXSERV, NI_NUMERICSERV);

		if (s == 0)
			plog("Connected with %s:%s\n",
			       host, service);
		else {
			plog("Error with getnameinfo: %s\n",
			       gai_strerror(s));
			close(cfd);
			return -1;
		}
		ret = process_client_net(msg_handle, host, service);
	} else if (mode == VIRT)
		ret = process_client_virt(msg_handle, domain, virtpid);

	tracecmd_msg_handle_close(msg_handle);

	if (!debug)
		exit(ret);

	return 0;
}

struct client_pid_list {
	int		pid;
	int		fd_idx;
};

static struct client_pid_list *client_pids;
static int free_pids;
static int saved_pids;

static void add_process(int pid, int idx)
{
	struct client_pid_list  *client = NULL;
	int i;

	if (free_pids) {
		for (i = 0; i < saved_pids; i++) {
			if (!client_pids[i].pid) {
				client = &client_pids[i];
				break;
			}
		}
		free_pids--;
		if (!client)
			warning("Could not find free pid");
	}
	if (!client) {
		client_pids = realloc(client_pids,
				      sizeof(*client_pids) * (saved_pids + 1));
		if (!client_pids)
			pdie("allocating pids");
		client = &client_pids[saved_pids++];
	}
	client->pid = pid;
	client->fd_idx = idx;
}

static int active_processes(void)
{
	int ret = 0;
	int i;

	for (i = 0; i < saved_pids; i++) {
		if (client_pids[i].pid) {
			ret = 1;
			break;
		}
	}

	return ret;
}

static void reset_fds(struct pollfd *fds)
{
	close(fds->fd);
	fds->fd = -1;
	fds->events = 0;
}

static void remove_process(int pid, int status, struct pollfd *fds)
{
	int idx;
	int i;

	for (i = 0; i < saved_pids; i++) {
		if (client_pids[i].pid == pid)
			break;
	}

	if (i == saved_pids)
		return;

	idx = client_pids[i].fd_idx;

	/* If this process errored, close the fd */
	if (status)
		reset_fds(&fds[idx]);
	else
		fds[idx].events |= POLLIN;

	client_pids[i].pid = 0;
	free_pids++;
}

static void kill_clients(void)
{
	int i;

	for (i = 0; i < saved_pids; i++) {
		if (!client_pids[i].pid)
			continue;
		kill(client_pids[i].pid, SIGINT);
		waitpid(client_pids[i].pid, NULL, 0);
	}

	saved_pids = 0;
}

static void clean_up(struct pollfd *fds)
{
	int status;
	int ret;

	/* Clean up any children that has started before */
	do {
		ret = waitpid(0, &status, WNOHANG);
		if (ret > 0)
			remove_process(ret, WEXITSTATUS(status), fds);
	} while (ret > 0);
}

enum {
	FD_NET		= 0,
	FD_VIRT		= 1,
	FD_CONNECTED,
};

struct client_list {
	const char	*name;
	int		pid;
};

static void
update_client(struct client_list *clients, int nr,
	      const char *domain, int virtpid)
{
	clients[nr].name = domain;
	clients[nr].pid = virtpid;
}

static struct client_list *
add_client(struct client_list *clients, int nr, const char *domain, int virtpid)
{
	nr -= FD_CONNECTED;

	clients = realloc(clients, sizeof(*clients) * (nr + 1));
	if (!clients)
		return NULL;

	update_client(clients, nr, domain, virtpid);

	return clients;
}

static void do_accept_loop(int nfd, int vfd)
{
	struct client_list *clients = NULL;
	struct client_list *client;
	struct sockaddr addr;
	socklen_t addrlen;
	struct pollfd *fds;
	char *domain = NULL;
	int timeout = -1;
	int free_fds = 0;
	int nr_fds = 2;
	int virtpid;
	int cfd, pid;
	int ret;
	int i;

	fds = calloc(nr_fds, sizeof(struct pollfd));
	if (!fds)
		pdie("allocating fds");

	fds[FD_NET].fd = nfd;
	if (nfd >= 0)
		fds[FD_NET].events = POLLIN;

	fds[FD_VIRT].fd = vfd;
	if (vfd >= 0)
		fds[FD_VIRT].events = POLLIN;

	do {
		/* If there are active threads, then timeout to
		 * make sure we can clean up. Otherwise we have a
		 * race between checking here and calling poll.
		 */
		timeout = active_processes() ? 500 : -1;

		ret = poll(fds, nr_fds, timeout);

		if (ret < 0) {
			if (errno == EINTR) {
				clean_up(fds);
				continue;
			}
			pdie("poll");
		}

		if (!ret) {
			/* Timed out */
			clean_up(fds);
			continue;
		}

		for (i = 0; i < nr_fds; i++) {

			if (fds[i].revents & POLLHUP) {
				reset_fds(&fds[i]);
				if (i < FD_CONNECTED)
					free_fds++;
				continue;
			}

			if (!fds[i].revents & POLLIN)
				continue;

			if (i < FD_CONNECTED) {
				if (i == FD_NET)
					addrlen = sizeof(struct sockaddr_storage);
				else
					addrlen = sizeof(struct sockaddr_un);

				cfd = accept(fds[i].fd, &addr, &addrlen);
				printf("connected!\n");
				if (cfd < 0 && errno == EINTR)
					continue;
				if (cfd < 0)
					pdie("connecting");

				/*
				 * The virt server connects when the machine
				 * boots up. But doesn't expect to do any
				 * tracing yet. Just add it to the poll list.
				 */
				if (i == FD_VIRT) {
					void *new;
					int fd;

					virtpid = get_virtpid(cfd);
					if (virtpid < 0) {
						plog("Unable to get virt pid\n");
						close(cfd);
						continue;
					}

					domain = get_guest_domain_from_pid(virtpid);
					if (!domain) {
						plog("Unable to get domain name from pid %d\n",
						     virtpid);
						close(cfd);
						continue;
					}

					if (free_fds) {
						int x;

						for (x = FD_CONNECTED; x < nr_fds; x++)
							if (fds[x].fd < 0)
								break;
						if (x == nr_fds) {
							warning("Could not find free file descriptor");
							free_fds = 0;
						} else {
							update_client(clients, x,
								      domain, virtpid);
							free_fds--;
							fd = x;
						}
					} else {
						new = add_client(clients, nr_fds,
								 domain, virtpid);
						if (!new) {
							plog("Failed to allocate client for %s:%d\n",
							     domain, virtpid);
							continue;
						}
						clients = new;
						fd = nr_fds;
					}

					plog("start %s:%d\n", domain, virtpid);

					if (fd == nr_fds) {
						new = realloc(fds, sizeof(*fds) * (nr_fds + 1));
						if (!new) {
							plog("Failed to allocate for new connection for %s", domain);
							close(cfd);
							continue;
						}
						fds = new;
						nr_fds++;
					}

					memset(&fds[fd], 0, sizeof(*fds));
					fds[fd].fd = cfd;
					fds[fd].events = POLLIN | POLLHUP;

					continue;
				} else {
					virtpid = 0;
					domain = NULL;
				}
			} else {
				cfd = dup(fds[i].fd);
				if (cfd < 0) {
					plog("Failed to dup fd");
					continue;
				}
				client = &clients[i - FD_CONNECTED];
			}

			if (i == FD_NET)
				pid = do_connection(cfd, &addr, addrlen, NULL, 0, NET);
			else {
				pid = do_connection(cfd, NULL, 0,
						    client->name,
						    client->pid, VIRT);
				/*
				 * The client is accessing this file descriptor,
				 * don't poll on it for now. The clean up
				 * will re-institute it.
				 */
				if (!debug && pid > 0)
					fds[i].events &= ~POLLIN;
			}

			if (pid > 0)
				add_process(pid, i);
		}
	} while (!done);

	/* Get any final stragglers */
	clean_up(fds);

	for (i = 0; i < nr_fds; i++)
		close(fds[i].fd);

	free(fds);
}

static void make_pid_file(void)
{
	char buf[PATH_MAX];
	int mode = do_daemon;
	int fd;

	if (!do_daemon)
		return;

	make_pid_name(mode, buf);

	fd = open(buf, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		perror(buf);
		return;
	}

	sprintf(buf, "%d\n", getpid());
	write(fd, buf, strlen(buf));
	close(fd);
}

static int set_up_net(char *port)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int sfd, s;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	s = getaddrinfo(NULL, port, &hints, &result);
	if (s != 0)
		pdie("getaddrinfo: error opening %s", port);

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket(rp->ai_family, rp->ai_socktype,
			     rp->ai_protocol);
		if (sfd < 0)
			continue;

		if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
			break;

		close(sfd);
	}

	if (rp == NULL)
		pdie("Could not bind");

	freeaddrinfo(result);

	if (listen(sfd, backlog) < 0)
		pdie("listen");

	return sfd;
}

#define for_each_domain(i) for (i = dom_dir_list; i; i = (i)->next)

static void make_dir(const char *path, mode_t perms)
{
	if (mkdir(path, perms) < 0) {
		if (errno != EEXIST)
			pdie("mkdir %s", path);
	}
	chmod(path, perms);
}

static void make_dir_group(const char *path, mode_t perms, const char *gr_name)
{
	struct group *group;

	make_dir(path, perms);

	group = getgrnam(gr_name);
	if (!group)
		pdie("Required group '%s' does not exist.", gr_name);
	if (chown(path, -1, group->gr_gid) < 0)
		pdie("chown %s", path);
}

static void make_traceif_in_dom_dir(const char *name, int cpu)
{
	char fifo_in[PATH_MAX];
	char fifo_out[PATH_MAX];
	int i;

	for (i = 0; i < cpu; i++) {
		snprintf(fifo_in, PATH_MAX, TRACE_PATH_DOMAIN_CPU_I, name, i);
		snprintf(fifo_out, PATH_MAX, TRACE_PATH_DOMAIN_CPU_O, name, i);
		if (mkfifo(fifo_in, 0644) < 0) {
			if (errno != EEXIST)
				pdie("mkfifo %s", fifo_in);
		}
		if (mkfifo(fifo_out, 0644) < 0) {
			if (errno != EEXIST)
				pdie("mkfifo %s", fifo_out);
		}
	}
	plog("CPUS: %d\n", cpu);
}

static void make_domain_dirs(void)
{
	struct domain_dir *dom_dir;
	char gr_name[5] = "qemu";
	char buf[PATH_MAX];
	mode_t perms;

	for_each_domain(dom_dir) {
		snprintf(buf, PATH_MAX, VIRT_DOMAIN_DIR, dom_dir->name);

		if (dom_dir->perms)
			perms = dom_dir->perms;
		else
			perms = 0710;

		if (dom_dir->group)
			make_dir_group(buf, perms, dom_dir->group);
		else
			make_dir_group(buf, perms, gr_name);

		plog("---\n"
		     "Process Directory: %s\n"
		     "Directory permission: %o\n"
		     "Group: %s\n", buf, perms, dom_dir->group ? dom_dir->group : gr_name);

		if (dom_dir->cpu)
			make_traceif_in_dom_dir(dom_dir->name, dom_dir->cpu);
	}

	plog("---\n");
	free(dom_dir_list);
}

static void make_virt_if_dir(void)
{
	char gr_name[5] = "qemu";

	/* QEMU operates as qemu:qemu */
	make_dir(TRACE_CMD_DIR, 0755);
	make_dir_group(VIRT_DIR, 0710, gr_name);
	make_dir(TRACE_CMD_RUN_DIR, 0755);

	if (dom_dir_list)
		make_domain_dirs();
}

static void remove_sock(void)
{
	if (unlink_sock)
		unlink(VIRT_TRACE_CTL_SOCK);
	unlink_sock = 0;
}

static int set_up_virt(void)
{
	struct sockaddr_un un_server;
	struct group *group;
	socklen_t slen;
	int sfd;

	make_virt_if_dir();

	slen = sizeof(un_server);
	sfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sfd < 0)
		pdie("socket");

	un_server.sun_family = AF_UNIX;
	snprintf(un_server.sun_path, PATH_MAX, VIRT_TRACE_CTL_SOCK);

	if (bind(sfd, (struct sockaddr *)&un_server, slen) < 0)
		pdie("bind");
	unlink_sock = 1;

	chmod(VIRT_TRACE_CTL_SOCK, 0660);
	group = getgrnam("qemu");
	if (chown(VIRT_TRACE_CTL_SOCK, -1, group->gr_gid) < 0)
		pdie("fchown %s", VIRT_TRACE_CTL_SOCK);

	if (listen(sfd, backlog) < 0)
		pdie("listen");

	return sfd;
}

static void do_listen(int nfd, int vfd)
{
	do_accept_loop(nfd, vfd);

	remove_sock();

	kill_clients();
	remove_pid_file();
}

static void start_daemon(void)
{
	do_daemon = 1;

	if (daemon(1, 0) < 0)
		die("starting daemon");
}

static void add_dom_dir(struct domain_dir *dom_dir)
{
	dom_dir->next = dom_dir_list;
	dom_dir_list = dom_dir;
}

enum {
	OPT_virt	= 253,
	OPT_dom		= 254,
	OPT_debug	= 255,
};

static void sigstub(int sig)
{
}

void trace_listen(int argc, char **argv)
{
	struct domain_dir *dom_dir = NULL;
	char *logfile = NULL;
	char *port = NULL;
	int daemon = 0;
	int virt = 0;
	int nfd = -1;
	int vfd = -1;
	int c;

	if (argc < 2)
		usage(argv);

	for (;;) {
		int option_index = 0;
		static struct option long_options[] = {
			{"port", required_argument, NULL, 'p'},
			{"virt", no_argument, NULL, OPT_virt},
			{"dom", required_argument, NULL, OPT_dom},
			{"help", no_argument, NULL, '?'},
			{"debug", no_argument, NULL, OPT_debug},
			{NULL, 0, NULL, 0}
		};

		c = getopt_long (argc-1, argv+1, "+hp:o:d:l:Dm:g:c:",
			long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			usage(argv);
			break;
		case 'd':
			output_dir = optarg;
			break;
		case 'o':
			output_file = optarg;
			break;
		case 'l':
			logfile = optarg;
			break;
		case 'D':
			daemon = 1;
			break;
		case OPT_debug:
			debug = 1;
			break;
		case 'p':
			port = optarg;
			break;
		case 'm':
			if (!virt)
				die("-m requires --virt first");
			if (!dom_dir)
				die("-m needs --dom <domain>");
			dom_dir->perms = strtol(optarg, NULL, 8);
			break;
		case 'g':
			if (!virt)
				die("-g requires --virt first");
			if (!dom_dir)
				die("-g needs --dom <domain>");
			dom_dir->group = optarg;
			break;
		case 'c':
			if (!virt)
				die("-c requires --virt first");
			if (!dom_dir)
				die("-c needs --dom <domain>");
			dom_dir->cpu = atoi(optarg);
			break;
		case OPT_dom:
			if (!virt)
				die("--dom requires --virt first");
			dom_dir = malloc_or_die(sizeof(*dom_dir));
			memset(dom_dir, 0, sizeof(*dom_dir));
			dom_dir->name = optarg;
			add_dom_dir(dom_dir);
			break;
		case OPT_virt:
			virt = 1;
			break;
		default:
			usage(argv);
		}
	}

	if (!port && !virt)
		usage(argv);

	if ((argc - optind) >= 2)
		usage(argv);

	if (!output_file)
		output_file = default_output_file;

	if (!output_dir)
		output_dir = default_output_dir;

	if (logfile) {
		/* set the writes to a logfile instead */
		logfp = fopen(logfile, "w");
		if (!logfp)
			die("creating log file %s", logfile);
	}

	if (chdir(output_dir) < 0)
		die("Can't access directory %s", output_dir);

	if (daemon)
		start_daemon();

	signal_setup(SIGINT, finish);
	signal_setup(SIGTERM, finish);

	if (!debug)
		signal_setup(SIGCHLD, sigstub);

	make_pid_file();

	if (port)
		nfd = set_up_net(port);

	if (virt) {
		atexit(remove_sock);
		vfd = set_up_virt();
	}

	do_listen(nfd, vfd);

	return;
}
