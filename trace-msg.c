/*
 * trace-msg.c : define message protocol for communication between clients and
 *               a server
 *
 * Copyright (C) 2013 Hitachi, Ltd.
 * Created by Yoshihiro YUNOMAE <yoshihiro.yunomae.ez@hitachi.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License (not later!)
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not,  see <http://www.gnu.org/licenses>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/types.h>

#include "trace-cmd-local.h"
#include "trace-local.h"
#include "trace-msg.h"

typedef __u32 u32;
typedef __be32 be32;

static inline void dprint(const char *fmt, ...)
{
	va_list ap;

	if (!debug)
		return;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

/* Two (4k) pages is the max transfer for now */
#define MSG_MAX_LEN			8192

					/* size + cmd */
#define MSG_HDR_LEN			((sizeof(be32)) + (sizeof(be32)))

#define MSG_DATA_LEN			(MSG_MAX_LEN - MSG_HDR_LEN)

					/* - header size for error msg */
#define MSG_META_MAX_LEN		(MSG_MAX_LEN - MIN_DATA_SIZE)


#define MIN_TINIT_SIZE		offsetof(struct tracecmd_msg, data.tinit.opt)

/* Not really the minimum, but I couldn't think of a better name */
#define MIN_RINIT_SIZE		offsetof(struct tracecmd_msg, data.rinit.port_array)

#define MIN_DATA_SIZE	 	offsetof(struct tracecmd_msg, data.data.buf)

/* use CONNECTION_MSG as a protocol version of trace-msg */
#define MSG_VERSION		"V2"
#define CONNECTION_MSG		"tracecmd-" MSG_VERSION
#define CONNECTION_MSGSIZE	sizeof(CONNECTION_MSG)

unsigned int page_size;

struct tracecmd_msg_client {
	struct tracecmd_msg_handle handle;
	int			*client_ports;
};

struct tracecmd_msg_server {
	struct tracecmd_msg_handle handle;
	int			*port_array;
	int			done;
};

static struct tracecmd_msg_client *
make_client(struct tracecmd_msg_handle *msg_handle)
{
	if (!(msg_handle->flags & TRACECMD_MSG_FL_CLIENT)) {
		plog("Message handle not of type client");
		return NULL;
	}
	return (struct tracecmd_msg_client *)msg_handle;
}

static struct tracecmd_msg_server *
make_server(struct tracecmd_msg_handle *msg_handle)
{
	if (!(msg_handle->flags & TRACECMD_MSG_FL_SERVER)) {
		plog("Message handle not of type server\n");
		return NULL;
	}
	return (struct tracecmd_msg_server *)msg_handle;
}

struct tracecmd_msg_opt {
	be32 size;
	be32 opt_cmd;
} __attribute__((packed));

struct tracecmd_msg_tinit {
	be32 cpus;
	be32 page_size;
	be32 opt_num;
	struct tracecmd_msg_opt *opt;
} __attribute__((packed));

struct tracecmd_msg_rinit {
	be32 cpus;
	be32 *port_array;
} __attribute__((packed));

struct tracecmd_msg_data {
	be32 size;
	void *buf;
} __attribute__((packed));

struct tracecmd_msg_error {
	be32 size;
	be32 cmd;
	union {
		struct tracecmd_msg_tinit tinit;
		struct tracecmd_msg_rinit rinit;
		struct tracecmd_msg_data data;
	} data;
} __attribute__((packed));

#define MSG_NAMES \
	C(CLOSE)				\
	C(TCONNECT)				\
	C(RCONNECT)				\
	C(TINIT)				\
	C(RINIT)				\
	C(SENDMETA)				\
	C(FINMETA)

#undef C
#define C(a)	MSG_##a,

enum tracecmd_msg_cmd {
	MSG_ERROR	= 0,
	MSG_NAMES
	MSG_MAX
};

#undef C
#define C(a)	#a,

static const char *msg_names[] = {
	"ERROR", MSG_NAMES "MAX" };

static const char *cmd_to_name(int cmd)
{
	if (cmd < MSG_MAX)
		return msg_names[cmd];
	return "Unkown";
}

struct tracecmd_msg {
	be32 size;
	be32 cmd;
	union {
		struct tracecmd_msg_tinit tinit;
		struct tracecmd_msg_rinit rinit;
		struct tracecmd_msg_data data;
		struct tracecmd_msg_error err;
	} data;
} __attribute__((packed));

struct tracecmd_msg *errmsg;

static int msg_write(int fd, struct tracecmd_msg *msg, int size, void *addr)
{
	int ret;

	ret = __do_write_check(fd, msg, size);
	if (ret < 0)
		return ret;
	if (ntohl(msg->size) <= size)
		return 0;
	return __do_write_check(fd, addr, ntohl(msg->size) - size);
}

static ssize_t msg_do_write_check(struct tracecmd_msg_handle *msg_handle,
				  struct tracecmd_msg *msg)
{
	int ret;
	int fd = msg_handle->fd;

	switch (ntohl(msg->cmd)) {
	case MSG_TINIT:
		ret = msg_write(fd, msg, MIN_TINIT_SIZE, msg->data.tinit.opt);
		break;
	case MSG_RINIT:
		ret = msg_write(fd, msg, MIN_RINIT_SIZE, msg->data.rinit.port_array);
		break;
	case MSG_SENDMETA:
	case MSG_RCONNECT:
		ret = msg_write(fd, msg, MIN_DATA_SIZE, msg->data.data.buf);
		break;
	default:
		ret = __do_write_check(fd, msg, ntohl(msg->size));
	}

	return ret;
}

int *tracecmd_msg_get_client_ports(struct tracecmd_msg_handle *msg_handle)
{
	struct tracecmd_msg_client *msg_client = make_client(msg_handle);

	return msg_client->client_ports;
}

int *tracecmd_msg_alloc_client_ports(struct tracecmd_msg_handle *msg_handle,
				     int cpu_count)
{
	struct tracecmd_msg_client *msg_client = make_client(msg_handle);

	msg_client->client_ports = malloc(sizeof(int) * cpu_count);
	return msg_client->client_ports;
}

static int make_data(const char *buf, int buflen, struct tracecmd_msg *msg)
{
	msg->data.data.size = htonl(buflen);
	msg->data.data.buf = malloc(buflen);
	if (!msg->data.data.buf)
		return -ENOMEM;
	memcpy(msg->data.data.buf, buf, buflen);

	msg->size = htonl(MIN_DATA_SIZE + buflen);

	return 0;
}

enum msg_opt_command {
	MSGOPT_USETCP = 1,
};

static int make_tinit(struct tracecmd_msg_handle *msg_handle,
		      struct tracecmd_msg *msg)
{
	struct tracecmd_msg_opt *opt;
	int opt_num = 0;
	int size = MIN_TINIT_SIZE;

	if (msg_handle->flags & TRACECMD_MSG_FL_USE_TCP) {
		opt_num++;
		opt = malloc(sizeof(*opt));
		if (!opt)
			return -ENOMEM;
		opt->size = htonl(sizeof(*opt));
		opt->opt_cmd = htonl(MSGOPT_USETCP);
		msg->data.tinit.opt = opt;
		size += sizeof(*opt);
	}

	msg->data.tinit.cpus = htonl(msg_handle->cpu_count);
	msg->data.tinit.page_size = htonl(page_size);
	msg->data.tinit.opt_num = htonl(opt_num);

	msg->size = htonl(size);

	return 0;
}

static int make_rinit(struct tracecmd_msg_handle *msg_handle,
		      struct tracecmd_msg *msg)
{
	struct tracecmd_msg_server *msg_server = make_server(msg_handle);
	int cpu_count = msg_handle->cpu_count;
	int size = MIN_RINIT_SIZE;
	int alloc_size;
	be32 *ptr;
	be32 port;
	int i;

	msg->data.rinit.cpus = htonl(cpu_count);

	if (msg_server->port_array) {
		alloc_size = sizeof(*msg->data.rinit.port_array) * cpu_count;
		msg->data.rinit.port_array = malloc(alloc_size);
		if (!msg->data.rinit.port_array)
			return -ENOMEM;

		size += alloc_size;

		ptr = msg->data.rinit.port_array;

		for (i = 0; i < cpu_count; i++) {
			/* + rrqports->cpus or rrqports->port_array[i] */
			port = htonl(msg_server->port_array[i]);
			*ptr = port;
			ptr++;
		}
	}

	msg->size = htonl(size);

	return 0;
}

static int make_error_msg(struct tracecmd_msg *msg)
{
	msg->data.err.size = errmsg->size;
	msg->data.err.cmd = errmsg->cmd;

	switch (ntohl(errmsg->cmd)) {
	case MSG_TINIT:
		msg->data.err.data.tinit = errmsg->data.tinit;
		break;
	case MSG_RINIT:
		msg->data.err.data.rinit = errmsg->data.rinit;
		break;
	case MSG_SENDMETA:
	case MSG_RCONNECT:
		msg->data.err.data.data = errmsg->data.data;
		break;
	}

	msg->size = htonl(sizeof(*msg));

	return 0;
}

static int tracecmd_msg_create(struct tracecmd_msg_handle *msg_handle,
			       u32 cmd, struct tracecmd_msg *msg)
{
	int ret = 0;

	memset(msg, 0, sizeof(*msg));
	msg->cmd = htonl(cmd);

	switch (cmd) {
	case MSG_ERROR:
		return make_error_msg(msg);
	case MSG_RCONNECT:
		return make_data(CONNECTION_MSG, CONNECTION_MSGSIZE, msg);
	case MSG_TINIT:
		return make_tinit(msg_handle, msg);
	case MSG_RINIT:
		return make_rinit(msg_handle, msg);
	case MSG_TCONNECT:
	case MSG_CLOSE:
	case MSG_SENDMETA: /* meta data is not stored here. */
	case MSG_FINMETA:
		break;
	}

	msg->size = htonl(MSG_HDR_LEN);

	return ret;
}

static void msg_free(struct tracecmd_msg *msg)
{
	switch (ntohl(msg->cmd)) {
	case MSG_TINIT:
		free(msg->data.tinit.opt);
		break;
	case MSG_RINIT:
		free(msg->data.rinit.port_array);
		break;
	case MSG_SENDMETA:
	case MSG_RCONNECT:
		free(msg->data.data.buf);
		break;
	}
}

static int tracecmd_msg_send(struct tracecmd_msg_handle *msg_handle, u32 cmd)
{
	struct tracecmd_msg msg;
	int ret = 0;

	if (cmd >= MSG_MAX) {
		plog("Unsupported command: %d\n", cmd);
		return -EINVAL;
	}

	ret = tracecmd_msg_create(msg_handle, cmd, &msg);
	if (ret < 0)
		return ret;

	dprint("msg send: %d (%s)\n", cmd, cmd_to_name(cmd));

	ret = msg_do_write_check(msg_handle, &msg);
	if (ret < 0)
		ret = -ECOMM;

	msg_free(&msg);

	return ret;
}

static void
tracecmd_msg_send_error(struct tracecmd_msg_handle *msg_handle,
			struct tracecmd_msg *msg)
{
	errmsg = msg;
	tracecmd_msg_send(msg_handle, MSG_ERROR);
}

static int msg_read(int fd, void *buf, u32 size, int *n)
{
	int r;

	while (size) {
		r = read(fd, buf + *n, size);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		} else if (!r)
			return -ENOTCONN;
		size -= r;
		*n += r;
	}

	return 0;
}

static int msg_read_extra(int fd, void *buf, int *n,
			  int size, int min_size, void **addr)
{
	int rsize;
	int ret;

	rsize = min_size - *n;
	ret = msg_read(fd, buf, rsize, n);
	if (ret < 0)
		return ret;
	size -= *n;
	if (size < 0)
		return -ENOMSG;
	*addr = malloc(size);
	if (!*addr)
		return -ENOMEM;
	*n = 0;
	return msg_read(fd, *addr, size, n);
}

static int tracecmd_msg_read_extra(int fd, struct tracecmd_msg *msg, int *n)
{
	int size = ntohl(msg->size);
	int rsize;
	int ret;

	switch (ntohl(msg->cmd)) {
	case MSG_TINIT:
		msg->data.tinit.opt = NULL;

		rsize = MIN_TINIT_SIZE - *n;

		ret = msg_read(fd, msg, rsize, n);
		if (ret < 0)
			return ret;

		if (size > *n) {
			size -= *n;
			msg->data.tinit.opt = malloc(size);
			if (!msg->data.tinit.opt)
				return -ENOMEM;
			*n = 0;
			return msg_read(fd, msg->data.tinit.opt, size, n);
		}
		return 0;
	case MSG_RINIT:
		return msg_read_extra(fd, msg, n, size, MIN_RINIT_SIZE,
				      (void **)&msg->data.rinit.port_array);
	case MSG_SENDMETA:
	case MSG_RCONNECT:
		return msg_read_extra(fd, msg, n, size, MIN_DATA_SIZE,
				      (void **)&msg->data.data.buf);
	}

	return msg_read(fd, msg, size - MSG_HDR_LEN, n);
}

/*
 * Read header information of msg first, then read all data
 */
static int tracecmd_msg_recv(struct tracecmd_msg_handle *msg_handle,
			     struct tracecmd_msg *msg)
{
	int fd = msg_handle->fd;
	u32 size = 0;
	int n = 0;
	int ret;

	ret = msg_read(fd, msg, MSG_HDR_LEN, &n);
	if (ret < 0)
		return ret;

	dprint("msg received: %d (%s)\n", ntohl(msg->cmd), cmd_to_name(ntohl(msg->cmd)));

	size = ntohl(msg->size);
	if (size > MSG_MAX_LEN)
		/* too big */
		goto error;
	else if (size < MSG_HDR_LEN)
		/* too small */
		goto error;
	else if (size > MSG_HDR_LEN)
		return tracecmd_msg_read_extra(fd, msg, &n);

	return 0;
error:
	plog("Receive an invalid message(size=%d)\n", size);
	return -ENOMSG;
}

#define MSG_WAIT_MSEC	5000
static int msg_wait_to = MSG_WAIT_MSEC;

bool tracecmd_msg_done(struct tracecmd_msg_handle *msg_handle)
{
	struct tracecmd_msg_server *msg_server = make_server(msg_handle);

	return (volatile int)msg_server->done;
}

void tracecmd_msg_set_done(struct tracecmd_msg_handle *msg_handle)
{
	struct tracecmd_msg_server *msg_server = make_server(msg_handle);

	msg_server->done = true;
}

/*
 * A return value of 0 indicates time-out
 */
static int tracecmd_msg_recv_wait(struct tracecmd_msg_handle *msg_handle,
				  struct tracecmd_msg *msg)
{
	struct pollfd pfd;
	int ret;

	pfd.fd = msg_handle->fd;
	pfd.events = POLLIN;
	ret = poll(&pfd, 1, debug ? -1 : msg_wait_to);
	if (ret < 0)
		return -errno;
	else if (ret == 0)
		return -ETIMEDOUT;

	return tracecmd_msg_recv(msg_handle, msg);
}

int tracecmd_msg_send_init_data(struct tracecmd_msg_handle *msg_handle)
{
	struct tracecmd_msg_client *msg_client = make_client(msg_handle);
	struct tracecmd_msg msg;
	char path[PATH_MAX];
	int i, cpus;
	int ret;
	u32 cmd;

	ret = tracecmd_msg_send(msg_handle, MSG_TINIT);
	if (ret < 0)
		return ret;

	ret = tracecmd_msg_recv_wait(msg_handle, &msg);
	if (ret < 0) {
		if (ret == -ETIMEDOUT)
			warning("Connection timed out\n");
		return ret;
	}

	cmd = ntohl(msg.cmd);
	if (cmd != MSG_RINIT) {
		warning("Expected RINIT and received %d\n", cmd);
		return -EINVAL;
	}

	if (msg_client->client_ports) {
		plog("msg_client already has ports defined");
		return -EINVAL;
	}

	cpus = ntohl(msg.data.rinit.cpus);
	msg_client->client_ports = malloc_or_die(sizeof(int) * cpus);
	if (msg_handle->flags & TRACECMD_MSG_FL_NETWORK) {
		for (i = 0; i < cpus; i++)
			msg_client->client_ports[i] =
				ntohl(msg.data.rinit.port_array[i]);
	} else if (msg_handle->flags & TRACECMD_MSG_FL_VIRT) {

		/* Open data paths of virtio-serial */
		for (i = 0; i < cpus; i++) {
			snprintf(path, PATH_MAX, TRACE_PATH_CPU, i);
			msg_client->client_ports[i] = open(path, O_WRONLY);
			if (msg_client->client_ports[i] < 0) {
				warning("Cannot open %s", TRACE_PATH_CPU, i);
				return -errno;
			}
		}
	} else {
		plog("Neither virt or network specified");
		return -EINVAL;
	}

	return 0;
}

int tracecmd_msg_connect_to_server(struct tracecmd_msg_handle *msg_handle)
{
	struct tracecmd_msg msg;
	u32 cmd;
	int ret;

	/* connect to a server */
	ret = tracecmd_msg_send(msg_handle, MSG_TCONNECT);
	if (ret < 0)
		return ret;

	ret = tracecmd_msg_recv_wait(msg_handle, &msg);
	if (ret < 0) {
		if (ret != -ETIMEDOUT)
			goto error;
		warning("Connection timed out\n");
		return ret;
	}

	cmd = ntohl(msg.cmd);
	if (cmd != MSG_RCONNECT) {
		warning("expected to received RCONNECT but received %d\n", cmd);
		goto error;
	}

	/* Make sure the server is the tracecmd server */
	if (memcmp(msg.data.data.buf, CONNECTION_MSG,
		   ntohl(msg.data.data.size) - 1) != 0) {
		warning("server not tracecmd server");
		return -EPROTONOSUPPORT;
	}

	return ret;

error:
	tracecmd_msg_send_error(msg_handle, &msg);
	return ret;
}

static bool process_option(struct tracecmd_msg_handle *msg_handle,
			   struct tracecmd_msg_opt *opt)
{
	/* currently the only option we have is to us TCP */
	if (ntohl(opt->opt_cmd) == MSGOPT_USETCP) {
		msg_handle->flags |= TRACECMD_MSG_FL_USE_TCP;
		return true;
	}
	return false;
}

static void error_operation_for_server(struct tracecmd_msg *msg)
{
	u32 cmd;

	cmd = ntohl(msg->cmd);

	if (cmd == MSG_ERROR)
		plog("Receive error message: cmd=%d size=%d\n",
		     ntohl(msg->data.err.cmd), ntohl(msg->data.err.size));
	else
		warning("Message: cmd=%d size=%d\n", cmd, ntohl(msg->size));
}

struct tracecmd_msg_handle *
tracecmd_msg_handle_alloc(int fd, unsigned long flags)
{
	struct tracecmd_msg_handle *handle;
	int size;

	if (flags & TRACECMD_MSG_FL_SERVER)
		size = sizeof(struct tracecmd_msg_server);
	else if (flags & TRACECMD_MSG_FL_CLIENT)
		size = sizeof(struct tracecmd_msg_client);
	else
		size = sizeof(struct tracecmd_msg_handle);

	handle = calloc(1, size);
	if (!handle)
		return NULL;

	handle->fd = fd;
	handle->flags = flags;
	return handle;
}

void tracecmd_msg_handle_close(struct tracecmd_msg_handle *msg_handle)
{
	close(msg_handle->fd);
	if (msg_handle->flags & TRACECMD_MSG_FL_CLIENT)
		free(((struct tracecmd_msg_client *)msg_handle)->client_ports);
	free(msg_handle);
}

int tracecmd_msg_set_connection(struct tracecmd_msg_handle *msg_handle,
				const char *domain)
{
	struct tracecmd_msg msg;
	u32 cmd;
	int ret;

	memset(&msg, 0, sizeof(msg));

	/*
	 * Wait for connection msg by a client first.
	 * If a client uses virtio-serial, a connection message will
	 * not be sent immediately after accept(). connect() is called
	 * in QEMU, so the client can send the connection message
	 * after guest boots. Therefore, the virt-server patiently
	 * waits for the connection request of a client.
	 */
	ret = tracecmd_msg_recv(msg_handle, &msg);
	if (ret < 0) {
		if (!msg.cmd) {
			/* No data means QEMU has already died. */
			tracecmd_msg_handle_close(msg_handle);
			die("Connection refused: %s", domain);
		}
		return -ENOMSG;
	}

	cmd = ntohl(msg.cmd);
	if (cmd == MSG_CLOSE)
		return -ECONNABORTED;
	else if (cmd != MSG_TCONNECT)
		return -EPROTONOSUPPORT;

	ret = tracecmd_msg_send(msg_handle, MSG_RCONNECT);
	if (ret < 0)
		goto error;

	return 0;

error:
	error_operation_for_server(&msg);
	return ret;
}

#define MAX_OPTION_SIZE 4096

int tracecmd_msg_initial_setting(struct tracecmd_msg_handle *msg_handle,
				 int *cpus, int *pagesize)
{
	struct tracecmd_msg_opt *opt;
	struct tracecmd_msg msg;
	int options, i, s;
	int ret;
	int offset = 0;
	u32 size = MIN_TINIT_SIZE;
	u32 cmd;

	ret = tracecmd_msg_recv_wait(msg_handle, &msg);
	if (ret < 0) {
		if (ret == -ETIMEDOUT)
			warning("Connection timed out\n");
		return ret;
	}

	cmd = ntohl(msg.cmd);
	if (cmd != MSG_TINIT) {
		ret = -EINVAL;
		goto error;
	}

	*cpus = ntohl(msg.data.tinit.cpus);
	plog("cpus=%d\n", *cpus);
	if (*cpus < 0) {
		ret = -EINVAL;
		goto error;
	}

	*pagesize = ntohl(msg.data.tinit.page_size);
	plog("pagesize=%d\n", *pagesize);
	if (*pagesize <= 0) {
		ret = -EINVAL;
		goto error;
	}

	options = ntohl(msg.data.tinit.opt_num);
	for (i = 0; i < options; i++) {
		if (size + sizeof(*opt) > ntohl(msg.size)) {
			plog("Not enough message for options\n");
			ret = -EINVAL;
			goto error;
		}
		opt = (void *)msg.data.tinit.opt + offset;
		offset += ntohl(opt->size);
		size += ntohl(opt->size);
		if (ntohl(msg.size) < size) {
			plog("Not enough message for options\n");
			ret = -EINVAL;
			goto error;
		}
		/* prevent a client from killing us */
		if (ntohl(opt->size) > MAX_OPTION_SIZE) {
			plog("Exceed MAX_OPTION_SIZE\n");
			ret = -EINVAL;
			goto error;
		}
		s = process_option(msg_handle, opt);
		/* do we understand this option? */
		if (!s) {
			plog("Cannot understand(%d:%d:%d)\n",
			     i, ntohl(opt->size), ntohl(opt->opt_cmd));
			ret = -EINVAL;
			goto error;
		}
	}

	return 0;

error:
	error_operation_for_server(&msg);
	return ret;
}

int tracecmd_msg_send_port_array(struct tracecmd_msg_handle *msg_handle,
				 int total_cpus, int *ports)
{
	struct tracecmd_msg_server *msg_server = make_server(msg_handle);
	int ret;

	msg_handle->cpu_count = total_cpus;
	msg_server->port_array = ports;

	ret = tracecmd_msg_send(msg_handle, MSG_RINIT);
	if (ret < 0)
		return ret;

	return 0;
}

void tracecmd_msg_send_close_msg(struct tracecmd_msg_handle *msg_handle)
{
	tracecmd_msg_send(msg_handle, MSG_CLOSE);
}

int tracecmd_msg_metadata_send(struct tracecmd_msg_handle *msg_handle,
			       const char *buf, int size)
{
	struct tracecmd_msg msg;
	int n;
	int ret;
	int count = 0;

	ret = tracecmd_msg_create(msg_handle, MSG_SENDMETA, &msg);
	if (ret < 0)
		return ret;

	msg.data.data.buf = malloc(MSG_META_MAX_LEN);
	if (!msg.data.data.buf)
		return -ENOMEM;

	msg.data.data.size = htonl(MSG_META_MAX_LEN);
	msg.size = htonl(MIN_DATA_SIZE + MSG_META_MAX_LEN);

	n = size;
	do {
		if (n > MSG_META_MAX_LEN) {
			memcpy(msg.data.data.buf, buf+count, MSG_META_MAX_LEN);
			n -= MSG_META_MAX_LEN;
			count += MSG_META_MAX_LEN;
		} else {
			msg.size = htonl(MIN_DATA_SIZE + n);
			msg.data.data.size = htonl(n);
			memcpy(msg.data.data.buf, buf+count, n);
			n = 0;
		}

		ret = msg_do_write_check(msg_handle, &msg);
		if (ret < 0)
			break;
	} while (n);

	msg_free(&msg);
	return ret;
}

int tracecmd_msg_finish_sending_metadata(struct tracecmd_msg_handle *msg_handle)
{
	int ret;

	ret = tracecmd_msg_send(msg_handle, MSG_FINMETA);
	if (ret < 0)
		return ret;
	return 0;
}

int tracecmd_msg_collect_metadata(struct tracecmd_msg_handle *msg_handle, int ofd)
{
	struct tracecmd_msg msg;
	u32 s, t, n, cmd;
	int ret;

	do {
		ret = tracecmd_msg_recv_wait(msg_handle, &msg);
		if (ret < 0) {
			if (ret == -ETIMEDOUT)
				warning("Connection timed out\n");
			else
				warning("reading client");
			return ret;
		}

		cmd = ntohl(msg.cmd);
		if (cmd == MSG_FINMETA) {
			/* Finish receiving meta data */
			break;
		} else if (cmd != MSG_SENDMETA)
			goto error;

		n = ntohl(msg.data.data.size);
		t = n;
		s = 0;
		do {
			s = write(ofd, msg.data.data.buf+s, t);
			if (s < 0) {
				if (errno == EINTR)
					continue;
				warning("writing to file");
				return -errno;
			}
			t -= s;
			s = n - t;
		} while (t);
	} while (cmd == MSG_SENDMETA);

	/* check the finish message of the client */
	while (!tracecmd_msg_done(msg_handle)) {
		ret = tracecmd_msg_recv(msg_handle, &msg);
		if (ret < 0) {
			warning("reading client");
			return ret;
		}

		cmd = ntohl(msg.cmd);
		if (cmd == MSG_CLOSE)
			/* Finish this connection */
			break;
		else {
			warning("Not accept the message %d", ntohl(msg.cmd));
			ret = -EINVAL;
			goto error;
		}
	}

	return 0;

error:
	error_operation_for_server(&msg);
	return ret;
}
