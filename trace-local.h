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
#ifndef __TRACE_LOCAL_H
#define __TRACE_LOCAL_H

#include <sys/types.h>
#include <dirent.h>	/* for DIR */

#include "trace-cmd.h"

/* fix stupid glib guint64 typecasts and printf formats */
typedef unsigned long long u64;

struct buffer_instance;

/* for local shared information with trace-cmd executable */

void usage(char **argv);

extern int silence_warnings;
extern int show_status;

struct pid_record_data {
	int			pid;
	int			brass[2];
	int			cpu;
	int			closed;
	struct tracecmd_input	*stream;
	struct buffer_instance	*instance;
	struct pevent_record	*record;
};

void show_file(const char *name);

struct tracecmd_input *read_trace_header(const char *file);
int read_trace_files(void);

void trace_record(int argc, char **argv);

void trace_report(int argc, char **argv);

void trace_split(int argc, char **argv);

void trace_listen(int argc, char **argv);

void trace_restore(int argc, char **argv);

void trace_stack(int argc, char **argv);

void trace_option(int argc, char **argv);

void trace_hist(int argc, char **argv);

void trace_snapshot(int argc, char **argv);

void trace_mem(int argc, char **argv);

void trace_stat(int argc, char **argv);

void trace_top(int argc, char **argv);

struct hook_list;

int trace_profile_record(struct tracecmd_input *handle,
			 struct pevent_record *record, int cpu);
void trace_init_profile(struct tracecmd_input *handle, struct hook_list *hooks,
			int global);
int trace_profile(void);
void trace_profile_set_merge_like_comms(void);

struct tracecmd_input *
trace_stream_init(struct buffer_instance *instance, int cpu, int fd, int cpus,
		  int profile, struct hook_list *hooks, int global);
int trace_stream_read(struct pid_record_data *pids, int nr_pids, struct timeval *tv,
		      int profile);

void trace_show_data(struct tracecmd_input *handle, struct pevent_record *record,
		     int profile);

/* --- event interation --- */

/*
 * Use this to iterate through the event directories
 */


enum event_process {
	PROCESSED_NONE,
	PROCESSED_EVENT,
	PROCESSED_SYSTEM
};

enum process_type {
	PROCESS_EVENT,
	PROCESS_SYSTEM
};

struct event_iter {
	DIR *system_dir;
	DIR *event_dir;
	struct dirent *system_dent;
	struct dirent *event_dent;
};

enum event_iter_type {
	EVENT_ITER_NONE,
	EVENT_ITER_SYSTEM,
	EVENT_ITER_EVENT
};

struct event_iter *trace_event_iter_alloc(const char *path);
enum event_iter_type trace_event_iter_next(struct event_iter *iter,
					   const char *path, const char *system);
void trace_event_iter_free(struct event_iter *iter);

char *append_file(const char *dir, const char *name);
char *get_file_content(const char *file);

char *strstrip(char *str);

/* --- instance manipulation --- */

struct func_list {
	struct func_list *next;
	const char *func;
};

struct buffer_instance {
	struct buffer_instance	*next;
	const char		*name;
	const char		*cpumask;
	struct event_list	*events;
	struct event_list	**event_next;

	struct event_list	*sched_switch_event;
	struct event_list	*sched_wakeup_event;
	struct event_list	*sched_wakeup_new_event;

	const char		*plugin;
	struct func_list	*filter_funcs;
	struct func_list	*notrace_funcs;

	const char		*clock;

	struct trace_seq	*s_save;
	struct trace_seq	*s_print;

	struct tracecmd_input	*handle;

	int			tracing_on_init_val;
	int			tracing_on_fd;
	int			keep;
	int			buffer_size;
	int			profile;
};

extern struct buffer_instance top_instance;
extern struct buffer_instance *buffer_instances;
extern struct buffer_instance *first_instance;

#define for_each_instance(i) for (i = buffer_instances; i; i = (i)->next)
#define for_all_instances(i) for (i = first_instance; i; \
				  i = i == &top_instance ? buffer_instances : (i)->next)

struct buffer_instance *create_instance(const char *name);
void add_instance(struct buffer_instance *instance);
char *get_instance_file(struct buffer_instance *instance, const char *file);
void update_first_instance(struct buffer_instance *instance, int topt);

void show_instance_file(struct buffer_instance *instance, const char *name);
int count_cpus(void);
char *read_file(char *file, int *psize);

#endif /* __TRACE_LOCAL_H */
