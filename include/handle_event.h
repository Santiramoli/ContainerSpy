#ifndef EVENT_HANDLER_H
#define EVENT_HANDLER_H

#include <stddef.h>
#include <sys/types.h>
#include "../include/utils.h"



void    event_handler_init();
void    event_handler_cleanup();
bool    should_ignore_comm(const char *comm);
int     validate_event(const struct event_t *e, size_t len);
void    process_exec(const struct event_t *e);
void    process_fork(const struct event_t *e);
void    process_exit(const struct event_t *e);
void    process_cgroup_mkdir(const struct event_t *e);
void    process_cgroup_rmdir(const struct event_t *e);
void    process_namespace_event(const struct event_t *e);
int     handle_event(void *ctx, void *data, size_t len);
pod_entry_t *find_pod(id_list_t *pods, const char *pod_id);
pod_entry_t *add_pod(id_list_t *pods, const char *pod_id);
container_entry_t *find_container(pod_entry_t *pod, uint64_t cgroup_id);
container_entry_t *add_container(pod_entry_t *pod, const char *container_id, uint64_t cgroup_id);


#endif