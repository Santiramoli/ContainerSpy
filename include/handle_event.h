#ifndef EVENT_HANDLER_H
#define EVENT_HANDLER_H

#include <stddef.h>
#include "../include/utils.h"


void    event_handler_init();
void    event_handler_cleanup();
bool    should_ignore_comm(const char *comm);
int     validate_event(const struct event_t *e, size_t len);
void    process_cgroup_mkdir(const struct event_t *e);
void    process_cgroup_rmdir(const struct event_t *e);
void    process_namespace_event(const struct event_t *e);
int     handle_event(void *ctx, void *data, size_t len);

#endif