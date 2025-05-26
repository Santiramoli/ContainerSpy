#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include "common.h"
#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <zlog.h>



// Funciones para la lista de pods
void    pod_list_init        (id_list_t *list, size_t init_cap);
bool    pod_list_contains    (id_list_t *list, const char *pod_id);
pod_entry_t* pod_list_find   (id_list_t *list, const char *pod_id);
bool    pod_list_add         (id_list_t *list, pod_entry_t pod);
bool    pod_list_remove      (id_list_t *list, const char *pod_id);
void    pod_list_free        (id_list_t *l);

// Funciones para la gestión de contenedores
void pod_init_containers(pod_entry_t *pod);
bool pod_add_container(pod_entry_t *pod, container_entry_t container);
container_entry_t *pod_find_container_by_id(pod_entry_t *pod, const char *container_id);
container_entry_t *pod_find_container_by_cgroup(pod_entry_t *pod, uint64_t cgroup_id);
bool pod_remove_container(pod_entry_t *pod, const char *container_id);
void add_container_to_pod(id_list_t *pods, const char *pod_id, container_entry_t container, const char *node_name);

// Funciones para la gestión de logs
void log_basic_event_info(const struct event_t *e);
void log_event_exit(const struct event_t *e, const char *event_name, bool has_latency);
void log_event_file(const struct event_t *e, const char *event_name);
void log_event_cgroup_mkdir(const struct event_t *e);
void log_event_cgroup_rmdir(const struct event_t *e);
void log_event_ns(const struct event_t *e);

// Funciones para eventos de cgroup_mkdir y cgroup_rmdir, clone, unshare y setns
void handle_event_cgroup_rmdir(const struct event_t *e);
void handle_event_cgroup_mkdir(const struct event_t *e);
void handle_event_ns(const struct event_t *e); 


// Otras funciones
char    *get_container_id(const char *cgroup_path);
char *get_time_str();
void    decode_clone_flags(uint64_t flags);
uint64_t get_cgroup_id_from_path(const char *cgroup_path);
void update_flags(ns_flags_counters_t *counters, uint64_t flags);
void extract_pod_and_container(const char *path, char *pod_id, size_t pod_len, char *container_id, size_t cont_len);
int get_node_name(char *buf, size_t bufsize);

#endif 