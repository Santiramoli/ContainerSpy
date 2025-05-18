#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include "common.h"

void    id_list_init   (id_list_t *l, size_t init_cap);
bool    id_list_contains(const id_list_t *l, const char *id);
bool    id_list_add    (id_list_t *l, const char *id);
bool    id_list_remove (id_list_t *l, const char *id);
void    id_list_print(const id_list_t *l);
void    id_list_free   (id_list_t *l);
char    *get_container_id(const char *cgroup_path);
void    get_time(uint64_t timestamp_ns);
void    decode_clone_flags(uint64_t flags);

#endif