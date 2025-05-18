#include "../include/utils.h"
#include <stdio.h>
#include <string.h>


void id_list_init(id_list_t *l, size_t init_cap) {
    l->ids   = malloc(init_cap * sizeof(char*));
    l->count = 0;
    l->cap   = init_cap;
    if (!l->ids) {
        perror("malloc");
        exit(1);
    }
}

void id_list_print(const id_list_t *l){
    printf("\nLista actual de contenedores (%zu):\n", l->count);
    for (size_t i = 0; i < l->count; i++) {
        printf("  [%zu] %s\n", i, l->ids[i]);
    }
    printf("\n");
}

bool id_list_contains(const id_list_t *l, const char *id) {
    for (size_t i = 0; i < l->count; i++) {
        if (strcmp(l->ids[i], id) == 0)
            return true;
    }
    return false;
}

bool id_list_add(id_list_t *l, const char *id) {
    if (id_list_contains(l, id))
        return false;
    if (l->count == l->cap) {
        size_t newcap = l->cap * 2;
        char **tmp = realloc(l->ids, newcap * sizeof(char*));
        if (!tmp) { perror("realloc"); return false; }
        l->ids = tmp;
        l->cap = newcap;
    }
    l->ids[l->count++] = strdup(id);
    id_list_print(l);
    return true;
}

bool id_list_remove(id_list_t *l, const char *id) {
    for (size_t i = 0; i < l->count; i++) {
        if (strcmp(l->ids[i], id) == 0) {
            free(l->ids[i]);
            memmove(&l->ids[i], &l->ids[i+1],
                    (l->count - i - 1) * sizeof(char*));
            l->count--;
            id_list_print(l);
            return true;
        }
    }
    return false;
}

void id_list_free(id_list_t *l) {
    for (size_t i = 0; i < l->count; i++)
        free(l->ids[i]);
    free(l->ids);
    l->ids = NULL;
    l->count = l->cap = 0;
}

char *get_container_id(const char *cgroup_path){
    char buf[512];
    strncpy(buf, cgroup_path, sizeof(buf)-1);
    buf[sizeof(buf)-1] = '\0';

    const char *delims = "/-.";
    char *tok = strtok(buf, delims);

    while (tok) {
        size_t len = strlen(tok);
        if (len >= 12 && len <= MAX_ID_LEN) {
            bool all_hex = true;
            for (size_t i = 0; i < len; i++) {
                if (!isxdigit((unsigned char)tok[i])) {
                    all_hex = false;
                    break;
                }
            }
            if (all_hex) {
                return strdup(tok);
            }
        }
        tok = strtok(NULL, delims);
    }

    // Si llegamos aquí, no encontramos nada válido
    return NULL;
}

void get_time(uint64_t timestamp_ns){
    // convierto nanoseg → segundos
    time_t ts = (time_t)(timestamp_ns / 1000000000ULL);
    char *s = ctime(&ts);
    if (s) {
        printf("Fecha y hora: %s", s);
    } else {
        perror("ctime");
    }
}

void decode_clone_flags(uint64_t flags) {
    
    printf("Flags: ");
        if (flags & CLONE_NEWNS)      printf("CLONE_NEWNS ");
        if (flags & CLONE_NEWCGROUP)  printf("CLONE_NEWCGROUP ");
        if (flags & CLONE_NEWUTS)     printf("CLONE_NEWUTS ");
        if (flags & CLONE_NEWIPC)     printf("CLONE_NEWIPC ");
        if (flags & CLONE_NEWUSER)    printf("CLONE_NEWUSER ");
        if (flags & CLONE_NEWPID)     printf("CLONE_NEWPID ");
        if (flags & CLONE_NEWNET)     printf("CLONE_NEWNET ");
        if (flags & CLONE_NEWTIME)    printf("CLONE_NEWTIME ");
    printf("\n");
    
}