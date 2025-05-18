#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stdlib.h>


#define TASK_COMM_LEN 16
#define EVT_CLONE        0
#define EVT_UNSHARE      1
#define EVT_SETNS        2
#define EVT_CGROUP_MKDIR 3
#define EVT_CGROUP_RMDIR 4
#define MAX_ID_LEN 64
#define CLONE_NEWNS      0x00020000
#define CLONE_NEWCGROUP  0x02000000
#define CLONE_NEWUTS     0x04000000
#define CLONE_NEWIPC     0x08000000
#define CLONE_NEWUSER    0x10000000
#define CLONE_NEWPID     0x20000000
#define CLONE_NEWNET     0x40000000
#define CLONE_NEWTIME    0x00000080
#define MAX_CONTAINERS 1024


// Estructura que se envía al espacio de usuario para cada evento
struct event_t {
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t tgid;
    char     comm[TASK_COMM_LEN];
    uint32_t type;
    uint64_t flags;
    uint64_t cgroup_id;
    char     cgroup_path[256];
};


// Variable que almacena los tipos de eventos que se capturan
static const char *event_names[] = {
    "CLONE",
    "UNSHARE",
    "SETNS",
    "CGROUP_MKDIR",
    "CGROUP_RMDIR"
};

// Estructura de la lista que almacena los ids de los contenedores
typedef struct {
    char  **ids;     
    size_t  count;   
    size_t  cap;     
} id_list_t;

#endif