#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stdlib.h>
#include <zlog.h>


#define TASK_COMM_LEN 16
#define EVT_CLONE        0
#define EVT_UNSHARE      1
#define EVT_SETNS        2
#define EVT_CGROUP_MKDIR 3
#define EVT_CGROUP_RMDIR 4
#define EVT_PROCESS_FORK 5
#define EVT_PROCESS_EXEC 6
#define EVT_PROCESS_EXIT 7
#define EVT_CLONE_EXIT 8
#define EVT_UNSHARE_EXIT 9
#define EVT_SETNS_EXIT 10
#define EVT_OPEN 11
#define EVT_OPENAT 12
#define EVT_OPEN_EXIT 13
#define EVT_OPENAT_EXIT 14
#define EVT_WRITE 15
#define EVT_CLOSE 16
#define EVT_WRITE_EXIT 17
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
#define BUFFER_SIZE 1024
#define MAX_PROCS   65536
#define MAX_CGROUPS 4096
#define NS_MASK (CLONE_NEWNS|CLONE_NEWCGROUP|CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWNET|CLONE_NEWTIME)
extern const char *base_path;
extern char pod_id[128];
extern char container_id[128];
extern char node_name[64];
extern zlog_category_t *c;

/****************************************************
* Estructuras para la gestión de pods y containers  *
*****************************************************/
typedef struct {
    uint64_t mnt;    // CLONE_NEWNS
    uint64_t uts;    // CLONE_NEWUTS
    uint64_t ipc;    // CLONE_NEWIPC
    uint64_t user;   // CLONE_NEWUSER
    uint64_t pid;    // CLONE_NEWPID
    uint64_t net;    // CLONE_NEWNET
    uint64_t cgroup; // CLONE_NEWCGROUP
    uint64_t time;   // CLONE_NEWTIME
} ns_flags_counters_t;

typedef struct {
    uint64_t cgroup_id;                         // Para saber el cgroupID del contenedor
    uint64_t running;                           // Para saber si el contenedor está vivo o no
    ns_flags_counters_t clone_flags_count;      // Contador de flags clone
    ns_flags_counters_t unshare_flags_count;    // Contador de flags unshare
    ns_flags_counters_t setns_flags_count;      // Contador de flags setns
} container_metrics_t;

typedef struct {
    char container_id[64];
    container_metrics_t metrics;
} container_entry_t;

typedef struct {
    char node[64];
    char pod_id[64];
    container_entry_t *containers;
    size_t container_count;
    size_t container_capacity;
} pod_entry_t;

// Estructura que se envía al espacio de usuario para cada evento
struct event_t {
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t tgid;
    uint32_t ppid;
    uint32_t uid;
    uint32_t gid;
    char comm[TASK_COMM_LEN];
    uint32_t type;
    uint64_t flags;
    uint64_t cgroup_id;
    char cgroup_path[256];
    char filename[128];
    long ret;
    uint64_t latency_ns;
};


// Variable que almacena los tipos de eventos que se capturan
static const char *event_names[] = {
    "CLONE",
    "UNSHARE",
    "SETNS",
    "CGROUP_MKDIR",
    "CGROUP_RMDIR",
    "FORK",
    "EXEC",
    "EXIT",
    "CLONE_EXIT",
    "UNSHARE_EXIT",
    "SETNS_EXIT",
    "OPENAT",
    "OPEN",
    "WRITE",
    "OPEN_EXIT",
    "OPENAT_EXIT",
    "WRITE_EXIT",
    "CLOSE"
};

// Estructura de la lista que almacena los ids de los pods
typedef struct {
    pod_entry_t *items;      // Array dinámico de pods
    size_t count;            // Número actual de pods
    size_t capacity;         // Capacidad reservada del array 
} id_list_t;

extern id_list_t pods;


#endif