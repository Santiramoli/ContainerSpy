// container_spy.bpf.c
// eBPF program to capture namespace syscalls and cgroup creation events via ring buffer
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


char LICENSE[] SEC("license") = "GPL";

// Namespace flags
#define CLONE_NEWNS      0x00020000
#define CLONE_NEWCGROUP  0x02000000
#define CLONE_NEWUTS     0x04000000
#define CLONE_NEWIPC     0x08000000
#define CLONE_NEWUSER    0x10000000
#define CLONE_NEWPID     0x20000000
#define CLONE_NEWNET     0x40000000
#define CLONE_NEWTIME    0x00000080
#define NS_MASK (CLONE_NEWNS|CLONE_NEWCGROUP|CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWNET|CLONE_NEWTIME)


#define MAX_CONTAINERS 1024
// Event types
enum syscall_type {
    EVT_CLONE = 0,
    EVT_UNSHARE,
    EVT_SETNS,
    EVT_CGROUP_MKDIR,
    EVT_CGROUP_RMDIR
};

// Struct sent to user-space
struct event_t {
    u64 timestamp_ns;
    u32 pid;
    u32 tgid;
    char comm[TASK_COMM_LEN];
    u32 type;
    u64 flags;
    u64 cgroup_id;
    char cgroup_path[256];
};

// Mapa Ring buffer para enviar eventos al espacio de usuario
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Mapa de tipo hash para almacenar el CGID y el PID del proceso que crea el cgroup
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   u64);  // cgroup_id
    __type(value, u32);  // init_pid
    __uint(max_entries, MAX_CONTAINERS);
} init_map SEC(".maps");



// Reserve, fill, and submit an event
static __always_inline void emit_event(u32 type, u64 flags, const void *path, u32 path_len) {
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return;

    // Fill core fields
    e->timestamp_ns = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid        = (u32)pid_tgid;
    e->tgid       = (u32)(pid_tgid >> 32);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->type       = type;
    e->flags      = flags;
    e->cgroup_id  = bpf_get_current_cgroup_id();

    // Read cgroup path if provided
    if (path && path_len > 0) {
        // Limit path_len to buffer size
        u32 len = path_len;
        if (len > sizeof(e->cgroup_path) - 1)
            len = sizeof(e->cgroup_path) - 1;
        // path points into ctx->__data
        bpf_core_read_str(e->cgroup_path, len + 1, path);
    } else {
        e->cgroup_path[0] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
}

// Trace clone syscalls
SEC("tracepoint/syscalls/sys_enter_clone")
int handle_clone(struct trace_event_raw_sys_enter *ctx) {
    u64 flags = ctx->args[0];
    emit_event(EVT_CLONE, flags, NULL, 0);
    return 0;
}

// Trace unshare syscalls
SEC("tracepoint/syscalls/sys_enter_unshare")
int handle_unshare(struct trace_event_raw_sys_enter *ctx) {
    u64 flags = ctx->args[0];
    emit_event(EVT_UNSHARE, flags, NULL, 0);
    return 0;
}

// Trace setns syscalls
SEC("tracepoint/syscalls/sys_enter_setns")
int handle_setns(struct trace_event_raw_sys_enter *ctx) {
    u64 nstype = ctx->args[1];
    emit_event(EVT_SETNS, nstype, NULL, 0);
    return 0;
}


// Tracepoint para la creación de cgroups
SEC("tracepoint/cgroup/cgroup_mkdir")
int handle_cgroup_mkdir(struct trace_event_raw_cgroup *ctx) {
    // Get cgroup path from ctx
    u32 data_loc = ctx->__data_loc_path;
    u32 offset   = data_loc & 0xFFFF;       // 16 bits bajos
    u32 path_len = data_loc >> 16;          // 16 bits altos
    const char *path = (const char *)ctx + offset;
    emit_event(EVT_CGROUP_MKDIR, 0, path, path_len);
    return 0;
}


SEC("tracepoint/cgroup/cgroup_rmdir")
int handle_cgroup_rmdir_tp(void *ctx) {
    // 1) cgroup_id está a offset 16 (u64)
    u64 cgid = 0;
    bpf_core_read(&cgid, sizeof(cgid), ctx + 16);

    // 2) __data_loc (offset/len) está a offset 24 (u32)
    u32 data_loc = 0;
    bpf_core_read(&data_loc, sizeof(data_loc), ctx + 24);
    u32 off = data_loc & 0xFFFF;
    u32 path_len = data_loc >> 16;

    // 3) puntero a la cadena
    const void *path = (const char *)ctx + off;

    // 4) emitimos el evento al ring-buffer
    emit_event(EVT_CGROUP_RMDIR, 0, path, path_len);

    // 5) borramos la entrada de init_map
    bpf_map_delete_elem(&init_map, &cgid);
    return 0;
}

