#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"


char LICENSE[] SEC("license") = "GPL";


struct trace_event_raw_sched_process_exit {
    struct trace_entry ent;
    char comm[16];
    pid_t pid;
    int prio;
};


// Struct sent to user-space
struct event_t {
    u64 timestamp_ns;
    u32 pid;
    u32 tgid;
    u32 ppid;
    u32 uid;
    u32 gid;
    char comm[TASK_COMM_LEN];
    u32 type;
    u64 flags;
    u8  is_ns_related;
    u64 cgroup_id;
    char cgroup_path[256];
    char filename[128];
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


static __always_inline u32 get_ppid() {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = 0;
    struct task_struct *real_parent = NULL;

    // Lee el puntero a real_parent (tamaño: sizeof(task->real_parent))
    bpf_core_read(&real_parent, sizeof(task->real_parent), &task->real_parent);

    // Lee el tgid (PID de proceso) del padre (tamaño: u32)
    if (real_parent)
        bpf_core_read(&ppid, sizeof(u32), &real_parent->tgid);

    return ppid;
}


static __always_inline void emit_event(
    u32 type,
    u32 pid,
    u32 tgid,
    u32 ppid,
    u32 uid,
    u32 gid,
    const char *comm,
    u64 flags,
    u8 is_ns_related,
    u64 cgroup_id,
    const char *cgroup_path, u32 cgroup_path_len,
    const char *filename)
{
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid  = pid;
    e->tgid = tgid;
    e->ppid = ppid;
    e->uid  = uid;
    e->gid  = gid;
    __builtin_memset(e->comm, 0, sizeof(e->comm));
    if (comm)
        __builtin_memcpy(e->comm, comm, TASK_COMM_LEN);

    e->type = type;
    e->flags = flags;
    e->is_ns_related = is_ns_related;
    e->cgroup_id = cgroup_id;

    // cgroup_path (puede ser NULL o cadena)
    if (cgroup_path && cgroup_path_len > 0) {
        u32 len = cgroup_path_len < sizeof(e->cgroup_path)-1 ? cgroup_path_len : sizeof(e->cgroup_path)-1;
        bpf_core_read_str(e->cgroup_path, len + 1, cgroup_path);
    } else {
        e->cgroup_path[0] = '\0';
    }

    // filename (puede ser NULL)
    if (filename) {
        bpf_core_read_str(e->filename, sizeof(e->filename), filename);
    } else {
        e->filename[0] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
}



SEC("tracepoint/syscalls/sys_enter_clone")
int handle_clone(struct trace_event_raw_sys_enter *ctx) {
    u64 flags = ctx->args[0];
    int is_ns_related = (flags & NS_MASK) != 0;

    // Datos de proceso actual
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid  = (u32)pid_tgid;
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 ppid = get_ppid();
    u32 uid  = bpf_get_current_uid_gid() & 0xffffffff;
    u32 gid  = bpf_get_current_uid_gid() >> 32;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    emit_event(
        EVT_CLONE,
        pid, tgid, ppid, uid, gid, comm,
        flags,           // flags de clone
        is_ns_related,   // es relevante a namespaces
        bpf_get_current_cgroup_id(),
        NULL, 0,         // cgroup_path (no aplica)
        NULL             // filename (no aplica)
    );
    return 0;
}


SEC("tracepoint/syscalls/sys_enter_unshare")
int handle_unshare(struct trace_event_raw_sys_enter *ctx) {
    u64 flags = ctx->args[0];
    int is_ns_related = (flags & NS_MASK) != 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid  = (u32)pid_tgid;
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 ppid = get_ppid();
    u32 uid  = bpf_get_current_uid_gid() & 0xffffffff;
    u32 gid  = bpf_get_current_uid_gid() >> 32;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    emit_event(
        EVT_UNSHARE,
        pid, tgid, ppid, uid, gid, comm,
        flags,
        is_ns_related,
        bpf_get_current_cgroup_id(),
        NULL, 0,
        NULL
    );
    return 0;
}


SEC("tracepoint/syscalls/sys_enter_setns")
int handle_setns(struct trace_event_raw_sys_enter *ctx) {
    u64 nstype = ctx->args[1];
    int is_ns_related = (nstype & NS_MASK) != 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid  = (u32)pid_tgid;
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 ppid = get_ppid();
    u32 uid  = bpf_get_current_uid_gid() & 0xffffffff;
    u32 gid  = bpf_get_current_uid_gid() >> 32;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    emit_event(
        EVT_SETNS,
        pid, tgid, ppid, uid, gid, comm,
        nstype,
        is_ns_related,
        bpf_get_current_cgroup_id(),
        NULL, 0,
        NULL
    );
    return 0;
}


SEC("tracepoint/cgroup/cgroup_mkdir")
// Tracepoint para la creación de cgroups
int handle_cgroup_mkdir(struct trace_event_raw_cgroup *ctx) {
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    u32 gid = bpf_get_current_uid_gid() >> 32;
    u64 cgid = bpf_get_current_cgroup_id();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)pid_tgid;
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 ppid = get_ppid();

    u32 data_loc = ctx->__data_loc_path;
    u32 offset   = data_loc & 0xFFFF;
    u32 path_len = data_loc >> 16;
    const char *path = (const char *)ctx + offset;

    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    emit_event(
        EVT_CGROUP_MKDIR,
        pid,
        tgid,
        ppid,
        uid,
        gid,
        comm,
        0, 0, cgid,
        path, path_len,
        NULL
    );
    return 0;
}


SEC("tracepoint/cgroup/cgroup_rmdir")
int handle_cgroup_rmdir_tp(void *ctx) {
    // 1) Lee el cgroup_id (offset 16)
    u64 cgid = 0;
    bpf_core_read(&cgid, sizeof(u64), ctx + 16);

    // 2) Lee __data_loc_path (offset 24)
    u32 data_loc = 0;
    bpf_core_read(&data_loc, sizeof(u32), ctx + 24);
    u32 off = data_loc & 0xFFFF;
    u32 path_len = data_loc >> 16;
    const char *path = (const char *)ctx + off;

    // 3) Obtén los campos de proceso actual
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)pid_tgid;
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 ppid = get_ppid();
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    u32 gid = bpf_get_current_uid_gid() >> 32;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    // 4) Emite el evento usando la interfaz centralizada
    emit_event(
        EVT_CGROUP_RMDIR,
        pid, tgid, ppid, uid, gid, comm,
        0, // flags
        0, // is_ns_related
        cgid, // cgroup_id
        path, path_len, // cgroup_path y su tamaño
        NULL // filename (no aplica)
    );

    // 5) Limpia el mapa auxiliar si usas uno (opcional)
    bpf_map_delete_elem(&init_map, &cgid);

    return 0;
}


SEC("tracepoint/sched/sched_process_fork")
int handle_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    u32 gid = bpf_get_current_uid_gid() >> 32;
    u64 cgid = bpf_get_current_cgroup_id();
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    emit_event(
        EVT_FORK,
        ctx->child_pid,         // pid
        ctx->child_pid,         // tgid
        ctx->parent_pid,        // ppid
        uid,
        gid,
        comm,                   // ahora es un array local, ¡no pointer a ctx!
        0, 0, cgid,
        NULL, 0,
        NULL
    );
    return 0;
}


SEC("tracepoint/sched/sched_process_exec")
int handle_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    u32 gid = bpf_get_current_uid_gid() >> 32;
    u32 ppid = get_ppid();
    u64 cgid = bpf_get_current_cgroup_id();
    char command[TASK_COMM_LEN];
    bpf_get_current_comm(&command, sizeof(command));
    unsigned int loc = ctx->__data_loc_filename;
    unsigned int offset = loc & 0xFFFF;
    unsigned int len = loc >> 16;
    const char *filename_ptr = (const char *)ctx + offset;

    emit_event(
        EVT_EXEC,
        ctx->pid,                   // pid
        ctx->pid,                   // tgid
        ppid,                       // ppid
        uid,
        gid,
        command,                  // comm (si existe en struct, si no, usa bpf_get_current_comm())
        0,                          // flags
        0,                          // is_ns_related
        cgid,
        NULL, 0,                    // cgroup_path, cgroup_path_len
        filename_ptr                // filename
    );
    return 0;
}


SEC("tracepoint/sched/sched_process_exit")
int handle_process_exit(struct trace_event_raw_sched_process_exit *ctx) {
    u32 pid  = ctx->pid;
    u32 tgid = ctx->pid;
    u32 ppid = get_ppid();
    u32 uid  = bpf_get_current_uid_gid() & 0xffffffff;
    u32 gid  = bpf_get_current_uid_gid() >> 32;
    char command[TASK_COMM_LEN];
    bpf_get_current_comm(&command, sizeof(command));

    emit_event(
        EVT_EXIT,
        pid, tgid, ppid, uid, gid, command,
        0, 0, bpf_get_current_cgroup_id(),
        NULL, 0, NULL
    );
    return 0;
}


