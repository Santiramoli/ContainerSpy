#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"


char LICENSE[] SEC("license") = "GPL";


struct enter_ctx_t {
    u64 flags;
    u64 ts_enter;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64); // pid_tgid
    __type(value, int); // fd
    __uint(max_entries, 10240);
} write_enter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);          // pid_tgid
    __type(value, struct enter_ctx_t);
    __uint(max_entries, 10240);
} enter_ctx_map SEC(".maps");

struct trace_event_raw_sched_process_exit {
    struct trace_entry ent;
    char comm[16];
    pid_t pid;
    int prio;
};

struct file_info_t {
    char filename[128];
    u64 cgroup_id;
    u32 pid;
    u32 tgid;
    // Otros campos que quieras
};

struct pid_fd_t {
    u64 pid_tgid;
    int fd;
};


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);      // pid_tgid (temporal en open enter)
    __type(value, struct file_info_t);
    __uint(max_entries, 10240);
} open_enter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct pid_fd_t);
    __type(value, struct file_info_t);
    __uint(max_entries, 10240);
} fd_map SEC(".maps");



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
    u64 cgroup_id;
    char cgroup_path[256];
    char filename[128];
    long ret;
    u64 latency_ns;
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

static __always_inline bool starts_with(const char *str, const char *prefix) {
    #pragma unroll 20
    for (int i = 0; i < MAX_PREFIX_LEN; i++) {
        char cstr = 0, cpre = 0;
        bpf_probe_read(&cstr, sizeof(cstr), &str[i]);
        bpf_probe_read(&cpre, sizeof(cpre), &prefix[i]);
        if (cstr != cpre) return false;
        if (cstr == 0) break;
    }
    return true;
}

static __always_inline bool is_relevant_path(const char *path) {
    const char prefixes[][20] = {
        "/var/lib/docker",
        "/run/docker",
        "/etc/docker",
        "/var/lib/kubelet",
        "/etc/kubernetes",
        "/run/kubernetes",
        "/sys/fs/cgroup",
        "/var/lib/containerd",
        "/run/containerd",
        "/run/cri-containerd",
        "/var/log/containers",
        "/var/log/pods"
    };
    #pragma unroll 20
    for (int i = 0; i < sizeof(prefixes)/sizeof(prefixes[0]); i++) {
        if (starts_with(path, prefixes[i])) {
            return true;
        }
    }
    return false;
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
    u64 cgroup_id,
    const char *cgroup_path, u32 cgroup_path_len,
    const char *filename,
    long ret,
    u64 latency_ns)
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

    if(!ret){
        e->ret = '\0'; // No hay retorno, es un evento de entrada
    }else {
        e->ret = ret; // Si hay retorno, lo asignamos
    }

    bpf_ringbuf_submit(e, 0);
}



SEC("tracepoint/syscalls/sys_enter_clone")
int handle_clone(struct trace_event_raw_sys_enter *ctx) {
    u64 flags = ctx->args[0];
    if ((flags & NS_MASK) == 0){
        return 0;
    }
    u64 ts_enter = bpf_ktime_get_ns();
    struct enter_ctx_t ctx_data = {};
    ctx_data.flags = ctx->args[0];
    ctx_data.ts_enter = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&enter_ctx_map, &pid_tgid, &ctx, BPF_ANY);
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
        bpf_get_current_cgroup_id(),
        NULL, 0,         // cgroup_path (no aplica)
        NULL,             // filename (no aplica)
        -1,
        ts_enter
    );
    return 0;
}


SEC("tracepoint/syscalls/sys_enter_unshare")
int handle_unshare(struct trace_event_raw_sys_enter *ctx) {
    u64 flags = ctx->args[0];
    if ((flags & NS_MASK) == 0){
        return 0;
    }
    u64 ts_enter = bpf_ktime_get_ns();
    struct enter_ctx_t ctx_data = {};
    ctx_data.flags = ctx->args[0];
    ctx_data.ts_enter = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&enter_ctx_map, &pid_tgid, &ctx, BPF_ANY);
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
        bpf_get_current_cgroup_id(),
        NULL, 0,
        NULL,
        -1,
        ts_enter
    );
    return 0;
}


SEC("tracepoint/syscalls/sys_enter_setns")
int handle_setns(struct trace_event_raw_sys_enter *ctx) {
    u64 nstype = ctx->args[1];
    if ((nstype & NS_MASK) == 0){
        return 0;
    }
    u64 ts_enter = bpf_ktime_get_ns();
    struct enter_ctx_t ctx_data = {};
    ctx_data.flags = ctx->args[1];
    ctx_data.ts_enter = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&enter_ctx_map, &pid_tgid, &ctx, BPF_ANY);
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
        bpf_get_current_cgroup_id(),
        NULL, 0,
        NULL,
        -1,
        ts_enter
    );
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_clone")
int handle_clone_exit(struct trace_event_raw_sys_exit *ctx) {
    long ret = ctx->ret;
    u64 ts_exit = bpf_ktime_get_ns();

    // Datos de proceso actual
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct enter_ctx_t *ctx_data = bpf_map_lookup_elem(&enter_ctx_map, &pid_tgid);
    if (!ctx_data)
        return 0;
    u32 pid  = (u32)pid_tgid;
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 ppid = get_ppid();
    u32 uid  = bpf_get_current_uid_gid() & 0xffffffff;
    u32 gid  = bpf_get_current_uid_gid() >> 32;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    u64 latency = ts_exit - ctx_data->ts_enter;

    emit_event(
        EVT_CLONE_EXIT,
        pid, tgid, ppid, uid, gid, comm,
        0,           // flags de clone
        bpf_get_current_cgroup_id(),
        NULL, 0,         // cgroup_path (no aplica)
        NULL,
        ret,             // filename (no aplica)
        latency
    );
    bpf_map_delete_elem(&enter_ctx_map, &pid_tgid);
    return 0;
}


SEC("tracepoint/syscalls/sys_exit_unshare")
int handle_unshare_exit(struct trace_event_raw_sys_exit *ctx) {
    long ret = ctx->ret;
    u64 ts_exit = bpf_ktime_get_ns();

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct enter_ctx_t *ctx_data = bpf_map_lookup_elem(&enter_ctx_map, &pid_tgid);
    if (!ctx_data)
        return 0;
    u32 pid  = (u32)pid_tgid;
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 ppid = get_ppid();
    u32 uid  = bpf_get_current_uid_gid() & 0xffffffff;
    u32 gid  = bpf_get_current_uid_gid() >> 32;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    u64 latency = ts_exit - ctx_data->ts_enter;


    emit_event(
        EVT_UNSHARE_EXIT,
        pid, tgid, ppid, uid, gid, comm,
        0,
        bpf_get_current_cgroup_id(),
        NULL, 0,
        NULL,
        ret,
        latency
    );
    bpf_map_delete_elem(&enter_ctx_map, &pid_tgid);
    return 0;
}


SEC("tracepoint/syscalls/sys_exit_setns")
int handle_setns_exit(struct trace_event_raw_sys_exit *ctx) {
    long ret = ctx->ret;
    u64 ts_exit = bpf_ktime_get_ns();


    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct enter_ctx_t *ctx_data = bpf_map_lookup_elem(&enter_ctx_map, &pid_tgid);
    if (!ctx_data)
        return 0;
    u32 pid  = (u32)pid_tgid;
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 ppid = get_ppid();
    u32 uid  = bpf_get_current_uid_gid() & 0xffffffff;
    u32 gid  = bpf_get_current_uid_gid() >> 32;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    u64 latency = ts_exit - ctx_data->ts_enter;

    emit_event(
        EVT_SETNS_EXIT,
        pid, tgid, ppid, uid, gid, comm,
        0,
        bpf_get_current_cgroup_id(),
        NULL, 0,
        NULL,
        ret,
        latency
    );
    
    bpf_map_delete_elem(&enter_ctx_map, &pid_tgid);
    return 0;
}


SEC("tracepoint/cgroup/cgroup_mkdir")
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
        0, cgid,
        path, path_len,
        NULL,
        0,
        0
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
        cgid, // cgroup_id
        path, path_len, // cgroup_path y su tamaño
        NULL, // filename (no aplica)
        0,
        0
    );

    // 5) Limpia el mapa auxiliar si usas uno (opcional)
    bpf_map_delete_elem(&init_map, &cgid);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int handle_file_operations(struct trace_event_raw_sys_enter *ctx) {
    u64 ts_enter = bpf_ktime_get_ns();
    const char *filename_ptr = (const char *)ctx->args[1];
    struct file_info_t info = {};

    if (!filename_ptr)
        return 0;

    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid  = (u32)pid_tgid;
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 ppid = get_ppid();
    u32 uid  = bpf_get_current_uid_gid() & 0xffffffff;
    u32 gid  = bpf_get_current_uid_gid() >> 32;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    bpf_probe_read_user_str(&info.filename, sizeof(info.filename), filename_ptr);
    info.cgroup_id = bpf_get_current_cgroup_id();
    info.pid = pid;
    info.tgid = tgid;

    if (!is_relevant_path(info.filename)) return 0;

    emit_event(
        EVT_OPEN, // Usamos EVT_EXEC para eventos de archivos
        pid, tgid, ppid, uid, gid, comm,
        0, bpf_get_current_cgroup_id(),
        NULL, 0,
        info.filename,
        -1,
        ts_enter
    );

    bpf_map_update_elem(&open_enter_map, &pid_tgid, &info, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
    u64 ts_enter = bpf_ktime_get_ns();

    const char *filename_ptr = (const char *)ctx->args[1];
    struct file_info_t info = {};

    if (!filename_ptr)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid  = (u32)pid_tgid;
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 ppid = get_ppid();
    u32 uid  = bpf_get_current_uid_gid() & 0xffffffff;
    u32 gid  = bpf_get_current_uid_gid() >> 32;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    bpf_probe_read_user_str(&info.filename, sizeof(info.filename), filename_ptr);
    info.cgroup_id = bpf_get_current_cgroup_id();
    info.pid = pid;
    info.tgid = tgid;

    if (!is_relevant_path(info.filename)) return 0;

    emit_event(
        EVT_OPENAT, // Usamos EVT_EXEC para eventos de archivos
        pid, tgid, ppid, uid, gid, comm,
        0, bpf_get_current_cgroup_id(),
        NULL, 0,
        info.filename,
        -1,
        ts_enter
    );

    bpf_map_update_elem(&open_enter_map, &pid_tgid, &info, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int handle_write(struct trace_event_raw_sys_enter *ctx) {
    int fd = (int)ctx->args[0];
    u64 ts_enter = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();

    // Guardamos fd temporal para usar en exit_write
    int err = bpf_map_update_elem(&write_enter_map, &pid_tgid, &fd, BPF_ANY);
    if (err < 0)
        return 0;

    // Buscamos info del archivo abierto
    struct pid_fd_t key = {};
    key.pid_tgid = pid_tgid;
    key.fd = fd;

    struct file_info_t *info = bpf_map_lookup_elem(&fd_map, &key);
    if (!info)
        return 0;  // No interesa

    if (!is_relevant_path(info->filename)) return 0;


    u32 pid  = (u32)pid_tgid;
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 ppid = get_ppid();
    u32 uid  = bpf_get_current_uid_gid() & 0xffffffff;
    u32 gid  = bpf_get_current_uid_gid() >> 32;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(comm, sizeof(comm));

    emit_event(
        EVT_WRITE,
        pid, tgid, ppid, uid, gid, comm,
        0, bpf_get_current_cgroup_id(),
        NULL, 0,
        info->filename,
        -1,
        ts_enter
    );
    return 0;
}


SEC("tracepoint/syscalls/sys_enter_close")
int handle_close(struct trace_event_raw_sys_enter *ctx) {
    
    int fd = (int)ctx->args[0];
    u64 ts_enter = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid  = (u32)pid_tgid;
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 ppid = get_ppid();
    u32 uid  = bpf_get_current_uid_gid() & 0xffffffff;
    u32 gid  = bpf_get_current_uid_gid() >> 32;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    struct pid_fd_t key = {};
    key.pid_tgid = pid_tgid;
    key.fd = fd;

    struct file_info_t *info = bpf_map_lookup_elem(&fd_map, &key);
    if (!info)
        return 0; // No conocemos el archivo, no hacemos nada

    if (!is_relevant_path(info->filename))
        return 0; // No es relevante, descartamos

    emit_event(
        EVT_CLOSE, // Usamos EVT_EXEC para eventos de archivos
        pid, tgid, ppid, uid, gid, comm,
        0, bpf_get_current_cgroup_id(),
        NULL, 0,
        info->filename,
        0,
        ts_enter
    );
    
    bpf_map_delete_elem(&fd_map, &key);
    return 0;
}


SEC("tracepoint/syscalls/sys_exit_open")
int handle_exit_open(struct trace_event_raw_sys_exit *ctx) {
    long ret = ctx->ret;
    u64 ts_exit = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct file_info_t *info = bpf_map_lookup_elem(&open_enter_map, &pid_tgid);
    if (!info)return 0;

    int fd = (int)ctx->ret;
    if (fd < 0) {
        bpf_map_delete_elem(&open_enter_map, &pid_tgid);
        return 0; // fallo open
    }

    struct pid_fd_t key = {};
    key.pid_tgid = pid_tgid;
    key.fd = fd;

    u32 pid  = (u32)pid_tgid;
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 ppid = get_ppid();
    u32 uid  = bpf_get_current_uid_gid() & 0xffffffff;
    u32 gid  = bpf_get_current_uid_gid() >> 32;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_map_update_elem(&fd_map, &key, info, BPF_ANY);

    emit_event(
        EVT_OPEN_EXIT, // Usamos EVT_EXEC para eventos de archivos
        pid, tgid, ppid, uid, gid, comm,
        0, bpf_get_current_cgroup_id(),
        NULL, 0,
        info->filename,
        ret,
        ts_exit
    );

    bpf_map_delete_elem(&open_enter_map, &pid_tgid);
    return 0;
}


SEC("tracepoint/syscalls/sys_exit_openat")
int handle_exit_openat(struct trace_event_raw_sys_exit *ctx) {
    long ret = ctx->ret;
    u64 ts_exit = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct file_info_t *info = bpf_map_lookup_elem(&open_enter_map, &pid_tgid);
    if (!info)return 0;

    int fd = (int)ctx->ret;
    if (fd < 0) {
        bpf_map_delete_elem(&open_enter_map, &pid_tgid);
        return 0; // fallo open
    }

    struct pid_fd_t key = {};
    key.pid_tgid = pid_tgid;
    key.fd = fd;

    u32 pid  = (u32)pid_tgid;
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 ppid = get_ppid();
    u32 uid  = bpf_get_current_uid_gid() & 0xffffffff;
    u32 gid  = bpf_get_current_uid_gid() >> 32;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_map_update_elem(&fd_map, &key, info, BPF_ANY);

    emit_event(
        EVT_OPENAT_EXIT, // Usamos EVT_EXEC para eventos de archivos
        pid, tgid, ppid, uid, gid, comm,
        0, bpf_get_current_cgroup_id(),
        NULL, 0,
        info->filename,
        ret,
        ts_exit
    );
    
    bpf_map_delete_elem(&open_enter_map, &pid_tgid);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int handle_exit_write(struct trace_event_raw_sys_exit *ctx) {
    long ret = ctx->ret;
    u64 ts_exit = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();

    int fd = -1; // Inicializamos

    // Intentamos obtener fd del mapa temporal para esta escritura (depende de implementación)
    int *fd_ptr = bpf_map_lookup_elem(&write_enter_map, &pid_tgid);
    if (fd_ptr)
        fd = *fd_ptr;
    else
        return 0; // No tenemos fd asociado, descartamos

    struct pid_fd_t key = {
        .pid_tgid = pid_tgid,
        .fd = fd,
    };

    struct file_info_t *info = bpf_map_lookup_elem(&fd_map, &key);
    if (!info)
        return 0; // No tenemos info de archivo, descartamos

    if (!is_relevant_path(info->filename))
        return 0; // Filtro por path relevante

    u32 pid  = (u32)pid_tgid;
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 ppid = get_ppid();
    u32 uid  = bpf_get_current_uid_gid() & 0xffffffff;
    u32 gid  = bpf_get_current_uid_gid() >> 32;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    emit_event(
        EVT_WRITE_EXIT,
        pid, tgid, ppid, uid, gid, comm,
        0, bpf_get_current_cgroup_id(),
        NULL, 0,
        info->filename,
        ret,
        ts_exit
    );

    // Limpiar la info temporal si tienes un mapa para eso
    bpf_map_delete_elem(&write_enter_map, &pid_tgid);

    return 0;
}

