#include "../include/handle_event.h"


zlog_category_t *c = NULL;
id_list_t pods = {0};
const char *base_path = "/sys/fs/cgroup";
char pod_id[128] = {0};
char container_id[128] = {0};
char node_name[64] = {0};


void event_handler_init(void) {
    pod_list_init(&pods, 8); 
}

void event_handler_cleanup(void) {
    pod_list_free(&pods);
}

bool should_ignore_comm(const char *comm) {
    return (strcmp(comm, "cpuUsage.sh") == 0) || (strcmp(comm, "node") == 0);
}

int validate_event(const struct event_t *e, size_t len) {
    if (len < sizeof(*e)) {
        fprintf(stderr, "ERROR: event size mismatch\n");
        return -1;
    }
    if (e->type >= sizeof(event_names)/sizeof(event_names[0])) {
        fprintf(stderr, "ERROR: unknown event type %u\n", e->type);
        return -1;
    }
    return 0;
}

int handle_event(void *ctx, void *data, size_t len) {
    (void)ctx;
    const struct event_t *e = data;

    // Ignorar ciertos comandos
    if (should_ignore_comm(e->comm))
        return 0;
    if (validate_event(e, len) < 0)
        return -1;

    switch (e->type) {
        case EVT_CLONE:
        case EVT_UNSHARE:
        case EVT_SETNS:
            log_event_ns(e);
            handle_event_ns(e);
            break;

        case EVT_CLONE_EXIT:
            log_event_exit(e, "CLONE EXIT", false);
            break;

        case EVT_UNSHARE_EXIT:
            log_event_exit(e, "UNSHARE EXIT", false);
            break;

        case EVT_SETNS_EXIT:
            log_event_exit(e, "SETNS EXIT", true);
            break;

        case EVT_OPEN:
            log_event_file(e, "OPEN");
            break;

        case EVT_OPENAT:
            log_event_file(e, "OPENAT");
            break;

        case EVT_WRITE:
            log_event_file(e, "WRITE");
            break;

        case EVT_OPEN_EXIT:
            zlog_info(c, "OPEN EXIT");
            log_basic_event_info(e);
            zlog_info(c, "Latencia: %lu", e->latency_ns);
            zlog_info(c, "Archivo: %s", e->filename);
            break;

        case EVT_OPENAT_EXIT:
            zlog_info(c, "OPENAT EXIT");
            log_basic_event_info(e);
            zlog_info(c, "Latencia: %lu", e->latency_ns);
            zlog_info(c, "Archivo: %s", e->filename);
            break;

        case EVT_WRITE_EXIT:
            zlog_info(c, "WRITE EXIT");
            log_basic_event_info(e);
            zlog_info(c, "Latencia: %lu", e->latency_ns);
            zlog_info(c, "Archivo: %s", e->filename);
            break;

        case EVT_CLOSE:
            log_event_file(e, "CLOSE");
            break;

        case EVT_CGROUP_MKDIR:
            log_event_cgroup_mkdir(e);
            handle_event_cgroup_mkdir(e);
            break;

        case EVT_CGROUP_RMDIR:
            log_event_cgroup_rmdir(e);
            handle_event_cgroup_rmdir(e);
            break;

        default:
            break;
    }
    return 0;
}
