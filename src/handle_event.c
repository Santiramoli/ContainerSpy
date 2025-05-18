#include "../include/handle_event.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "../include/metrics.h"

static id_list_t lista;


void event_handler_init(void) {
    id_list_init(&lista, 20);
}

void event_handler_cleanup(void) {
    id_list_free(&lista);
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

void process_cgroup_mkdir(const struct event_t *e) {
    printf("\nCGROUP DETECTADO\n");
    time_t now = time(NULL);
    char *s = ctime(&now);
    printf("Fecha y hora: %s", s);
    printf("ID del cgroup: %lu\n", e->cgroup_id);
    printf("Ruta del cgroup: %s\n", e->cgroup_path);
    char *id = get_container_id(e->cgroup_path);
    if (id) {
        if (id_list_add(&lista, id)) {}
        metrics_increment(id, METRIC_CGROUP_MKDIR);
        metrics_set_active(id, 1);
        free(id);
    }
}

void process_cgroup_rmdir(const struct event_t *e) {
    printf("\nCGROUP ELIMINADO\n");
    time_t now = time(NULL);
    char *s = ctime(&now);
    printf("Fecha y hora: %s", s);
    printf("ID del cgroup: %lu\n", e->cgroup_id);
    printf("Ruta del cgroup: %s\n", e->cgroup_path);
    
    char *id = get_container_id(e->cgroup_path);
    if (id) {
        id_list_remove(&lista, id);
        metrics_increment(id, METRIC_CGROUP_MKDIR); 
        metrics_set_active(id, 0);
        free(id);
    }

}


void process_namespace_event(const struct event_t *e) {
    // 1) ignorar runtime
    if (should_ignore_comm(e->comm)) return;

    // 2) obtener ruta de cgroup real del pid
    char path[256] = {0}, filename[64];
    snprintf(filename, sizeof(filename), "/proc/%u/cgroup", e->pid);
    FILE *f = fopen(filename, "r");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char *p = strstr(line, "::");
        if (p) {
            strncpy(path, p+2, sizeof(path)-1);
            path[strcspn(path, "\n")] = '\0';
            break;
        }
    }
    fclose(f);

    // 3) extraer container ID
    char *cid = get_container_id(path);
    if (!cid) return;

    // 4) imprimir y contar
    const char *evt = e->type == EVT_CLONE   ? "CLONE" :
                      e->type == EVT_UNSHARE ? "UNSHARE" :
                      e->type == EVT_SETNS   ? "SETNS" : "UNKNOWN";
    printf("\n%s en contenedor %s\n", evt, cid);

    // timestamp y detalles
    time_t now = time(NULL);
    printf("Fecha y hora: %s", ctime(&now));
    printf("PID=%u, TID=%u, comm=%s\n", e->pid, e->tgid, e->comm);
    decode_clone_flags(e->flags);
    metrics_increment(  cid, e->type == EVT_CLONE   ? METRIC_NS_CLONE : e->type == EVT_UNSHARE ? METRIC_NS_UNSHARE : METRIC_NS_SETNS);
    free(cid);
}


int handle_event(void *ctx, void *data, size_t len) {
    (void)ctx;
    const struct event_t *e = data;
    if (should_ignore_comm(e->comm))
        return 0;
    if (validate_event(e, len) < 0)
        return -1;
    switch (e->type) {
        case EVT_CGROUP_MKDIR:
            process_cgroup_mkdir(e);
            break;
        case EVT_CGROUP_RMDIR:
            process_cgroup_rmdir(e);
            break;
        case EVT_CLONE:
        case EVT_UNSHARE:
        case EVT_SETNS:
            process_namespace_event(e);
            break;
        default:
            // unreachable
            break;
    }
    return 0;
}
