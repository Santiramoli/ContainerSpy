#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "../include/metrics.h"
#include "../include/utils.h"
#include "../include/handle_event.h"


const char *base_path = "/sys/fs/cgroup";
char pod_id[128];
char container_id[128];
id_list_t pods;
char node_name[64];



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

    char pod_id[64];
    char container_id[64];

    switch (e->type) {
        case EVT_CGROUP_MKDIR: {
            printf("\nCGROUP MKDIR\n");
            printf("Command: %s\n", e->comm);
            printf("Path: %s\n", e->cgroup_path);

            char full_path[4096];
            snprintf(full_path, sizeof(full_path), "%s%s", base_path, e->cgroup_path);
            uint64_t cgroup_id = get_cgroup_id_from_path(full_path);

            if (cgroup_id == 0) {
                printf("Error obteniendo Cgroup ID\n");
                break;
            }
            printf("Cgroup ID es: %lu\n", cgroup_id);
            if (get_node_name(node_name, sizeof(node_name)) != 0) {
                printf("No se pudo obtener el nombre del nodo\n");
            }

            extract_pod_and_container(e->cgroup_path, pod_id, sizeof(pod_id), container_id, sizeof(container_id));
            
            if (strcmp(pod_id, "unknown") != 0 && strcmp(container_id, "unknown") != 0) {
                printf("POD ID: %s\n", pod_id);
                printf("Container ID: %s\n", container_id);
                

                container_entry_t new_container = {0};
                strncpy(new_container.container_id, container_id, sizeof(new_container.container_id) - 1);
                new_container.metrics.cgroup_id = cgroup_id;
                new_container.metrics.running = 1;

                
                add_container_to_pod(&pods, pod_id, new_container, node_name);
            }

            break;
        }
        case EVT_CGROUP_RMDIR: {
            printf("\nCGROUP RMDIR\n");
            printf("Command: %s\n", e->comm);
            printf("Path: %s\n", e->cgroup_path);
            printf("Cgroup ID: %lu\n", e->cgroup_id);

            extract_pod_and_container(e->cgroup_path, pod_id, sizeof(pod_id), container_id, sizeof(container_id));
            printf("POD ID: %s\n", pod_id);
            printf("Container ID: %s\n", container_id);

            if (strcmp(pod_id, "unknown") != 0 && strcmp(container_id, "unknown") != 0) {
                pod_entry_t *pod = pod_list_find(&pods, pod_id);
                if (pod) {
                    bool removed = pod_remove_container(pod, container_id);
                    if (removed) {
                        printf("Contenedor eliminado correctamente\n");
                        if (pod->container_count == 0) {
                            pod_list_remove(&pods, pod_id);
                            printf("Pod eliminado porque no tiene contenedores\n");
                        }
                    } else {
                        printf("No se encontró el contenedor para eliminar\n");
                    }
                }
            }
            break;
        }
        case EVT_CLONE:
        case EVT_UNSHARE:
        case EVT_SETNS: {
            if (!(e->flags & NS_MASK)) return 0;

            printf("\n%s\n", e->type == EVT_CLONE ? "CLONE" : e->type == EVT_UNSHARE ? "UNSHARE" : "SETNS");
            printf("PID: %u, TGID: %u, PPID: %u, UID: %u, GID: %u, Command: %s\n",
                   e->pid, e->tgid, e->ppid, e->uid, e->gid, e->comm);
            printf("CGROUPID: %lu\n", e->cgroup_id);
            decode_clone_flags(e->flags);

            // Buscar contenedor por cgroup_id
            for (size_t i = 0; i < pods.count; i++) {
                pod_entry_t *pod = &pods.items[i];
                for (size_t j = 0; j < pod->container_count; j++) {
                    container_entry_t *container = &pod->containers[j];
                    if (container->metrics.cgroup_id == e->cgroup_id) {
                        // Actualizar métricas
                        switch (e->type) {
                            case EVT_CLONE:
                                update_flags(&container->metrics.clone_flags_count, e->flags);
                                break;
                            case EVT_UNSHARE:
                                update_flags(&container->metrics.unshare_flags_count, e->flags);
                                break;
                            case EVT_SETNS:
                                update_flags(&container->metrics.setns_flags_count, e->flags);
                                break;
                        }
                        goto metrics_updated;
                    }
                }
            }
        metrics_updated:
            break;
        }
        default:
            break;
    }
    return 0;
}
