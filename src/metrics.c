#include "../include/metrics.h"
#include "civetweb.h"
#include <stdio.h>
#include <string.h>
#include "../include/common.h"

// Declaración externa de la estructura pods (defínela en otro sitio)
extern id_list_t pods;


size_t generate_metrics(char *buffer, size_t max_len) {
    size_t offset = 0;

    // Métricas de estado running
    for (size_t i = 0; i < pods.count; i++) {
        pod_entry_t *pod = &pods.items[i];
        for (size_t j = 0; j < pod->container_count; j++) {
            container_entry_t *cont = &pod->containers[j];

            // Aquí supongo que tienes un campo explícito running en cont->metrics
            int running = cont->metrics.running; // Debes tenerlo definido y actualizado

            offset += snprintf(buffer + offset, max_len - offset,
                "containerspy_container_running{nodo=\"%s\",podID=\"%s\",containerID=\"%s\"} %d\n",
                pod->node, pod->pod_id, cont->container_id, running);
        }
    }


    // Macro para imprimir flags de un ns_flags_counters_t con event y labels
#define PRINT_FLAG(event, flagname, value) \
    offset += snprintf(buffer + offset, max_len - offset, \
        "containerspy_flags_total{nodo=\"%s\",podID=\"%s\",containerID=\"%s\",event=\"%s\",flag=\"%s\"} %lu\n", \
        pod->node, pod->pod_id, cont->container_id, event, flagname, value);

    for (size_t i = 0; i < pods.count; i++) {
        pod_entry_t *pod = &pods.items[i];
        for (size_t j = 0; j < pod->container_count; j++) {
            container_entry_t *cont = &pod->containers[j];

            // CLONE flags
            PRINT_FLAG("CLONE", "mnt", cont->metrics.clone_flags_count.mnt);
            PRINT_FLAG("CLONE", "uts", cont->metrics.clone_flags_count.uts);
            PRINT_FLAG("CLONE", "ipc", cont->metrics.clone_flags_count.ipc);
            PRINT_FLAG("CLONE", "user", cont->metrics.clone_flags_count.user);
            PRINT_FLAG("CLONE", "pid", cont->metrics.clone_flags_count.pid);
            PRINT_FLAG("CLONE", "net", cont->metrics.clone_flags_count.net);
            PRINT_FLAG("CLONE", "cgroup", cont->metrics.clone_flags_count.cgroup);
            PRINT_FLAG("CLONE", "time", cont->metrics.clone_flags_count.time);

            // UNSHARE flags
            PRINT_FLAG("UNSHARE", "mnt", cont->metrics.unshare_flags_count.mnt);
            PRINT_FLAG("UNSHARE", "uts", cont->metrics.unshare_flags_count.uts);
            PRINT_FLAG("UNSHARE", "ipc", cont->metrics.unshare_flags_count.ipc);
            PRINT_FLAG("UNSHARE", "user", cont->metrics.unshare_flags_count.user);
            PRINT_FLAG("UNSHARE", "pid", cont->metrics.unshare_flags_count.pid);
            PRINT_FLAG("UNSHARE", "net", cont->metrics.unshare_flags_count.net);
            PRINT_FLAG("UNSHARE", "cgroup", cont->metrics.unshare_flags_count.cgroup);
            PRINT_FLAG("UNSHARE", "time", cont->metrics.unshare_flags_count.time);

            // SETNS flags
            PRINT_FLAG("SETNS", "mnt", cont->metrics.setns_flags_count.mnt);
            PRINT_FLAG("SETNS", "uts", cont->metrics.setns_flags_count.uts);
            PRINT_FLAG("SETNS", "ipc", cont->metrics.setns_flags_count.ipc);
            PRINT_FLAG("SETNS", "user", cont->metrics.setns_flags_count.user);
            PRINT_FLAG("SETNS", "pid", cont->metrics.setns_flags_count.pid);
            PRINT_FLAG("SETNS", "net", cont->metrics.setns_flags_count.net);
            PRINT_FLAG("SETNS", "cgroup", cont->metrics.setns_flags_count.cgroup);
            PRINT_FLAG("SETNS", "time", cont->metrics.setns_flags_count.time);
        }
    }

#undef PRINT_FLAG

    return offset;
}



int metrics_handler(struct mg_connection *conn, void *cbdata) {
    (void)cbdata;
    char metrics_buffer[65536];
    size_t len = generate_metrics(metrics_buffer, sizeof(metrics_buffer));
    mg_printf(conn,
              "HTTP/1.1 200 OK\r\n"
              "Content-Type: text/plain; version=0.0.4\r\n"
              "Content-Length: %zu\r\n"
              "\r\n%s",
              len, metrics_buffer);
    return 200;
}
