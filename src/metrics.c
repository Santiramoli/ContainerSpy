#include "../include/metrics.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Almacena las métricas globalmente
container_metrics_t metrics_list[MAX_CONTAINERS];
size_t             metrics_count = 0;

static double active_list[MAX_CONTAINERS];

// Nombres y ayuda para Prometheus
enum { NAME_LEN = 64, LINE_BUF = 256 };
static const char *metric_names[METRIC_EVENT_TYPE_COUNT] = {
    [METRIC_NS_CLONE]      = "container_namespaces_clone_total",
    [METRIC_NS_UNSHARE]    = "container_namespaces_unshare_total",
    [METRIC_NS_SETNS]      = "container_namespaces_setns_total",
    [METRIC_CGROUP_MKDIR]  = "container_cgroup_mkdir_total",
    [METRIC_CGROUP_RMDIR]  = "container_cgroup_rmdir_total",
};
static const char *metric_help[METRIC_EVENT_TYPE_COUNT] = {
    [METRIC_NS_CLONE]      = "Total de namespace clone invocados por contenedor",
    [METRIC_NS_UNSHARE]    = "Total de namespace unshare invocados por contenedor",
    [METRIC_NS_SETNS]      = "Total de namespace setns invocados por contenedor",
    [METRIC_CGROUP_MKDIR]  = "Total de eventos cgroup mkdir por contenedor",
    [METRIC_CGROUP_RMDIR]  = "Total de eventos cgroup rmdir por contenedor",
};

void metrics_init(void) {
    metrics_count = 0;
    // Opcional: memset(metrics_list,0,...)
}

void metrics_cleanup(void) {
    for (size_t i = 0; i < metrics_count; i++) {
        free(metrics_list[i].container_id);
    }
    metrics_count = 0;
}

void metrics_increment(const char *container_id, metric_event_type_t type) {
    // Buscar contenedor existente
    container_metrics_t *m = NULL;
    for (size_t i = 0; i < metrics_count; i++) {
        if (strcmp(metrics_list[i].container_id, container_id) == 0) {
            m = &metrics_list[i];
            break;
        }
    }
    // Si no existe, crearlo
    if (!m) {
        if (metrics_count >= MAX_CONTAINERS) return; // desbordamiento
        m = &metrics_list[metrics_count++];
        m->container_id = strdup(container_id);
        memset(m->counts, 0, sizeof(m->counts));
    }
    // Incrementar
    if (type < METRIC_EVENT_TYPE_COUNT) {
        m->counts[type]++;
    }
}

int metrics_render_prometheus(char **out_buf, size_t *out_len) {
    if (!out_buf || !out_len) return -1;
    char *buf = NULL;
    size_t len = 0;
    char line[LINE_BUF];
    int written;

    // 1) HELP/TYPE de counters
    for (int t = 0; t < METRIC_EVENT_TYPE_COUNT; t++) {
        written = snprintf(line, LINE_BUF,
            "# HELP %s %s\n"
            "# TYPE %s counter\n",
            metric_names[t], metric_help[t], metric_names[t]);
        if (written < 0) continue;
        buf = realloc(buf, len + written + 1);
        memcpy(buf + len, line, written);
        len += written;
        buf[len] = '\0';
    }

    // 2) Valores de los counters por contenedor
    for (size_t i = 0; i < metrics_count; i++) {
        for (int t = 0; t < METRIC_EVENT_TYPE_COUNT; t++) {
            written = snprintf(line, LINE_BUF,
                "%s{container=\"%s\"} %llu\n",
                metric_names[t],
                metrics_list[i].container_id,
                (unsigned long long)metrics_list[i].counts[t]);
            if (written < 0) continue;
            buf = realloc(buf, len + written + 1);
            memcpy(buf + len, line, written);
            len += written;
            buf[len] = '\0';
        }
    }

    // 3) HELP/TYPE del gauge container_active
    written = snprintf(line, LINE_BUF,
        "\n# HELP container_active Gauge: 1 si el contenedor está vivo, 0 si no\n"
        "# TYPE container_active gauge\n");
    if (written > 0) {
        buf = realloc(buf, len + written + 1);
        memcpy(buf + len, line, written);
        len += written;
        buf[len] = '\0';
    }

    // 4) Valores del gauge por contenedor
    for (size_t i = 0; i < metrics_count; i++) {
        // asumimos que tienes un array `active_list` con double por contenedor
        written = snprintf(line, LINE_BUF,
            "container_active{container=\"%s\"} %.0f\n",
            metrics_list[i].container_id,
            active_list[i]);
        if (written < 0) continue;
        buf = realloc(buf, len + written + 1);
        memcpy(buf + len, line, written);
        len += written;
        buf[len] = '\0';
    }

    *out_buf = buf;
    *out_len = len;
    return 0;
}


void metrics_set_active(const char *container_id, int active) {
    // Busca o crea exactamente igual que en metrics_increment
    container_metrics_t *m = NULL;
    for (size_t i = 0; i < metrics_count; i++) {
      if (strcmp(metrics_list[i].container_id, container_id) == 0) {
        m = &metrics_list[i];
        break;
      }
    }
    if (!m) {
      if (metrics_count >= MAX_CONTAINERS) return;
      m = &metrics_list[metrics_count++];
      m->container_id = strdup(container_id);
      memset(m->counts, 0, sizeof m->counts);
      active_list[metrics_count-1] = 0;
    }
    active_list[m - metrics_list] = active ? 1.0 : 0.0;
}