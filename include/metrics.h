#ifndef METRICS_H
#define METRICS_H

#include <stdint.h>
#include <stddef.h>
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

// Tipos de namespaces/events
typedef enum {
    METRIC_NS_CLONE = 0,
    METRIC_NS_UNSHARE,
    METRIC_NS_SETNS,
    METRIC_CGROUP_MKDIR,
    METRIC_CGROUP_RMDIR,
    METRIC_EVENT_TYPE_COUNT
} metric_event_type_t;

// Estructura de métricas por contenedor
typedef struct {
    char    *container_id;                      // Identificador del contenedor (heap)
    uint64_t counts[METRIC_EVENT_TYPE_COUNT];   // Contadores por tipo de evento
} container_metrics_t;

// Lista global de métricas
extern container_metrics_t metrics_list[MAX_CONTAINERS];
extern size_t             metrics_count;

/**
 * Inicializa el módulo de métricas.
 * Debe llamarse antes de usar cualquier otra función.
 */
void metrics_init(void);

/**
 * Libera la memoria y recursos usados por las métricas.
 */
void metrics_cleanup(void);

/**
 * Incrementa el contador para un contenedor dado y tipo de evento.
 * @param container_id  Cadena identificadora del contenedor.
 * @param type          Tipo de evento a incrementar.
 */
void metrics_increment(const char *container_id, metric_event_type_t type);

/**
 * Setea el gauge de actividad de un contenedor:
 *  - 1 = activo (creado, o sigue vivo)
 *  - 0 = inactivo (su cgroup ha sido eliminado)
 */
void metrics_set_active(const char *container_id, int active);

/**
 * Formatea todas las métricas actuales en el estilo Prometheus.
 * Devuelve un buffer con los datos (malloc'd) y su longitud.
 * El caller debe free().
 *
 * @param out_buf  Puntero donde recibir el buffer malloc'd.
 * @param out_len  Puntero donde recibir la longitud.
 * @return 0 en éxito, <0 en error.
 */
int metrics_render_prometheus(char **out_buf, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif // METRICS_H
