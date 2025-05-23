#include <stddef.h>
#include "civetweb.h"

// Genera las métricas Prometheus y escribe en buffer
size_t generate_metrics(char *buffer, size_t max_len);

// Handler HTTP para CivetWeb que sirve las métricas
int metrics_handler(struct mg_connection *conn, void *cbdata);

