#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include "metrics.h"
#include "civetweb.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Inicializa y arranca el servidor HTTP embebido en el puerto especificado.
 * Registra la ruta /metrics para exponer las métricas en formato Prometheus.
 *
 * @param port Puerto en el que escuchar (p.ej. "8080").
 * @return Puntero al contexto de CivetWeb, o NULL en caso de error.
 */
struct mg_context *http_server_start(const char *port);

/**
 * Detiene el servidor HTTP y libera recursos.
 *
 * @param ctx Contexto devuelto por http_server_start().
 */
void http_server_stop(struct mg_context *ctx);

#ifdef __cplusplus
}
#endif

#endif // HTTP_SERVER_H