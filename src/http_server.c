#include "../include/http_server.h"
#include <string.h>
#include <stdio.h>


// Función para arrancar el servidor local por un puerto que se pasa como parámetro
struct mg_context* http_server_start(const char *port) {
    struct mg_callbacks callbacks;
    memset(&callbacks, 0, sizeof(callbacks));

    char listen_str[64];
    snprintf(listen_str, sizeof(listen_str), "0.0.0.0:%s", port);

    const char *options[] = {
        "listening_ports", listen_str,
        NULL
    };

    struct mg_context *ctx = mg_start(&callbacks, NULL, options);
    if (!ctx) {
        fprintf(stderr, "Error arrancando servidor HTTP en puerto %s\n", port);
    }
    return ctx;
}


// Función para parar el servidor
void http_server_stop(struct mg_context *ctx) {
    if (ctx) {
        mg_stop(ctx);
    }
}


// Función para acceder a las métricas
void http_server_register_handler(struct mg_context *ctx, const char *uri,
                                  mg_request_handler handler, void *cbdata) {
    if (!ctx || !uri || !handler) return;
    mg_set_request_handler(ctx, uri, handler, cbdata);
}
