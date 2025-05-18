#include "../include/http_server.h"
#include <stdlib.h>
#include <string.h>

// Handler para la ruta /metrics
static int metrics_handler(struct mg_connection *conn, void *cbdata) {
    (void)cbdata;
    char *buf = NULL;
    size_t len = 0;
    if (metrics_render_prometheus(&buf, &len) != 0 || !buf) {
        mg_printf(conn,
            "HTTP/1.1 500 Internal Server Error\r\n"
            "Content-Type: text/plain\r\n"
            "Connection: close\r\n\r\n"
            "Error generating metrics\n");
        free(buf);
        return 500;
    }

    mg_printf(conn,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n",
        len);
    mg_write(conn, buf, len);
    free(buf);
    return 200;
}

struct mg_context *http_server_start(const char *port) {
    const char *options[] = {
        "listening_ports", port,
        NULL
    };
    struct mg_callbacks callbacks;
    memset(&callbacks, 0, sizeof(callbacks));

    struct mg_context *ctx = mg_start(&callbacks, NULL, options);
    if (!ctx) return NULL;

    // Registrar handler para /metrics
    mg_set_request_handler(ctx, "/metrics", metrics_handler, NULL);
    return ctx;
}

void http_server_stop(struct mg_context *ctx) {
    if (ctx) {
        mg_stop(ctx);
    }
}
