#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include "civetweb.h"

// Inicializa y arranca el servidor HTTP en el puerto indicado
// Devuelve el contexto del servidor o NULL en caso de error
struct mg_context* http_server_start(const char *port);

// Detiene el servidor HTTP y libera recursos
void http_server_stop(struct mg_context *ctx);

// Registra un handler para una ruta concreta, con un callback de manejo
void http_server_register_handler(struct mg_context *ctx, const char *uri,
                                  mg_request_handler handler, void *cbdata);

#endif // HTTP_SERVER_H
