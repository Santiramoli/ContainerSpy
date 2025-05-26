/*
 * main.c
 * User-space program to read namespace syscall and cgroup removal events from BPF ring buffer
 * and print them in real time using libbpf skeleton.
 */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <time.h>
#include <inttypes.h>
#include "../bpf/containerSpy.skel.h"
#include "../include/handle_event.h"
#include "../include/metrics.h"
#include "../include/http_server.h"
#include <zlog.h>



static volatile bool exiting = false;
static void handle_signal(int sig) { exiting = true; }


int main(int argc, char **argv) {

    event_handler_init();
    struct mg_context *ctx = http_server_start("8080");
    if (!ctx) {
        fprintf(stderr, "No se pudo arrancar HTTP server\n");
        return 1;
    }
    
    http_server_register_handler(ctx, "/metrics", metrics_handler, NULL);
    printf("Servidor métricas escuchando en http://localhost:8080/metrics\n");


    struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rl) && errno != EPERM) {
        perror("setrlimit");
        return 1;
    }

    /* Open and load BPF skeleton */
    struct containerSpy_bpf *skel = containerSpy_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "ERROR: failed to open and load BPF skeleton\n");
        return 1;
    }

    /* Attach all programs */
    if (containerSpy_bpf__attach(skel)) {
        fprintf(stderr, "ERROR: failed to attach BPF programs\n");
        goto cleanup;
    }

    /* Setup signal handlers */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);


    int rc = zlog_init("./zlog.conf");
    if (rc) {
        fprintf(stderr, "Fallo al inicializar zlog\n");
        return -1;
    }

    c = zlog_get_category("containerspy");
    if (!c) {
        fprintf(stderr, "Fallo al detectar la categoría 'containerSpy'\n");
        zlog_fini();
        return -2;
    }
    printf("zlog inicializado correctamente y categoría cargada\n");


    /* Allocate ring buffer */
    struct ring_buffer *rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "ERROR: failed to create ring buffer\n");
        goto cleanup;
    }


    printf("Listening for events... Press Ctrl-C to exit.\n");
    while (!exiting) {
        int err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "ERROR: ring buffer poll failed: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    http_server_stop(ctx);
    zlog_fini();
    event_handler_cleanup();

cleanup:
    containerSpy_bpf__destroy(skel);
    return 0;
}
