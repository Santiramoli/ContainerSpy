#include "../include/utils.h"


extern zlog_category_t *c;


/**********************************************
***Funciones para gestionar la lista de pods***
***********************************************/

void pod_list_init (id_list_t *list, size_t init_cap){
    list->count = 0;
    if (init_cap > 0) {
        list->items = malloc(init_cap * sizeof(pod_entry_t));
        if (!list->items) {
            perror("malloc failed in pod_list_init");
            list->capacity = 0;
            return;
        }
        list->capacity = init_cap;
    } else {
        list->items = NULL;
        list->capacity = 0;
    }
}

bool pod_list_contains (id_list_t *list, const char *pod_id){
    for (size_t i = 0; i < list->count; i++) {
        if (strcmp(list->items[i].pod_id, pod_id) == 0) {
            return true;
        }
    }
    return false;
}

pod_entry_t* pod_list_find (id_list_t *list, const char *pod_id){

    for (size_t i = 0; i < list->count; i++) {
        if (strcmp(list->items[i].pod_id, pod_id) == 0) {
            return &list->items[i];
        }
    }
    
    return NULL;
}

bool pod_list_add (id_list_t *list, pod_entry_t pod){

    if (pod_list_contains(list, pod.pod_id)) {
        // Ya existe, no añadimos duplicado
        return false;
    }

    if (list->count == list->capacity) {
        size_t new_capacity = (list->capacity == 0) ? 4 : list->capacity * 2;
        pod_entry_t *new_items = realloc(list->items, new_capacity * sizeof(pod_entry_t));
        if (!new_items) {
            perror("realloc failed in pod_list_add");
            return false;
        }
        list->items = new_items;
        list->capacity = new_capacity;
    }

    // Añadir pod al final
    list->items[list->count++] = pod;
    return true;
}

bool pod_list_remove (id_list_t *list, const char *pod_id){
    for (size_t i = 0; i < list->count; i++) {
        if (strcmp(list->items[i].pod_id, pod_id) == 0) {
            // Liberar contenedores del pod
            free(list->items[i].containers);
            // Mover último pod a esta posición
            list->items[i] = list->items[list->count - 1];
            list->count--;
            return true;
        }
    }
    return false;
}

void pod_list_free (id_list_t *list){

    for (size_t i = 0; i < list->count; i++) {
        free(list->items[i].containers);
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}


/**********************************************
*  Funciones para gestionar los contenedores  *
***********************************************/

void pod_init_containers(pod_entry_t *pod){
    pod->containers = NULL;
    pod->container_count = 0;
    pod->container_capacity = 0;
}

bool pod_add_container(pod_entry_t *pod, container_entry_t container){
    if (pod->container_count == pod->container_capacity) {
        size_t new_capacity = (pod->container_capacity == 0) ? 2 : pod->container_capacity * 2;
        container_entry_t *new_containers = realloc(pod->containers, new_capacity * sizeof(container_entry_t));
        if (!new_containers) {
            perror("realloc failed in pod_add_container");
            return false;
        }
        pod->containers = new_containers;
        pod->container_capacity = new_capacity;
    }
    pod->containers[pod->container_count++] = container;
    return true;
}

void add_container_to_pod(id_list_t *pods, const char *pod_id, container_entry_t container, const char *node_name) {
    pod_entry_t *pod = pod_list_find(pods, pod_id);
    if (!pod) {
        pod_entry_t new_pod = {0};
        strncpy(new_pod.pod_id, pod_id, sizeof(new_pod.pod_id) - 1);
        pod_init_containers(&new_pod);
        pod_list_add(pods, new_pod);
        strncpy(new_pod.node, node_name, sizeof(new_pod.node) - 1);
        new_pod.node[sizeof(new_pod.node) - 1] = '\0';
        pod = pod_list_find(pods, pod_id);
    }

    container_entry_t *existing = pod_find_container_by_id(pod, container.container_id);
    if (existing) {
        return;
    }

    pod_add_container(pod, container);
}

container_entry_t *pod_find_container_by_id(pod_entry_t *pod, const char *container_id){
    for (size_t i = 0; i < pod->container_count; i++) {
        if (strcmp(pod->containers[i].container_id, container_id) == 0) {
            return &pod->containers[i];
        }
    }
    return NULL;
}

container_entry_t *pod_find_container_by_cgroup(pod_entry_t *pod, uint64_t cgroup_id){
    for (size_t i = 0; i < pod->container_count; i++) {
        if (pod->containers[i].metrics.cgroup_id == cgroup_id) {
            return &pod->containers[i];
        }
    }
    return NULL;
}

bool pod_remove_container(pod_entry_t *pod, const char *container_id){
    for (size_t i = 0; i < pod->container_count; i++) {
        if (strcmp(pod->containers[i].container_id, container_id) == 0) {
            pod->containers[i].metrics.running = 0;
            // Mover último contenedor a esta posición
            pod->containers[i] = pod->containers[pod->container_count - 1];
            pod->container_count--;
            return true;
        }
    }
    return false;
}

/**************************************
*  Funciones para gestionar los logs  *
***************************************/

void log_basic_event_info(const struct event_t *e) {
    zlog_info(c, "PID: %u, TGID: %u, PPID: %u, UID: %u, GID: %u, Command: %s",
              e->pid, e->tgid, e->ppid, e->uid, e->gid, e->comm);
    zlog_info(c, "CGROUPID: %lu", e->cgroup_id);
}

void log_event_exit(const struct event_t *e, const char *event_name, bool has_latency) {
    zlog_info(c, "%s", event_name);
    log_basic_event_info(e);
    zlog_info(c, "RESULTADO: %lu", e->ret);
    if (has_latency) {
        zlog_info(c, "Latencia: %lu", e->latency_ns);
    }
}

void log_event_file(const struct event_t *e, const char *event_name) {
    zlog_info(c, "%s", event_name);
    log_basic_event_info(e);
    zlog_info(c, "Archivo: %s", e->filename);
}

void log_event_cgroup_mkdir(const struct event_t *e) {
    char pod_id[64] = {0};
    char container_id[64] = {0};

    zlog_info(c, "CGROUP MKDIR");
    zlog_info(c, "Command: %s", e->comm);
    zlog_info(c, "Path: %s", e->cgroup_path);

    char full_path[4096];
    snprintf(full_path, sizeof(full_path), "%s%s", base_path, e->cgroup_path);
    uint64_t cgroup_id = get_cgroup_id_from_path(full_path);

    if (cgroup_id == 0) {
        zlog_error(c, "Error obteniendo Cgroup ID");
        return;
    }
    zlog_info(c, "Cgroup ID es: %lu", cgroup_id);

    extract_pod_and_container(e->cgroup_path, pod_id, sizeof(pod_id), container_id, sizeof(container_id));

    if (strcmp(pod_id, "unknown") != 0 && strcmp(container_id, "unknown") != 0) {
        zlog_info(c, "POD ID: %s", pod_id);
        zlog_info(c, "Container ID: %s", container_id);
    }
}

void log_event_cgroup_rmdir(const struct event_t *e) {
    char pod_id[64] = {0};
    char container_id[64] = {0};

    zlog_info(c, "CGROUP RMDIR");
    zlog_info(c, "Command: %s", e->comm);
    zlog_info(c, "Path: %s", e->cgroup_path);
    zlog_info(c, "Cgroup ID: %lu", e->cgroup_id);

    extract_pod_and_container(e->cgroup_path, pod_id, sizeof(pod_id), container_id, sizeof(container_id));

    zlog_info(c, "POD ID: %s", pod_id);
    zlog_info(c, "Container ID: %s", container_id);
}

void log_event_ns(const struct event_t *e) {
    zlog_info(c, "%s", e->type == EVT_CLONE ? "CLONE" : e->type == EVT_UNSHARE ? "UNSHARE" : "SETNS");
    log_basic_event_info(e);
    decode_clone_flags(e->flags);
}

/********************************************
*  Funciones para eventos cgroup y nsevent  *
*********************************************/


void handle_event_cgroup_rmdir(const struct event_t *e) {
    char pod_id[64] = {0};
    char container_id[64] = {0};

    extract_pod_and_container(e->cgroup_path, pod_id, sizeof(pod_id), container_id, sizeof(container_id));

    if (strcmp(pod_id, "unknown") != 0 && strcmp(container_id, "unknown") != 0) {
        pod_entry_t *pod = pod_list_find(&pods, pod_id);
        if (pod) {
            bool removed = pod_remove_container(pod, container_id);
            if (removed) {
                zlog_info(c, "Contenedor eliminado correctamente");
                if (pod->container_count == 0) {
                    pod_list_remove(&pods, pod_id);
                    zlog_info(c, "Pod eliminado porque no tiene contenedores");
                }
            } else {
                zlog_warn(c, "No se encontró el contenedor para eliminar");
            }
        }
    }
}

void handle_event_cgroup_mkdir(const struct event_t *e) {
    char pod_id[64] = {0};
    char container_id[64] = {0};

    extract_pod_and_container(e->cgroup_path, pod_id, sizeof(pod_id), container_id, sizeof(container_id));

    char full_path[4096];
    snprintf(full_path, sizeof(full_path), "%s%s", base_path, e->cgroup_path);
    uint64_t cgroup_id = get_cgroup_id_from_path(full_path);
    if (cgroup_id == 0) {
        // Ya logueado en la función de log, aquí solo ignoramos la lógica.
        return;
    }

    container_entry_t new_container = {0};
    strncpy(new_container.container_id, container_id, sizeof(new_container.container_id) - 1);
    new_container.metrics.cgroup_id = cgroup_id;
    new_container.metrics.running = 1;

    add_container_to_pod(&pods, pod_id, new_container, node_name);
}

void handle_event_ns(const struct event_t *e) {
    if (!(e->flags & NS_MASK)) return;

    // Buscar contenedor por cgroup_id y actualizar métricas
    for (size_t i = 0; i < pods.count; i++) {
        pod_entry_t *pod = &pods.items[i];
        for (size_t j = 0; j < pod->container_count; j++) {
            container_entry_t *container = &pod->containers[j];
            if (container->metrics.cgroup_id == e->cgroup_id) {
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
                return;  // Salir luego de actualizar
            }
        }
    }
}



/*************************
*  Funciones auxiliares  *
**************************/

char *get_container_id(const char *cgroup_path){
    char buf[512];
    strncpy(buf, cgroup_path, sizeof(buf)-1);
    buf[sizeof(buf)-1] = '\0';

    const char *delims = "/-.";
    char *tok = strtok(buf, delims);

    while (tok) {
        size_t len = strlen(tok);
        if (len >= 12 && len <= MAX_ID_LEN) {
            bool all_hex = true;
            for (size_t i = 0; i < len; i++) {
                if (!isxdigit((unsigned char)tok[i])) {
                    all_hex = false;
                    break;
                }
            }
            if (all_hex) {
                return strdup(tok);
            }
        }
        tok = strtok(NULL, delims);
    }

    // Si llegamos aquí, no encontramos nada válido
    return NULL;
}

char *get_time_str() {
    static char buf[64];
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    return buf;
}

void update_flags(ns_flags_counters_t *counters, uint64_t flags) {
    if (flags & CLONE_NEWNS)     counters->mnt++;
    if (flags & CLONE_NEWUTS)    counters->uts++;
    if (flags & CLONE_NEWIPC)    counters->ipc++;
    if (flags & CLONE_NEWUSER)   counters->user++;
    if (flags & CLONE_NEWPID)    counters->pid++;
    if (flags & CLONE_NEWNET)    counters->net++;
    if (flags & CLONE_NEWCGROUP) counters->cgroup++;
    if (flags & CLONE_NEWTIME)   counters->time++;
}

uint64_t get_cgroup_id_from_path(const char *cgroup_path) {
    struct stat st;
    if (stat(cgroup_path, &st) == 0) {
        return (uint64_t) st.st_ino;
    } else {
        perror("stat cgroup path");
        return 0;
    }
}

void extract_pod_and_container(const char *path, char *pod_id, size_t pod_len, char *container_id, size_t cont_len) {

    // Inicializa las cadenas de salida
    if (pod_id && pod_len > 0) pod_id[0] = '\0';
    if (container_id && cont_len > 0) container_id[0] = '\0';

    // Buscar "pod" en el path
    const char *pod_start = strstr(path, "-pod");
    if (pod_start) {
        pod_start += 4; // saltar "-pod"
        const char *pod_end = strstr(pod_start, ".slice");
        if (!pod_end) pod_end = pod_start + strlen(pod_start);
        size_t len = pod_end - pod_start;
        if (len >= pod_len) len = pod_len - 1;
        strncpy(pod_id, pod_start, len);
        pod_id[len] = '\0';
    } else {
        snprintf(pod_id, pod_len, "unknown");
    }

    // Buscar container id con prefijo "cri-containerd-"
    const char *ctr_prefix = "cri-containerd-";
    const char *ctr_start = strstr(path, ctr_prefix);
    if (ctr_start) {
        ctr_start += strlen(ctr_prefix);
        const char *ctr_end = strstr(ctr_start, ".scope");
        if (!ctr_end) ctr_end = ctr_start + strlen(ctr_start);
        size_t len = ctr_end - ctr_start;
        if (len >= cont_len) len = cont_len - 1;
        strncpy(container_id, ctr_start, len);
        container_id[len] = '\0';
    } else {
        snprintf(container_id, cont_len, "unknown");
    }
}

void decode_clone_flags(uint64_t flags) {
    char flags_str[256] = "Flags: ";

    if (flags & CLONE_NEWNS)      strcat(flags_str, "CLONE_NEWNS ");
    if (flags & CLONE_NEWCGROUP)  strcat(flags_str, "CLONE_NEWCGROUP ");
    if (flags & CLONE_NEWUTS)     strcat(flags_str, "CLONE_NEWUTS ");
    if (flags & CLONE_NEWIPC)     strcat(flags_str, "CLONE_NEWIPC ");
    if (flags & CLONE_NEWUSER)    strcat(flags_str, "CLONE_NEWUSER ");
    if (flags & CLONE_NEWPID)     strcat(flags_str, "CLONE_NEWPID ");
    if (flags & CLONE_NEWNET)     strcat(flags_str, "CLONE_NEWNET ");
    if (flags & CLONE_NEWTIME)    strcat(flags_str, "CLONE_NEWTIME ");

    zlog_info(c, "%s", flags_str);
}