#include <check.h>
#include <stdlib.h>
#include <stdio.h>
#include "../include/utils.h"

static id_list_t list;

void inicio_lista(void) {
    id_list_init(&list, 2);
}

void liberar_lista(void) {
    id_list_free(&list);
}

START_TEST(test_init_empty) {
    ck_assert_uint_eq(list.count, 0);
    ck_assert_uint_ge(list.cap, 2);
}
END_TEST

START_TEST(test_add_and_contains) {
    bool added = id_list_add(&list, "deadbeef1234");
    ck_assert(added);
    ck_assert_uint_eq(list.count, 1);
    ck_assert(id_list_contains(&list, "deadbeef1234"));

    /* volver a añadir debe fallar */
    added = id_list_add(&list, "deadbeef1234");
    ck_assert(!added);
    ck_assert_uint_eq(list.count, 1);
}
END_TEST

START_TEST(test_remove) {
    id_list_add(&list, "cafecafe1234");
    ck_assert_uint_eq(list.count, 1);

    bool removed = id_list_remove(&list, "cafecafe1234");
    ck_assert(removed);
    ck_assert_uint_eq(list.count, 0);

    /* eliminar otra vez devuelve false */
    removed = id_list_remove(&list, "cafecafe1234");
    ck_assert(!removed);
}
END_TEST

START_TEST(test_free_clears) {
    id_list_add(&list, "a1b2c3d4e5f6");
    id_list_free(&list);
    ck_assert_ptr_null(list.ids);
    ck_assert_uint_eq(list.count, 0);
    ck_assert_uint_eq(list.cap, 0);
}
END_TEST

START_TEST(test_get_container_id_valid) {
    char *id = get_container_id("system.slice/docker-123456abcdef.scope");
    ck_assert_ptr_nonnull(id);
    ck_assert_str_eq(id, "123456abcdef");
    free(id);
}
END_TEST

START_TEST(test_get_container_id_invalid) {
    char *id = get_container_id("/no/id/here");
    ck_assert_ptr_null(id);
}
END_TEST


/* Capacity growth */
START_TEST(test_capacity_growth) {
    /* initial cap = 2 */
    id_list_add(&list, "id1");
    id_list_add(&list, "id2");
    ck_assert_uint_eq(list.cap, 2);
    id_list_add(&list, "id3");
    /* cap se ha duplicado */
    ck_assert_uint_eq(list.count, 3);
    ck_assert_uint_ge(list.cap, 3);
    ck_assert(id_list_contains(&list, "id3"));
}
END_TEST

/* Remove element in the middle */
START_TEST(test_remove_middle) {
    id_list_add(&list, "first");
    id_list_add(&list, "middle");
    id_list_add(&list, "last");
    ck_assert_uint_eq(list.count, 3);
    ck_assert(id_list_remove(&list, "middle"));
    ck_assert_uint_eq(list.count, 2);
    ck_assert(id_list_contains(&list, "first"));
    ck_assert(id_list_contains(&list, "last"));
}
END_TEST

/* Duplicate removal */
START_TEST(test_duplicate_removal) {
    id_list_add(&list, "dup");
    ck_assert(id_list_remove(&list, "dup"));
    /* Ya está vacío, no hay nada que eliminar */
    ck_assert(!id_list_remove(&list, "dup"));
}
END_TEST

/* get_container_id: CRI-O prefix */
START_TEST(test_get_container_id_crio) {
    char *id = get_container_id(
      "kubepods.slice/crio-abcdefabcdefabcdefabcdefabcdefabcdefabcdef.scope"
    );
    ck_assert_ptr_nonnull(id);
    ck_assert_str_eq(id,
        "abcdefabcdefabcdefabcdefabcdefabcdefabcdef");
    free(id);
}
END_TEST

/* get_container_id: containerd prefix */
START_TEST(test_get_container_id_containerd) {
    char hex[65];
    for (int i = 0; i < 64; i++) hex[i] = "0123456789abcdef"[i % 16];
    hex[64] = '\0';

    char path[128];
    snprintf(path, sizeof(path),
        "kubepods.slice/containerd-%s.scope", hex);
    char *id = get_container_id(path);
    ck_assert_ptr_nonnull(id);
    ck_assert_str_eq(id, hex);
    free(id);
}
END_TEST

/* get_container_id: too short */
START_TEST(test_get_container_id_short) {
    char *id = get_container_id("docker-abc123.scope");
    ck_assert_ptr_null(id);
}
END_TEST

/* get_container_id: exactly max length */
START_TEST(test_get_container_id_maxlen) {
    char hex[65];
    for (int i = 0; i < 64; i++) hex[i] = "0123456789abcdef"[i % 16];
    hex[64] = '\0';

    char path[128];
    snprintf(path, sizeof(path), "docker-%s.scope", hex);
    char *id = get_container_id(path);
    ck_assert_ptr_nonnull(id);
    ck_assert_str_eq(id, hex);
    free(id);
}
END_TEST


Suite *utils_suite(void) {
    Suite *s = suite_create("Utils");
    TCase *tc_core = tcase_create("Core");

    tcase_add_checked_fixture(tc_core, inicio_lista, liberar_lista);
    tcase_add_test(tc_core, test_init_empty);
    tcase_add_test(tc_core, test_add_and_contains);
    tcase_add_test(tc_core, test_remove);
    tcase_add_test(tc_core, test_free_clears);

    tcase_add_test(tc_core, test_get_container_id_valid);
    tcase_add_test(tc_core, test_get_container_id_invalid);
    tcase_add_test(tc_core, test_capacity_growth);
    tcase_add_test(tc_core, test_remove_middle);
    tcase_add_test(tc_core, test_duplicate_removal);
    tcase_add_test(tc_core, test_get_container_id_crio);
    tcase_add_test(tc_core, test_get_container_id_containerd);
    tcase_add_test(tc_core, test_get_container_id_short);
    tcase_add_test(tc_core, test_get_container_id_maxlen);

    suite_add_tcase(s, tc_core);
    return s;
}

int main(void) {
    int number_failed;
    SRunner *sr = srunner_create(utils_suite());
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
