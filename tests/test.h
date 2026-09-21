#ifndef ARGUS_TEST_H
#define ARGUS_TEST_H

#include <stdio.h>

extern int argus_test_failures;

#define ARGUS_CHECK(expression)                                                   \
    do {                                                                          \
        if (!(expression)) {                                                      \
            fprintf(stderr, "%s:%d: check failed: %s\n",                       \
                    __FILE__, __LINE__, #expression);                             \
            ++argus_test_failures;                                                \
        }                                                                         \
    } while (0)

void test_checksum(void);
void test_connect(void);
void test_engine(void);
void test_port_list(void);
void test_thread_pool(void);

#endif
