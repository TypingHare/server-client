#ifndef COMMON_H
#define COMMON_H

#include <stdbool.h>
#include <stdlib.h>

#define printf_flush(...)                                                      \
    do {                                                                       \
        printf(__VA_ARGS__);                                                   \
        fflush(stdout);                                                        \
    }                                                                          \
    while (0)

#define error(fmt, ...)                                                        \
    do {                                                                       \
        fprintf(stderr, "Error: " fmt "\n", ##__VA_ARGS__);                    \
        fflush(stderr);                                                        \
    }                                                                          \
    while (0)

bool mbedtls_fail(int result);

size_t extract_prefix_len(const char* data);

void attach_prefix_len(char* dest, size_t size);

#endif
