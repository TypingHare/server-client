#include "common.h"

bool mbedtls_fail(const int result) { return result != 0; }

size_t extract_prefix_len(const char* data) {
    size_t size = 0;
    for (int i = 0; i < sizeof(size_t); i++) {
        size = size << 8 | (uint8_t)data[i];
    }
    return sizeof(size_t) + size;
}

void attach_prefix_len(char* dest, size_t size) {
    for (int i = 7; i >= 0; i--) {
        dest[i] = (char)(size & 0xFF);
        size >>= sizeof(size_t);
    }
}
