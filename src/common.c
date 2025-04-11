#include "common.h"
#include <string.h>

bool mbedtls_fail(const int result) { return result != 0; }

bool mbedtls_want_read_or_write(const int result) {
    return result == MBEDTLS_ERR_SSL_WANT_READ ||
           result == MBEDTLS_ERR_SSL_WANT_WRITE;
}

void mbedtls_ssl_debug(
    void* fd, const int level, const char* file, const int line, const char* str
) {
    fprintf((FILE*)fd, "%04d: %s", line, str);
    fflush(fd);
}

void print_mbedtls_error(const int ret) {
    char error_buf[0x100];
    mbedtls_strerror(ret, error_buf, sizeof(error_buf));
    printf("%s\n", error_buf);
}

size_t extract_prefix_len(const uint8_t* data) {
    size_t size = 0;
    for (int i = 0; i < sizeof(size_t); i++) {
        size = size << 8 | (uint8_t)data[i];
    }
    return sizeof(size_t) + size;
}

void attach_prefix_len(uint8_t* dest, size_t size) {
    for (int i = 7; i >= 0; i--) {
        dest[i] = (char)(size & 0xFF);
        size >>= sizeof(size_t);
    }
}

int receive_message(mbedtls_ssl_context* ctx, uint8_t* buffer) {
    int total_length = 0;
    int received = 0;

    while (1) {
        uint8_t temp[1024] = { 0 };
        int len = mbedtls_ssl_read(ctx, temp, sizeof(temp) - 1);

        if (len == MBEDTLS_ERR_SSL_WANT_READ ||
            len == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;

        if (len < 0)
            return len;

        memcpy(buffer + received, temp, len);
        received += len;

        if (total_length == 0 && received >= sizeof(size_t)) {
            total_length = (int)extract_prefix_len(buffer);
            if (total_length == 0)
                return 0;
        }

        if (total_length > 0 && received >= total_length)
            break;
    }

    buffer[total_length] = '\0';
    return total_length;
}

// void print_cert(const mbedtls_x509_crt* cert) {
//     const mbedtls_pk_context* pubkey = &cert->pk;
//     char buf[0x10000];
//     const int ret = mbedtls_pk_write_pubkey_pem(pubkey, buf, sizeof(buf));
//     if (ret == 0) {
//         printf("%s\n", buf);
//     } else {
//         error("! Failed to print the peer's public key.");
//     }
// }
