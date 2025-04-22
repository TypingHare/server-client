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

void export_keys_callback(
    // ReSharper disable once CppParameterMayBeConstPtrOrRef
    void* p_expkey,
    const mbedtls_ssl_key_export_type type,
    const unsigned char* secret,
    const size_t secret_len,
    const unsigned char client_random[32],
    const unsigned char server_random[32],
    const mbedtls_tls_prf_types tls_prf_type
) {
    (void)p_expkey;
    (void)client_random;
    (void)server_random;
    (void)tls_prf_type;

#ifdef MBEDTLS_SSL_PROTO_TLS1_3
    switch (type) {
        case MBEDTLS_SSL_KEY_EXPORT_TLS1_3_CLIENT_HANDSHAKE_TRAFFIC_SECRET:
            // Derive keys for encrypting handshake messages between the client
            // and server
            printf("Client Handshake Traffic Secret:   ");
            break;
        case MBEDTLS_SSL_KEY_EXPORT_TLS1_3_SERVER_HANDSHAKE_TRAFFIC_SECRET:
            // Derive keys for encrypting handshake messages between the client
            // and server
            printf("Server Handshake Traffic Secret:   ");
            break;
        case MBEDTLS_SSL_KEY_EXPORT_TLS1_3_CLIENT_APPLICATION_TRAFFIC_SECRET:
            // Derive keys for encrypting application data sent from the client
            // to the server after the handshake
            printf("Client Application Traffic Secret: ");
            break;
        case MBEDTLS_SSL_KEY_EXPORT_TLS1_3_SERVER_APPLICATION_TRAFFIC_SECRET:
            // Derive keys for encrypting application data sent from the server
            // to the client after the handshake
            printf("Server Application Traffic Secret: ");
            break;
        default:;
    }
    for (size_t i = 0; i < secret_len; i++) {
        printf("%02x", secret[i]);
    }

    printf("\n");
#endif
}
