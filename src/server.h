#ifndef SERVER_H
#define SERVER_H

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/net_sockets.h>

typedef struct {
    char* port;
    char* server_crt_path;
    char* server_key_path;
    char* ca_cert_path;
    mbedtls_net_context server_ctx;
    mbedtls_net_context client_ctx;
    mbedtls_ssl_context ssl_ctx;
    mbedtls_ssl_config ssl_config;
    mbedtls_x509_crt x509_crt;
    mbedtls_pk_context pk_ctx;
    mbedtls_entropy_context entropy_ctx;
    mbedtls_ctr_drbg_context ctr_drbg_ctx;
} server_context_t;

typedef void (*request_callback_t)(char* data);

void ssl_debug(
    void* fd, int level, const char* file, int line, const char* str
);

void server_context_init(server_context_t* ctx);

void server_context_free(server_context_t* ctx);

void server_context_prepare(server_context_t* ctx);

int server_listen(
    server_context_t* ctx,
    char* data,
    request_callback_t callback,
    const volatile sig_atomic_t* stop
);

#endif  // SERVER_H
