#ifndef CLIENT_H
#define CLIENT_H

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/net_sockets.h>

typedef struct {
    char* hostname;
    char* port;
    char* ca_cert_path;
    mbedtls_net_context net_ctx;
    mbedtls_ssl_context ssl_ctx;
    mbedtls_ssl_config ssl_config;
    mbedtls_x509_crt x509_crt;
    mbedtls_ctr_drbg_context ctr_drbg_ctx;
    mbedtls_entropy_context entropy_ctx;
} client_context_t;

void client_context_init(client_context_t* ctx);

void client_context_free(client_context_t* ctx);

/**
 * Sends a message to the server.
 *
 * @param ctx
 * @param message
 * @param length
 * @param response
 * @return
 */
int send_message(
    client_context_t* ctx, char* message, size_t length, char* response
);

#endif
