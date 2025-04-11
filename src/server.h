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

typedef void (*request_callback_t)(uint8_t* content, size_t size);

/**
 * @brief Initializes the server context by setting up all required mbedTLS
 * components.
 *
 * This function must be called before using the server context to configure or
 * handle TLS connections.
 *
 * @param ctx Pointer to the server context to initialize.
 */
void server_context_init(server_context_t* ctx);

/**
 * @brief Frees and cleans up all resources associated with the server context.
 *
 * This function should be called after the server context is no longer needed
 * to prevent memory leaks and cleanly release system resources.
 *
 * @param ctx Pointer to the server context to free.
 */
void server_context_free(server_context_t* ctx);

/**
 * @brief Prepares the server context for accepting secure TLS connections.
 *
 * This includes seeding the random generator, loading certificates and keys,
 * binding to the server port, and configuring SSL/TLS settings.
 *
 * @param ctx Pointer to the server context to prepare.
 */
void server_context_prepare(server_context_t* ctx);

/**
 * @brief Listens for incoming client connections, performs the TLS handshake,
 *        receives a message, processes it via a callback, and sends a response.
 *
 * The server accepts a connection in non-blocking mode, handles SSL/TLS
 * negotiation, and securely transmits data to and from the client.
 *
 * @param ctx Pointer to the initialized server context.
 * @param callback Function pointer that processes the incoming request and
 * prepares the response.
 * @param stop Pointer to a flag that can be set asynchronously to signal the
 * server to stop listening.
 *
 * @return 0 on success, -1 on recoverable network or handshake error, or
 * EXIT_FAILURE on protocol issues.
 */
int server_listen(
    server_context_t* ctx,
    request_callback_t callback,
    const volatile sig_atomic_t* stop
);

#endif  // SERVER_H
