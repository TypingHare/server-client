#ifndef CLIENT_H
#define CLIENT_H

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/net_sockets.h>

typedef struct {
    char* hostname;
    char* port;
    char* ca_cert_path;
    mbedtls_net_context server_ctx;
    mbedtls_ssl_context ssl_ctx;
    mbedtls_ssl_config ssl_config;
    mbedtls_x509_crt x509_crt;
    mbedtls_ctr_drbg_context ctr_drbg_ctx;
    mbedtls_entropy_context entropy_ctx;
} client_context_t;

/**
 * @brief Initializes all components of the client context.
 *
 * This function prepares the client context for use by initializing
 * all underlying mbedTLS structures required for a secure TLS connection,
 * including network, SSL, certificate, random number generation, and entropy
 * contexts.
 *
 * @param ctx Pointer to the client context structure to initialize.
 */
void client_context_init(client_context_t* ctx);

/**
 * @brief Frees all components of the client context.
 *
 * This function releases resources held by the client context,
 * cleaning up all associated mbedTLS structures. It should be called
 * when the context is no longer needed to avoid memory leaks.
 *
 * @param ctx Pointer to the client context structure to free.
 */
void client_context_free(client_context_t* ctx);

/**
 * Sends a message to a server over TLS connection and receives a response.
 *
 * This function establishes a secure SSL/TLS connection using mbedTLS, sends
 * a message to the server, and receives the response. It performs all necessary
 * setup and breakdown of the cryptographic context, including:
 * - Seeding the random number generator
 * - Establishing a TCP connection
 * - Configuring the SSL context
 * - Loading the CA certificate
 * - Performing the SSL handshake
 * - Verifying the server certificate
 *
 * After the communication, it gracefully shuts down the TLS session and
 * releases resources.
 *
 * A piece of message consists of two parts: a prefix and the content. The
 * prefix consists of the first eight bytes, representing the length of the
 * message (including the prefix). For example:
 *
 * [20]Hello world!
 *
 * @param ctx Pointer to an initialized client context containing connection
 * parameters, SSL/TLS configuration, and certificate paths.
 * @param message Pointer to the message to be sent to the server.
 * @param length Length of the message in bytes.
 * @param response Pointer to a buffer to store the server's response.
 */
void send_message(
    client_context_t* ctx, const char* message, size_t length, uint8_t* response
);

#endif
