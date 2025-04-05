#include "server.h"
#include <string.h>
#include "common.h"

void ssl_debug(
    void* fd, const int level, const char* file, const int line, const char* str
) {
    (void)level;
    fprintf((FILE*)fd, "%s:%04d: %s\n", file, line, str);
    fflush(fd);
}

void server_context_init(server_context_t* ctx) {
    mbedtls_net_init(&ctx->server_ctx);
    mbedtls_net_init(&ctx->client_ctx);
    mbedtls_ssl_init(&ctx->ssl_ctx);
    mbedtls_ssl_config_init(&ctx->ssl_config);
    mbedtls_x509_crt_init(&ctx->x509_crt);
    mbedtls_pk_init(&ctx->pk_ctx);
    mbedtls_entropy_init(&ctx->entropy_ctx);
    mbedtls_ctr_drbg_init(&ctx->ctr_drbg_ctx);
}

void server_context_free(server_context_t* ctx) {
    mbedtls_net_free(&ctx->client_ctx);
    mbedtls_net_free(&ctx->server_ctx);
    mbedtls_x509_crt_free(&ctx->x509_crt);
    mbedtls_pk_free(&ctx->pk_ctx);
    mbedtls_ssl_free(&ctx->ssl_ctx);
    mbedtls_ssl_config_free(&ctx->ssl_config);
    mbedtls_ctr_drbg_free(&ctx->ctr_drbg_ctx);
    mbedtls_entropy_free(&ctx->entropy_ctx);
}

void check_mbedtls_result(
    const int result, server_context_t* ctx, const char* function_name
) {
    if (mbedtls_fail(result)) {
        error("%s returned: %d", function_name, result);
        server_context_free(ctx);
        exit(EXIT_FAILURE);
    }
}

void server_context_prepare(server_context_t* ctx) {
    printf_flush("Seeding the random generator...  ");
    int result = mbedtls_ctr_drbg_seed(
        &ctx->ctr_drbg_ctx, mbedtls_entropy_func, &ctx->entropy_ctx, NULL, 0
    );
    check_mbedtls_result(result, ctx, "mbedtls_ctr_drbg_seed");
    printf("OK\n");

    // Load the certificate and private RSA key
    // Run on a native server
    printf_flush("Creating normal server and key...  ");
    result = mbedtls_x509_crt_parse_file(&ctx->x509_crt, ctx->server_crt_path);
    check_mbedtls_result(
        result, ctx, "(server key) mbedtls_x509_crt_parse_file"
    );

    result = mbedtls_x509_crt_parse_file(&ctx->x509_crt, ctx->ca_cert_path);
    check_mbedtls_result(result, ctx, "(CA) mbedtls_x509_crt_parse_file");

    result = mbedtls_pk_parse_keyfile(
        &ctx->pk_ctx,
        ctx->server_key_path,
        NULL,
        mbedtls_ctr_drbg_random,
        &ctx->ctr_drbg_ctx
    );
    check_mbedtls_result(result, ctx, "mbedtls_pk_parse_keyfile");
    printf("OK\n");

    // Set up the listening socket
    printf_flush("Listening on https://localhost:%s...  ", ctx->port);
    result = mbedtls_net_bind(
        &ctx->server_ctx, NULL, ctx->port, MBEDTLS_NET_PROTO_TCP
    );
    check_mbedtls_result(result, ctx, "mbedtls_net_bind");
    printf("OK\n");

    // Set up SSL data
    printf_flush("Setting up the SSL data...  ");
    result = mbedtls_ssl_config_defaults(
        &ctx->ssl_config,
        MBEDTLS_SSL_IS_SERVER,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT
    );
    check_mbedtls_result(result, ctx, "mbedtls_ssl_config_defaults");
    mbedtls_ssl_conf_rng(
        &ctx->ssl_config, mbedtls_ctr_drbg_random, &ctx->ctr_drbg_ctx
    );
    mbedtls_ssl_conf_dbg(&ctx->ssl_config, ssl_debug, stdout);
    mbedtls_ssl_conf_ca_chain(&ctx->ssl_config, ctx->x509_crt.next, NULL);

    result = mbedtls_ssl_conf_own_cert(
        &ctx->ssl_config, &ctx->x509_crt, &ctx->pk_ctx
    );
    check_mbedtls_result(result, ctx, "mbedtls_ssl_conf_own_cert");
    result = mbedtls_ssl_setup(&ctx->ssl_ctx, &ctx->ssl_config);
    check_mbedtls_result(result, ctx, "mbedtls_ssl_setup");
    printf("OK\n");
}

int server_listen(
    server_context_t* ctx,
    char* data,
    const request_callback_t callback,
    const volatile sig_atomic_t* stop
) {
    int result = 0;

    // Reset the client net context and ssl context before
    mbedtls_net_free(&ctx->client_ctx);
    mbedtls_ssl_session_reset(&ctx->ssl_ctx);

    // Set the `mbedtls_net_accept` as non-blocking
    mbedtls_net_set_nonblock(&ctx->server_ctx);
    printf_flush("Waiting for a remote connection...  ");
    while (!*stop) {
        result = mbedtls_net_accept(
            &ctx->server_ctx, &ctx->client_ctx, NULL, 0, NULL
        );
        if (result == 0) {
            break;
        }

        if (result == MBEDTLS_ERR_SSL_WANT_READ ||
            result == MBEDTLS_ERR_SSL_WANT_WRITE ||
            result == MBEDTLS_ERR_NET_RECV_FAILED ||
            result == MBEDTLS_ERR_NET_ACCEPT_FAILED) {
            mbedtls_net_usleep(100000);
        } else {
            error("mbedtls_net_accept failed with error: %d", result);
            return -1;
        }
    }
    if (*stop) {
        return 0;
    }

    mbedtls_ssl_set_bio(
        &ctx->ssl_ctx,
        &ctx->client_ctx,
        mbedtls_net_send,
        mbedtls_net_recv,
        NULL
    );
    printf("OK\n");

    // SSL/TLS Handshake
    printf_flush("Performing the SSL/TLS handshake...  ");
    while ((result = mbedtls_ssl_handshake(&ctx->ssl_ctx)) != 0) {
        if (result != MBEDTLS_ERR_SSL_WANT_READ &&
            result != MBEDTLS_ERR_SSL_WANT_WRITE) {
            error("mbedtls_ssl_handshake returned %d", result);
            return -1;
        }
    }
    printf_flush("OK\n");

    unsigned char buffer[8192];
    size_t request_length = 0;
    do {
        unsigned char read_buffer[1024];
        const int len = sizeof(read_buffer) - 1;
        memset(read_buffer, 0, sizeof(read_buffer));
        result = mbedtls_ssl_read(&ctx->ssl_ctx, read_buffer, len);

        if (result == MBEDTLS_ERR_SSL_WANT_READ ||
            result == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;

        if (result < 0) {
            switch (result) {
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    printf_flush("Connection was closed gracefully.\n");
                    break;
                case MBEDTLS_ERR_NET_CONN_RESET:
                    printf_flush("Connection was reset by peer.\n");
                    break;
                default:
                    error("mbedtls_ssl_read returned -0x%x\n", -result);
            }

            break;
        }

        if (request_length + result < sizeof(buffer)) {
            memcpy(buffer + request_length, read_buffer, result);
            request_length += result;
        } else {
            printf_flush("Buffer overflow!\n");
            break;
        }

        break;
    }
    while (true);

    buffer[request_length] = '\0';
    printf_flush("<< Read from client:\n%s", (char*)buffer);

    // Copy the buffer to data
    memcpy(data, buffer, request_length);
    printf_flush("%s\n", data + sizeof(size_t));

    // Fire the callback, which should process the request and put the response
    // back to `data`
    printf_flush("Firing callback function...  ");
    callback(data);
    printf_flush("OK\n");

    // Read from data to buffer
    size_t response_length = extract_prefix_len(data);
    memcpy(buffer, data, response_length);

    printf_flush(">> Write to client: ");
    while ((result = mbedtls_ssl_write(&ctx->ssl_ctx, buffer, response_length)
           ) <= 0) {
        if (result == MBEDTLS_ERR_NET_CONN_RESET) {
            error("Client closed the connection.");
            return -1;
        }

        if (result != MBEDTLS_ERR_SSL_WANT_READ &&
            result != MBEDTLS_ERR_SSL_WANT_WRITE) {
            error("mbedtls_ssl_write returned %d", result);
            return -1;
        }
    }

    return 0;
}
