#include "server.h"
#include <mbedtls/debug.h>
#include <string.h>
#include "common.h"

void server_context_init(server_context_t* ctx) {
#ifdef MBEDTLS_SSL_PROTO_TLS1_3
    printf("Server support TLS 1.3\n");
#endif
#ifdef MBEDTLS_CHACHAPOLY_C
    printf("Server support ChaCha20\n");
#endif

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
        error("%s returned: -0x%x", function_name, -result);
        print_mbedtls_error(result);
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
    mbedtls_debug_set_threshold(DEBUG_THRESHOLD);
    mbedtls_ssl_conf_dbg(&ctx->ssl_config, mbedtls_ssl_debug, stdout);
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
    const request_callback_t callback,
    const volatile sig_atomic_t* stop
) {
    int result = 0;

    // Reset the client net context and ssl context before
    mbedtls_net_free(&ctx->client_ctx);
    mbedtls_ssl_session_reset(&ctx->ssl_ctx);

    // !! Set up the accepted ciphersuites (it is not copied)
    const int custom_ciphersuites[] = { MY_CUSTOM_CIPHERSUITE,
                                        MBEDTLS_TLS1_3_AES_256_GCM_SHA384,
                                        MBEDTLS_TLS1_3_AES_128_CCM_SHA256,
                                        MBEDTLS_TLS1_3_CHACHA20_POLY1305_SHA256,
                                        MBEDTLS_TLS1_3_AES_128_CCM_SHA256,
                                        MBEDTLS_TLS1_3_AES_128_CCM_8_SHA256,
                                        0 };
    mbedtls_ssl_conf_ciphersuites(&ctx->ssl_config, custom_ciphersuites);

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
            error("mbedtls_ssl_handshake returned: -0x%x", -result);
            print_mbedtls_error(result);
            return -1;
        }
    }
    printf_flush("OK\n");

    unsigned char buffer[MESSAGE_MAX_LENGTH];
    const int request_length = receive_message(&ctx->ssl_ctx, buffer);
    if (request_length <= 0) {
        switch (request_length) {
            case 0:
                error("The request length is 0, which is invalid.");
                return EXIT_FAILURE;
            case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                printf_flush("Connection was closed.\n");
                return EXIT_FAILURE;
            case MBEDTLS_ERR_NET_CONN_RESET:
                printf_flush("Connection was reset by the client.\n");
                return EXIT_FAILURE;
            default:;
        }
    }

    printf_flush(
        ANSI_YELLOW "<< (%d bytes)\n%s\n" ANSI_RESET,
        request_length,
        (char*)(buffer + sizeof(size_t))
    );

    // Copy the buffer to `message`
    uint8_t message[MESSAGE_MAX_LENGTH];
    memcpy(message, (char*)buffer, request_length);

    // Fire the callback, which should process the request and put the response
    // back to `data`
    printf_flush("Firing callback function...  ");
    callback(message, request_length);
    printf_flush("OK\n");

    // Read from data to buffer
    size_t response_length = extract_prefix_len(message);
    memcpy(buffer, message, response_length);
    buffer[response_length] = '\0';

    printf_flush("Writing to client...  ");
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
    printf("OK\n");
    printf_flush(
        ANSI_YELLOW ">> (%lu bytes)\n%s\n" ANSI_RESET,
        response_length,
        (char*)(buffer + sizeof(size_t))
    );

    return 0;
}
