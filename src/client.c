#include "client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

void client_context_init(client_context_t* ctx) {
    mbedtls_net_init(&ctx->server_ctx);
    mbedtls_ssl_init(&ctx->ssl_ctx);
    mbedtls_ssl_config_init(&ctx->ssl_config);
    mbedtls_x509_crt_init(&ctx->x509_crt);
    mbedtls_ctr_drbg_init(&ctx->ctr_drbg_ctx);
    mbedtls_entropy_init(&ctx->entropy_ctx);
}

void client_context_free(client_context_t* ctx) {
    mbedtls_net_free(&ctx->server_ctx);
    mbedtls_x509_crt_free(&ctx->x509_crt);
    mbedtls_ssl_free(&ctx->ssl_ctx);
    mbedtls_ssl_config_free(&ctx->ssl_config);
    mbedtls_ctr_drbg_free(&ctx->ctr_drbg_ctx);
    mbedtls_entropy_free(&ctx->entropy_ctx);
}

void check_mbedtls_result(
    const int result, client_context_t* ctx, const char* function_name
) {
    if (mbedtls_fail(result)) {
        error("%s returned: -0x%x", function_name, -result);
        print_mbedtls_error(result);
        client_context_free(ctx);
        exit(EXIT_FAILURE);
    }
}

void send_message(
    client_context_t* ctx, const char* message, size_t length, uint8_t* response
) {
    printf_flush("Seeding the random generator...  ");
    int result = mbedtls_ctr_drbg_seed(
        &ctx->ctr_drbg_ctx, mbedtls_entropy_func, &ctx->entropy_ctx, NULL, 0
    );
    check_mbedtls_result(result, ctx, "mbedtls_ctr_drbg_seed");
    printf("OK\n");

    // Connect to the server using TCP
    printf_flush("Connecting to TCP %s:%s...  ", ctx->hostname, ctx->port);
    result = mbedtls_net_connect(
        &ctx->server_ctx, ctx->hostname, ctx->port, MBEDTLS_NET_PROTO_TCP
    );
    check_mbedtls_result(result, ctx, "mbedtls_net_connect");
    printf_flush("OK\n");

    // Set up the SSL/TLS structure
    printf_flush("Setting up the SSL/TLS structure...  ");
    result = mbedtls_ssl_config_defaults(
        &ctx->ssl_config,
        MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT
    );
    check_mbedtls_result(result, ctx, "mbedtls_ssl_config_defaults");
    printf_flush("OK\n");

    // !! Change the cipher suites
    const int custom_ciphersuites[] = { MY_CUSTOM_CIPHERSUITE,
                                        MBEDTLS_TLS1_3_AES_256_GCM_SHA384,
                                        0 };
    mbedtls_ssl_conf_ciphersuites(&ctx->ssl_config, custom_ciphersuites);

    // Load the CA root certificate
    printf_flush("Loading the CA root certificate...  ");
    result = mbedtls_x509_crt_parse_file(&ctx->x509_crt, ctx->ca_cert_path);
    check_mbedtls_result(result, ctx, "mbedtls_x509_crt_parse_file");
    mbedtls_ssl_conf_authmode(&ctx->ssl_config, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&ctx->ssl_config, &ctx->x509_crt, NULL);
    printf("OK\n");

    // Set up RNG function (CTR-DRBG) for the SSL/TLS connection
    mbedtls_ssl_conf_rng(
        &ctx->ssl_config, mbedtls_ctr_drbg_random, &ctx->ctr_drbg_ctx
    );

    // Enable debug output during SSL operations.
    mbedtls_ssl_conf_dbg(&ctx->ssl_config, mbedtls_ssl_debug, stdout);

    // Bind the config and the hostname to the context
    result = mbedtls_ssl_setup(&ctx->ssl_ctx, &ctx->ssl_config);
    check_mbedtls_result(result, ctx, "mbedtls_ssl_setup");
    result = mbedtls_ssl_set_hostname(&ctx->ssl_ctx, ctx->hostname);
    check_mbedtls_result(result, ctx, "mbedtls_ssl_set_hostname");

    // Connects the SSL layer to the underlying transport I/O (TCP socket)
    mbedtls_ssl_set_bio(
        &ctx->ssl_ctx,
        &ctx->server_ctx,
        mbedtls_net_send,
        mbedtls_net_recv,
        NULL
    );

    printf_flush("Performing the SSL/TLS handshake...  ");
    while ((result = mbedtls_ssl_handshake(&ctx->ssl_ctx)) != 0) {
        if (!mbedtls_want_read_or_write(result)) {
            check_mbedtls_result(result, ctx, "mbedtls_ssl_handshake");
        }
    }
    printf("OK\n");

    // Verify the certificate of the server
    printf_flush("Verifying server X.509 certificate...  ");
    uint32_t flags = 0;
    flags = mbedtls_ssl_get_verify_result(&ctx->ssl_ctx);
    if (flags != 0) {
        char verify_buffer[0x1000];
        mbedtls_x509_crt_verify_info(
            verify_buffer, sizeof(verify_buffer), "! ", flags
        );
        error("Failed:\n%s\n", verify_buffer);
        check_mbedtls_result(flags, ctx, "mbedtls_x509_crt_verify_result");
    }
    printf("OK\n");

    // Write the message to server
    const size_t buffer_size = sizeof(size_t) + length;
    uint8_t buffer[buffer_size];
    attach_prefix_len(buffer, length);
    memcpy(buffer + sizeof(size_t), message, length);

    printf("Writing message to the server... ");
    while ((result = mbedtls_ssl_write(&ctx->ssl_ctx, buffer, buffer_size)) <= 0
    ) {
        if (result != MBEDTLS_ERR_SSL_WANT_READ &&
            result != MBEDTLS_ERR_SSL_WANT_WRITE) {
            check_mbedtls_result(result, ctx, "mbedtls_ssl_write");
        }
    }
    printf("OK\n");
    printf_flush(ANSI_YELLOW ">> (%d bytes)\n%s\n" ANSI_RESET, result, message);

    const int received_length = receive_message(&ctx->ssl_ctx, response);
    printf(
        ANSI_YELLOW "<< (%d bytes)\n%s\n" ANSI_RESET,
        received_length,
        (char*)(response + sizeof(size_t))
    );

    mbedtls_ssl_close_notify(&ctx->ssl_ctx);
    client_context_free(ctx);
}
