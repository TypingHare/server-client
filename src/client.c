#include "client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

void my_debug(
    void* ctx,
    const int level,
    const char* file,
    const int line,
    const char* str
) {
    (void)level;

    fprintf((FILE*)ctx, "%s:%04d: %s\n", file, line, str);
    fflush(ctx);
}

void client_context_init(client_context_t* ctx) {
    mbedtls_net_init(&ctx->net_ctx);
    mbedtls_ssl_init(&ctx->ssl_ctx);
    mbedtls_ssl_config_init(&ctx->ssl_config);
    mbedtls_x509_crt_init(&ctx->x509_crt);
    mbedtls_ctr_drbg_init(&ctx->ctr_drbg_ctx);
    mbedtls_entropy_init(&ctx->entropy_ctx);
}

void client_context_free(client_context_t* ctx) {
    mbedtls_net_free(&ctx->net_ctx);
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
        error("%s returned: %d", function_name, result);
        client_context_free(ctx);
        exit(EXIT_FAILURE);
    }
}

int send_message(
    client_context_t* ctx, char* message, size_t length, char* response
) {
    printf_flush("Seeding the random generator...  ");
    int result = mbedtls_ctr_drbg_seed(
        &ctx->ctr_drbg_ctx, mbedtls_entropy_func, &ctx->entropy_ctx, NULL, 0
    );
    check_mbedtls_result(result, ctx, "mbedtls_ctr_drbg_seed");
    printf("OK\n");

    // Connect to the server
    printf_flush("Connecting to TCP %s:%s...  ", ctx->hostname, ctx->port);
    result = mbedtls_net_connect(
        &ctx->net_ctx, ctx->hostname, ctx->port, MBEDTLS_NET_PROTO_TCP
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

    // Load the CA root certificate
    printf_flush("Loading the CA root certificate...  ");
    result = mbedtls_x509_crt_parse_file(&ctx->x509_crt, ctx->ca_cert_path);
    check_mbedtls_result(result, ctx, "mbedtls_x509_crt_parse_file");
    mbedtls_ssl_conf_authmode(&ctx->ssl_config, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&ctx->ssl_config, &ctx->x509_crt, NULL);
    printf("OK\n");

    mbedtls_ssl_conf_rng(
        &ctx->ssl_config, mbedtls_ctr_drbg_random, &ctx->ctr_drbg_ctx
    );
    mbedtls_ssl_conf_dbg(&ctx->ssl_config, my_debug, stdout);
    result = mbedtls_ssl_setup(&ctx->ssl_ctx, &ctx->ssl_config);
    check_mbedtls_result(result, ctx, "mbedtls_ssl_setup");
    result = mbedtls_ssl_set_hostname(&ctx->ssl_ctx, ctx->hostname);
    check_mbedtls_result(result, ctx, "mbedtls_ssl_set_hostname");
    mbedtls_ssl_set_bio(
        &ctx->ssl_ctx, &ctx->net_ctx, mbedtls_net_send, mbedtls_net_recv, NULL
    );

    printf_flush("Performing the SSL/TLS handshake...  ");
    while ((result = mbedtls_ssl_handshake(&ctx->ssl_ctx)) != 0) {
        if (result != MBEDTLS_ERR_SSL_WANT_READ &&
            result != MBEDTLS_ERR_SSL_WANT_WRITE) {
            error("mbedtls_ssl_handshake returned -0x%x", -result);
            client_context_free(ctx);
            exit(EXIT_FAILURE);
        }
    }
    printf("OK\n");

    // Verify server certificate
    // printf_flush("Verifying server X.509 certificate...  ");
    // uint32_t flags = 0;
    // flags = mbedtls_ssl_get_verify_result(&ctx->ssl_ctx);
    // if (flags != 0) {
    //     char verify_buffer[0x1000];
    //     mbedtls_x509_crt_verify_info(
    //         verify_buffer, sizeof(verify_buffer), "! ", flags
    //     );
    //     error("Failed:\n%s\n", verify_buffer);
    //     client_context_free(ctx);
    //     exit(EXIT_FAILURE);
    // }
    // printf("OK\n");

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
    printf_flush(">> (%d bytes written)\n%s\n", result, message);

    printf_flush("<< Read from server:");
    fflush(stdout);

    do {
        length = sizeof(buffer) - 1;
        memset(buffer, 0, sizeof(buffer));
        result = mbedtls_ssl_read(&ctx->ssl_ctx, buffer, length);

        if (result == MBEDTLS_ERR_SSL_WANT_READ ||
            result == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;

        if (result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
            break;

        if (result < 0) {
            check_mbedtls_result(result, ctx, "mbedtls_ssl_read");
        }

        if (result == 0) {
            printf("\n(EOF)\n");
            break;
        }

        length = result;
        printf_flush(" %lu bytes read\n\n%s", length, (char*)buffer);
        memcpy(response, buffer, 1024);
    }
    while (true);

    mbedtls_ssl_close_notify(&ctx->ssl_ctx);
    client_context_free(ctx);

    return EXIT_SUCCESS;
}
