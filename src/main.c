#include <string.h>
#include "common.h"

#ifdef CLIENT
#include "client.h"
#endif

#ifdef SERVER
#include <stdlib.h>
#include "server.h"

volatile sig_atomic_t stop = 0;

void handle_sigint(int _) { stop = 1; }

void demo_callback(uint8_t* message, const size_t size) {
    char request[MESSAGE_MAX_LENGTH];
    size_t request_content_len = size - sizeof(size_t);
    memcpy(request, message + sizeof(size_t), request_content_len);
    request[request_content_len] = '\0';

    const char prompt[] = "Your name is: ";
    strcpy((char*)(message + sizeof(size_t)), prompt);
    strcpy((char*)(message + sizeof(size_t) + strlen(prompt)), request);

    const size_t content_len = strlen(prompt) + request_content_len;
    message[sizeof(size_t) + content_len] = '\0';

    attach_prefix_len(message, content_len);
}
#endif

int main(const int argc, const char** argv) {
    char ca_cert_path[] = "ssl/ca.crt";
    char port[] = "4433";

#ifdef CLIENT
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <message>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char hostname[] = "localhost";
    client_context_t ctx;
    ctx.hostname = hostname;
    ctx.port = port;
    ctx.ca_cert_path = ca_cert_path;
    client_context_init(&ctx);

    uint8_t response[0x4000];
    send_message(&ctx, argv[1], strlen(argv[1]), response);
#endif

#ifdef SERVER
    char server_crt_path[] = "ssl/server.crt";
    char server_key_path[] = "ssl/server.key";
    server_context_t ctx;
    ctx.port = port;
    ctx.server_crt_path = server_crt_path;
    ctx.server_key_path = server_key_path;
    ctx.ca_cert_path = ca_cert_path;
    server_context_init(&ctx);
    server_context_prepare(&ctx);

    signal(SIGINT, handle_sigint);
    while (!stop) {
        printf("\n");
        server_listen(&ctx, demo_callback, &stop);
    }

    printf("\nShutting down the server...\n");
#endif

    return EXIT_SUCCESS;
}
