#include <stdlib.h>
#include <string.h>

#ifdef CLIENT
#include "client.h"
#endif

#ifdef SERVER
#include "common.h"
#include "server.h"

volatile sig_atomic_t stop = 0;

void handle_sigint(int _) { stop = 1; }

void demo_callback(uint8_t* data) {
    const char message[] = "You too!";
    attach_prefix_len(data, strlen(message));
    strcpy((char*)(data + sizeof(size_t)), message);
}
#endif

int main(int _, char** argv) {
    char ca_cert_path[] = "ssl/ca.crt";
    char port[] = "4433";

#ifdef CLIENT
    char hostname[] = "localhost";
    client_context_t ctx;
    ctx.hostname = hostname;
    ctx.port = port;
    ctx.ca_cert_path = ca_cert_path;
    client_context_init(&ctx);

    char response[0x4000];
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
        uint8_t data[0x4000];
        printf("\n");
        server_listen(&ctx, data, demo_callback, &stop);
    }

    printf("\nShutting down the server...\n");
#endif

    return EXIT_SUCCESS;
}
