#ifndef COMMON_H
#define COMMON_H

// Use TLS 1.2
#undef MBEDTLS_SSL_PROTO_TLS1_3
#define MBEDTLS_SSL_PROTO_TLS1_2

#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <stdbool.h>

#define ANSI_YELLOW "\033[33m"
#define ANSI_RESET "\033[0m"

#define MESSAGE_MAX_LENGTH 0x4000

// Enable debug mode and set the debug level (threshold)
#define MBEDTLS_DEBUG_C
#define DEBUG_THRESHOLD 0

#define printf_flush(...)                                                      \
    do {                                                                       \
        printf(__VA_ARGS__);                                                   \
        fflush(stdout);                                                        \
    }                                                                          \
    while (0)

#define error(fmt, ...)                                                        \
    do {                                                                       \
        fprintf(stderr, "Error: " fmt "\n", ##__VA_ARGS__);                    \
        fflush(stderr);                                                        \
    }                                                                          \
    while (0)

static int CUSTOM_CIPHERSUITES[] = { MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA256,
                                     MBEDTLS_TLS1_3_AES_128_GCM_SHA256,
                                     0 };

/**
 * @brief Checks if an mbedTLS function call failed.
 *
 * A non-zero result typically indicates an error in mbedTLS functions.
 *
 * @param result The result code returned by an mbedTLS function.
 * @return true if the result indicates a failure, false otherwise.
 */
bool mbedtls_fail(int result);

/**
 * @brief Checks if an mbedTLS read/write operation should be retried.
 *
 * @param result The return value from an mbedTLS read or write function.
 * @return true if the operation should be retried (WANT_READ or WANT_WRITE);
 * false otherwise.
 */
bool mbedtls_want_read_or_write(int result);

/**
 * @brief Logs an SSL-related debug message to the specified file stream.
 *
 * This function prints a debug message with the source file name and line
 * number to the provided file descriptor. The output is immediately flushed to
 * ensure it is written in real-time.
 *
 * @param fd A pointer to a FILE stream.
 * @param level The level of the debug message.
 * @param file The name of the source file where the debug message originated.
 * @param line The line number in the source file where the message was
 * generated.
 * @param str  The debug message to log.
 */
void mbedtls_ssl_debug(
    void* fd, int level, const char* file, int line, const char* str
);

void print_mbedtls_error(const int ret);

/**
 * @brief Extracts the total message length (including prefix) from the given
 * data.
 *
 * Assume that the first sizeof(size_t) bytes represent the big-endian encoded
 * length of the actual message payload. The returned size includes both the
 * prefix and the payload.
 *
 * @param data Pointer to the buffer containing the prefixed data.
 * @return Total size (prefix and payload).
 */
size_t extract_prefix_len(const uint8_t* data);

/**
 * @brief Attaches a big-endian size prefix to the beginning of a buffer.
 *
 * Encodes the size value into the first sizeof(size_t) bytes of the destination
 * buffer in big-endian order. Used for framing messages.
 *
 * @param dest Pointer to the buffer where the prefix will be written.
 * @param size The size of the actual message payload (excluding the prefix).
 */
void attach_prefix_len(uint8_t* dest, size_t size);

/**
 * @brief Receives a complete message over an mbedTLS SSL connection.
 *
 * The function reads from the SSL context until a complete message is received.
 * The expected total message length is extracted from a prefix (assumed to be
 * located at the beginning of the message and of size `sizeof(size_t)`).
 *
 * @param ctx    Pointer to the initialized mbedtls_ssl_context.
 * @param buffer Pointer to the buffer where the full message will be stored.
 *               The buffer must be large enough to hold the complete message.
 *
 * @return The total number of bytes received and stored in the buffer,
 *         or a negative value on error.
 */
int receive_message(mbedtls_ssl_context* ctx, uint8_t* buffer);

void export_keys_callback(
    void* p_expkey,
    mbedtls_ssl_key_export_type type,
    const unsigned char* secret,
    size_t secret_len,
    const unsigned char client_random[32],
    const unsigned char server_random[32],
    mbedtls_tls_prf_types tls_prf_type
);

#endif
