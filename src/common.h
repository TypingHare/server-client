#ifndef COMMON_H
#define COMMON_H

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <stdbool.h>

#define ANSI_YELLOW "\033[33m"
#define ANSI_RESET "\033[0m"

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
bool mbedtls_want_read_or_write(const int result);

/**
 * @brief Extracts the total message length (including prefix) from the given
 * data.
 *
 * Assumes the first sizeof(size_t) bytes represent the big-endian encoded
 * length of the actual message payload. The returned size includes both the
 * prefix and the payload.
 *
 * @param data Pointer to the buffer containing the prefixed data.
 * @return Total size (prefix + payload).
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

#endif
