#ifndef MEMORY_CLEANSE_H
#define MEMORY_CLEANSE_H

#include <stddef.h> // For size_t

/**
 * Securely overwrite a buffer (possibly containing sensitive data) with zero-bytes.
 * The compiler is prevented from optimizing out the memset operation.
 *
 * @param ptr Pointer to the buffer to be cleansed.
 * @param len Length of the buffer in bytes.
 */
void memory_cleanse(void *ptr, size_t len);

#endif // MEMORY_CLEANSE_H
