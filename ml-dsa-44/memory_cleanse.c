#include "memory_cleanse.h"

#if defined(_MSC_VER)
#include <Windows.h> // For SecureZeroMemory
#else
#include <string.h>  // For memset
#endif

void memory_cleanse(void *ptr, size_t len)
{
#if defined(_MSC_VER)
    /* SecureZeroMemory is guaranteed not to be optimized out by MSVC. */
    SecureZeroMemory(ptr, len);
#else
    /* Use memset to fill memory with zero. */
    memset(ptr, 0, len);

    /* Memory barrier to prevent compiler optimizations that may eliminate memset.
     *
     * This is a commonly used trick to prevent Dead Store Elimination (DSE), which could
     * optimize away memset if the memory is not read afterward.
     */
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
}
