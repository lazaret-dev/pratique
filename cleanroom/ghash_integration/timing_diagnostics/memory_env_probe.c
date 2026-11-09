#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#if defined(__GLIBC__)
#include <gnu/libc-version.h>
#if __has_include(<sys/platform/x86.h>)
#include <sys/platform/x86.h>
#endif
#endif
#if defined(__x86_64__)
#include <cpuid.h>
#endif

int main(void) {
    unsigned long long xcr0 = 0;
    int xcr0_available = 0;
#if defined(__x86_64__)
    unsigned a, b, c, d;
    __cpuid(1, a, b, c, d);
    if (c & (1u << 27)) {
        unsigned lo, hi;
        __asm__ volatile ("xgetbv" : "=a" (lo), "=d" (hi) : "c" (0));
        xcr0 = ((unsigned long long) hi << 32) | lo;
        xcr0_available = 1;
    }
#endif
    int active_f = -1, active_vl = -1;
#if defined(CPU_FEATURE_ACTIVE)
    active_f = !!CPU_FEATURE_ACTIVE(AVX512F);
    active_vl = !!CPU_FEATURE_ACTIVE(AVX512VL);
#endif
    const char *version = "not-glibc", *release = "unknown";
#if defined(__GLIBC__)
    version = gnu_get_libc_version();
    release = gnu_get_libc_release();
#endif
    printf("{\"glibc_version\":\"%s\",\"glibc_release\":\"%s\",\"xcr0_available\":%d,\"xcr0_hex\":\"%llx\",\"active_AVX512F\":%d,\"active_AVX512VL\":%d,\"memory\":{", version, release, xcr0_available, xcr0, active_f, active_vl);
    const char *names[] = {"memcpy", "memmove", "memset"};
    for (unsigned i = 0; i < 3; ++i) {
        void *address = dlsym(RTLD_DEFAULT, names[i]);
        Dl_info info;
        if (!address || !dladdr(address, &info)) return 2;
        printf("%s\"%s\":{\"library\":\"%s\",\"offset_hex\":\"%lx\"}", i ? "," : "", names[i], info.dli_fname, (unsigned long)((uintptr_t)address - (uintptr_t)info.dli_fbase));
    }
    printf("}}\n");
    return 0;
}
