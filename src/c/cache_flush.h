#ifndef CACHE_FLUSH_H
#define CACHE_FLUSH_H

#include <stdint.h>
#include <stddef.h>

#if defined(__x86_64__) || defined(_M_X64)
    #define HAS_CLWB 1
    #define HAS_CLFLUSHOPT 1
    #define HAS_SFENCE 1
    #define HAS_CLFLUSH 1

    static inline void _clwb(volatile void *addr) {
        __asm__ __volatile__("clwb %0" : : "m"(*(char *)addr) : "memory");
    }

    static inline void _clflushopt(volatile void *addr) {
        __asm__ __volatile__("clflushopt %0" : : "m"(*(char *)addr) : "memory");
    }

    static inline void _clflush(volatile void *addr) {
        __asm__ __volatile__("clflush %0" : : "m"(*(char *)addr) : "memory");
    }

    static inline void _sfence(void) {
        __asm__ __volatile__("sfence" : : : "memory");
    }

    static inline void _mfence(void) {
        __asm__ __volatile__("mfence" : : : "memory");
    }

    static inline void _lfence(void) {
        __asm__ __volatile__("lfence" : : : "memory");
    }

    static inline void cache_flush(void *addr, size_t len) {
        uintptr_t start = (uintptr_t)addr & ~63ULL;
        uintptr_t end = ((uintptr_t)addr + len + 63) & ~63ULL;
        
        for (uintptr_t p = start; p < end; p += 64) {
            _clwb((void *)p);
        }
        _sfence();
    }

    static inline void cache_flush_opt(void *addr, size_t len) {
        uintptr_t start = (uintptr_t)addr & ~63ULL;
        uintptr_t end = ((uintptr_t)addr + len + 63) & ~63ULL;
        
        for (uintptr_t p = start; p < end; p += 64) {
            _clflushopt((void *)p);
        }
        _sfence();
    }

    static inline void cache_flush_legacy(void *addr, size_t len) {
        uintptr_t start = (uintptr_t)addr & ~63ULL;
        uintptr_t end = ((uintptr_t)addr + len + 63) & ~63ULL;
        
        for (uintptr_t p = start; p < end; p += 64) {
            _clflush((void *)p);
        }
        _mfence();
    }

#elif defined(__aarch64__)
    static inline void cache_flush(void *addr, size_t len) {
        __asm__ __volatile__(
            "dc cvac, %0\n"
            "dsb sy\n"
            "isb\n"
            : : "r"(addr) : "memory"
        );
    }

    static inline void _sfence(void) {
        __asm__ __volatile__("dsb sy\nisb" : : : "memory");
    }

    static inline void _mfence(void) {
        __asm__ __volatile__("dmb sy" : : : "memory");
    }

#else
    static inline void cache_flush(void *addr, size_t len) {
        (void)addr;
        (void)len;
    }

    static inline void _sfence(void) {
        __asm__ __volatile__("" : : : "memory");
    }

    static inline void _mfence(void) {
        __asm__ __volatile__("" : : : "memory");
    }
#endif

#if defined(__linux__)
    #include <sys/mman.h>
    #include <unistd.h>
    #include <fcntl.h>

    static inline int persistent_sync(int fd) {
        return fdatasync(fd);
    }

    static inline int persistent_sync_full(int fd) {
        return fsync(fd);
    }

    static inline void *map_persistent(int fd, size_t size) {
        return mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    }

    static inline int unmap_persistent(void *addr, size_t size) {
        return munmap(addr, size);
    }

    static inline int persistent_msync(void *addr, size_t len) {
        return msync(addr, len, MS_SYNC);
    }

    static inline int persistent_msync_async(void *addr, size_t len) {
        return msync(addr, len, MS_ASYNC);
    }

    static inline int persistent_msync_invalidate(void *addr, size_t len) {
        return msync(addr, len, MS_SYNC | MS_INVALIDATE);
    }

#elif defined(__APPLE__)
    #include <sys/mman.h>
    #include <unistd.h>

    static inline int persistent_sync(int fd) {
        return fcntl(fd, F_FULLFSYNC);
    }

    static inline int persistent_sync_full(int fd) {
        return fcntl(fd, F_FULLFSYNC);
    }

    static inline void *map_persistent(int fd, size_t size) {
        return mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    }

    static inline int unmap_persistent(void *addr, size_t size) {
        return munmap(addr, size);
    }

    static inline int persistent_msync(void *addr, size_t len) {
        return msync(addr, len, MS_SYNC);
    }

#elif defined(_WIN32)
    #include <windows.h>

    static inline int persistent_sync(HANDLE hFile) {
        return FlushFileBuffers(hFile) ? 0 : -1;
    }

    static inline void *map_persistent(HANDLE hFile, size_t size) {
        HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, (DWORD)size, NULL);
        if (hMap == NULL) return NULL;
        void *addr = MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, size);
        CloseHandle(hMap);
        return addr;
    }

    static inline int unmap_persistent(void *addr, size_t size) {
        (void)size;
        return UnmapViewOfFile(addr) ? 0 : -1;
    }

    static inline int persistent_msync(void *addr, size_t len) {
        (void)len;
        return FlushViewOfFile(addr, 0) ? 0 : -1;
    }

    static inline void cache_flush(void *addr, size_t len) {
        (void)addr;
        (void)len;
        FlushViewOfFile(addr, len);
    }

    static inline void _sfence(void) {
        MemoryBarrier();
    }

    static inline void _mfence(void) {
        MemoryBarrier();
    }
#endif

static inline void flush_range(void *addr, size_t len) {
    if (addr == NULL || len == 0) return;
    
#if HAS_CLWB
    cache_flush(addr, len);
#elif HAS_CLFLUSHOPT
    cache_flush_opt(addr, len);
#elif HAS_CLFLUSH
    cache_flush_legacy(addr, len);
#else
    _sfence();
#endif
}

static inline void flush_and_fence(void *addr, size_t len) {
    flush_range(addr, len);
    _sfence();
}

static inline void store_release(volatile uint64_t *addr, uint64_t val) {
    _sfence();
    *addr = val;
    _sfence();
}

static inline uint64_t load_acquire(volatile uint64_t *addr) {
    uint64_t val = *addr;
    _sfence();
    return val;
}

typedef struct {
    void *addr;
    size_t len;
    uint32_t checksum;
} flush_record_t;

typedef struct {
    flush_record_t *records;
    size_t count;
    size_t capacity;
} flush_batch_t;

static inline void flush_batch_init(flush_batch_t *batch, size_t capacity) {
    batch->records = (flush_record_t *)malloc(capacity * sizeof(flush_record_t));
    batch->count = 0;
    batch->capacity = capacity;
}

static inline void flush_batch_add(flush_batch_t *batch, void *addr, size_t len, uint32_t checksum) {
    if (batch->count >= batch->capacity) return;
    batch->records[batch->count].addr = addr;
    batch->records[batch->count].len = len;
    batch->records[batch->count].checksum = checksum;
    batch->count++;
}

static inline void flush_batch_execute(flush_batch_t *batch) {
    for (size_t i = 0; i < batch->count; i++) {
        flush_range(batch->records[i].addr, batch->records[i].len);
    }
    _sfence();
    batch->count = 0;
}

static inline void flush_batch_deinit(flush_batch_t *batch) {
    free(batch->records);
    batch->records = NULL;
    batch->count = 0;
    batch->capacity = 0;
}

#endif
