#ifndef ARGUS_ENGINE_THREAD_POOL_H
#define ARGUS_ENGINE_THREAD_POOL_H

#include <stdbool.h>
#include <stddef.h>

typedef void (*ArgusTaskFunction)(void *context);

typedef struct ArgusThreadPool ArgusThreadPool;

ArgusThreadPool *argus_thread_pool_create(size_t thread_count, size_t queue_capacity);
bool argus_thread_pool_submit(
    ArgusThreadPool *pool,
    ArgusTaskFunction function,
    void *context
);
void argus_thread_pool_wait(ArgusThreadPool *pool);
void argus_thread_pool_destroy(ArgusThreadPool *pool);

#endif

