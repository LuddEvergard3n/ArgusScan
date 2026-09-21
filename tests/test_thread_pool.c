#include "test.h"

#include "engine/thread_pool.h"

#include <pthread.h>
#include <stddef.h>

typedef struct {
    pthread_mutex_t mutex;
    size_t value;
} Counter;

static void increment_counter(void *context)
{
    Counter *counter = context;

    (void)pthread_mutex_lock(&counter->mutex);
    ++counter->value;
    (void)pthread_mutex_unlock(&counter->mutex);
}

void test_thread_pool(void)
{
    ArgusThreadPool *pool;
    Counter counter;
    size_t index;

    counter.value = 0U;
    ARGUS_CHECK(pthread_mutex_init(&counter.mutex, NULL) == 0);
    pool = argus_thread_pool_create(4U, 8U);
    ARGUS_CHECK(pool != NULL);
    if (pool != NULL) {
        for (index = 0U; index < 1000U; ++index) {
            ARGUS_CHECK(argus_thread_pool_submit(pool, increment_counter, &counter));
        }
        argus_thread_pool_wait(pool);
        ARGUS_CHECK(counter.value == 1000U);
        argus_thread_pool_destroy(pool);
    }
    (void)pthread_mutex_destroy(&counter.mutex);

    ARGUS_CHECK(argus_thread_pool_create(0U, 1U) == NULL);
    ARGUS_CHECK(argus_thread_pool_create(1U, 0U) == NULL);
}

