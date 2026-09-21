#include "engine/thread_pool.h"

#include <pthread.h>
#include <stdlib.h>

typedef struct {
    ArgusTaskFunction function;
    void *context;
} ArgusTask;

struct ArgusThreadPool {
    pthread_t *threads;
    size_t thread_count;
    ArgusTask *queue;
    size_t queue_capacity;
    size_t queue_head;
    size_t queue_tail;
    size_t queue_count;
    size_t active_count;
    bool shutting_down;
    pthread_mutex_t mutex;
    pthread_cond_t has_work;
    pthread_cond_t has_space;
    pthread_cond_t idle;
};

static void *worker_main(void *context)
{
    ArgusThreadPool *pool = context;

    for (;;) {
        ArgusTask task;

        (void)pthread_mutex_lock(&pool->mutex);
        while (pool->queue_count == 0U && !pool->shutting_down) {
            (void)pthread_cond_wait(&pool->has_work, &pool->mutex);
        }

        if (pool->queue_count == 0U && pool->shutting_down) {
            (void)pthread_mutex_unlock(&pool->mutex);
            return NULL;
        }

        task = pool->queue[pool->queue_head];
        pool->queue_head = (pool->queue_head + 1U) % pool->queue_capacity;
        --pool->queue_count;
        ++pool->active_count;
        (void)pthread_cond_signal(&pool->has_space);
        (void)pthread_mutex_unlock(&pool->mutex);

        task.function(task.context);

        (void)pthread_mutex_lock(&pool->mutex);
        --pool->active_count;
        if (pool->queue_count == 0U && pool->active_count == 0U) {
            (void)pthread_cond_broadcast(&pool->idle);
        }
        (void)pthread_mutex_unlock(&pool->mutex);
    }
}

static void destroy_sync(ArgusThreadPool *pool)
{
    (void)pthread_cond_destroy(&pool->idle);
    (void)pthread_cond_destroy(&pool->has_space);
    (void)pthread_cond_destroy(&pool->has_work);
    (void)pthread_mutex_destroy(&pool->mutex);
}

ArgusThreadPool *argus_thread_pool_create(size_t thread_count, size_t queue_capacity)
{
    ArgusThreadPool *pool;
    size_t created = 0U;

    if (thread_count == 0U || queue_capacity == 0U) {
        return NULL;
    }

    pool = calloc(1U, sizeof(*pool));
    if (pool == NULL) {
        return NULL;
    }

    pool->threads = calloc(thread_count, sizeof(*pool->threads));
    pool->queue = calloc(queue_capacity, sizeof(*pool->queue));
    if (pool->threads == NULL || pool->queue == NULL) {
        free(pool->queue);
        free(pool->threads);
        free(pool);
        return NULL;
    }

    pool->thread_count = thread_count;
    pool->queue_capacity = queue_capacity;
    if (pthread_mutex_init(&pool->mutex, NULL) != 0 ||
        pthread_cond_init(&pool->has_work, NULL) != 0 ||
        pthread_cond_init(&pool->has_space, NULL) != 0 ||
        pthread_cond_init(&pool->idle, NULL) != 0) {
        free(pool->queue);
        free(pool->threads);
        free(pool);
        return NULL;
    }

    for (created = 0U; created < thread_count; ++created) {
        if (pthread_create(&pool->threads[created], NULL, worker_main, pool) != 0) {
            size_t index;

            (void)pthread_mutex_lock(&pool->mutex);
            pool->shutting_down = true;
            (void)pthread_cond_broadcast(&pool->has_work);
            (void)pthread_mutex_unlock(&pool->mutex);
            for (index = 0U; index < created; ++index) {
                (void)pthread_join(pool->threads[index], NULL);
            }
            destroy_sync(pool);
            free(pool->queue);
            free(pool->threads);
            free(pool);
            return NULL;
        }
    }

    return pool;
}

bool argus_thread_pool_submit(
    ArgusThreadPool *pool,
    ArgusTaskFunction function,
    void *context
)
{
    if (pool == NULL || function == NULL) {
        return false;
    }

    (void)pthread_mutex_lock(&pool->mutex);
    while (pool->queue_count == pool->queue_capacity && !pool->shutting_down) {
        (void)pthread_cond_wait(&pool->has_space, &pool->mutex);
    }

    if (pool->shutting_down) {
        (void)pthread_mutex_unlock(&pool->mutex);
        return false;
    }

    pool->queue[pool->queue_tail].function = function;
    pool->queue[pool->queue_tail].context = context;
    pool->queue_tail = (pool->queue_tail + 1U) % pool->queue_capacity;
    ++pool->queue_count;
    (void)pthread_cond_signal(&pool->has_work);
    (void)pthread_mutex_unlock(&pool->mutex);
    return true;
}

void argus_thread_pool_wait(ArgusThreadPool *pool)
{
    if (pool == NULL) {
        return;
    }

    (void)pthread_mutex_lock(&pool->mutex);
    while (pool->queue_count != 0U || pool->active_count != 0U) {
        (void)pthread_cond_wait(&pool->idle, &pool->mutex);
    }
    (void)pthread_mutex_unlock(&pool->mutex);
}

void argus_thread_pool_destroy(ArgusThreadPool *pool)
{
    size_t index;

    if (pool == NULL) {
        return;
    }

    argus_thread_pool_wait(pool);
    (void)pthread_mutex_lock(&pool->mutex);
    pool->shutting_down = true;
    (void)pthread_cond_broadcast(&pool->has_work);
    (void)pthread_mutex_unlock(&pool->mutex);

    for (index = 0U; index < pool->thread_count; ++index) {
        (void)pthread_join(pool->threads[index], NULL);
    }

    destroy_sync(pool);
    free(pool->queue);
    free(pool->threads);
    free(pool);
}

