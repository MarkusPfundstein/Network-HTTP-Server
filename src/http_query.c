#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#define __USE_GNU 1
#include <search.h>
#include "http_query.h"

static int
http_query_cmp_func(const void *l, const void *r)
{
    const query_map_t *ml = (query_map_t*)l;
    const query_map_t *mr = (query_map_t*)r;
    return strcmp(ml->key, mr->key);
}

static void
http_query_map_free(void *p)
{
    query_map_t *map;
    if (!p) {
        return;
    }
    map = p;
    if (map->key) {
        free(map->key);
    }
    if (map->value) {
        free(map->value);
    }
    free(map);
}

static query_map_t*
http_query_map_alloc(const char *key, int key_len, const char *value, int val_len)
{
    query_map_t *map;
    /* mandatory */
    assert(key);

    map = malloc(sizeof(query_map_t));
    if (!map) {
        return NULL;
    }
    memset(map, 0, sizeof(query_map_t));

    /*
     * should probably use strndup here
     */

    map->key = malloc(key_len + 1);
    if (!map->key) {
        free(map);
        return NULL;
    }
    strncpy(map->key, key, key_len);
    map->key[key_len] = '\0';

    /* optional */
    if (value && val_len > 0) {
        map->value = malloc(val_len + 1);
        if (!map->value) {
            free(map);
            free(map->key);
            return NULL;
        }
        strncpy(map->value, value, val_len);
        map->value[val_len] = '\0';
    }

    return map;
}

void
query_map_destroy(query_map_t *map_root)
{
    tdestroy(map_root, http_query_map_free);
}

query_map_t* 
query_map_find(query_map_t *root, const char *key)
{
    query_map_t *predicate;
    query_map_t **res;
    predicate = http_query_map_alloc(key, strlen(key), NULL, 0);
    res = tfind(predicate, (void**)&root, http_query_cmp_func);
    http_query_map_free(predicate);
    return res ? *res : NULL;
}

int
query_map_init(query_map_t **map_root, const char* query, int len)
{
    int it, q_it, last;
    query_map_t *current_map;
    it = 0;
    q_it = 0;
    last = 0;

    do {
        if (it == len - 1 || query[it + 1] == '&') {
            /* parse from last to it */ 
            for (q_it = last; q_it < it; q_it++) {
                if (query[q_it] == '=') {
                    /* here we have a key and a value */
                    current_map = http_query_map_alloc(query + last, q_it - last, query + q_it + 1, it - q_it);
                    if (!current_map) {
                        fprintf(stderr, "error malloc current_map\n");
                        return 1;
                    }
                    if (tsearch((void *)current_map, (void**)map_root, http_query_cmp_func) == NULL) {
                        perror("tsearch");
                        return 1;
                    }
                }
            }

            if (query[it + 1] == '&') {
                it++;
            }
            /* set reminder to it+1 */
            last = it+1;
        }
        it++;
    } while (it < len);

    return 0;
}



