#ifndef __HTTP_QUERY_H__
#define __HTTP_QUERY_H__

typedef struct query_map_s {
    char *key;
    char *value;
} query_map_t;

extern int http_query_parse(query_map_t **map_root, const char *query, int len);

void http_query_destroy(query_map_t *map_root);

#endif
