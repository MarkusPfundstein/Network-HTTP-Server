#ifndef __HTTP_QUERY_H__
#define __HTTP_QUERY_H__

typedef struct query_map_s {
    char *key;
    char *value;
} query_map_t;

/* parses a query and creates a binary tree 
 * if successful, map_root will point to the head of the tree
 * tree must be destroyed using http_query_destroy 
 */
extern int http_query_parse(query_map_t **map_root, const char *query, int len);

/* destroys the data obtained from http_query_parse */
void http_query_destroy(query_map_t *map_root);

/*
 * searches tree for a certain element
 * returns NULL if element is not there
 */

query_map_t *http_query_find(query_map_t *root, const char *key);

#endif
