#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "json_handler.h"

json_handler_t *
json_handler_init(int content_size, json_handler_new_event_cb_t new_event_cb)
{
    json_handler_t *handler;

    handler = malloc(sizeof(json_handler_t));
    if (!handler) {
        fprintf(stderr, "couldn't allocate memory for json_handler_t\n");
        return NULL;
    }
    memset(handler, 0, sizeof(json_handler_t));
    
    if (json_parser_init(&handler->parser, 
                         NULL, 
                         new_event_cb,
                         handler)) {
        fprintf(stderr, "error json_parser_init\n");
        free(handler);
        return NULL;
    }

    return handler;
}

void
json_handler_destroy(void *p)
{
    json_handler_t *handler;
    handler = p;
    json_parser_free(&handler->parser);
    free(handler);
}

int
json_handler_new_data(void *p, const char *data, int n)
{
    json_handler_t *handler;
    int ret;
    handler = p;
    ret = json_parser_string(&handler->parser, data, n, NULL);
    if (ret) {
        fprintf(stderr, "ERROR PARSING JSON\n");
    }
    return ret;
}
