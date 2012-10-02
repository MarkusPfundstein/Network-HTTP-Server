#ifndef __JSON_HANDLER_H__
#define __JSON_HANDLER_H__

#include <json.h>

typedef struct json_handler_s {
    json_parser parser;
} json_handler_t;

typedef int (*json_handler_new_event_cb_t)(void *, int, const char*, uint32_t);

extern json_handler_t*
json_handler_init(int content_size, json_handler_new_event_cb_t new_event_cb);

extern void
json_handler_destroy(void *p);

extern int
json_handler_new_data(void *p, const char *data, int n);



#endif
