#ifndef __BUFFER_H__
#define __BUFFER_H__

typedef struct buffer_s {
    int len;
    int size;
    char *data;
} buffer_t;

extern int buffer_init(buffer_t *buffer, int s);
extern void buffer_destroy(buffer_t *buffer);
extern int buffer_append(buffer_t *buffer, const char *data, int len);

#endif
