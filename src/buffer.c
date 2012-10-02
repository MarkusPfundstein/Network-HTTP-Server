#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "buffer.h"

int
buffer_init(buffer_t *buffer, int s)
{
    if (s <= 0) {
        s = 32;
    }
    buffer->data = malloc(s);
    if (!buffer->data) {
        return 1;
    }
    buffer->size = s;
    buffer->len = 0;
    fprintf(stderr, "init buffer of size %d\n", buffer->size);
    return 0;
}

int 
buffer_append(buffer_t *buffer, const char* data, int len)
{
    while (buffer->len + len > buffer->size) {
        buffer->size *= 2;
        buffer->data = realloc(buffer->data, buffer->size);
        if (!buffer->data) {
            return 1;
        }
    }

    strncpy(buffer->data + buffer->len, data, len);
    buffer->len += len;
    return 0;
}

void
buffer_destroy(buffer_t *buffer)
{
    if (buffer->data) {
        fprintf(stderr, "destroy buffer data\n");
        free(buffer->data);
    }
}
