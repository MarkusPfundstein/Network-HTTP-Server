#include "http_helper.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

/* map these with RESP_CODE_E */
const char* _RESPONSES[] = {
  "200 OK",
  "400 Bad Request",
  "404 Not Found",
  "431 Request Header Fields Too Long"
};

int
http_response(char *buffer, enum RESP_CODE_E code, const char* type, const char* content, int length)
{
  char length_buf[10];
  memset(length_buf, 0, sizeof(length_buf));
  sprintf(length_buf, "%d", length);

  strcpy(buffer, "HTTP/1.1 ");
  strcat(buffer, _RESPONSES[code]);
  strcat(buffer, "\r\n"
                 "Connection: close");
  strcat(buffer, "\r\n"
                 "Content-Type: ");
  strcat(buffer, type);
  strcat(buffer, "\r\n"
                 "Content-Length: ");
  strcat(buffer, length_buf);
  strcat(buffer, "\r\n\r\n");
  strncat(buffer, content, length);

  return (int)strlen(buffer);
}

int
http_parse_query(struct http_query_info_s* info, parse_query_cb cb)
{
  assert(info && cb);
  int err = 0;
  int it = 0;
  int q_it = 0;
  int last = 0;
  int q_len = 0;
  int k = 0;
  int k_len = 0;
  int v = 0;
  int v_len = 0;

  do {
    if (it == info->length - 1 || info->query[it + 1] == '&') {
      
      /* parse from last to it */ 
      q_len = it - last;
      for (q_it = last; q_it < last + q_len; q_it++) {
        if (info->query[q_it] == '=') {
          k = last;
          k_len = q_it - last;
          v = q_it + 1;
          v_len = it - q_it;
          if ((err = cb(info, k, k_len, v, v_len)) != 0) {
            goto stop;
          }
        }
      }


      if (info->query[it + 1] == '&') {
        it++;
      }
      /* set reminder to it+1 */
      last = it+1;
    }
    it++;
  } while (it < info->length);

stop:

  return err;
}
