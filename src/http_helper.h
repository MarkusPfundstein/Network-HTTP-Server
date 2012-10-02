#ifndef __HTTP_HELPER_H__
#define __HTTP_HELPER_H__

#define RESPONSE_404 ("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\n404\n")

enum RESP_CODE_E {
  RESP_200 = 0,
  RESP_400,
  RESP_404,
  RESP_431
};

extern int http_response(char *buffer, enum RESP_CODE_E code, const char* type, const char *content, int n);

struct http_query_info_s {
  void *data;
  const char* query;
  int length;
};

typedef int (*parse_query_cb)(struct http_query_info_s *, int, int, int, int);

extern int http_parse_query(struct http_query_info_s* info, parse_query_cb cb);

#endif
