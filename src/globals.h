#ifndef __GLOBALS_H__
#define __GLOBALS_H__

#include "module_map.h"
#include "http_query.h"

/*
 * saves all necessary variables from
 * config file
 */

/* xxx.xxx.xxx.xxx. + '\0' */
#define IP_V4_LEN 17

#define MAX_BUF_SIZE 4096

struct config_s {
    /*
     * which port do we listen on
     */
    int listen_port;
    /*
     * which ip do we listen on. 
     */
    char accept_ip_v4[IP_V4_LEN];
    /*
     * n = read(fd, buffer, read_package_size)
     * note: not allowed to be bigger than MAX_BUF_SIZE
     * default: MAX_BUF_SIZE
     */
    int read_package_size;
    /*
     * backlog value for listen().
     * default: 128
     */
    int backlog;

    /*
     * root of modules
     */
    module_t *module_root;
};

enum HEADER_INFO_STATE {
    HEADER_INFO_STATE_IGNORE_FIELD = -2,
    HEADER_INFO_STATE_ERROR = -1,
    HEADER_INFO_STATE_DONE = 0,
    HEADER_INFO_STATE_HOST = 1,
    HEADER_INFO_STATE_USER_AGENT = 2,
    HEADER_INFO_STATE_ACCEPT = 3,
    HEADER_INFO_STATE_CONTENT_TYPE = 4,
    HEADER_INFO_STATE_CONTENT_LENGTH = 5,
    HEADER_INFO_STATE_EXPECT = 6,
    HEADER_INFO_STATE_BODY = 77
};

typedef struct header_info_s {
    enum HEADER_INFO_STATE state; /* current state of parsing */
    int method; /* GET/POST whatever */
    /* http header fields */
    char *url;
    char *base_url;
    char *host;
    char *user_agent;
    char *accept;
    char *content_type;
    char *content_length;
    char *expect;
    /*
     * root of query map
     */
    query_map_t *query_map;
} header_info_t;

/* 
 * defined and filled in main.c
 */
extern struct config_s g_config;

#endif
