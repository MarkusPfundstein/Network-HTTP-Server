#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netinet/in.h>
#include "http_parser.h"
#include "http_query.h"
#include "json_handler.h"
#include "http_query.h"
#include "buffer.h"

static int g_go_on;
static int g_sockfd;

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

typedef struct header_info_state_s {
    char *ident;
    enum HEADER_INFO_STATE state;
} header_info_state_t;

static const header_info_state_t HEADER_STATE_MAP[] = {
    { "Host", HEADER_INFO_STATE_HOST },
    { "User-Agent", HEADER_INFO_STATE_USER_AGENT },
    { "Accept", HEADER_INFO_STATE_ACCEPT },
    { "Content-Type", HEADER_INFO_STATE_CONTENT_TYPE },
    { "Content-Length", HEADER_INFO_STATE_CONTENT_LENGTH },
    { "Expect", HEADER_INFO_STATE_EXPECT }
};

#define CONTENT_TYPE_JSON "application/json"

typedef void (*type_handler_cb_t)(void *);

typedef int (*type_handler_data_cb_t)(void *, const char*, int);

typedef struct header_info_s {
    enum HEADER_INFO_STATE state; /* current state of parsing */
    int method; /* GET/POST whatever */
    /* http header fields */
    char *url;
    char *host;
    char *user_agent;
    char *accept;
    char *content_type;
    char *content_length;
    char *expect;
    query_map_t *query_map_root;
    /* 
     * handler for content_type. for example json parser for application/json 
     * maybe i should pack this in a struct for itself
     */
    void *type_handler;
    /* type handler gets free'd */
    type_handler_cb_t type_handler_free_cb;
    /* new data for type handler */
    /* return 1 to indicate you dont want to go on with receiving data */
    type_handler_data_cb_t type_handler_data_cb;
    /* gets called when type handler is done */
    type_handler_cb_t type_handler_done_cb;
} header_info_t;

static int
json_handler_json_event(void *p, int type, const char *data, uint32_t len)
{
//    fprintf(stderr, "PARSED JSON EVENT: %d\n", type);
    return 0;
}

static char *
header_info_get_field(header_info_t *header, enum HEADER_INFO_STATE state, int *bytes)
{
    char *ptr;
    *bytes = 0;
    ptr = NULL;
    switch(state) {
        /* mostly we can just assign the buffer pointer 
         * to the pointer in the header_info_t.
         * it will get freed at the end of child_main */
        case HEADER_INFO_STATE_HOST:
            ptr = header->host;
            break;
        case HEADER_INFO_STATE_ACCEPT:
            ptr = header->accept;
            break;
        case HEADER_INFO_STATE_CONTENT_TYPE:
            ptr = header->content_type;
            break;
        case HEADER_INFO_STATE_USER_AGENT:
            ptr = header->user_agent;
            break;
        case HEADER_INFO_STATE_CONTENT_LENGTH:
            ptr = header->content_length;
            break;
        case HEADER_INFO_STATE_EXPECT:
            ptr = header->expect;
            break;
        default:
            break;
    }
    if (ptr) {
        *bytes += strlen(ptr);
    }
    return ptr;
}

static int
header_parse_url(http_parser *parser, const char *at, size_t n)
{
    header_info_t *header;
    int question_mark_offset;
    char *query_start;
    int query_len;
    
    header = (header_info_t*)parser->data;
    /* GET */
    if (parser->method == 1) {
        header->method = 1;
    } else if (parser->method == 3) {
        header->method = 3;
    } else {
        fprintf(stderr, "UNSUPPORTED METHOD\n");
        header->method = -1;
        header->state = HEADER_INFO_STATE_ERROR;
        return 1;
    }
    header->url = malloc(n + 1);
    if (!header->url) {
        fprintf(stderr, "couldn't allocate %d bytes\n", n+1);
        header->state = HEADER_INFO_STATE_ERROR;
        return 1;
    }
    strncpy(header->url,
            at,
            n);
    header->url[n] = '\0'; /*never trust a 3rd party lib*/

    question_mark_offset = strcspn(header->url, "?");
    if (question_mark_offset < n + 1) {
        query_start = header->url + question_mark_offset + 1;
        query_len = n - question_mark_offset - 1;
        if (query_len > 0) {
            fprintf(stderr, "query_LENGTH: %d\n", query_len);
            if (query_map_init(&header->query_map_root, query_start, query_len)) {
                fprintf(stderr, "HTTP_PARSE_QUERY ERROR\n");
                header->state = HEADER_INFO_STATE_ERROR;
                return 1;
            }
        }
    }
              
    return 0;
}

static int
header_parse_field(http_parser *parser, const char *at, size_t n)
{
    int i;
    int found;
    header_info_t *header;
    
    header = (header_info_t*)parser->data;
    found = 0;
    for (i = 0;
         i < sizeof(HEADER_STATE_MAP) / sizeof(header_info_state_t); ++i) {
        if (strncmp(HEADER_STATE_MAP[i].ident,
                    at,
                    n) == 0) {
            header->state = HEADER_STATE_MAP[i].state;
            found = 1;
            break;
        }
    }
    if (!found) {
        header->state = HEADER_INFO_STATE_IGNORE_FIELD;
    }

    return 0;
}

static int
header_parse_value(http_parser *parser, const char *at, size_t n)
{
    char *buffer;
    int offset;
    header_info_t *header;
    header = (header_info_t*)parser->data;
    if (header->state == HEADER_INFO_STATE_IGNORE_FIELD) {
        return 0;
    }
    offset = 0;

    /* check if we already have stuff in a certain buffer. if yes we have to realloc memory and place the new stuff after the old one */
    buffer = header_info_get_field(header, header->state, &offset);
    buffer = realloc(buffer, n + offset + 1);
    if (!buffer) {
        fprintf(stderr, "couldn't allocate %d bytes", n+1);
        header->state = HEADER_INFO_STATE_ERROR;
        return 1;
    }
    strncpy(buffer + offset, at, n);
    buffer[offset + n] = '\0';
    switch(header->state) {
        /* we can just assign the buffer pointer 
         * to the pointer in the header_info_t.
         * it will get freed at the end of child_main */
        case HEADER_INFO_STATE_HOST:
            header->host = buffer;
            break;
        case HEADER_INFO_STATE_ACCEPT:
            header->accept = buffer;
            break;
        case HEADER_INFO_STATE_CONTENT_TYPE:
            header->content_type = buffer;
            break;
        case HEADER_INFO_STATE_USER_AGENT:
            header->user_agent = buffer;
            break;
        case HEADER_INFO_STATE_CONTENT_LENGTH:
            header->content_length = buffer;
            break;
        case HEADER_INFO_STATE_EXPECT:
            header->expect = buffer;
            break;
        default:
            /* we dont handle, so lets free */
            free (buffer);
            break;
    }
    return 0;
}

static int
header_parse_body(http_parser *parser, const char *a, size_t n)
{
    header_info_t *header;
    int err;
    err = 0;
    header = (header_info_t*)parser->data;
    if (header->type_handler_data_cb) {
        err = header->type_handler_data_cb(header->type_handler,
                                           a, 
                                           (int)n);
        if (err) {
            header->state = HEADER_INFO_STATE_ERROR;
        }
    }

    return err;
}

static int
header_done(http_parser *parser)
{
    header_info_t *header;
    int content_type_len;
    int content_length;
    header = (header_info_t*)parser->data;
    fprintf(stderr, "*** HEADER DONE ***\n");
    if (header->state == HEADER_INFO_STATE_ERROR) {
        fprintf(stderr, "*** error while parsing header... abort\n");
        return 1;
    }
    /* here we can set our header->user data to the appropriate handler */
    if (header->content_length) {
        content_length = atoi(header->content_length);
    } else {
        content_length = 0;
    }
    if (content_length > 0 && header->content_type) {
        content_type_len = strlen(header->content_type);
        if (content_type_len >= strlen(CONTENT_TYPE_JSON) &&
            strncmp(CONTENT_TYPE_JSON,
                    header->content_type,
                    content_type_len) == 0) {
            
            fprintf(stderr, "l: %d\n", content_length);
            header->type_handler = json_handler_init(content_length, &json_handler_json_event);
            if (!header->type_handler) {
                header->state = HEADER_INFO_STATE_ERROR;
                return 1;
            } else {
                header->type_handler_data_cb = &json_handler_new_data;
                header->type_handler_free_cb = &json_handler_destroy;
                header->type_handler_done_cb = NULL;
            }
        }
    }
    header->state = HEADER_INFO_STATE_BODY;
    return 0;
}

static int
header_message_done(http_parser *parser)
{
    header_info_t *header;
    header = (header_info_t*)parser->data;
    fprintf(stderr, "*** MESSAGE_DONE ***\n");
    if (header->type_handler_done_cb) {
        header->type_handler_done_cb(header->type_handler);
    }
    if (header->state != HEADER_INFO_STATE_ERROR) {
        header->state = HEADER_INFO_STATE_DONE;
    }

    /* reference how to search query map */ 
    query_map_t *res1 = query_map_find(header->query_map_root, "idx");
    query_map_t *res2 = query_map_find(header->query_map_root, "name");
    query_map_t *res3 = query_map_find(header->query_map_root, "address");

    if (res1) {
        fprintf(stderr, "res1: %s - %s\n", res1->key, res1->value);
    }
    if (res2) {
        fprintf(stderr, "res2: %s - %s\n", res2->key, res2->value);
    }
    if (res3) {
        fprintf(stderr, "res3: %s - %s\n", res3->key, res3->value);
    }

    return 0;
}


static int
read_request(int fd, header_info_t *header)
{
    char buffer[4096];
    int bytes_read;
    struct http_parser_settings parser_settings;
    http_parser parser;

    memset(&parser_settings, 
           0,
           sizeof(struct http_parser_settings));

    parser_settings.on_url = &header_parse_url;
    parser_settings.on_header_field = &header_parse_field;
    parser_settings.on_header_value = &header_parse_value;
    parser_settings.on_message_complete = &header_message_done;
    parser_settings.on_headers_complete = &header_done;
    parser_settings.on_body = &header_parse_body;

    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = header;

    do {
        bytes_read = read(fd, buffer, sizeof(buffer));
        if (bytes_read <= 0) {
            if (bytes_read < 0) {
                perror("read_header::read()");
            }
            return 1;
        }

        http_parser_execute(&parser, 
                            &parser_settings, 
                            buffer,
                            bytes_read);

        if (header->state == HEADER_INFO_STATE_DONE ||
            header->state == HEADER_INFO_STATE_ERROR) {
            fprintf(stderr, "WE ARE DONE... BREAK\n");
            break;
        }
    } while (1);

    if (header->state == HEADER_INFO_STATE_ERROR) {
        fprintf(stderr, "OOOOH NOOOOO !!!! A ERROR OCCURED\n");
    }

    return 0;
}

static int 
child_main(int fd)
{
    header_info_t header;
    memset(&header, 0, sizeof(header_info_t));
    read_request(fd, &header);

    /* interpret stuff */
    fprintf(stderr, "\nDONE\n");
    fprintf(stderr, "url: %s\n", header.url);
    fprintf(stderr, "content-length: %s\n", header.content_length);
    fprintf(stderr, "content-type: %s\n", header.content_type);
    fprintf(stderr, "accept: %s\n", header.accept);
    fprintf(stderr, "host: %s\n", header.host);
    fprintf(stderr, "UA: %s\n", header.user_agent);
    fprintf(stderr, "expect: %s\n", header.expect);

    /* echo back shit */

    /* close */
    if (header.url) {
        fprintf(stderr, "*** free header->url\n");
        free(header.url);
    }
    if (header.host) {
        fprintf(stderr, "*** free header->host\n");
        free(header.host);
    }
    if (header.accept) {
        fprintf(stderr, "*** free header->accept\n");
        free(header.accept);
    }
    if (header.content_type) {
        fprintf(stderr, "*** free header->content_type\n");
        free(header.content_type);
    }
    if (header.user_agent) {
        fprintf(stderr, "*** free header->user_agent\n");
        free(header.user_agent);
    }
    if (header.content_length) {
        fprintf(stderr, "*** free header->content_length\n");
        free(header.content_length);
    }
    if (header.expect) {
        fprintf(stderr, "*** free header->expect\n");
        free(header.expect);
    }
    if (header.query_map_root) {
        fprintf(stderr, "*** free header->query_map\n");
        query_map_destroy(header.query_map_root);
    }
    if (header.type_handler_free_cb) {
        fprintf(stderr, "*** call type_handler_free_cb\n");
        header.type_handler_free_cb(header.type_handler);
    } else {
        if (header.type_handler) {
            fprintf(stderr, "*** lazy free header.type_handler\n");
            free(header.type_handler);
        }
    }
    close(fd);
    return 0;
}

static void
handle_sigint(int sig)
{
    fprintf(stderr, "signal %d received\n", sig);
    g_go_on = 0;
    close(g_sockfd);
}

int 
main(int argc, char **argv)
{
    int child_pid;
    int newfd;
    int portno;
    socklen_t socklen;
    struct sockaddr_in serv_addr;
    struct sockaddr_in cli_addr;

    if (argc < 2) {
        fprintf(stderr, "arg 1 has to be port\n");
        return 0;
    }

    signal(SIGCHLD, SIG_IGN);
    signal(SIGINT, handle_sigint);

    g_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_sockfd < 0) {
        perror("socket");
        return 1;
    }
    memset(&serv_addr, 0, sizeof(serv_addr));
    portno = atoi(argv[1]);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);
    if (bind(g_sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind");
        return 1;
    }

    listen(g_sockfd, 5);
    socklen = sizeof(cli_addr);
    g_go_on = 1;
    while (g_go_on) {
        newfd = accept(g_sockfd, (struct sockaddr *)&cli_addr, &socklen);
        if (newfd < 0) {
            perror("accept");
        } else {
            child_pid = fork();
            if (child_pid < 0) {
                perror("fork");
                close(newfd);
            } else if (child_pid == 0) {
                close(g_sockfd);
                exit(child_main(newfd));
            } else {
                close(newfd);
            }
        }
    }
    
    fprintf(stderr, "shutdown\n");

    close(g_sockfd);

    return 0;
}
