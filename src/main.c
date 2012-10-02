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
#include "http_helper.h"

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

typedef struct header_info_s {
    enum HEADER_INFO_STATE state; /* current state of parsing */
    int method;
    char *url;
    char *host;
    char *user_agent;
    char *accept;
    char *content_type;
    char *content_length;
    char *expect;
} header_info_t;

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
    header_info_t *header = (header_info_t*)parser->data;
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
              
    return 0;
}

static int
header_parse_field(http_parser *parser, const char *at, size_t n)
{
    char dbg_buffer[4096];
    strncpy(dbg_buffer, at, n);
    dbg_buffer[n] = '\0';
    fprintf(stderr, "+++ FIELD +++\n%s\n", dbg_buffer);
    int i;
    int found;
    header_info_t *header = (header_info_t*)parser->data;
    
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
    char buffer[4096];
    strncpy(buffer, a, n);
    buffer[n] = '\0';
    fprintf(stderr, "%s\n", buffer);
    return 0;
}

static int
header_done(http_parser *parser)
{
    header_info_t *header = (header_info_t*)parser->data;
    fprintf(stderr, "*** HEADER DONE ***\n");
    if (header->state == HEADER_INFO_STATE_ERROR) {
        fprintf(stderr, "*** error while parsing header... abort\n");
        return 1;
    }
    header->state = HEADER_INFO_STATE_BODY;
    return 0;
}

static int
message_done(http_parser *parser)
{
    header_info_t *header = (header_info_t*)parser->data;
    fprintf(stderr, "*** MESSAGE_DONE ***\n");
    if (header->state != HEADER_INFO_STATE_ERROR) {
        header->state = HEADER_INFO_STATE_DONE;
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
    parser_settings.on_message_complete = &message_done;
    parser_settings.on_headers_complete = &header_done;
    parser_settings.on_body = &header_parse_body;

    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = header;

    do {
        memset(buffer, 0, sizeof(buffer));
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
