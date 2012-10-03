#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#define __USE_GNU 1
#include <search.h>
#include <time.h>
#include <libconfig.h>
#include "module_map.h"
#include "globals.h"
#include "http_parser.h"
#include "http_query.h"
#include "http_query.h"
#include "buffer.h"
#include "list.h"

static int g_go_on;
static int g_sockfd;

typedef struct connection_s {
    int fd;
    struct http_parser_settings parser_settings;
    http_parser parser;
    header_info_t header;
} connection_t; 

static connection_t *g_connection_root;

static int g_highsock;

struct config_s g_config;

fd_set g_read_master;
fd_set g_read_set;

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

static int
make_socket_nonblock(int fd)
{
    int x;
    x = fcntl(fd, F_GETFL, 0);
    if (x < 0) {
        return x;
    }
    return fcntl(fd, F_SETFL, x | O_NONBLOCK);
}

static module_t *
get_mod_for_url(const char *url)
{
    /* should cache that */

    char *file_ext;
    module_t *mod;
    mod = NULL;
    if (url) {
        file_ext = strrchr(url, '.');
        if (file_ext) {
            mod = module_map_find_ident(g_config.module_root, file_ext + 1);
            if (!mod) {
                /* check for wild card mod */
                mod = module_map_find_ident(g_config.module_root, "*");
            }
        }
    }
    return mod;
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
    header->base_url = malloc(question_mark_offset + 1);
    if (!header->base_url) {
        fprintf(stderr, "header->base_url malloc failed\n");
        header->state = HEADER_INFO_STATE_ERROR;
        return 1;
    }
    strncpy(header->base_url, header->url, question_mark_offset);
    header->base_url[question_mark_offset] = '\0';
    if (question_mark_offset < n + 1) {
        query_start = header->url + question_mark_offset + 1;
        query_len = n - question_mark_offset - 1;
        if (query_len > 0) {
            if (query_map_init(&header->query_map, query_start, query_len)) {
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
header_done(http_parser *parser)
{
    header_info_t *header;
    header = (header_info_t*)parser->data;
    if (header->state == HEADER_INFO_STATE_ERROR) {
        fprintf(stderr, "*** error while parsing header... abort\n");
        return 1;
    }
    
    header->mod = get_mod_for_url(header->base_url);
    if (header->mod) {
        if (module_call_func(header->mod, "MOD_on_headers_done", &g_config, header)) {
            header->state = HEADER_INFO_STATE_ERROR;
            return 1;
        }
    }
   
    header->state = HEADER_INFO_STATE_BODY;
    return 0;
}

static int
header_parse_body(http_parser *parser, const char *a, size_t n)
{
    header_info_t *header;
    int err;
    err = 0;
    header = (header_info_t*)parser->data;

    if (header->mod) {
        if (module_call_data_func(header->mod, "MOD_on_body", &g_config, header, a, n)) {
            header->state = HEADER_INFO_STATE_ERROR;
            return 1;
        }
    }

    return err;
}

static int
header_message_done(http_parser *parser)
{
    header_info_t *header;
    header = (header_info_t*)parser->data;
    
    if (header->state != HEADER_INFO_STATE_ERROR) {
        header->state = HEADER_INFO_STATE_DONE;
    }

    if (header->mod) {
        if (module_call_func(header->mod, "MOD_on_message_done", &g_config, header)) {
            header->state = HEADER_INFO_STATE_ERROR;
            return 1;
        }
    }

    return 0;
}

static void 
request_done(connection_t *con)
{
    /* interpret stuff */
    fprintf(stderr, "\nDONE\n");
    fprintf(stderr, "url: %s\n", con->header.url);
    fprintf(stderr, "content-length: %s\n", con->header.content_length);
    fprintf(stderr, "content-type: %s\n", con->header.content_type);
    fprintf(stderr, "accept: %s\n", con->header.accept);
    fprintf(stderr, "host: %s\n", con->header.host);
    fprintf(stderr, "UA: %s\n", con->header.user_agent);
    fprintf(stderr, "expect: %s\n", con->header.expect);
    /* echo back shit */

    /* close */
    if (con->header.url) {
        free(con->header.url);
    }
    if (con->header.base_url) {
        free(con->header.base_url);
    }
    if (con->header.host) {
        free(con->header.host);
    }
    if (con->header.accept) {
        free(con->header.accept);
    }
    if (con->header.content_type) {
        free(con->header.content_type);
    }
    if (con->header.user_agent) {
        free(con->header.user_agent);
    }
    if (con->header.content_length) {
        free(con->header.content_length);
    }
    if (con->header.expect) {
        free(con->header.expect);
    }
    if (con->header.query_map) {
        query_map_destroy(con->header.query_map);
    }
}

static int
read_request(connection_t *con)
{
    char buffer[MAX_BUF_SIZE];
    int bytes_read;

    bytes_read = read(con->header.fd, buffer, g_config.read_package_size);
    if (bytes_read <= 0) {
        if (bytes_read < 0) {
            if (errno == EAGAIN) {
                fprintf(stderr, "EAGAIN\n");
                return 0;
            }
            perror("read_header::read()");
        }
        return 1;
    }

    http_parser_execute(&con->parser, 
                        &con->parser_settings, 
                        buffer,
                        bytes_read);

    if (con->header.state == HEADER_INFO_STATE_DONE ||
        con->header.state == HEADER_INFO_STATE_ERROR) {
        return 1;
    }

    if (con->header.state == HEADER_INFO_STATE_ERROR) {
        fprintf(stderr, "OOOOH NOOOOO !!!! A ERROR OCCURED\n");
    }

    return 0;
}

static void
handle_sigint(int sig)
{
    fprintf(stderr, "signal %d received\n", sig);
    g_go_on = 0;
    close(g_sockfd);
}

static int
load_mods(config_t *config, config_setting_t *setting)
{
    int err;
    unsigned int mod_count;
    int i;
    const char* mod_name;
    const char* mod_so;
    const char* mod_ident;
    config_setting_t *mod_setting;
    err = 0;

    fprintf(stderr, "load mods from config\n");
    setting = config_lookup(config, "mods");
    if (setting != NULL) {
        mod_count = config_setting_length(setting);
        for (i = 0; i < mod_count; ++i) {
            mod_setting = config_setting_get_elem(setting, i);
            if (mod_setting) {
                if (!config_setting_lookup_string(mod_setting,
                                                  "name",
                                                  &mod_name) ||
                    !config_setting_lookup_string(mod_setting,
                                                  "so",
                                                  &mod_so)) {
                    continue;
                }
                if (!config_setting_lookup_string(mod_setting,
                                                  "ident",
                                                  &mod_ident)) {
                    mod_ident = NULL;
                }
                fprintf(stderr, "load module %s - %s - [%s]\n", 
                        mod_name, mod_so, mod_ident);
                module_t *mod = module_open(mod_name,
                                            mod_ident,
                                            mod_so,
                                            RTLD_NOW);
                if (!mod) {
                    err = 1;
                    break;
                }
                if (module_map_insert(&g_config.module_root, mod) == NULL) {
                    err = 1;
                    module_close(mod);
                    break;
                }
                if (module_call_init_func(mod, &g_config)) {
                    fprintf(stderr, "ERROR %s returned not 0\n", mod->name);
                    err = 1;
                    module_close(mod);
                    break;
                }
            }
        }
    }

    return err;
}

static void
clean_config_file()
{
    if (g_config.base_path) {
        free(g_config.base_path);
    }
}

static int
parse_config_file(const char *path)
{
    int err;
    long int int_val; 
    const char *string_val;
    int string_val_len;
    config_t config;
    config_setting_t *setting;
    memset(&g_config, 0, sizeof(struct config_s));
    err = 0;
    config_init(&config);
    fprintf(stderr, "read config: %s\n", path);
    if (config_read_file(&config,
                         path) == CONFIG_FALSE) {
        fprintf(stderr, "config_read_file(): %s - %d - %s\n", path, config_error_line(&config), config_error_text(&config));
        err = 1;
        goto error;
    }

    setting = config_lookup(&config, "server");
    if (setting != NULL) {
        if (!config_setting_lookup_int(setting, 
                                       "listen_port", 
                                       &int_val)) {
            fprintf(stderr, "ERROR ... no listen port in config file %s\n",
                    path);
            err = 1;
            goto error;
        }
        if (int_val > 65535) {
            fprintf(stderr, "ERROR ... port has to be smaller 65535\n");
            err = 1;
            goto error;
        }
        g_config.listen_port = (int)int_val;
        if (!config_setting_lookup_string(setting,
                                          "accept_ip",
                                          &string_val)) {
            fprintf(stderr, "ERROR ... no accept_ip in config file %s\n",
                    path);
            err = 1;
            goto error;
        }
        string_val_len = strlen(string_val);
        /* check if supplied argument is max of 16 */
        if (string_val_len > IP_V4_LEN - 1) {
            fprintf(stderr, "ERROR ... accept_ip too long\n");
            err = 1;
            goto error;
        }
        memset(g_config.accept_ip_v4, 0, IP_V4_LEN);
        memcpy(g_config.accept_ip_v4, string_val, string_val_len);
        if (!config_setting_lookup_int(setting,
                                       "read_package_size",
                                       &int_val)) {
            int_val = MAX_BUF_SIZE;            
        }
        if (int_val > MAX_BUF_SIZE) {
            fprintf(stderr, "WARNING ... read_package_size given bigger than MAX_BUF_SIZE (%d)\n", MAX_BUF_SIZE);
            int_val = MAX_BUF_SIZE;
        } else if (int_val < 100) {
            fprintf(stderr, "WARNING ... read_package_size to small.\n");
            int_val = 100;
        }
        
        g_config.read_package_size = int_val;

        if (!config_setting_lookup_int(setting,
                                       "backlog",
                                       &int_val)) {
            int_val = 128;
        }

        g_config.backlog = int_val;

        if (!config_setting_lookup_string(setting,
                                          "base_path",
                                          &string_val)) {
            fprintf(stderr, "ERROR ... no base path specified\n");
            err = 1;
            goto error;
        }
        g_config.base_path = strdup(string_val);
    }
    

    fprintf(stderr, "listen_port: %d\n", g_config.listen_port); 
    fprintf(stderr, "accept_ip: %s\n", g_config.accept_ip_v4);
    fprintf(stderr, "read_package_size: %d\n", g_config.read_package_size);
    fprintf(stderr, "backlog: %d\n", g_config.backlog);
    fprintf(stderr, "base_path: %s\n", g_config.base_path);

    err = load_mods(&config, setting);

error:
    config_destroy(&config);
    return err;
}

static int
connection_cmp_func(const void *l, const void *r)
{
    connection_t *cl;
    connection_t *cr;
    cl = (connection_t*)l;
    cr = (connection_t*)r;
    if (cl->fd > cr->fd) {
        return -1;
    } else if (cl->fd < cr->fd ) {
        return 1;
    }
    return 0;
}

static connection_t*
connection_make(int fd)
{
    connection_t *con;
    con = malloc(sizeof(connection_t));
    if (!con) {
        fprintf(stderr, "error allocating memory for connection\n");
        return NULL;
    }
    memset(con, 0, sizeof(connection_t));
    con->fd = fd;

    if (tsearch((void*)con, 
                (void**)&g_connection_root,
                connection_cmp_func) == NULL) {
        fprintf(stderr, "error inserting new connection in tree\n");
        free(con);
        return NULL;
    }

    con->parser_settings.on_url = &header_parse_url;
    con->parser_settings.on_header_field = &header_parse_field;
    con->parser_settings.on_header_value = &header_parse_value;
    con->parser_settings.on_message_complete = &header_message_done;
    con->parser_settings.on_headers_complete = &header_done;
    con->parser_settings.on_body = &header_parse_body;

    http_parser_init(&con->parser, HTTP_REQUEST);
    con->parser.data = &con->header;

    con->header.fd = fd;
    make_socket_nonblock(fd);

    FD_SET(fd, &g_read_master);
    return con;
}

static void
connection_delete(void *p)
{
    connection_t *con;
    if (!p) {
        return;
    }
    con = p;
    fprintf(stderr, "delete connection: %d\n", con->fd);
    if (FD_ISSET(con->fd, &g_read_master)) {
        FD_CLR(con->fd, &g_read_master);
    }
    if (tdelete((void*)con, (void**)&g_connection_root, connection_cmp_func) == NULL) {
        fprintf(stderr, "ERROR *** deleting connection from tree\n");
    }
    free(con);
}

static void
connection_handle_socket_ready(const void *p, const VISIT which, const int depth)
{
    connection_t *con;
    con = *(connection_t**)p;
    if (which != 1) {
        return;
    }
    fprintf(stderr, "twalk %d - %d\n", con->fd, which);
    if (FD_ISSET(con->fd, &g_read_master)) {
        fprintf(stderr, "read %d\n", con->fd);
        if (read_request(con)) {
            request_done(con);
            close(con->fd);
            connection_delete(con);
        }
    }
}

int 
main(int argc, char **argv)
{
    int newfd;
    int fd_ready;
    int ret;
    socklen_t socklen;
    struct sockaddr_in serv_addr;
    struct sockaddr_in cli_addr;
    struct timeval timeout;
    connection_t *new_connection;

    g_sockfd = -1;

    if (parse_config_file("bone_http_serv.conf")) {
        ret = 1;
        goto error;
    }

    signal(SIGCHLD, SIG_IGN);
    signal(SIGINT, handle_sigint);

    g_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_sockfd < 0) {
        perror("socket");
        ret = 1;
        goto error;
    }
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    if (inet_aton(g_config.accept_ip_v4, &serv_addr.sin_addr) == 0) {
        perror("inet_aton");
        ret = 1;
        goto error;
    }
    fprintf(stderr, "ip %s\n", inet_ntoa(serv_addr.sin_addr));
    serv_addr.sin_port = htons(g_config.listen_port);
    if (bind(g_sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind");
        ret = 1;
        goto error;
    }

    if (listen(g_sockfd, g_config.backlog) < 0) {
        perror("listen");
        ret = 1;
        goto error;
    }
    socklen = sizeof(cli_addr);
    g_go_on = 1;
    g_connection_root = NULL;
    FD_ZERO(&g_read_master);
    FD_SET(g_sockfd, &g_read_master);
    make_socket_nonblock(g_sockfd);
    while (g_go_on) {
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        g_read_set = g_read_master;
        fd_ready = select(1024, &g_read_set, NULL, NULL, &timeout);
        if (fd_ready < 0) {
            perror("select");
            g_go_on = 0;
        } else if (fd_ready > 0) {
            if (FD_ISSET(g_sockfd, &g_read_set)) {
                newfd = accept(g_sockfd, (struct sockaddr *)&cli_addr, &socklen);
                if (newfd < 0) {
                    perror("accept");
                } else {
                    new_connection = connection_make(newfd);
                    if (!new_connection) {
                        continue;
                    }
                    
                    fprintf(stderr, "new con :%d\n", new_connection->fd);
                }
            }
            if (g_connection_root) {
                twalk(g_connection_root, connection_handle_socket_ready);
            }
        }
    }
    ret = 0;

    if (g_connection_root) {
        tdestroy(g_connection_root, connection_delete);
    }
    
error:
    fprintf(stderr, "shutdown\n");

    module_map_destroy(g_config.module_root);
    clean_config_file();
    if (g_sockfd != -1) {
        close(g_sockfd);
    }

    return ret;
}
