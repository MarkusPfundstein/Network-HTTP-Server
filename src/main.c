#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <libconfig.h>
#include "module_map.h"
#include "globals.h"
#include "http_parser.h"
#include "http_query.h"
#include "http_query.h"
#include "buffer.h"

static int g_go_on;
static int g_sockfd;

struct config_s g_config;

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
header_parse_body(http_parser *parser, const char *a, size_t n)
{
    header_info_t *header;
    int err;
    err = 0;
    header = (header_info_t*)parser->data;

    return err;
}

static int
header_done(http_parser *parser)
{
    header_info_t *header;
    module_t *mod;
    char *file_ext;
    header = (header_info_t*)parser->data;
    if (header->state == HEADER_INFO_STATE_ERROR) {
        fprintf(stderr, "*** error while parsing header... abort\n");
        return 1;
    }
    
    file_ext = strrchr(header->base_url, '.');
    fprintf(stderr, "file_ext: %s\n", file_ext);
    if (file_ext) {
        mod = module_map_find_ident(g_config.module_root, file_ext + 1);
        if (mod) {
            module_call_func(mod, "MOD_on_headers_done", &g_config, header);
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
    
    if (header->state != HEADER_INFO_STATE_ERROR) {
        header->state = HEADER_INFO_STATE_DONE;
    }

    /* reference how to search query map */ 
    /*
    query_map_t *res1 = query_map_find(header->query_map, "idx");
    query_map_t *res2 = query_map_find(header->query_map, "name");
    query_map_t *res3 = query_map_find(header->query_map, "address");

    if (res1) {
        fprintf(stderr, "res1: %s - %s\n", res1->key, res1->value);
    }
    if (res2) {
        fprintf(stderr, "res2: %s - %s\n", res2->key, res2->value);
    }
    if (res3) {
        fprintf(stderr, "res3: %s - %s\n", res3->key, res3->value);
    }*/

    return 0;
}

static int
read_request(int fd, header_info_t *header)
{
    char buffer[MAX_BUF_SIZE];
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
        bytes_read = read(fd, buffer, g_config.read_package_size);
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
    /*
    fprintf(stderr, "\nDONE\n");
    fprintf(stderr, "url: %s\n", header.url);
    fprintf(stderr, "content-length: %s\n", header.content_length);
    fprintf(stderr, "content-type: %s\n", header.content_type);
    fprintf(stderr, "accept: %s\n", header.accept);
    fprintf(stderr, "host: %s\n", header.host);
    fprintf(stderr, "UA: %s\n", header.user_agent);
    fprintf(stderr, "expect: %s\n", header.expect);
    */
    /* echo back shit */

    /* close */
    if (header.url) {
        free(header.url);
    }
    if (header.base_url) {
        free(header.base_url);
    }
    if (header.host) {
        free(header.host);
    }
    if (header.accept) {
        free(header.accept);
    }
    if (header.content_type) {
        free(header.content_type);
    }
    if (header.user_agent) {
        free(header.user_agent);
    }
    if (header.content_length) {
        free(header.content_length);
    }
    if (header.expect) {
        free(header.expect);
    }
    if (header.query_map) {
        query_map_destroy(header.query_map);
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
    }
    

    fprintf(stderr, "listen_port: %d\n", g_config.listen_port); 
    fprintf(stderr, "accept_ip: %s\n", g_config.accept_ip_v4);
    fprintf(stderr, "read_package_size: %d\n", g_config.read_package_size);
    fprintf(stderr, "backlog: %d\n", g_config.backlog);

    err = load_mods(&config, setting);

error:
    config_destroy(&config);
    return err;
}

int 
main(int argc, char **argv)
{
    int child_pid;
    int newfd;
    int ret;
    int child_return;
    socklen_t socklen;
    struct sockaddr_in serv_addr;
    struct sockaddr_in cli_addr;

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
                child_return = child_main(newfd);
                module_map_destroy(g_config.module_root);
                exit(child_return);
            } else {
                close(newfd);
            }
        }
    }
    ret = 0;
    
error:
    fprintf(stderr, "shutdown\n");

    module_map_destroy(g_config.module_root);
    if (g_sockfd != -1) {
        close(g_sockfd);
    }

    return ret;
}
