#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "mod_html.h"

typedef struct config_s config_t;

int 
MOD_on_init(config_t *config)
{
    fprintf(stderr, "MOD_HTML INIT CALLED: %d\n", config->listen_port);
    return 0;
}

int
MOD_on_headers_done(config_t *config, header_info_t *header) {
    fprintf(stderr, "HEADERS DONE: %s\n", header->url);
    return 0;
}
