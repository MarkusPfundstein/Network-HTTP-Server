#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "mod_html.h"
#include "globals.h"

int 
mod_init(int argc, char **argv)
{
    fprintf(stderr, "MOD_HTML INIT CALLED\n");
    return 0;
}
