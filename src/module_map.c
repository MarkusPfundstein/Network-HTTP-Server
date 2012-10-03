#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
/* tdestroy */
#define __USE_GNU 1
#include <search.h>
#include "module_map.h"

static void
module_map_destroy_module(void *p)
{
    if (!p) {
        return;
    }
    module_close((module_t*)p);
}

static int
module_map_cmp_func(const void *l, const void *r)
{
    const module_t *ml; 
    const module_t *mr; 
    ml = (module_t *)l;
    mr = (module_t *)r;
    return strcmp(ml->name, mr->name);
}

static int
module_map_ident_cmp_func(const void *l, const void *r)
{
    const module_t *ml; 
    const module_t *mr; 
    ml = (module_t *)l;
    mr = (module_t *)r;
    assert(ml->ident && mr->ident);
    return strcmp(ml->ident, mr->ident);
}


module_t*
module_open(const char *name, const char *ident, const char *so, int flag)
{
    module_t *mod;
    /* name is necessary */
    assert(name);
    mod = malloc(sizeof(struct module_s));
    if (!mod) {
        fprintf(stderr, "malloc module_open failed()\n");
        return NULL;
    }
    memset(mod, 0, sizeof(struct module_s));
    mod->name = strdup(name);
    if (!mod->name) {
        perror("strdup");
        free (mod);
        return NULL;
    }
    if (ident) {
        mod->ident = strdup(ident);
        if (!mod->ident) {
            perror("strdup ident");
            free(mod);
            free(mod->name);
            return NULL;
        }
    }
    if (so) {
        mod->handle = dlopen(so, flag);
        if (!mod->handle) {
            fprintf(stderr, "%s - %s\n", name, dlerror());
            if (mod->ident) {
                free(mod->ident);
            }
            free (mod->name);
            free (mod);
            return NULL;
        }
    }
    
    return mod;
}

void
module_close(module_t *mod)
{
    if (mod->handle) {
        dlclose(mod->handle);
    }
    if (mod->name) {
        free(mod->name);
    }
    if (mod->ident) {
        free(mod->ident);
    }
    free(mod);
}


module_t *
module_map_insert(module_t **root, module_t *module)
{
    if (tsearch((void*)module, (void**)root, module_map_cmp_func) == NULL) {
        fprintf(stderr, "module_map_insert tsearch failed()\n");
        return NULL;
    }
    return module;
}

module_t *
module_map_find_name(module_t *root, const char *name)
{
    module_t *predicate;
    module_t **res;
    predicate = module_open(name, NULL, NULL, 0);
    res = tfind(predicate, (void **)&root, module_map_cmp_func);
    module_close(predicate);
    return res ? *res : NULL;
}

module_t *
module_map_find_ident(module_t *root, const char *ident)
{
    module_t *predicate;
    module_t **res;
    predicate = module_open("", ident, NULL, 0);
    res = tfind(predicate, (void **)&root, module_map_ident_cmp_func);
    module_close(predicate);
    return res ? *res : NULL;
}

void
module_map_destroy(module_t *root)
{
    tdestroy(root, module_map_destroy_module);
}
