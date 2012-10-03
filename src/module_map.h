#ifndef __MODULE_MAP_H__
#define __MODULE_MAP_H__

/* we export this header for all files which will include module_map.h */
#include <dlfcn.h>

/* structure for a module */
typedef struct module_s {
    char *name;
    char *ident;
    void *handle; 
} module_t;

/* 
 * opens module at path <so> and assings <name>
 */
extern module_t *module_open(const char *name, const char *ident, const char *so, int flag);
/*
 * closes that basstard
 */
extern void module_close(module_t *module);

/*
 * inserts module in a binary tree. 
 */
extern module_t *module_map_insert(module_t **root, module_t *module);

/*
 * finds module inside a binary tree by name
 */
extern module_t *module_map_find_name(module_t *root, const char *name);

/*
 * finds module inside a binary tree by ident
 */
extern module_t *module_map_find_ident(module_t *root, const char *ident);

/*
 * destroys module map and ALL modules in it
 */
extern void module_map_destroy(module_t *root);

#endif
