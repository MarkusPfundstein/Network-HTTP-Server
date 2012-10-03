#ifndef __GLOBALS_H__
#define __GLOBALS_H__

/*
 * saves all necessary variables from
 * config file
 */

/* xxx.xxx.xxx.xxx. + '\0' */
#define IP_V4_LEN 17

#define MAX_BUF_SIZE 4096

struct config_s {
    int listen_port;
    char accept_ip_v4[IP_V4_LEN];
    int read_package_size;
};

/* 
 * defined and filled in main.c
 */
extern struct config_s g_config;

#endif
