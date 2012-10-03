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
};

/* 
 * defined and filled in main.c
 */
extern struct config_s g_config;

#endif
