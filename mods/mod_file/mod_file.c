#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "mod_file.h"

typedef struct config_s config_t;

static int
write_response_header(int fd, size_t size, const char *resp_code, const char* http_code,
                      const char *type, const char *keep_alive_or_close)
{
  char buffer[512];
  char length_buf[65];
  int bytes_written;
  if (sprintf(length_buf, "%d", size) < 0) {
    return 1;
  }
    
  strcpy(buffer, http_code);
  strcat(buffer, " ");
  strcat(buffer, resp_code);
  strcat(buffer, "\r\n"
                 "Connection: ");
  strcat(buffer, keep_alive_or_close);
  strcat(buffer, "\r\n"
                 "Content-Type: ");
  strcat(buffer, type);
  strcat(buffer, "\r\n"
                 "Content-Length: ");
  strcat(buffer, length_buf);
  strcat(buffer, "\r\n\r\n");

  bytes_written = write(fd, buffer, strlen(buffer));
  if (bytes_written <= 0) {
    if (bytes_written < 0) {
        perror("mod_file - write_response_header - write()");
        return 1;
    }
  }

  return 0;
}

static int
send_file_to_socket(const char *file, int fd)
{
    FILE *fp;
    char buffer[MAX_BUF_SIZE];
    int bytes_read;
    int bytes_written;
    int err;
    size_t file_size;
    const char *end_of_msg = "\r\n";
    const char *file_not_found = "<html><head><title>ERROR 404</title><body><p>I ain't got this file dude</p></body><html>";
    fprintf(stderr, "SEND: %s\n", file);
    err = 0;
    fp = fopen(file, "r");
    if (fp) {
        fseek(fp, 0, SEEK_END);
        file_size = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        err = write_response_header(fd, 
                                    file_size, 
                                    "200 OK", 
                                    "HTTP/1.1",
                                    "text/html", 
                                    "close");
        if (!err) {
            do {
                bytes_read = fread(buffer, 
                                   1, 
                                   sizeof(buffer),
                                   fp);
                if (bytes_read <= 0) {
                    if (bytes_read < 0) {
                        perror("mod_file - fread");
                    }
                    break;
                } else {
                    bytes_written = write(fd, buffer, bytes_read);
                    if (bytes_written <= 0) {
                        perror("mod_file - write\n");
                        break;
                    }
                }
            } while (1);
        }
        fclose(fp);
    } else {
        err = write_response_header(fd,
                                    strlen(file_not_found),
                                    "404 Not Found",
                                    "HTTP/1.1",
                                    "text/html",
                                    "close");
        err = (write(fd, file_not_found, strlen(file_not_found)) <= 0 ? 1 : 0);
    }

    if (!err) {
        err = (write(fd, end_of_msg, strlen(end_of_msg)) <= 0 ? 1 : 0);
    }

    return err;
}

int 
MOD_on_init(config_t *config)
{
    return 0;
}

int
MOD_on_headers_done(config_t *config, header_info_t *header) 
{
    char *full_path;
    int err;
    int full_path_len;
    full_path_len = 0;
    err = 0;
    if (!config->base_path) {
        fprintf(stderr, "mod_file - no base_path\n");
        return 1;
    }
    if (!header->base_url) {
        fprintf(stderr, "mod_file - no base_url\n");
        return 1;
    }

    full_path_len += strlen(config->base_path);
    full_path_len += strlen(header->base_url);
    if (full_path_len > 0) {
        full_path = malloc(full_path_len + 1);
        if (!full_path) {
            fprintf(stderr, "mod_file - no memory for full_path\n");
            return 1;
        }
        strcpy(full_path, config->base_path);
        strcat(full_path, header->base_url);
        send_file_to_socket(full_path, header->fd);
        free(full_path);
    }
    return err;
}

int
MOD_on_body(config_t *config, header_info_t *header, const char *data, size_t len)
{
    return 0;
}

int
MOD_on_message_done(config_t *config, header_info_t *header) 
{
    return 0;
}
