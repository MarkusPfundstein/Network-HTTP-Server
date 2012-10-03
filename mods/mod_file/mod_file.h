#ifndef __MOD_FILE_H__
#define __MOD_FILE_H__

#include "globals.h"

extern int MOD_on_init(struct config_s *config);

extern int MOD_on_headers_done(struct config_s *config, header_info_t *header);

extern int MOD_on_body(struct config_s *config, header_info_t *header, const char *data, size_t len);

extern int MOD_on_message_done(struct config_s *config, header_info_t *header);

#endif
