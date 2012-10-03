#ifndef __MOD_FS_H__
#define __MOD_FS_H__

#include "globals.h"

extern int MOD_on_init(struct config_s *config);
extern int MOD_on_headers_done(struct config_s *config, header_info_t *header);

#endif
