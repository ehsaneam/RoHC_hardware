#ifndef ROHC_COMPRESS_H
#define ROHC_COMPRESS_H

#include "tcp_encode.h"
#include "udp_encode.h"
#include "uncomp_encode.h"
#include "ctxt_find.h"
#include "base.h"

int rohc_compress4(uint8_t *const uncomp_data, uint16_t uncomp_time, size_t uncomp_len, uint8_t *const rohc_packet);
void rohc_update_time(struct rohc_comp *const comp, uint16_t uncomp_time);
int rohc_get_payload_offset(size_t cid);

#endif //ROHC_COMPRESS_H
