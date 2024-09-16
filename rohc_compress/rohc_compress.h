#include "tcp_encode.h"
#include "ctxt_find.h"
#include "base.h"

int rohc_compress4(uint8_t *const uncomp_data, struct rohc_ts uncomp_time, size_t uncomp_len,
		uint8_t *const rohc_packet, bool reset);
