#include "tcp_encode.h"
#include "ctxt_find.h"
#include "base.h"

struct rohc_buf
{
	struct rohc_ts time;
	uint8_t data[2048];
	size_t len;
};

int rohc_compress4(const struct rohc_buf uncomp_packet,
		uint8_t *const rohc_packet, bool reset);
