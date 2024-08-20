#include "tcp_encode.h"
#include "ctxt_find.h"
#include "base.h"

typedef enum
{
	ROHC_STATUS_OK                = 0,
	ROHC_STATUS_MALFORMED         = 2,
	ROHC_STATUS_NO_CONTEXT        = 3,
	ROHC_STATUS_BAD_CRC           = 4,
	ROHC_STATUS_OUTPUT_TOO_SMALL  = 5,
	ROHC_STATUS_ERROR             = 6,

} rohc_status_t;

struct rohc_buf
{
	struct rohc_ts time;
	uint8_t data[2048];
	size_t len;
};

rohc_status_t rohc_compress4(struct rohc_comp *const comp,
                             const struct rohc_buf uncomp_packet,
                             struct rohc_buf *const rohc_packet);
