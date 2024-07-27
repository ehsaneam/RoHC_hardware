#include "tcp_encode.h"
#include "ctxt_find.h"
#include "base.h"

typedef enum
{
	/** The action was successful */
	ROHC_STATUS_OK                = 0,
	/** The action failed due to a malformed packet */
	ROHC_STATUS_MALFORMED         = 2,
	/** The action failed because no matching context exists */
	ROHC_STATUS_NO_CONTEXT        = 3,
	/** The action failed due to a CRC failure */
	ROHC_STATUS_BAD_CRC           = 4,
	/** The action failed because output buffer is too small */
	ROHC_STATUS_OUTPUT_TOO_SMALL  = 5,
	/** The action encountered an undefined problem */
	ROHC_STATUS_ERROR             = 6,

} rohc_status_t;

rohc_status_t rohc_compress4(struct rohc_comp *const comp,
                             const struct rohc_buf uncomp_packet,
                             struct rohc_buf *const rohc_packet);
