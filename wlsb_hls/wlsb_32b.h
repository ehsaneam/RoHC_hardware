#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#define ROHC_WLSB_WIDTH_MAX  64U

struct c_wlsb
{
	/** The count of entries in the window */
	uint8_t count;

	/** The window in which previous values of the encoded value are stored */
	uint32_t window_value[ROHC_WLSB_WIDTH_MAX];
};

uint8_t wlsb_get_minkp_32bits(const struct c_wlsb *const wlsb,
								const uint32_t value,
								const int p);
