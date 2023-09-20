#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#define ROHC_WLSB_WIDTH_MAX  64U

struct c_wlsb
{
	uint8_t count;
	uint32_t window_value[ROHC_WLSB_WIDTH_MAX];
	uint32_t window_used[ROHC_WLSB_WIDTH_MAX];
};

uint8_t wlsb_get_minkp_16bits(const struct c_wlsb *const wlsb,
                             const uint16_t value,
                             const int p);
