#include "wlsb_32b.h"

uint8_t wlsb_get_minkp_32bits(const struct c_wlsb *const wlsb,
                                    const uint32_t value,
                                    const int p)
{
	uint8_t bits_nr;
	if(wlsb->count == 0)
	{
		bits_nr = 32;
	}
	else
	{
		uint8_t k;

		for( k=0 ; k<32 ; k++ )
		{
			const uint32_t interval_width = (1U << k) - 1; /* interval width = 2^k - 1 */
			int32_t computed_p = p;
			size_t i;
			for( i=0 ; i<4 ; i++ )
			{
				const uint32_t v_ref = wlsb->window_value[i];
				const uint32_t min = v_ref - computed_p;
				const uint32_t max = min + interval_width;

				if( (min<=max && (value<min || value>max)) ||
					(min>max && (value<min && value>max)) )
				{
					break;
				}
			}
			if( i==4 )
			{
				break;
			}
		}
		bits_nr = k;
	}

	return bits_nr;
}
