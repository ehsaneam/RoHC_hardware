#include "wlsb_16b.h"

uint8_t wlsb_get_minkp_16bits(const struct c_wlsb *const wlsb,
                             const uint16_t value,
                             const int p)
{
	uint8_t bits_nr;

	if( wlsb->count==0 )
	{
		bits_nr = 16;
	}
	else
	{
		uint8_t k;

		for( k=0 ; k<16 ; k++ )
		{
			const uint16_t interval_width = (1U << k) - 1; /* interval width = 2^k - 1 */
			int16_t computed_p = p;
			uint8_t i;

			for( i=0 ; i<wlsb->count ; i++ )
			{
				const uint16_t v_ref = wlsb->window_value[i];
				const uint16_t min = v_ref - computed_p;
				const uint16_t max = min + interval_width;

				if( (min<=max && (value<min || value>max)) ||
					(min>max && (value<min && value>max)) )
				{
					break;
				}
			}

			if( i==wlsb->count )
			{
				break;
			}
		}
		bits_nr = k;
	}

	return bits_nr;
}
