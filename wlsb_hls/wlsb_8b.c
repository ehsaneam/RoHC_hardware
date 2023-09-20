#include "wlsb_8b.h"

uint8_t wlsb_get_kp_8bits(const struct c_wlsb *const wlsb,
                         const uint8_t value,
                         const int p)
{
	uint8_t bits_nr;

	if(wlsb->count == 0)
	{
		bits_nr = 8;
	}
	else
	{
		uint8_t k;

		for( k=0 ; k<8 ; k++ )
		{
			const uint8_t interval_width = (1U << k) - 1; /* interval width = 2^k - 1 */
			uint8_t i;
			int8_t computed_p = p;

			for( i=0 ; i<4 ; i++ )
			{
				if( wlsb->window_used[i] )
				{
					const uint8_t v_ref = wlsb->window_value[i];
					const uint8_t min = v_ref - computed_p;
					const uint8_t max = min + interval_width;

					if( (min<=max && (value<min || value>max)) ||
						(min>max && (value<min && value>max)) )
					{
						break;
					}
				}
			}

			if( wlsb->window_used[i]==0 )
			{
				break;
			}
		}
		bits_nr = k;
	}
	return bits_nr;
}
