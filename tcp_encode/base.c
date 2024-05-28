#include "base.h"

uint8_t wlsb_get_kp_8bits(const struct c_wlsb *const wlsb,
                         const uint8_t value,
                         const int p)
{
	uint8_t bits_nr;
	const uint8_t iws[] = {0, 1, 3, 7, 15, 31, 63, 127};

	if(wlsb->count == 0)
	{
		bits_nr = 8;
	}
	else
	{
		uint8_t k;

		for( k=0 ; k<8 ; k++ )
		{
			uint8_t i;
			int8_t computed_p = p;

			for( i=0 ; i<4 ; i++ )
			{
#pragma HLS UNROLL factor=4
				if( wlsb->window_used[i] )
				{
					const uint8_t v_ref = wlsb->window_value[i];
					const uint8_t min = v_ref - computed_p;
					const uint8_t max = min + iws[k];

					if( (min<=max && (value<min || value>max)) ||
						(min>max && (value<min && value>max)) )
					{
						break;
					}
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

uint8_t wlsb_get_minkp_16bits(const struct c_wlsb *const wlsb,
                             const uint16_t value,
                             const int p)
{
	uint8_t bits_nr;
	const uint16_t iws[] = {0, 1, 3, 7, 15, 31, 63, 127, 255, 511, 1023, 2047,
							4095, 8191, 16383, 32767};

	if( wlsb->count==0 )
	{
		bits_nr = 16;
	}
	else
	{
		uint8_t k;

		for( k=0 ; k<16 ; k++ )
		{
			int16_t computed_p = p;
			uint8_t i;

			for( i=0 ; i<4 ; i++ )
			{
#pragma HLS UNROLL factor=4
				if( wlsb->window_used[i] )
				{
					const uint16_t v_ref = wlsb->window_value[i];
					const uint16_t min = v_ref - computed_p;
					const uint16_t max = min + iws[k];

					if( (min<=max && (value<min || value>max)) ||
						(min>max && (value<min && value>max)) )
					{
						break;
					}
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

uint8_t wlsb_get_minkp_32bits(const struct c_wlsb *const wlsb,
								const uint32_t value,
								const int p)
{
	uint8_t bits_nr;
	const uint32_t iws[] = {0, 1, 3, 7, 15, 31, 63, 127, 255, 511, 1023, 2047,
							  4095, 8191, 16383, 32767, 65535, 131071, 262143, 524287,
							  1048575, 2097151, 4194303, 8388607, 16777215, 33554431,
							  67108863, 134217727, 268435455, 536870911, 1073741823,
							  2147483647};
	if(wlsb->count == 0)
	{
		bits_nr = 32;
	}
	else
	{
		uint8_t k;

		for( k=0 ; k<32 ; k++ )
		{
			uint8_t i;

			for( i=0 ; i<4 ; i++ )
			{
#pragma HLS UNROLL factor=4

				if( wlsb->window_used[i] )
				{
					const uint32_t min = wlsb->window_value[i] - p;
					const uint32_t max = min + iws[k];

					if( (min<=max && (value<min || value>max)) ||
						(min>max && (value<min && value>max)) )
					{
						break;
					}
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

void c_add_wlsb(struct c_wlsb *const wlsb,
                const uint32_t sn,
                const uint32_t value)
{
	if(wlsb->count == wlsb->window_width)
	{
		wlsb->oldest = (wlsb->oldest + 1) & 3;
	}
	else
	{
		wlsb->count++;
	}

	wlsb->window_used[wlsb->next] = 1;
	wlsb->window_sn[wlsb->next] = sn;
	wlsb->window_value[wlsb->next] = value;
	wlsb->next = (wlsb->next + 1) & 3;
}

bool rsf_index_enc_possible(const uint8_t rsf_flags)
{
	uint8_t ret = rsf_flags;
	while( ret )
	{
		ret += ret & 1;
		ret >>= 1;
	}
//	return (__builtin_popcount(rsf_flags) <= 1);
	return (ret <= 1);
}

int code_cid_values(const size_t cid,
                    uint8_t *const dest,
                    const size_t dest_size,
                    size_t *const first_position)
{
	size_t counter = 0;

	if(cid > 0)
	{
		/* Add-CID */
		if(dest_size < 2)
		{
			return -1;
		}
		dest[counter] = c_add_cid(cid);
		*first_position = 1;
		counter = 2;
	}
	else
	{
		/* no Add-CID */
		if(dest_size < 1)
		{
			return -1;
		}
		*first_position = 0;
		counter = 1;
	}

	return counter;
}

uint8_t c_add_cid(const size_t cid)
{
	const uint8_t add_cid_type = 0xe0;
	return (add_cid_type | (cid & 0x0f));
}

int c_static_or_irreg8(const uint8_t packet_value,
                       const bool is_static,
                       uint8_t *const rohc_data,
                       const size_t rohc_max_len,
                       int *const indicator)
{
	size_t length;

	if(is_static)
	{
		*indicator = 0;
		length = 0;
	}
	else
	{
		if(rohc_max_len < 1)
		{
			return -1;
		}
		rohc_data[0] = packet_value;
		*indicator = 1;
		length = 1;
	}

	return length;
}

int c_static_or_irreg16(const uint16_t packet_value,
                        const bool is_static,
                        uint8_t *const rohc_data,
                        const size_t rohc_max_len,
                        int *const indicator)
{
	size_t field_len;

	if(is_static)
	{
		field_len = 0;
		*indicator = 0;
	}
	else
	{
		field_len = sizeof(uint16_t);

		if(rohc_max_len < field_len)
		{
			return -1;
		}

		memcpy(rohc_data, &packet_value, sizeof(uint16_t));
		*indicator = 1;
	}

	return field_len;
}

bool tcp_is_ack_stride_static(const uint16_t ack_stride, const size_t nr_trans)
{
	return (ack_stride == 0 || nr_trans >= ROHC_INIT_TS_STRIDE_MIN);
}

bool tcp_is_ack_scaled_possible(const uint16_t ack_stride,
                                const size_t nr_trans)
{
	return (ack_stride != 0 && nr_trans >= ROHC_INIT_TS_STRIDE_MIN);
}

unsigned int rsf_index_enc(const uint8_t rsf_flags)
{
	switch(rsf_flags)
	{
		case RSF_NONE:
			return 0;
		case RSF_RST_ONLY:
			return 1;
		case RSF_SYN_ONLY:
			return 2;
		case RSF_FIN_ONLY:
			return 3;
		default:
			return 0;
	}
}

uint32_t rohc_bswap32(const uint32_t value)
{
	return (((value & 0xff000000) >> 24) |
	        ((value & 0x00ff0000) >>  8) |
	        ((value & 0x0000ff00) <<  8) |
	        ((value & 0x000000ff) << 24));
}

uint16_t rohc_bswap16(const uint16_t value)
{
	return (((value >> 8) & 0xff) | ((value & 0xff) << 8));
}

uint16_t swab16(const uint16_t value)
{
	return ((value & 0x00ff) << 8) | ((value & 0xff00) >> 8);
}
