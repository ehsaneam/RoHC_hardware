#include "base.h"

void rohc_comp_periodic_down_transition(struct rohc_comp_ctxt *const context)
{
	rohc_comp_state_t next_state;

	if(context->go_back_ir_count >= CHANGE_TO_IR_COUNT)
	{
		context->go_back_ir_count = 0;
		next_state = ROHC_COMP_STATE_IR;
	}
	else if(context->go_back_fo_count >= CHANGE_TO_FO_COUNT)
	{
		context->go_back_fo_count = 0;
		next_state = ROHC_COMP_STATE_FO;
	}
	else
	{
		next_state = context->state;
	}

	rohc_comp_change_state(context, next_state);

	if(context->state == ROHC_COMP_STATE_SO)
	{
		context->go_back_ir_count++;
		context->go_back_fo_count++;
	}
	else if(context->state == ROHC_COMP_STATE_FO)
	{
		context->go_back_ir_count++;
	}
}

void rohc_comp_change_state(struct rohc_comp_ctxt *const context,
                            const int new_state)
{
	if(new_state != context->state)
	{
		/* reset counters */
		context->ir_count = 0;
		context->fo_count = 0;
		context->so_count = 0;

		/* change state */
		context->state = new_state;
	}
}

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

void wlsb_init(struct c_wlsb *const wlsb,
               const size_t bits,
               const size_t window_width,
               const size_t p)
{
	size_t i;
	wlsb->oldest = 0;
	wlsb->next = 0;
	wlsb->count = 0;
	wlsb->window_width = window_width;
	wlsb->bits = bits;
	wlsb->p = p;

	for(i = 0; i < ROHC_WLSB_WIDTH_MAX; i++)
	{
		wlsb->window_used[i] = false;
	}
}

bool rsf_index_enc_possible(const uint8_t rsf_flags)
{
	uint8_t ret = rsf_flags;
	while( ret )
	{
#pragma HLS loop_tripcount min=1 max=3
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

inline bool tcp_is_ack_scaled_possible(const uint16_t ack_stride,
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

uint8_t crc_calc_8(const uint8_t *const buf,
				 const size_t size)
{
	size_t i;
	uint8_t crc = CRC_INIT_8;
	const uint8_t crc_table_8[256] = {
			0,145,227,114,7,150,228,117,14,159,237,124,9,
			152,234,123,28,141,255,110,27,138,248,105,18,
			131,241,96,21,132,246,103,56,169,219,74,63,174,
			220,77,54,167,213,68,49,160,210,67,36,181,199,
			86,35,178,192,81,42,187,201,88,45,188,206,95,
			112,225,147,2,119,230,148,5,126,239,157,12,121,
			232,154,11,108,253,143,30,107,250,136,25,98,243,
			129,16,101,244,134,23,72,217,171,58,79,222,172,
			61,70,215,165,52,65,208,162,51,84,197,183,38,83,
			194,176,33,90,203,185,40,93,204,190,47,224,113,
			3,146,231,118,4,149,238,127,13,156,233,120,10,
			155,252,109,31,142,251,106,24,137,242,99,17,128,
			245,100,22,135,216,73,59,170,223,78,60,173,214,
			71,53,164,209,64,50,163,196,85,39,182,195,82,32,
			177,202,91,41,184,205,92,46,191,144,1,115,226,
			151,6,116,229,158,15,125,236,153,8,122,235,140,
			29,111,254,139,26,104,249,130,19,97,240,133,20,
			102,247,168,57,75,218,175,62,76,221,166,55,69,
			212,161,48,66,211,180,37,87,198,179,34,80,193,
			186,43,89,200,189,44,94,207};
#pragma HLS bind_storage variable=crc_table_8 type=rom_1p impl=bram

	for(i = 0; i < size; i++)
	{
#pragma HLS loop_tripcount min=1 max=40
		crc = crc_table_8[buf[i] ^ crc];
	}

	return crc;
}

uint8_t crc_calc_7(const uint8_t *const buf, const size_t size)
{
	size_t i;
	uint8_t crc = CRC_INIT_7;
	const uint8_t crc_table_7[256] = {
			0,64,115,51,21,85,102,38,42,106,89,25,63,127,
			76,12,84,20,39,103,65,1,50,114,126,62,13,77,
			107,43,24,88,91,27,40,104,78,14,61,125,113,49,
			2,66,100,36,23,87,15,79,124,60,26,90,105,41,
			37,101,86,22,48,112,67,3,69,5,54,118,80,16,35,
			99,111,47,28,92,122,58,9,73,17,81,98,34,4,68,
			119,55,59,123,72,8,46,110,93,29,30,94,109,45,
			11,75,120,56,52,116,71,7,33,97,82,18,74,10,57,
			121,95,31,44,108,96,32,19,83,117,53,6,70,121,
			57,10,74,108,44,31,95,83,19,32,96,70,6,53,117,
			45,109,94,30,56,120,75,11,7,71,116,52,18,82,
			97,33,34,98,81,17,55,119,68,4,8,72,123,59,29,
			93,110,46,118,54,5,69,99,35,16,80,92,28,47,111,
			73,9,58,122,60,124,79,15,41,105,90,26,22,86,
			101,37,3,67,112,48,104,40,27,91,125,61,14,78,
			66,2,49,113,87,23,36,100,103,39,20,84,114,50,
			1,65,77,13,62,126,88,24,43,107,51,115,64,0,38,
			102,85,21,25,89,106,42,12,76,127,63};
#pragma HLS bind_storage variable=crc_table_7 type=rom_1p impl=bram

	for(i = 0; i < size; i++)
	{
#pragma HLS loop_tripcount min=1 max=40
		crc = crc_table_7[buf[i] ^ (crc & 127)];
	}

	return crc;
}

uint8_t crc_calc_3(const uint8_t *const buf, const size_t size)
{
	size_t i;
	uint8_t crc = CRC_INIT_3;
	const uint8_t crc_table_3[256] = {
			0,6,1,7,2,4,3,5,4,2,5,3,6,0,7,1,5,3,4,2,7,1,6,
			0,1,7,0,6,3,5,2,4,7,1,6,0,5,3,4,2,3,5,2,4,1,7,
			0,6,2,4,3,5,0,6,1,7,6,0,7,1,4,2,5,3,3,5,2,4,1,
			7,0,6,7,1,6,0,5,3,4,2,6,0,7,1,4,2,5,3,2,4,3,5,
			0,6,1,7,4,2,5,3,6,0,7,1,0,6,1,7,2,4,3,5,1,7,0,
			6,3,5,2,4,5,3,4,2,7,1,6,0,6,0,7,1,4,2,5,3,2,4,
			3,5,0,6,1,7,3,5,2,4,1,7,0,6,7,1,6,0,5,3,4,2,1,
			7,0,6,3,5,2,4,5,3,4,2,7,1,6,0,4,2,5,3,6,0,7,1,
			0,6,1,7,2,4,3,5,5,3,4,2,7,1,6,0,1,7,0,6,3,5,2,
			4,0,6,1,7,2,4,3,5,4,2,5,3,6,0,7,1,2,4,3,5,0,6,
			1,7,6,0,7,1,4,2,5,3,7,1,6,0,5,3,4,2,3,5,2,4,1,
			7,0,6};
#pragma HLS bind_storage variable=crc_table_3 type=rom_1p impl=bram

	for(i = 0; i < size; i++)
	{
#pragma HLS loop_tripcount min=1 max=40
		crc = crc_table_3[buf[i] ^ (crc & 7)];
	}

	return crc;
}
