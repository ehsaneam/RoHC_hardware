#include "uncomp_tcp.h"

bool tcp_encode_uncomp_tcp_fields(struct rohc_comp_ctxt *const context,
								  const struct tcphdr *const tcp)
{
	struct sc_tcp_context *const tcp_context = &context->specific;
	const uint32_t seq_num_hbo = rohc_bswap32(tcp->seq_num);
	const uint32_t ack_num_hbo = rohc_bswap32(tcp->ack_num);
	tcp_context->tmp.tcp_ack_flag_changed =
		(tcp->ack_flag != tcp_context->old_tcphdr.ack_flag);
	tcp_context->tmp.tcp_urg_flag_present = (tcp->urg_flag != 0);
	tcp_context->tmp.tcp_urg_flag_changed =
		(tcp->urg_flag != tcp_context->old_tcphdr.urg_flag);


	if(tcp->window != tcp_context->old_tcphdr.window)
	{
		tcp_context->tmp.tcp_window_changed = true;
		tcp_context->tcp_window_change_count = 0;
	}
	else if(tcp_context->tcp_window_change_count < MAX_FO_COUNT)
	{
		tcp_context->tmp.tcp_window_changed = true;
		tcp_context->tcp_window_change_count++;
	}
	else
	{
		tcp_context->tmp.tcp_window_changed = false;
	}

	tcp_context->tmp.nr_window_bits_16383 =
			wlsb_get_minkp_16bits(&tcp_context->window_wlsb, rohc_bswap16(tcp->window),
		                   ROHC_LSB_SHIFT_TCP_WINDOW);

	c_add_wlsb(&tcp_context->window_wlsb, tcp_context->msn, rohc_bswap16(tcp->window));

	const size_t seq_num_factor = tcp_context->tmp.payload_len;
	uint32_t seq_num_scaled;
	uint32_t seq_num_residue;

	c_field_scaling(&seq_num_scaled, &seq_num_residue, seq_num_factor,
					seq_num_hbo);

	if(context->num_sent_packets == 0 ||
	   seq_num_factor == 0 ||
	   seq_num_factor != tcp_context->seq_num_factor ||
	   seq_num_residue != tcp_context->seq_num_residue)
	{
		tcp_context->seq_num_scaling_nr = 0;
	}

	tcp_context->seq_num_scaled = seq_num_scaled;
	tcp_context->seq_num_residue = seq_num_residue;
	tcp_context->seq_num_factor = seq_num_factor;

	const uint32_t old_ack_num_hbo = rohc_bswap32(tcp_context->old_tcphdr.ack_num);
	const uint32_t ack_delta = ack_num_hbo - old_ack_num_hbo;
	uint16_t ack_stride = 0;
	uint32_t ack_num_scaled;
	uint32_t ack_num_residue;

	if( ack_delta==0 )
	{
		ack_stride = tcp_context->ack_stride;
	}
	else
	{
		size_t ack_stride_count = 0;
		size_t i;
		size_t j;

		tcp_context->ack_deltas_width[tcp_context->ack_deltas_next] = ack_delta;
		tcp_context->ack_deltas_next = (tcp_context->ack_deltas_next + 1) & (ACK_DELTAS_WIDTH-1);

		for( i=0 ; i<ACK_DELTAS_WIDTH ; i++ )
		{
#pragma HLS UNROLL factor=16
			const uint16_t val =
				tcp_context->ack_deltas_width[(tcp_context->ack_deltas_next + i) &
											  (ACK_DELTAS_WIDTH-1)];
			size_t val_count = 1;

			for( j=0; j<ACK_DELTAS_WIDTH ; j++ )
			{
#pragma HLS UNROLL factor=16
				if( j<=i )
				{
					continue;
				}
				else if(val == tcp_context->ack_deltas_width[(tcp_context->ack_deltas_next + j) &
															 (ACK_DELTAS_WIDTH-1)])
				{
					val_count++;
				}
			}

			if(val_count > ack_stride_count)
			{
				ack_stride = val;
				ack_stride_count = val_count;
				if(ack_stride_count > 10)
				{
					break;
				}
			}
		}
	}

	c_field_scaling(&ack_num_scaled, &ack_num_residue, ack_stride, ack_num_hbo);
	if(context->num_sent_packets == 0)
	{
		tcp_context->ack_num_scaling_nr = ROHC_INIT_TS_STRIDE_MIN;
	}
	else
	{
		if(ack_stride != tcp_context->ack_stride ||
		   ack_num_residue != tcp_context->ack_num_residue)
		{
			tcp_context->ack_num_scaling_nr = 0;
		}
	}

	tcp_context->ack_num_scaled = ack_num_scaled;
	tcp_context->ack_num_residue = ack_num_residue;
	tcp_context->ack_stride = ack_stride;

	bool tcp_seq_num_changed, tcp_ack_num_changed;
	uint32_t nr_seq_scaled_bits, nr_ack_bits_16383, nr_ack_scaled_bits;

	calc_wlsbs(&tcp_context->seq_scaled_wlsb, &tcp_context->ack_wlsb,
				&tcp_context->ack_scaled_wlsb, &tcp_seq_num_changed, tcp->seq_num,
				tcp_context->old_tcphdr.seq_num,
				tcp_context->seq_num_factor, tcp_context->seq_num_scaling_nr,
				&nr_seq_scaled_bits, tcp_context->seq_num_scaled, &tcp_ack_num_changed,
				tcp->ack_num, tcp_context->old_tcphdr.ack_num, ack_num_hbo, &nr_ack_bits_16383,
				tcp_context->ack_stride,
				tcp_context->ack_num_scaling_nr, &nr_ack_scaled_bits,
				tcp_context->ack_num_scaled);

	tcp_context->tmp.tcp_seq_num_changed = tcp_seq_num_changed;
	tcp_context->tmp.nr_seq_scaled_bits = nr_seq_scaled_bits;
	tcp_context->tmp.tcp_ack_num_changed = tcp_ack_num_changed;
	tcp_context->tmp.nr_ack_bits_16383 = nr_ack_bits_16383;
	tcp_context->tmp.nr_ack_scaled_bits = nr_ack_scaled_bits;

	return true;
}

void calc_wlsbs(struct c_wlsb *seq_scaled_wlsb, struct c_wlsb *ack_wlsb, struct c_wlsb *ack_scaled_wlsb,
		bool *tcp_seq_num_changed, uint32_t seq_num, uint32_t old_seq_num, uint32_t tcp_seq_num_factor,
		uint32_t seq_num_scaling_nr, uint32_t *nr_seq_scaled_bits, uint32_t tcp_seq_num_scaled,
		bool *tcp_ack_num_changed, uint32_t ack_num, uint32_t old_ack_num, uint32_t ack_num_hbo,
		uint32_t *nr_ack_bits_16383, uint16_t tcp_ack_stride, uint32_t ack_num_scaling_nr,
		uint32_t *nr_ack_scaled_bits, uint32_t tcp_ack_num_scaled)
{
#pragma HLS dataflow
	*tcp_seq_num_changed = (seq_num != old_seq_num);
	if(tcp_seq_num_factor == 0 || seq_num_scaling_nr < ROHC_INIT_TS_STRIDE_MIN)
	{
		*nr_seq_scaled_bits = 32;
	}
	else
	{
		*nr_seq_scaled_bits = wlsb_get_minkp_32bits(seq_scaled_wlsb, tcp_seq_num_scaled,
				seq_scaled_wlsb->p);
	}

	*tcp_ack_num_changed = (ack_num != old_ack_num);
	*nr_ack_bits_16383 = wlsb_get_minkp_32bits(ack_wlsb, ack_num_hbo, 16383);

	if(!tcp_is_ack_scaled_possible(tcp_ack_stride, ack_num_scaling_nr))
	{
		*nr_ack_scaled_bits = 32;
	}
	else
	{
		*nr_ack_scaled_bits = wlsb_get_minkp_32bits(ack_scaled_wlsb, tcp_ack_num_scaled,
				ack_scaled_wlsb->p);
	}
}

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
			uint8_t i;

			for( i=0 ; i<4 ; i++ )
			{
#pragma HLS UNROLL factor=4
				uint32_t entry = wlsb->window_value[i];

				if( wlsb->window_used[i] )
				{
					const uint32_t v_ref = entry;
					const uint32_t min = v_ref - computed_p;
					const uint32_t max = min + interval_width;

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

			for( i=0 ; i<4 ; i++ )
			{
#pragma HLS UNROLL factor=4
				if( wlsb->window_used[i] )
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

void c_field_scaling(uint32_t *const scaled_value,
                     uint32_t *const residue_field,
                     const uint32_t scaling_factor,
                     const uint32_t unscaled_value)
{
	if(scaling_factor == 0)
	{
		*residue_field = unscaled_value;
		*scaled_value = 0;
	}
	else
	{
		uint32_t sf = 1;
		for( uint32_t i=0 ; i<32 ; i++ )
		{
#pragma HLS UNROLL factor=32
			if( sf>=scaling_factor )
			{
				break;
			}
			sf = sf << 1;
		}
		*scaled_value = unscaled_value >> sf;
		uint32_t temp = *scaled_value << sf;
		*residue_field = unscaled_value - temp;
	}
}

bool tcp_is_ack_scaled_possible(const uint16_t ack_stride,
                                const size_t nr_trans)
{
	return (ack_stride != 0 && nr_trans >= ROHC_INIT_TS_STRIDE_MIN);
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
