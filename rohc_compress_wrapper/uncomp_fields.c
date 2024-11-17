#include "uncomp_fields.h"

///////////////////////////
//			TCP			 //
///////////////////////////
bool tcp_encode_uncomp_fields(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt)
{
#pragma HLS INTERFACE m_axi port = ip_pkt depth = 1500
	struct sc_tcp_context *const tcp_context = &context->tcp_specific;

	/* how many bits are required to encode the new SN ? */
	tcp_context->tmp.nr_msn_bits =
			wlsb_get_minkp_16bits(&tcp_context->msn_wlsb, tcp_context->msn, tcp_context->msn_wlsb.p);
	/* add the new MSN to the W-LSB encoding object */
	/* TODO: move this after successful packet compression */
	c_add_wlsb(&tcp_context->msn_wlsb, tcp_context->msn, tcp_context->msn);

	struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) ip_pkt;
	if(!tcp_encode_uncomp_ip_fields(context, ipv4))
	{
		return false;
	}

	const struct tcphdr *tcp = (struct tcphdr *)(ip_pkt + sizeof(struct ipv4_hdr));
	if(!tcp_encode_uncomp_tcp_fields(context, tcp))
	{
		return false;
	}

	return true;
}

bool tcp_encode_uncomp_ip_fields(struct rohc_comp_ctxt *const context, const struct ipv4_hdr *const ip)
{
	struct sc_tcp_context *tcp_context = &context->tcp_specific;

	ipv4_context_t *inner_ip_ctxt = &(tcp_context->ip_context);

	/* parse IP headers */
	tcp_context->tmp.ttl_irreg_chain_flag = 0;

	uint8_t ttl_hopl = ip->ttl;
	if( ttl_hopl!=inner_ip_ctxt->ttl_hopl )
	{
		tcp_context->tmp.ttl_irreg_chain_flag |= 1;
	}

	tcp_context->tmp.outer_ip_ttl_changed =
		(tcp_context->tmp.ttl_irreg_chain_flag != 0);

	const uint16_t ip_id = rohc_bswap16(ip->id);

	/* does IP-ID behavior changed? */
	tcp_context->tmp.ip_id_behavior_changed =
		(inner_ip_ctxt->last_ip_id_behavior != inner_ip_ctxt->ip_id_behavior);

	/* compute the new IP-ID / SN delta */
	if(inner_ip_ctxt->ip_id_behavior == IP_ID_BEHAVIOR_SEQ_SWAP)
	{
		/* specific case of IP-ID delta for sequential swapped behavior */
		tcp_context->tmp.ip_id_delta = swab16(ip_id) - tcp_context->msn;
	}
	else
	{
		/* compute delta the same way for sequential, zero or random: it is
		 * important to always compute the IP-ID delta and record it in W-LSB,
		 * so that the IP-ID deltas of next packets may be correctly encoded */
		tcp_context->tmp.ip_id_delta = ip_id - tcp_context->msn;
	}

	/* how many bits are required to encode the new IP-ID / SN delta ? */
	if(inner_ip_ctxt->ip_id_behavior != IP_ID_BEHAVIOR_SEQ &&
	   inner_ip_ctxt->ip_id_behavior != IP_ID_BEHAVIOR_SEQ_SWAP)
	{
		/* send all bits if IP-ID behavior is not sequential */
		tcp_context->tmp.nr_ip_id_bits_3 = 16;
		tcp_context->tmp.nr_ip_id_bits_1 = 16;
	}
	else
	{
		/* send only required bits in FO or SO states */
		tcp_context->tmp.nr_ip_id_bits_3 = wlsb_get_minkp_16bits(&tcp_context->ip_id_wlsb,
							   tcp_context->tmp.ip_id_delta, 3);
		tcp_context->tmp.nr_ip_id_bits_1 = wlsb_get_minkp_16bits(&tcp_context->ip_id_wlsb,
							   tcp_context->tmp.ip_id_delta, 1);
	}
	/* add the new IP-ID / SN delta to the W-LSB encoding object */
	c_add_wlsb(&tcp_context->ip_id_wlsb, tcp_context->msn,
			   tcp_context->tmp.ip_id_delta);

	// ip->df
	uint16_t ipdf = ip->frag_off & 0x0040;

	if( ipdf != inner_ip_ctxt->df )
	{
		tcp_context->tmp.ip_df_changed = true;
	}
	else
	{
		tcp_context->tmp.ip_df_changed = false;
	}

	if( ip->dscp != inner_ip_ctxt->dscp )
	{
		tcp_context->tmp.dscp_changed = true;
	}
	else
	{
		tcp_context->tmp.dscp_changed = false;
	}

	tcp_context->tmp.ttl_hopl = ip->ttl;

	/* encode innermost IPv4 TTL or IPv6 Hop Limit */
	if(tcp_context->tmp.ttl_hopl != inner_ip_ctxt->ttl_hopl)
	{
		tcp_context->tmp.ttl_hopl_changed = true;
		tcp_context->ttl_hopl_change_count = 0;
	}
	else if(tcp_context->ttl_hopl_change_count < MAX_FO_COUNT)
	{
		tcp_context->tmp.ttl_hopl_changed = true;
		tcp_context->ttl_hopl_change_count++;
	}
	else
	{
		tcp_context->tmp.ttl_hopl_changed = false;
	}
	tcp_context->tmp.nr_ttl_hopl_bits = wlsb_get_kp_8bits(&tcp_context->ttl_hopl_wlsb,
			tcp_context->tmp.ttl_hopl, tcp_context->ttl_hopl_wlsb.p);
	/* add the new TTL/Hop Limit to the W-LSB encoding object */
	c_add_wlsb(&tcp_context->ttl_hopl_wlsb, tcp_context->msn,
	           tcp_context->tmp.ttl_hopl);

	return true;
}

bool tcp_encode_uncomp_tcp_fields(struct rohc_comp_ctxt *const context,
								  const struct tcphdr *const tcp)
{
	struct sc_tcp_context *const tcp_context = &context->tcp_specific;
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

void c_field_scaling(uint32_t *const scaled_value, uint32_t *const residue_field,
                     const uint32_t scaling_factor, const uint32_t unscaled_value)
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

///////////////////////////
//			UDP			 //
///////////////////////////
bool udp_encode_uncomp_fields(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	rfc3095_ctxt = &context->rfc3095_specific;

	rfc3095_ctxt->rfc_tmp.nr_sn_bits_more_than_4 = wlsb_get_minkp_16bits(&rfc3095_ctxt->sn_window,
			rfc3095_ctxt->sn, rfc3095_ctxt->sn_window.p);
	rfc3095_ctxt->rfc_tmp.nr_sn_bits_less_equal_than_4 = rfc3095_ctxt->rfc_tmp.nr_sn_bits_more_than_4;

	/* add the new SN to the W-LSB encoding object */
	c_add_wlsb(&rfc3095_ctxt->sn_window, rfc3095_ctxt->sn, rfc3095_ctxt->sn);

	/* update info related to the IP-ID of the outer header
	 * only if header is IPv4 */
	const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) ip_pkt;
	if(ipv4->version == 4)
	{
		uint16_t id = ipv4->id;
		if(!rfc3095_ctxt->outer_ip_flags.info.v4.nbo)
		{
			id = swab16(id);
		}
		rfc3095_ctxt->outer_ip_flags.info.v4.id_delta = rohc_bswap16(id) - rfc3095_ctxt->sn;

		/* how many bits are required to encode the new IP-ID / SN delta ? */
		if(rfc3095_ctxt->outer_ip_flags.info.v4.sid)
		{
			/* IP-ID is constant, no IP-ID bit to transmit */
			rfc3095_ctxt->rfc_tmp.nr_ip_id_bits = 0;
		}
		else
		{
			/* send only required bits in FO or SO states */
			rfc3095_ctxt->rfc_tmp.nr_ip_id_bits =
					wlsb_get_minkp_16bits(&rfc3095_ctxt->outer_ip_flags.info.v4.ip_id_window,
				                  rfc3095_ctxt->outer_ip_flags.info.v4.id_delta,
								  rfc3095_ctxt->outer_ip_flags.info.v4.ip_id_window.p);
		}

		/* add the new IP-ID / SN delta to the W-LSB encoding object */
		c_add_wlsb(&rfc3095_ctxt->outer_ip_flags.info.v4.ip_id_window, rfc3095_ctxt->sn,
		           rfc3095_ctxt->outer_ip_flags.info.v4.id_delta);
	}

	return true;
}

///////////////////////////
//		  COMMON		 //
///////////////////////////
bool rohc_packet_carry_crc_7_or_8(const rohc_packet_t packet_type)
{
	bool carry_crc_7_or_8;

	switch(packet_type)
	{
		case ROHC_PACKET_IR:
		case ROHC_PACKET_IR_DYN:
		case ROHC_PACKET_UOR_2:
		case ROHC_PACKET_TCP_CO_COMMON:
		case ROHC_PACKET_TCP_SEQ_8:
		case ROHC_PACKET_TCP_RND_8:
			carry_crc_7_or_8 = true;
			break;
		case ROHC_PACKET_UO_0:
		case ROHC_PACKET_UO_1:
		case ROHC_PACKET_NORMAL:
		case ROHC_PACKET_TCP_SEQ_1:
		case ROHC_PACKET_TCP_SEQ_2:
		case ROHC_PACKET_TCP_SEQ_3:
		case ROHC_PACKET_TCP_SEQ_4:
		case ROHC_PACKET_TCP_SEQ_5:
		case ROHC_PACKET_TCP_SEQ_6:
		case ROHC_PACKET_TCP_SEQ_7:
		case ROHC_PACKET_TCP_RND_1:
		case ROHC_PACKET_TCP_RND_2:
		case ROHC_PACKET_TCP_RND_3:
		case ROHC_PACKET_TCP_RND_4:
		case ROHC_PACKET_TCP_RND_5:
		case ROHC_PACKET_TCP_RND_6:
		case ROHC_PACKET_TCP_RND_7:
			carry_crc_7_or_8 = false;
			break;
		case ROHC_PACKET_UNKNOWN:
		case ROHC_PACKET_MAX:
		default:
			carry_crc_7_or_8 = false;
			break;
	}

	return carry_crc_7_or_8;
}
