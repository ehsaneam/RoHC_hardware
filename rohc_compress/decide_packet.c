#include "decide_packet.h"

int tcp_decide_packet(struct rohc_comp_ctxt *const context,
		uint8_t *ip_pkt)
{
#pragma HLS INTERFACE m_axi port = ip_pkt depth = 1500
	rohc_packet_t packet_type;
	bool crc7_at_least;

	const struct tcphdr *tcp = (struct tcphdr *)(ip_pkt + sizeof(struct ipv4_hdr));
	switch(context->state)
	{
		case ROHC_COMP_STATE_IR: /* The Initialization and Refresh (IR) state */
			packet_type = ROHC_PACKET_IR;
			context->ir_count++;
			break;
		case ROHC_COMP_STATE_FO: /* The First Order (FO) state */
			context->fo_count++;
			crc7_at_least = true;
			packet_type = tcp_decide_FO_SO_packet(context, tcp, crc7_at_least);
			break;
		case ROHC_COMP_STATE_SO: /* The Second Order (SO) state */
			context->so_count++;
			crc7_at_least = false;
			packet_type = tcp_decide_FO_SO_packet(context, tcp, crc7_at_least);
			break;
		case ROHC_COMP_STATE_UNKNOWN:
		default:
			break;
	}

	return packet_type;
}

rohc_packet_t tcp_decide_FO_SO_packet(const struct rohc_comp_ctxt *const context,
                                             const struct tcphdr *const tcp,
                                             const bool crc7_at_least)
{
	const struct sc_tcp_context *tcp_context = &context->specific;
	rohc_packet_t packet_type;

	if(tcp_context->tmp.nr_msn_bits > 4)
	{
		packet_type = ROHC_PACKET_IR_DYN;
	}
	else if(!rsf_index_enc_possible(tcp->rsf_flags))
	{
		packet_type = ROHC_PACKET_IR_DYN;
	}
	else if(tcp_context->tmp.outer_ip_ttl_changed ||
	        tcp_context->tmp.ip_id_behavior_changed ||
	        tcp_context->tmp.ip_df_changed ||
	        tcp_context->tmp.dscp_changed ||
	        tcp_context->tmp.tcp_ack_flag_changed ||
	        tcp_context->tmp.tcp_urg_flag_present ||
	        tcp_context->tmp.tcp_urg_flag_changed ||
	        tcp_context->old_tcphdr.urg_ptr != tcp->urg_ptr ||
	        !tcp_is_ack_stride_static(tcp_context->ack_stride,
	                                  tcp_context->ack_num_scaling_nr))
	{
		packet_type = ROHC_PACKET_TCP_CO_COMMON;
	}
	else if(tcp_context->tmp.ecn_used_changed ||
	        tcp_context->tmp.ttl_hopl_changed)
	{
		const uint32_t seq_num_hbo = rohc_bswap32(tcp->seq_num);
		const uint32_t ack_num_hbo = rohc_bswap32(tcp->ack_num);
		size_t nr_seq_bits_65535; /* min bits required to encode TCP seqnum with p = 65535 */
		size_t nr_seq_bits_8191; /* min bits required to encode TCP seqnum with p = 8191 */
		size_t nr_ack_bits_8191; /* min bits required to encode TCP ACK number with p = 8191 */

//#pragma HLS pipeline
		nr_seq_bits_65535 = wlsb_get_minkp_32bits(&tcp_context->seq_wlsb, seq_num_hbo, 65535);
		nr_seq_bits_8191 = wlsb_get_minkp_32bits(&tcp_context->seq_wlsb, seq_num_hbo, 8191);
		nr_ack_bits_8191 = wlsb_get_minkp_32bits(&tcp_context->ack_wlsb, ack_num_hbo, 8191);

		/* use compressed header with a 7-bit CRC (rnd_8, seq_8 or common):
		 *  - use common if too many LSB of sequence number are required
		 *  - use common if too many LSB of sequence number are required
		 *  - use common if too many LSB of innermost TTL/Hop Limit are required
		 *  - use common if window changed */
		if(tcp_context->ip_context.ip_id_behavior <= IP_ID_BEHAVIOR_SEQ_SWAP &&
		   tcp_context->tmp.nr_ip_id_bits_3 <= 4 &&
		   nr_seq_bits_8191 <= 14 &&
		   nr_ack_bits_8191 <= 15 &&
		   tcp_context->tmp.nr_ttl_hopl_bits <= 3 &&
		   !tcp_context->tmp.tcp_window_changed)
		{
			/* IP_ID_BEHAVIOR_SEQ or IP_ID_BEHAVIOR_SEQ_SWAP */
			packet_type = ROHC_PACKET_TCP_SEQ_8;
		}
		else if(tcp_context->ip_context.ip_id_behavior > IP_ID_BEHAVIOR_SEQ_SWAP &&
		        nr_seq_bits_65535 <= 16 &&
		        tcp_context->tmp.nr_ack_bits_16383 <= 16 &&
		        tcp_context->tmp.nr_ttl_hopl_bits <= 3 &&
		        !tcp_context->tmp.tcp_window_changed)
		{
			packet_type = ROHC_PACKET_TCP_RND_8;
		}
		else
		{
			packet_type = ROHC_PACKET_TCP_CO_COMMON;
		}
	}
	else if(tcp_context->ip_context.ip_id_behavior <= IP_ID_BEHAVIOR_SEQ_SWAP)
	{
		/* IP_ID_BEHAVIOR_SEQ or IP_ID_BEHAVIOR_SEQ_SWAP:
		 * co_common or seq_X packet types */
		packet_type = tcp_decide_FO_SO_packet_seq(context, tcp, crc7_at_least);
	}
	else if(tcp_context->ip_context.ip_id_behavior == IP_ID_BEHAVIOR_RAND ||
			tcp_context->ip_context.ip_id_behavior == IP_ID_BEHAVIOR_ZERO)
	{
		/* IP_ID_BEHAVIOR_RAND or IP_ID_BEHAVIOR_ZERO:
		 * co_common or rnd_X packet types */
//		packet_type = tcp_decide_FO_SO_packet_rnd(context, tcp, crc7_at_least);
		const uint32_t seq_num_hbo = rohc_bswap32(tcp->seq_num);
		const uint32_t ack_num_hbo = rohc_bswap32(tcp->ack_num);
		size_t nr_seq_bits_65535 = wlsb_get_minkp_32bits(&tcp_context->seq_wlsb, seq_num_hbo, 65535);
		size_t nr_ack_bits_65535 = wlsb_get_minkp_32bits(&tcp_context->ack_wlsb, ack_num_hbo, 65535);
		size_t nr_seq_bits_8191 = wlsb_get_minkp_32bits(&tcp_context->seq_wlsb, seq_num_hbo, 8191);
		size_t nr_ack_bits_8191 = wlsb_get_minkp_32bits(&tcp_context->ack_wlsb, ack_num_hbo, 8191);
		const bool ack_scale_possible = tcp_is_ack_scaled_possible(tcp_context->ack_stride,
				tcp_context->ack_num_scaling_nr);

		{
#pragma HLS pipeline
			packet_type = tcp_decide_FO_SO_packet_rnd123(tcp->rsf_flags, tcp_context->tmp.tcp_window_changed,
					nr_seq_bits_65535, tcp_context->tmp.nr_ack_bits_16383, nr_ack_bits_65535, crc7_at_least,
					tcp_context->tmp.tcp_seq_num_changed);
			if( packet_type==ROHC_PACKET_UNKNOWN )
			{
				packet_type = tcp_decide_FO_SO_packet_rnd456(tcp_context->tmp.tcp_window_changed, crc7_at_least,
						tcp_context->seq_num_scaling_nr, tcp_context->tmp.nr_seq_scaled_bits,
						tcp_context->tmp.tcp_ack_num_changed, tcp_context->tmp.payload_len, tcp->ack_flag,
						tcp_context->tmp.nr_ack_scaled_bits, tcp_context->tmp.tcp_seq_num_changed,
						ack_scale_possible);
				if( packet_type==ROHC_PACKET_UNKNOWN )
				{
					packet_type = tcp_decide_FO_SO_packet_rnd789(tcp->ack_flag, nr_ack_bits_8191, crc7_at_least,
							tcp_context->tmp.tcp_seq_num_changed, nr_seq_bits_65535,
							tcp_context->tmp.tcp_ack_num_changed, tcp_context->tmp.nr_ack_bits_16383,
							tcp_context->seq_num_scaling_nr, tcp_context->tmp.nr_seq_scaled_bits);
					if( packet_type==ROHC_PACKET_UNKNOWN )
					{
						packet_type = tcp_decide_FO_SO_packet_rndab(crc7_at_least, nr_seq_bits_8191, tcp->ack_flag,
								nr_ack_bits_8191, tcp_context->tmp.nr_ack_bits_16383, nr_seq_bits_65535);
					}
				}
			}
		}
	}
	else
	{
		return ROHC_PACKET_UNKNOWN;
	}

	return packet_type;
}

rohc_packet_t tcp_decide_FO_SO_packet_seq(const struct rohc_comp_ctxt *const context,
                                                 const struct tcphdr *const tcp,
                                                 const bool crc7_at_least)
{
	const struct sc_tcp_context *tcp_context = &context->specific;
	const uint32_t seq_num_hbo = rohc_bswap32(tcp->seq_num);
	const uint32_t ack_num_hbo = rohc_bswap32(tcp->ack_num);
	size_t nr_seq_bits_32767; /* min bits required to encode TCP seqnum with p = 32767 */
	size_t nr_seq_bits_8191; /* min bits required to encode TCP seqnum with p = 8191 */
	size_t nr_ack_bits_8191; /* min bits required to encode TCP ACK number with p = 8191 */
	rohc_packet_t packet_type;

	nr_seq_bits_32767 = wlsb_get_minkp_32bits(&tcp_context->seq_wlsb, seq_num_hbo, 32767);
	nr_seq_bits_8191 = wlsb_get_minkp_32bits(&tcp_context->seq_wlsb, seq_num_hbo, 8191);
	nr_ack_bits_8191 = wlsb_get_minkp_32bits(&tcp_context->ack_wlsb, ack_num_hbo, 8191);

	if(tcp->rsf_flags != 0)
	{
		/* seq_8 or co_common
		 *
		 * seq_8 can be used if:
		 *  - TCP window didn't change,
		 *  - at most 14 LSB of the TCP sequence number are required,
		 *  - at most 15 LSB of the TCP ACK number are required,
		 *  - at most 4 LSBs of IP-ID must be transmitted
		 * otherwise use co_common packet */
		if(tcp_context->tmp.nr_ip_id_bits_3 <= 4 &&
		   nr_seq_bits_8191 <= 14 &&
		   nr_ack_bits_8191 <= 15 &&
		   tcp_context->tmp.nr_ttl_hopl_bits <= 3 &&
		   !tcp_context->tmp.tcp_window_changed)
		{
			/* seq_8 is possible */
			packet_type = ROHC_PACKET_TCP_SEQ_8;
		}
		else
		{
			packet_type = ROHC_PACKET_TCP_CO_COMMON;
		}
	}
	else if(tcp_context->tmp.tcp_window_changed)
	{
		size_t nr_ack_bits_32767; /* min bits required to encode TCP ACK number with p = 32767 */

		nr_ack_bits_32767 = wlsb_get_minkp_32bits(&tcp_context->ack_wlsb, ack_num_hbo, 32767);

		/* seq_7 or co_common */
		if(!crc7_at_least &&
		   tcp_context->tmp.nr_window_bits_16383 <= 15 &&
		   tcp_context->tmp.nr_ip_id_bits_3 <= 5 &&
		   nr_ack_bits_32767 <= 16 &&
		   !tcp_context->tmp.tcp_seq_num_changed)
		{
			/* seq_7 is possible */
			packet_type = ROHC_PACKET_TCP_SEQ_7;
		}
		else
		{
			/* rnd_7 is not possible, rnd_8 neither so fallback on co_common */
			packet_type = ROHC_PACKET_TCP_CO_COMMON;
		}
	}
	else if(tcp->ack_flag == 0 || !tcp_context->tmp.tcp_ack_num_changed)
	{
		/* seq_2, seq_1 or co_common */
		if(!crc7_at_least &&
		   tcp_context->tmp.nr_ip_id_bits_3 <= 7 &&
		   tcp_context->seq_num_scaling_nr >= ROHC_INIT_TS_STRIDE_MIN &&
		   tcp_context->tmp.nr_seq_scaled_bits <= 4)
		{
			/* seq_2 is possible */
			packet_type = ROHC_PACKET_TCP_SEQ_2;
		}
		else if(!crc7_at_least &&
		        tcp_context->tmp.nr_ip_id_bits_3 <= 4 &&
		        nr_seq_bits_32767 <= 16)
		{
			/* seq_1 is possible */
			packet_type = ROHC_PACKET_TCP_SEQ_1;
		}
		else if(tcp_context->tmp.nr_ip_id_bits_3 <= 4 &&
		        nr_ack_bits_8191 <= 15 && nr_seq_bits_8191 <= 14)
		{
			packet_type = ROHC_PACKET_TCP_SEQ_8;
		}
		else
		{

			packet_type = ROHC_PACKET_TCP_CO_COMMON;
		}
	}
	else if(!tcp_context->tmp.tcp_seq_num_changed)
	{
		/* seq_4, seq_3, or co_common */
		if(!crc7_at_least &&
		   tcp_context->tmp.nr_ip_id_bits_1 <= 3 &&
		   tcp_is_ack_scaled_possible(tcp_context->ack_stride,
		                              tcp_context->ack_num_scaling_nr) &&
		   tcp_context->tmp.nr_ack_scaled_bits <= 4)
		{

			packet_type = ROHC_PACKET_TCP_SEQ_4;
		}
		else if(!crc7_at_least &&
		        tcp_context->tmp.nr_ip_id_bits_3 <= 4 &&
		        tcp_context->tmp.nr_ack_bits_16383 <= 16)
		{

			packet_type = ROHC_PACKET_TCP_SEQ_3;
		}
		else if(tcp_context->tmp.nr_ip_id_bits_3 <= 4 &&
		        nr_ack_bits_8191 <= 15 &&
		        nr_seq_bits_8191 <= 14)
		{

			packet_type = ROHC_PACKET_TCP_SEQ_8;
		}
		else
		{

			packet_type = ROHC_PACKET_TCP_CO_COMMON;
		}
	}
	else
	{
		/* sequence and acknowledgment numbers changed:
		 * seq_6, seq_5, seq_8 or co_common */
		if(!crc7_at_least &&
		   tcp_context->tmp.nr_ip_id_bits_3 <= 4 &&
		   tcp_context->seq_num_scaling_nr >= ROHC_INIT_TS_STRIDE_MIN &&
		   tcp_context->tmp.nr_seq_scaled_bits <= 4 &&
		   tcp_context->tmp.nr_ack_bits_16383 <= 16)
		{
			packet_type = ROHC_PACKET_TCP_SEQ_6;
		}
		else if(!crc7_at_least &&
		        tcp_context->tmp.nr_ip_id_bits_3 <= 4 &&
		        tcp_context->tmp.nr_ack_bits_16383 <= 16 &&
		        nr_seq_bits_32767 <= 16)
		{

			packet_type = ROHC_PACKET_TCP_SEQ_5;
		}
		else if(tcp_context->tmp.nr_ip_id_bits_3 <= 4 &&
		        nr_seq_bits_8191 <= 14 &&
		        nr_ack_bits_8191 <= 15 &&
		        tcp_context->tmp.nr_ttl_hopl_bits <= 3 &&
		        !tcp_context->tmp.tcp_window_changed)
		{

			packet_type = ROHC_PACKET_TCP_SEQ_8;
		}
		else
		{

			packet_type = ROHC_PACKET_TCP_CO_COMMON;
		}
	}

	return packet_type;
}

rohc_packet_t tcp_decide_FO_SO_packet_rnd123(uint8_t rsf_flags, bool tcp_window_changed,
			 size_t nr_seq_bits_65535, size_t nr_ack_bits_16383, size_t nr_ack_bits_65535,
			 const bool crc7_at_least, bool tcp_seq_num_changed)
{
	if(rsf_flags != 0 && !tcp_window_changed && nr_seq_bits_65535 <= 16 && nr_ack_bits_16383 <= 16)
	{
		return ROHC_PACKET_TCP_RND_8;
	}
	else if(rsf_flags != 0)
	{
		return ROHC_PACKET_TCP_CO_COMMON;
	}
	else if(tcp_window_changed && !crc7_at_least && !tcp_seq_num_changed && nr_ack_bits_65535 <= 18)
	{
		return ROHC_PACKET_TCP_RND_7;
	}
	else
	{
		return ROHC_PACKET_UNKNOWN;
	}
}

rohc_packet_t tcp_decide_FO_SO_packet_rnd456(bool tcp_window_changed, const bool crc7_at_least,
		size_t seq_num_scaling_nr, size_t nr_seq_scaled_bits, bool tcp_ack_num_changed, size_t payload_len,
		uint8_t ack_flag, size_t nr_ack_scaled_bits, bool tcp_seq_num_changed, bool ack_scale_possible)
{
	if(tcp_window_changed)
	{
		return ROHC_PACKET_TCP_CO_COMMON;
	}
	else if(!crc7_at_least && seq_num_scaling_nr >= ROHC_INIT_TS_STRIDE_MIN && nr_seq_scaled_bits <= 4 &&
			!tcp_ack_num_changed && payload_len > 0)
	{
		return ROHC_PACKET_TCP_RND_2;
	}
	else if(!crc7_at_least && !tcp_seq_num_changed && ack_flag != 0 && ack_scale_possible &&
			nr_ack_scaled_bits <= 4)
	{
		return ROHC_PACKET_TCP_RND_4;
	}
	else
	{
		return ROHC_PACKET_UNKNOWN;
	}
}
rohc_packet_t tcp_decide_FO_SO_packet_rnd789(uint8_t ack_flag, size_t nr_ack_bits_8191, const bool crc7_at_least,
		bool tcp_seq_num_changed, size_t nr_seq_bits_65535, bool tcp_ack_num_changed, size_t nr_ack_bits_16383,
		size_t seq_num_scaling_nr, size_t nr_seq_scaled_bits)
{
	if(ack_flag != 0 && nr_ack_bits_8191 <= 15 && !crc7_at_least && !tcp_seq_num_changed)
	{
		return ROHC_PACKET_TCP_RND_3;
	}
	else if(!crc7_at_least && nr_seq_bits_65535 <= 18 && !tcp_ack_num_changed)
	{
		return ROHC_PACKET_TCP_RND_1;
	}
	else if(ack_flag != 0 && nr_ack_bits_16383 <= 16 && !crc7_at_least &&
			seq_num_scaling_nr >= ROHC_INIT_TS_STRIDE_MIN &&
			nr_seq_scaled_bits <= 4)
	{
		return ROHC_PACKET_TCP_RND_6;
	}
	else
	{
		return ROHC_PACKET_UNKNOWN;
	}
}
rohc_packet_t tcp_decide_FO_SO_packet_rndab(const bool crc7_at_least, size_t nr_seq_bits_8191,
		uint8_t ack_flag, size_t nr_ack_bits_8191, size_t nr_ack_bits_16383, size_t nr_seq_bits_65535)
{
	if(!crc7_at_least &&  ack_flag != 0 && nr_ack_bits_8191 <= 15 && nr_seq_bits_8191 <= 14)
	{
		return ROHC_PACKET_TCP_RND_5;
	}
	else if(nr_ack_bits_16383 <= 16 && nr_seq_bits_65535 <= 16)
	{
		return ROHC_PACKET_TCP_RND_8;
	}
	else
	{
		return ROHC_PACKET_TCP_CO_COMMON;
	}
}
rohc_packet_t tcp_decide_FO_SO_packet_rnd(const struct rohc_comp_ctxt *const context,
                                                 const struct tcphdr *const tcp,
                                                 const bool crc7_at_least)
{
	const struct sc_tcp_context *tcp_context = &context->specific;
	const uint32_t seq_num_hbo = rohc_bswap32(tcp->seq_num);
	const uint32_t ack_num_hbo = rohc_bswap32(tcp->ack_num);
	size_t nr_seq_bits_65535 = wlsb_get_minkp_32bits(&tcp_context->seq_wlsb, seq_num_hbo, 65535);
	size_t nr_ack_bits_65535 = wlsb_get_minkp_32bits(&tcp_context->ack_wlsb, ack_num_hbo, 65535);
	size_t nr_seq_bits_8191 = wlsb_get_minkp_32bits(&tcp_context->seq_wlsb, seq_num_hbo, 8191);
	size_t nr_ack_bits_8191 = wlsb_get_minkp_32bits(&tcp_context->ack_wlsb, ack_num_hbo, 8191);

	const bool cond1 = tcp->rsf_flags != 0 && !tcp_context->tmp.tcp_window_changed && nr_seq_bits_65535 <= 16 &&
			tcp_context->tmp.nr_ack_bits_16383 <= 16;
	const bool rnd7 = !crc7_at_least && !tcp_context->tmp.tcp_seq_num_changed;
	const bool cond3 = tcp_context->tmp.tcp_window_changed && rnd7 && nr_ack_bits_65535 <= 18;
	const bool rnd2 = !crc7_at_least && tcp_context->seq_num_scaling_nr >= ROHC_INIT_TS_STRIDE_MIN &&
			tcp_context->tmp.nr_seq_scaled_bits <= 4;
	const bool cond5 = rnd2 && !tcp_context->tmp.tcp_ack_num_changed && tcp_context->tmp.payload_len > 0;
	const bool rnd4 = tcp_is_ack_scaled_possible(tcp_context->ack_stride, tcp_context->ack_num_scaling_nr);
	const bool cond6 = rnd7 && tcp->ack_flag != 0 && rnd4 && tcp_context->tmp.nr_ack_scaled_bits <= 4;
	const bool rnd3 = tcp->ack_flag != 0 && nr_ack_bits_8191 <= 15;
	const bool cond7 = rnd7 && rnd3;
	const bool cond8 = !crc7_at_least && nr_seq_bits_65535 <= 18 && !tcp_context->tmp.tcp_ack_num_changed;
	const bool cond9 = rnd2 && tcp->ack_flag != 0 && tcp_context->tmp.nr_ack_bits_16383 <= 16;
	const bool conda = !crc7_at_least && rnd3 && nr_seq_bits_8191 <= 14;
	const bool condb = tcp_context->tmp.nr_ack_bits_16383 <= 16 && nr_seq_bits_65535 <= 16;

	if(cond1)
	{
		return ROHC_PACKET_TCP_RND_8;
	}

	if(tcp->rsf_flags != 0)
	{
		return ROHC_PACKET_TCP_CO_COMMON;
	}

	if(cond3)
	{
		return ROHC_PACKET_TCP_RND_7;
	}

	if(tcp_context->tmp.tcp_window_changed)
	{
		return ROHC_PACKET_TCP_CO_COMMON;
	}

	if(cond5)
	{
		return ROHC_PACKET_TCP_RND_2;
	}

	if(cond6)
	{
		return ROHC_PACKET_TCP_RND_4;
	}

	if(cond7)
	{
		return ROHC_PACKET_TCP_RND_3;
	}

	if(cond8)
	{
		return ROHC_PACKET_TCP_RND_1;
	}

	if(cond9)
	{
		/* ACK number present */
		return ROHC_PACKET_TCP_RND_6;
	}

	if(conda)
	{
		/* ACK number present */
		return ROHC_PACKET_TCP_RND_5;
	}

	if(condb)
	{
		return ROHC_PACKET_TCP_RND_8;
	}

	return ROHC_PACKET_TCP_CO_COMMON;
}
