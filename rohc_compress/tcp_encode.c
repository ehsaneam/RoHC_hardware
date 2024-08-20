#include "tcp_encode.h"

struct rohc_comp compressor;

int c_tcp_encode(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt, int ip_pkt_len,
		uint8_t *const rohc_pkt, const size_t rohc_pkt_max_len)
{
#pragma HLS INTERFACE m_axi port = ip_pkt depth = 1500
#pragma HLS INTERFACE m_axi port = rohc_pkt depth = 1500
	struct sc_tcp_context *const tcp_context = &context->specific;
	struct tcphdr *tcp;
	uint8_t bit_cntr = 0;

	tcp_context->packet_type = ROHC_PACKET_UNKNOWN;

	/* detect changes between new uncompressed packet and context */
	tcp_detect_changes(context, ip_pkt, ip_pkt_len);

	/* decide in which state to go */
	tcp_decide_state(context);

	/* compute how many bits are needed to send header fields */
	if(!tcp_encode_uncomp_fields(context, ip_pkt))
	{
		return -1;
	}

	/* decide which packet to send */
	tcp_context->packet_type = tcp_decide_packet(context, ip_pkt);

	/* does the packet update the decompressor context? */
	if(rohc_packet_carry_crc_7_or_8(tcp_context->packet_type))
	{
		tcp_context->msn_of_last_ctxt_updating_pkt = tcp_context->msn;
	}

	/* code the chosen packet */
	if(tcp_context->packet_type == ROHC_PACKET_UNKNOWN)
	{
		return -1;
	}
	else if(tcp_context->packet_type != ROHC_PACKET_IR &&
			tcp_context->packet_type != ROHC_PACKET_IR_DYN)
	{
		/* co_common, seq_X, or rnd_X */
		bit_cntr = code_CO_packet(context, ip_pkt, rohc_pkt,
		                         rohc_pkt_max_len, tcp_context->packet_type);
		printf("cntr %d %d\n", bit_cntr, bit_cntr<0);
		if(bit_cntr < 0)
		{
			return -1;
		}
	}
	else /* ROHC_PACKET_IR, ROHC_PACKET_IR_DYN */
	{

		bit_cntr = code_IR_packet(context, ip_pkt, rohc_pkt,
		                         rohc_pkt_max_len, tcp_context->packet_type);
		printf("cntr %d %d\n", bit_cntr, bit_cntr<0);
		if(bit_cntr < 0)
		{
			return -1;
		}
	}

	/* update the context with the new TCP header */
//	memcpy(&(tcp_context->old_tcphdr), tcp, sizeof(struct tcphdr));

//	tcp_context->old_tcphdr.seq_num = tcp->seq_num;
//	tcp_context->old_tcphdr.ack_num = tcp->ack_num;
//	tcp_context->old_tcphdr.ack_flag = tcp->ack_flag;
//	tcp_context->old_tcphdr.ecn_flags = tcp->ecn_flags;
//	tcp_context->old_tcphdr.psh_flag = tcp->psh_flag;
//	tcp_context->old_tcphdr.res_flags = tcp->res_flags;
//	tcp_context->old_tcphdr.rsf_flags = tcp->rsf_flags;
//	tcp_context->old_tcphdr.urg_flag = tcp->urg_flag;
//	tcp_context->old_tcphdr.urg_ptr = tcp->urg_ptr;
//	tcp_context->old_tcphdr.checksum = tcp->checksum;
//	tcp_context->old_tcphdr.window = tcp->window;
//	tcp_context->old_tcphdr.data_offset = tcp->data_offset;
//	tcp_context->old_tcphdr.src_port = tcp->src_port;
//	tcp_context->old_tcphdr.dst_port = tcp->dst_port;

//	tcp_context->seq_num = rohc_bswap32(tcp->seq_num);
//	tcp_context->ack_num = rohc_bswap32(tcp->ack_num);

	/* sequence number */
	c_add_wlsb(&tcp_context->seq_wlsb, tcp_context->msn, tcp_context->seq_num);
	if(tcp_context->seq_num_factor != 0)
	{
		c_add_wlsb(&tcp_context->seq_scaled_wlsb, tcp_context->msn,
		           tcp_context->seq_num_scaled);

		/* sequence number sent once more, count the number of transmissions to
		 * know when scaled sequence number is possible */
		if(tcp_context->seq_num_scaling_nr < ROHC_INIT_TS_STRIDE_MIN)
		{
			tcp_context->seq_num_scaling_nr++;
		}
	}

	/* ACK number */
	c_add_wlsb(&tcp_context->ack_wlsb, tcp_context->msn, tcp_context->ack_num);
	if(tcp_context->ack_stride != 0)
	{
		c_add_wlsb(&tcp_context->ack_scaled_wlsb, tcp_context->msn,
		           tcp_context->ack_num_scaled);

		/* ACK number sent once more, count the number of transmissions to
		 * know when scaled ACK number is possible */
		if(tcp_context->ack_num_scaling_nr < ROHC_INIT_TS_STRIDE_MIN)
		{
			tcp_context->ack_num_scaling_nr++;
		}
	}

	return bit_cntr;
}
