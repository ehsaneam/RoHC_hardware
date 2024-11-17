#include "udp_encode.h"

int c_udp_encode(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt, uint8_t *const rohc_pkt,
		const size_t rohc_pkt_max_len)
{
#pragma HLS INTERFACE m_axi port = ip_pkt depth = 1500
#pragma HLS INTERFACE m_axi port = rohc_pkt depth = 1500
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt = &context->rfc3095_specific;
	struct sc_udp_context *udp_context = &rfc3095_ctxt->specific;
	const struct udphdr *udp = (struct udphdr *) (ip_pkt + sizeof(struct ipv4_hdr));
	int size;

	/* how many UDP fields changed? */
	udp_context->send_udp_dynamic = udp_changed_udp_dynamic(udp_context, udp);

	/* encode the IP packet */
	size = rohc_comp_rfc3095_encode(context, ip_pkt, rohc_pkt, rohc_pkt_max_len);
	if(size < 0)
	{
		return size;
	}

	/* update the context with the new UDP header */
	if(rfc3095_ctxt->rfc_tmp.packet_type == ROHC_PACKET_IR ||
	   rfc3095_ctxt->rfc_tmp.packet_type == ROHC_PACKET_IR_DYN)
	{
		// memcpy is not a valid function in HLS!
		//memcpy(&udp_context->old_udp, udp, sizeof(struct udphdr));
		udp_context->old_udp.source = udp->source;
		udp_context->old_udp.dest = udp->dest;
		udp_context->old_udp.len = udp->len;
		udp_context->old_udp.check = udp->check;
	}
	return size;
}

int rohc_comp_rfc3095_encode(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt, uint8_t *const rohc_pkt,
                             const size_t rohc_pkt_max_len)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	int size;

	rfc3095_ctxt = &context->rfc3095_specific;
	rfc3095_ctxt->rfc_tmp.changed_fields2 = 0;
	rfc3095_ctxt->rfc_tmp.nr_ip_id_bits2 = 0;
	rfc3095_ctxt->rfc_tmp.packet_type = ROHC_PACKET_UNKNOWN;

	/* detect changes between new uncompressed packet and context */
	if(!rohc_comp_rfc3095_detect_changes(context, ip_pkt))
	{
		return -1;
	}

	/* decide in which state to go */
	udp_decide_state(context);
	if(context->mode == ROHC_U_MODE)
	{
		rohc_comp_periodic_down_transition(context);
	}

	/* compute how many bits are needed to send header fields */
	if(!udp_encode_uncomp_fields(context, ip_pkt))
	{
		return -1;
	}

	/* decide which packet to send */
	rfc3095_ctxt->rfc_tmp.packet_type = udp_decide_packet(context);

	/* does the packet update the decompressor context? */
	if(rohc_packet_carry_crc_7_or_8(rfc3095_ctxt->rfc_tmp.packet_type))
	{
		rfc3095_ctxt->msn_of_last_ctxt_updating_pkt = rfc3095_ctxt->sn;
	}

	/* code the ROHC header (and the extension if needed) */
	size = udp_code_packet(context, ip_pkt, rohc_pkt, rohc_pkt_max_len);
	if(size < 0)
	{
		return -1;
	}

	update_context(rfc3095_ctxt, ip_pkt);
	context->packet_type = rfc3095_ctxt->rfc_tmp.packet_type;
	return size;
}

void udp_decide_state(struct rohc_comp_ctxt *const context)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	struct sc_udp_context *udp_context;

	rfc3095_ctxt = &context->rfc3095_specific;
	udp_context = &rfc3095_ctxt->specific;

	if(udp_context->send_udp_dynamic)
	{
		rohc_comp_change_state(context, ROHC_COMP_STATE_IR);
	}
	else
	{
		rohc_comp_rfc3095_decide_state(context);
	}
}

void rohc_comp_rfc3095_decide_state(struct rohc_comp_ctxt *const context)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	rohc_comp_state_t curr_state;
	rohc_comp_state_t next_state;

	curr_state = context->state;
	rfc3095_ctxt = &context->rfc3095_specific;

	if(curr_state == ROHC_COMP_STATE_IR)
	{
		if(context->ir_count < MAX_IR_COUNT)
		{
			next_state = ROHC_COMP_STATE_IR;
		}
		else if(rfc3095_ctxt->rfc_tmp.send_static)
		{
			next_state = ROHC_COMP_STATE_IR;
		}
		else if(rfc3095_ctxt->rfc_tmp.send_dynamic)
		{
			next_state = ROHC_COMP_STATE_FO;
		}
		else
		{
			next_state = ROHC_COMP_STATE_SO;
		}
	}
	else if(curr_state == ROHC_COMP_STATE_FO)
	{
		if(context->fo_count < MAX_FO_COUNT)
		{
			next_state = ROHC_COMP_STATE_FO;
		}
		else if(rfc3095_ctxt->rfc_tmp.send_static || rfc3095_ctxt->rfc_tmp.send_dynamic)
		{
			next_state = ROHC_COMP_STATE_FO;
		}
		else
		{
			next_state = ROHC_COMP_STATE_SO;
		}
	}
	else if(curr_state == ROHC_COMP_STATE_SO)
	{
		if(rfc3095_ctxt->rfc_tmp.send_static || rfc3095_ctxt->rfc_tmp.send_dynamic)
		{
			next_state = ROHC_COMP_STATE_FO;
		}
		else
		{
			next_state = ROHC_COMP_STATE_SO;
		}
	}
	else
	{
		return;
	}

	rohc_comp_change_state(context, next_state);
}

void update_context(struct rohc_comp_rfc3095_ctxt *const rfc3095_ctxt, uint8_t *ip_pkt)
{
	const struct ipv4_hdr *ip_hdr = (struct ipv4_hdr *) ip_pkt;

	/* update the context with the new headers */
	rfc3095_ctxt->outer_ip_flags.is_first_header = false;
	rfc3095_ctxt->outer_ip_flags.info.v4.old_rnd = rfc3095_ctxt->outer_ip_flags.info.v4.rnd;
	rfc3095_ctxt->outer_ip_flags.info.v4.old_nbo = rfc3095_ctxt->outer_ip_flags.info.v4.nbo;
	rfc3095_ctxt->outer_ip_flags.info.v4.old_sid = rfc3095_ctxt->outer_ip_flags.info.v4.sid;

	rfc3095_ctxt->outer_ip_flags.info.v4.old_ip.check = ip_hdr->check;
	rfc3095_ctxt->outer_ip_flags.info.v4.old_ip.daddr = ip_hdr->daddr;
	rfc3095_ctxt->outer_ip_flags.info.v4.old_ip.saddr = ip_hdr->saddr;
	rfc3095_ctxt->outer_ip_flags.info.v4.old_ip.protocol = ip_hdr->protocol;
	rfc3095_ctxt->outer_ip_flags.info.v4.old_ip.dscp_ecn = ip_hdr->dscp_ecn;
	rfc3095_ctxt->outer_ip_flags.info.v4.old_ip.frag_off = ip_hdr->frag_off;
	rfc3095_ctxt->outer_ip_flags.info.v4.old_ip.ttl = ip_hdr->ttl;
	rfc3095_ctxt->outer_ip_flags.info.v4.old_ip.tot_len = ip_hdr->tot_len;
	rfc3095_ctxt->outer_ip_flags.info.v4.old_ip.id = ip_hdr->id;
	rfc3095_ctxt->outer_ip_flags.info.v4.old_ip.tos = ip_hdr->tos;
	rfc3095_ctxt->outer_ip_flags.info.v4.old_ip.ihl = ip_hdr->ihl;
	rfc3095_ctxt->outer_ip_flags.info.v4.old_ip.version = ip_hdr->version;
}
