#include "change_detection.h"

///////////////////////////
//			TCP			 //
///////////////////////////
void tcp_detect_changes(struct rohc_comp_ctxt *const context,
	   uint8_t *ip_pkt, int ip_pkt_len)
{
#pragma HLS INTERFACE m_axi port = ip_pkt depth = 1500
	struct sc_tcp_context *const tcp_context = &context->tcp_specific;
	uint8_t pkt_ecn_vals = 0;

	const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) ip_pkt;
	const uint16_t ip_id = rohc_bswap16(ipv4->id);
	pkt_ecn_vals |= ipv4->ecn;
	const struct tcphdr *tcp = (struct tcphdr *)(ip_pkt + sizeof(struct ipv4_hdr));
	pkt_ecn_vals |= tcp->ecn_flags;

	tcp_detect_ecn_used_behavior(context, pkt_ecn_vals,
	                             tcp->res_flags);
	if(context->num_sent_packets == 0)
	{
		tcp_context->ip_context.ip_id_behavior = IP_ID_BEHAVIOR_SEQ;
	}
	else
	{
		tcp_context->ip_context.ip_id_behavior =
			tcp_detect_ip_id_behavior(tcp_context->ip_context.ip_id_behavior, ip_id);
	}
	tcp_context->tmp.payload_len = ip_pkt_len - sizeof(struct ipv4_hdr) - sizeof(struct tcphdr);
	tcp_context->msn = c_tcp_get_next_msn(context);
}

void tcp_detect_ecn_used_behavior(struct rohc_comp_ctxt *const context,
                                         const uint8_t pkt_ecn_vals,
                                         const uint8_t pkt_res_val)
{
	struct sc_tcp_context *const tcp_context = &context->tcp_specific;

	const bool tcp_res_flag_changed =
		(pkt_res_val != tcp_context->old_tcphdr.res_flags);
	const bool ecn_used_change_needed_by_res_flags =
		(tcp_res_flag_changed && !tcp_context->ecn_used);
	const bool ecn_used_change_needed_by_ecn_flags_unset =
		(pkt_ecn_vals == 0 && tcp_context->ecn_used);
	const bool ecn_used_change_needed_by_ecn_flags_set =
		(pkt_ecn_vals != 0 && !tcp_context->ecn_used);
	const bool ecn_used_change_needed =
		(ecn_used_change_needed_by_res_flags ||
		 ecn_used_change_needed_by_ecn_flags_unset ||
		 ecn_used_change_needed_by_ecn_flags_set);

	/* is a change of ecn_used value required? */
	if(ecn_used_change_needed)
	{
		/* a change of ecn_used value seems to be required */
		if(ecn_used_change_needed_by_ecn_flags_unset &&
		   tcp_context->ecn_used_zero_count < MAX_FO_COUNT)
		{
			/* do not change ecn_used = 0 too quickly, wait for a few packets
			 * that do not need ecn_used = 1 to actually perform the change */
			tcp_context->tmp.ecn_used_changed = false;
			tcp_context->ecn_used_zero_count++;
		}
		else
		{
			tcp_context->tmp.ecn_used_changed = true;
			tcp_context->ecn_used =
				!!(pkt_ecn_vals != 0 || tcp_res_flag_changed);
			tcp_context->ecn_used_change_count = 0;
			tcp_context->ecn_used_zero_count = 0;
		}
	}
	else if(tcp_context->ecn_used_change_count < MAX_FO_COUNT)
	{
		tcp_context->tmp.ecn_used_changed = true;
		tcp_context->ecn_used_change_count++;
		tcp_context->ecn_used_zero_count = 0;
	}
	else
	{
		tcp_context->tmp.ecn_used_changed = false;
		tcp_context->ecn_used_zero_count = 0;
	}
}

uint16_t c_tcp_get_next_msn(const struct rohc_comp_ctxt *const context)
{
	const struct sc_tcp_context *const tcp_context = &context->tcp_specific;
	return ((tcp_context->msn + 1) % 0xffff);
}

tcp_ip_id_behavior_t tcp_detect_ip_id_behavior(const uint16_t last_ip_id,
											  const uint16_t new_ip_id)
{
	tcp_ip_id_behavior_t behavior;

	if(is_ip_id_increasing(last_ip_id, new_ip_id))
	{
		behavior = IP_ID_BEHAVIOR_SEQ;
	}
	else
	{
		const uint16_t swapped_last_ip_id = swab16(last_ip_id);
		const uint16_t swapped_new_ip_id = swab16(new_ip_id);

		if(is_ip_id_increasing(swapped_last_ip_id, swapped_new_ip_id))
		{
			behavior = IP_ID_BEHAVIOR_SEQ_SWAP;
		}
		else if(new_ip_id == 0)
		{
			behavior = IP_ID_BEHAVIOR_ZERO;
		}
		else
		{
			behavior = IP_ID_BEHAVIOR_RAND;
		}
	}

	return behavior;
}

///////////////////////////
//			UDP			 //
///////////////////////////
int udp_changed_udp_dynamic(struct sc_udp_context *udp_context, const struct udphdr *udp)
{
	if((udp->check != 0 && udp_context->old_udp.check == 0) ||
	   (udp->check == 0 && udp_context->old_udp.check != 0) ||
	   (udp_context->udp_checksum_change_count < MAX_IR_COUNT))
	{
		if((udp->check != 0 && udp_context->old_udp.check == 0) ||
		   (udp->check == 0 && udp_context->old_udp.check != 0))
		{
			udp_context->udp_checksum_change_count = 0;
		}
		return 1;
	}
	else
	{
		return 0;
	}
}

bool rohc_comp_rfc3095_detect_changes(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt = &context->rfc3095_specific;

	/* compute or find the new SN */
	if(rfc3095_ctxt->sn == 0xffff)
	{
		rfc3095_ctxt->sn = 0;
	}
	else
	{
		rfc3095_ctxt->sn = rfc3095_ctxt->sn + 1;
	}

	/* check NBO and RND of the IP-ID of the IP headers (IPv4 only) */
	udp_detect_ip_id_behaviours(&context->rfc3095_specific.outer_ip_flags, ip_pkt);

	/* find outer IP fields that changed */
	rfc3095_ctxt->rfc_tmp.changed_fields = udp_detect_changed_fields(&rfc3095_ctxt->outer_ip_flags, ip_pkt);
	if(rfc3095_ctxt->rfc_tmp.changed_fields & MOD_ERROR)
	{
		return false;
	}

	/* how many changed fields are static ones? */
	rfc3095_ctxt->rfc_tmp.send_static = udp_changed_static_both_hdr(context);

	/* how many changed fields are dynamic ones? */
	rfc3095_ctxt->rfc_tmp.send_dynamic = udp_changed_dynamic_both_hdr(context, ip_pkt);

	return true;
}

void udp_detect_ip_id_behaviours(struct ip_header_info *const header_info, uint8_t *data)
{
	if(header_info->is_first_header)
	{
		/* IP-ID behaviour cannot be detected for the first header (2 headers are
		 * needed), so consider that IP-ID is not random/static and in NBO. */
		header_info->info.v4.rnd = 0;
		header_info->info.v4.nbo = 1;
		header_info->info.v4.sid = 0;
	}
	else
	{
		/* we have seen at least one header before this one, so we can (try to)
		 * detect IP-ID behaviour */
		const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) data;
		uint16_t old_id; /* the IP-ID of the previous IPv4 header */
		uint16_t new_id; /* the IP-ID of the IPv4 header being compressed */

		old_id = rohc_bswap16(header_info->info.v4.old_ip.id);
		new_id = rohc_bswap16(ipv4->id);

		if(new_id == old_id)
		{
			/* previous and current IP-ID values are equal: IP-ID is constant */
			header_info->info.v4.rnd = 0;
			header_info->info.v4.nbo = 1;
			header_info->info.v4.sid = 1;
		}
		else if(is_ip_id_increasing(old_id, new_id))
		{
			/* IP-ID is increasing in NBO */
			header_info->info.v4.rnd = 0;
			header_info->info.v4.nbo = 1;
			header_info->info.v4.sid = 0;
		}
		else
		{
			/* change byte ordering and check behaviour again */
			old_id = swab16(old_id);
			new_id = swab16(new_id);

			if(is_ip_id_increasing(old_id, new_id))
			{
				/* IP-ID is increasing in Little Endian */
				header_info->info.v4.rnd = 0;
				header_info->info.v4.nbo = 0;
				header_info->info.v4.sid = 0;
			}
			else
			{
				header_info->info.v4.rnd = 1;
				header_info->info.v4.nbo = 1; /* do not change bit order if RND */
				header_info->info.v4.sid = 0;
			}
		}
	}
}

unsigned short udp_detect_changed_fields(struct ip_header_info *const header_info, uint8_t *data)
{
	unsigned short ret_value = 0;
	uint8_t old_tos;
	uint8_t old_ttl;
	uint8_t old_protocol;

	const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) data;
	if(ipv4->version == 4)
	{
		const struct ipv4_hdr *old_ip;

		old_ip = &header_info->info.v4.old_ip;
		old_tos = old_ip->tos;
		old_ttl = old_ip->ttl;
		old_protocol = old_ip->protocol;
	}

	if(old_tos != ipv4->tos)
	{
		ret_value |= MOD_TOS;
	}

	if(old_ttl != ipv4->ttl)
	{
		ret_value |= MOD_TTL;
	}

	if(old_protocol != ipv4->protocol)
	{
		ret_value |= MOD_PROTOCOL;
	}

	return ret_value;
}

int udp_changed_static_both_hdr(struct rohc_comp_ctxt *const context)
{
	/* TODO: should not alter the counters in the context there */
	int nb_fields = 0; /* number of fields that changed */
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt = &context->rfc3095_specific;

	/* check the IPv4 Protocol / IPv6 Next Header field for change */
	if(is_field_changed(rfc3095_ctxt->rfc_tmp.changed_fields, MOD_PROTOCOL) ||
			rfc3095_ctxt->outer_ip_flags.protocol_count < MAX_FO_COUNT)
	{
		if(is_field_changed(rfc3095_ctxt->rfc_tmp.changed_fields, MOD_PROTOCOL))
		{
			rfc3095_ctxt->outer_ip_flags.protocol_count = 0;
			context->fo_count = 0;
		}
		nb_fields += 1;
	}

	return nb_fields;
}

int udp_changed_dynamic_both_hdr(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt)
{
	/* TODO: should not alter the counters in the context there */
	int nb_fields = 0; /* number of fields that changed */
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;

	rfc3095_ctxt = &context->rfc3095_specific;

	if(is_field_changed(rfc3095_ctxt->rfc_tmp.changed_fields, MOD_TOS) ||
	   rfc3095_ctxt->outer_ip_flags.tos_count < MAX_FO_COUNT)
	{
		if(is_field_changed(rfc3095_ctxt->rfc_tmp.changed_fields, MOD_TOS))
		{
			rfc3095_ctxt->outer_ip_flags.tos_count = 0;
			context->fo_count = 0;
		}
		nb_fields++;
	}

	/* check the Time To Live / Hop Limit field for change */
	if(is_field_changed(rfc3095_ctxt->rfc_tmp.changed_fields, MOD_TTL) ||
	   rfc3095_ctxt->outer_ip_flags.ttl_count < MAX_FO_COUNT)
	{
		if(is_field_changed(rfc3095_ctxt->rfc_tmp.changed_fields, MOD_TTL))
		{
			rfc3095_ctxt->outer_ip_flags.ttl_count = 0;
			context->fo_count = 0;
		}
		nb_fields++;
	}

	/* IPv4 only checks */
	const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) ip_pkt;
	if(ipv4->version == 4)
	{
		size_t nb_flags = 0; /* number of flags that changed */

		/* check the Don't Fragment flag for change (IPv4 only) */
		if(ipv4->df != rfc3095_ctxt->outer_ip_flags.info.v4.old_ip.df ||
			rfc3095_ctxt->outer_ip_flags.info.v4.df_count < MAX_FO_COUNT)
		{
			if(ipv4->df != rfc3095_ctxt->outer_ip_flags.info.v4.old_ip.df)
			{
				rfc3095_ctxt->outer_ip_flags.info.v4.df_count = 0;
				context->fo_count = 0;
			}
			nb_fields++;
		}

		/* check the RND flag for change (IPv4 only) */
		if(rfc3095_ctxt->outer_ip_flags.info.v4.rnd != rfc3095_ctxt->outer_ip_flags.info.v4.old_rnd ||
		   rfc3095_ctxt->outer_ip_flags.info.v4.rnd_count < MAX_FO_COUNT)
		{
			if(rfc3095_ctxt->outer_ip_flags.info.v4.rnd != rfc3095_ctxt->outer_ip_flags.info.v4.old_rnd)
			{
				rfc3095_ctxt->outer_ip_flags.info.v4.rnd_count = 0;
				context->fo_count = 0;
			}
			nb_flags++;
		}

		/*  check the NBO flag for change (IPv4 only) */
		if(rfc3095_ctxt->outer_ip_flags.info.v4.nbo != rfc3095_ctxt->outer_ip_flags.info.v4.old_nbo ||
		   rfc3095_ctxt->outer_ip_flags.info.v4.nbo_count < MAX_FO_COUNT)
		{
			if(rfc3095_ctxt->outer_ip_flags.info.v4.nbo != rfc3095_ctxt->outer_ip_flags.info.v4.old_nbo)
			{
				rfc3095_ctxt->outer_ip_flags.info.v4.nbo_count = 0;
				context->fo_count = 0;
			}
			nb_flags += 1;
		}

		if(nb_flags > 0)
		{
			nb_fields++;
		}

		/*  check the SID flag for change (IPv4 only) */
		if(rfc3095_ctxt->outer_ip_flags.info.v4.sid != rfc3095_ctxt->outer_ip_flags.info.v4.old_sid ||
		   rfc3095_ctxt->outer_ip_flags.info.v4.sid_count < MAX_FO_COUNT)
		{
			if(rfc3095_ctxt->outer_ip_flags.info.v4.sid != rfc3095_ctxt->outer_ip_flags.info.v4.old_sid)
			{
				rfc3095_ctxt->outer_ip_flags.info.v4.sid_count = 0;
				context->fo_count = 0;
			}
		}
	}

	return nb_fields;
}

///////////////////////////
//		  COMMON		 //
///////////////////////////
bool is_ip_id_increasing(const uint16_t old_id, const uint16_t new_id)
{
	/* The maximal delta accepted between two consecutive IPv4 ID so that it
	 * can be considered as increasing */
	const uint16_t max_id_delta = 20;
	bool is_increasing;

	/* the new IP-ID is increasing if it belongs to:
	 *  - interval ]old_id ; old_id + IPID_MAX_DELTA[ (no wraparound)
	 *  - intervals ]old_id ; 0xffff] or
	 *    [0 ; (old_id + IPID_MAX_DELTA) % 0xffff[ (wraparound) */
	if(new_id > old_id && (new_id - old_id) < max_id_delta)
	{
		is_increasing = true;
	}
	else if(old_id > (0xffff - max_id_delta) &&
	        (new_id > old_id || new_id < (max_id_delta - (0xffff - old_id))))
	{
		is_increasing = true;
	}
	else
	{
		is_increasing = false;
	}

	return is_increasing;
}

bool is_field_changed(const unsigned short changed_fields, const unsigned short check_field)
{
	return ((changed_fields & check_field) != 0);
}
