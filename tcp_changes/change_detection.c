#include "change_detection.h"

void tcp_detect_changes(struct rohc_comp_ctxt *const context,
	   int uncomp_pkt_len, struct ipv4_hdr *ipv4_hdr, struct tcphdr *tcp)
{
	struct sc_tcp_context *const tcp_context = &context->specific;
	size_t hdrs_len = 0;
	uint8_t pkt_ecn_vals = 0;

	const uint16_t ip_id = rohc_bswap16(ipv4_hdr->id);
	pkt_ecn_vals |= ipv4_hdr->ecn;
	hdrs_len += sizeof(struct ipv4_hdr);
	pkt_ecn_vals |= tcp->ecn_flags;

	hdrs_len += sizeof(struct tcphdr);
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
	tcp_context->tmp.payload_len = uncomp_pkt_len - hdrs_len;
	tcp_context->msn = c_tcp_get_next_msn(context);
}


void tcp_detect_ecn_used_behavior(struct rohc_comp_ctxt *const context,
                                         const uint8_t pkt_ecn_vals,
                                         const uint8_t pkt_res_val)
{
	struct sc_tcp_context *const tcp_context = &context->specific;

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
	struct sc_tcp_context *const tcp_context = &context->specific;
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

uint16_t rohc_bswap16(const uint16_t value)
{
	return (((value >> 8) & 0xff) | ((value & 0xff) << 8));
}

uint16_t swab16(const uint16_t value)
{
	return ((value & 0x00ff) << 8) | ((value & 0xff00) >> 8);
}
