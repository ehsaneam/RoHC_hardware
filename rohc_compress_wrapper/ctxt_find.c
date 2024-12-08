#include "ctxt_find.h"

unsigned int lcg_rand_seed = 12345; // Initial seed for LCG

size_t rohc_comp_find_ctxt(struct rohc_comp *const comp,
		const uint8_t *data, const int profile_id_hint, uint16_t arrival_time)
{
#pragma HLS INTERFACE m_axi port = data depth = 1500
	int profile = profile_id_hint;
	size_t cid_to_use = CID_NOT_USED;
	size_t num_used_ctxt_seen = 0;
	size_t i;

	if(profile_id_hint < 0)
	{
		profile = c_get_profile_from_packet(comp, data);
	}

	/* get the context using help from the profile we just found */
	for(i = 0; i <= ROHC_SMALL_CID_MAX; i++)
	{
#pragma HLS loop_tripcount min=1 max=16
		cid_to_use = i;

		if(!comp->contexts[i].used)
		{
			continue;
		}
		num_used_ctxt_seen++;

		if(comp->contexts[i].pid != profile)
		{
			continue;
		}

		if( profile==ROHC_PROFILE_TCP )
		{
			if( c_tcp_check_context(&comp->contexts[i].tcp_specific, data) )
			{
				break;
			}
		}
		else if( profile==ROHC_PROFILE_UDP )
		{
			if( c_udp_check_context(&comp->contexts[i].rfc3095_specific, data) )
			{
				break;
			}
		}
		else // uncompressed profile is always true!
		{
			break;
		}

		if(num_used_ctxt_seen >= comp->num_contexts_used)
		{
			cid_to_use = CID_NOT_USED;
			break;
		}
	}
	if( cid_to_use==CID_NOT_USED || i > ROHC_SMALL_CID_MAX)
	{
		cid_to_use = c_create_context(comp, profile, data, arrival_time);
		if( cid_to_use==CID_NOT_USED )
		{
			return cid_to_use;
		}
	}
	else
	{
		comp->contexts[cid_to_use].latest_used = arrival_time;
	}

	return cid_to_use;
}

int c_get_profile_from_packet(const struct rohc_comp *const comp, const uint8_t *data)
{
	if( c_tcp_check_profile(data) )
	{
		return ROHC_PROFILE_TCP;
	}
	else if( c_udp_check_profile(data) )
	{
		return ROHC_PROFILE_UDP;
	}
	else
	{
		return ROHC_PROFILE_UNCOMPRESSED;
	}
}

bool c_tcp_check_context(struct sc_tcp_context *tcp_context,
		const uint8_t *data)
{
	uint8_t next_proto;
	const struct tcphdr *tcp;
	const ipv4_context_t *const ip_context = &(tcp_context->ip_context);
	const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) data;
	/* check source address */
	if(ipv4->saddr != ip_context->src_addr)
	{
		return false;
	}

	/* check destination address */
	if(ipv4->daddr != ip_context->dst_addr)
	{
		return false;
	}

	next_proto = ipv4->protocol;
	if(next_proto != ip_context->protocol)
	{
		return false;
	}

	tcp = (struct tcphdr *) (data + sizeof(struct ipv4_hdr));

	if(tcp_context->old_tcphdr.src_port != tcp->src_port || tcp_context->old_tcphdr.dst_port != tcp->dst_port)
	{
		return false;
	}

	return true;
}

bool c_udp_check_context(struct rohc_comp_rfc3095_ctxt *const rfc3095_ctxt, const uint8_t *data)
{
	const struct ipv4_hdr *const ipv4_hdr = (struct ipv4_hdr *) data;
	struct ip_header_info *ip_flags;

	ip_flags = &rfc3095_ctxt->outer_ip_flags;

	if(ipv4_hdr->version != 4)
	{
		return false;
	}
	if( ip_flags->info.v4.old_ip.saddr != ipv4_hdr->saddr ||
		ip_flags->info.v4.old_ip.daddr != ipv4_hdr->daddr )
	{
		return false;
	}


	struct sc_udp_context *udp_context = &rfc3095_ctxt->specific;
	const struct udphdr *udp_header = (const struct udphdr *) (data + sizeof(struct ipv4_hdr));
	if(udp_context->old_udp.source != udp_header->source || udp_context->old_udp.dest != udp_header->dest)
	{
		return false;
	}

	return true;
}

bool c_tcp_check_profile(const uint8_t *data)
{
	uint8_t next_proto;
	const struct tcphdr *tcp_header;
	const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) data;
	const size_t ipv4_min_words_nr = sizeof(struct ipv4_hdr) / sizeof(uint32_t);


	if(ipv4->ihl != ipv4_min_words_nr)
	{
		return false;
	}

	if(ipv4_is_fragment(ipv4))
	{
		return false;
	}

	if(ip_fast_csum(data, ipv4_min_words_nr) != 0)
	{
		return false;
	}

	next_proto = ipv4->protocol;
	if(next_proto != ROHC_IPPROTO_TCP )
	{
		return false;
	}

	tcp_header = (const struct tcphdr *) (data + sizeof(struct ipv4_hdr));
	if(tcp_header->data_offset < 5)
	{
		return false;
	}

	return true;
}

bool c_udp_check_profile(const uint8_t *data)
{
	const struct ip_hdr *const ip_hdr = (struct ip_hdr *) data;
	if(ip_hdr->version != 4)
	{
		return false;
	}

	const struct ipv4_hdr *const ipv4_hdr = (struct ipv4_hdr *) data;
	if(ipv4_hdr->ihl*4 != sizeof(struct ipv4_hdr))
	{
		return false;
	}

	/* check if the checksum of the outer IP header is correct */
	if(ip_fast_csum(data, sizeof(struct ipv4_hdr) / sizeof(uint32_t)) != 0)
	{
		return false;
	}

	const struct udphdr *udp_header = (const struct udphdr *) (data + sizeof(struct ipv4_hdr));
	if(udp_header->len < sizeof(struct udphdr))
	{
		return false;
	}

	return true;
}

size_t c_create_context(struct rohc_comp *const comp, int profile,
					 const uint8_t *data, uint16_t arrival_time)
{
	size_t cid_to_use = 0;
	if(comp->num_contexts_used > ROHC_SMALL_CID_MAX)
	{
		uint64_t oldest;
		size_t i;

		/* find the oldest context */
		oldest = 0xffffffff;
		for(i = 0; i <= ROHC_SMALL_CID_MAX; i++)
		{
#pragma HLS loop_tripcount min=1 max=16
			if(comp->contexts[i].latest_used < oldest)
			{
				oldest = comp->contexts[i].latest_used;
				cid_to_use = i;
			}
		}

		comp->contexts[cid_to_use].used = 0;
		comp->num_contexts_used--;
	}
	else
	{
		/* there was at least one unused context in the array, pick the first
		 * unused context in the context array */

		size_t i;

		/* find the first unused context */
		for(i = 0; i <= ROHC_SMALL_CID_MAX; i++)
		{
#pragma HLS loop_tripcount min=1 max=16
			if(comp->contexts[i].used == 0)
			{
				cid_to_use = i;
				break;
			}
		}
	}

	/* initialize the previously found context */
	comp->contexts[cid_to_use].ir_count = 0;
	comp->contexts[cid_to_use].fo_count = 0;
	comp->contexts[cid_to_use].so_count = 0;
	comp->contexts[cid_to_use].go_back_fo_count = 0;
	comp->contexts[cid_to_use].go_back_ir_count = 0;
	comp->contexts[cid_to_use].num_sent_packets = 0;

	comp->contexts[cid_to_use].cid = cid_to_use;
	comp->contexts[cid_to_use].pid = profile;

	comp->contexts[cid_to_use].mode = ROHC_U_MODE;
	comp->contexts[cid_to_use].state = ROHC_COMP_STATE_IR;

	if( profile==ROHC_PROFILE_TCP )
	{
		c_tcp_create_from_pkt(&comp->contexts[cid_to_use], data);
	}
	else
	{
		c_udp_create(&comp->contexts[cid_to_use], data);
	}

	/* if creation is successful, mark the context as used */
	comp->contexts[cid_to_use].used = 1;
	comp->contexts[cid_to_use].latest_used = arrival_time;
	comp->num_contexts_used++;
	return cid_to_use;
}

void c_tcp_create_from_pkt(struct rohc_comp_ctxt *const context,
		const uint8_t *data)
{
	struct sc_tcp_context *tcp_context = &(context->tcp_specific);
	const struct tcphdr *tcp;

	tcp_context->ip_contexts_nr = 0;
	const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) data;
	ipv4_context_t *const ip_context = &(tcp_context->ip_context);

	ip_context->last_ip_id = rohc_bswap16(ipv4->id);
	ip_context->last_ip_id_behavior = IP_ID_BEHAVIOR_SEQ;
	ip_context->ip_id_behavior = IP_ID_BEHAVIOR_SEQ;
	ip_context->version = ipv4->version;
	ip_context->protocol = ipv4->protocol;
	ip_context->dscp = ipv4->dscp;
	ip_context->df = ipv4->df;
	ip_context->ttl_hopl = ipv4->ttl;
	ip_context->src_addr = ipv4->saddr;
	ip_context->dst_addr = ipv4->daddr;

	tcp_context->ip_contexts_nr++;

	/* create context for TCP header */
	tcp_context->tcp_seq_num_change_count = 0;
	tcp_context->ttl_hopl_change_count = 0;
	tcp_context->tcp_window_change_count = 0;
	tcp_context->ecn_used = false;
	tcp_context->ecn_used_change_count = MAX_FO_COUNT;
	tcp_context->ecn_used_zero_count = 0;

	/* TCP header begins just after the IP headers */
	tcp = (struct tcphdr *) (data + sizeof(struct ipv4_hdr));
	tcp_context->old_tcphdr.src_port = tcp->src_port;
	tcp_context->old_tcphdr.dst_port = tcp->dst_port;
	tcp_context->old_tcphdr.seq_num = tcp->seq_num;
	tcp_context->old_tcphdr.ack_num = tcp->ack_num;
	tcp_context->old_tcphdr.res_flags = tcp->res_flags;
	tcp_context->old_tcphdr.data_offset = tcp->data_offset;
	tcp_context->old_tcphdr.rsf_flags = tcp->rsf_flags;
	tcp_context->old_tcphdr.psh_flag = tcp->psh_flag;
	tcp_context->old_tcphdr.ack_flag = tcp->ack_flag;
	tcp_context->old_tcphdr.urg_flag = tcp->urg_flag;
	tcp_context->old_tcphdr.ecn_flags = tcp->ecn_flags;
	tcp_context->old_tcphdr.window = tcp->window;
	tcp_context->old_tcphdr.checksum = tcp->checksum;
	tcp_context->old_tcphdr.urg_ptr = tcp->urg_ptr;

	/* MSN */
	wlsb_init(&tcp_context->msn_wlsb, 16, ROHC_WLSB_WIDTH_MAX, ROHC_LSB_SHIFT_TCP_SN);
	/* IP-ID offset */
	wlsb_init(&tcp_context->ip_id_wlsb, 16, ROHC_WLSB_WIDTH_MAX, ROHC_LSB_SHIFT_VAR);
	/* innermost IPv4 TTL or IPv6 Hop Limit */
	wlsb_init(&tcp_context->ttl_hopl_wlsb, 8, ROHC_WLSB_WIDTH_MAX, ROHC_LSB_SHIFT_TCP_TTL);
	/* TCP window */
	wlsb_init(&tcp_context->window_wlsb, 16, ROHC_WLSB_WIDTH_MAX, ROHC_LSB_SHIFT_TCP_WINDOW);
	/* TCP sequence number */
	tcp_context->seq_num = rohc_bswap32(tcp->seq_num);
	wlsb_init(&tcp_context->seq_wlsb, 32, ROHC_WLSB_WIDTH_MAX, ROHC_LSB_SHIFT_VAR);
	wlsb_init(&tcp_context->seq_scaled_wlsb, 32, ROHC_WLSB_WIDTH_MAX, 7);
	/* TCP acknowledgment (ACK) number */
	tcp_context->ack_num = rohc_bswap32(tcp->ack_num);
	wlsb_init(&tcp_context->ack_wlsb, 32, ROHC_WLSB_WIDTH_MAX, ROHC_LSB_SHIFT_VAR);
	wlsb_init(&tcp_context->ack_scaled_wlsb, 32, ROHC_WLSB_WIDTH_MAX, 3);

	/* init the Master Sequence Number to a random value */
	tcp_context->msn = lcg_rand() & 0xffff;
	tcp_context->ack_stride = 0;
}

bool c_udp_create(struct rohc_comp_ctxt *const context, const uint8_t *data)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	struct sc_udp_context *udp_context;
	const struct udphdr *udp;

	/* create and initialize the generic part of the profile context */
	rohc_comp_rfc3095_create(context, 16, ROHC_LSB_SHIFT_SN, data);
	rfc3095_ctxt = &context->rfc3095_specific;

	/* initialize SN to a random value (RFC 3095, 5.11.1) */
	rfc3095_ctxt->sn = lcg_rand() & 0xffff;

	/* check that transport protocol is UDP */
	udp = (struct udphdr *) (data + sizeof(struct ipv4_hdr));

	udp_context = &rfc3095_ctxt->specific;
	/* initialize the UDP part of the profile context */
	udp_context->udp_checksum_change_count = 0;

	// memcpy is not a valid function in HLS!
	//memcpy(&udp_context->old_udp, udp, sizeof(struct udphdr));
	udp_context->old_udp.source = udp->source;
	udp_context->old_udp.dest = udp->dest;
	udp_context->old_udp.len = udp->len;
	udp_context->old_udp.check = udp->check;
	udp_context->send_udp_dynamic = -1;
	rfc3095_ctxt->next_header_len = sizeof(struct udphdr);

	return true;
}

void rohc_comp_rfc3095_create(struct rohc_comp_ctxt *const context, const size_t sn_bits_nr,
                              const rohc_lsb_shift_t sn_shift, uint8_t *ip_pkt)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt = &context->rfc3095_specific;
	const struct ipv4_hdr *const ipv4_hdr = (struct ipv4_hdr *) ip_pkt;

	wlsb_init(&rfc3095_ctxt->sn_window, sn_bits_nr, ROHC_WLSB_WIDTH_MAX, sn_shift);
	wlsb_init(&rfc3095_ctxt->msn_non_acked, 16, ROHC_WLSB_WIDTH_MAX, sn_shift);

	/* step 3 */
	ip_header_info_new(&rfc3095_ctxt->outer_ip_flags, ipv4_hdr->version);
	rfc3095_ctxt->ip_hdr_nr = 1;

	/* step 4 */
	c_init_tmp_variables(&rfc3095_ctxt->rfc_tmp);

	/* step 5 */
	rfc3095_ctxt->next_header_proto = ipv4_hdr->protocol;
	rfc3095_ctxt->next_header_len = 0;
	rfc3095_ctxt->is_crc_static_3_cached_valid = false;
	rfc3095_ctxt->is_crc_static_7_cached_valid = false;
}

void ip_header_info_new(struct ip_header_info *const header_info, uint8_t version)
{
	header_info->version = version;
	header_info->is_first_header = true;
	if(header_info->version == 4)
	{
		wlsb_init(&header_info->info.v4.ip_id_window, 16, ROHC_WLSB_WIDTH_MAX, ROHC_LSB_SHIFT_IP_ID);
		header_info->tos_count = MAX_FO_COUNT;
		header_info->ttl_count = MAX_FO_COUNT;
		header_info->info.v4.df_count = MAX_FO_COUNT;
		header_info->protocol_count = MAX_FO_COUNT;
		header_info->info.v4.rnd_count = MAX_FO_COUNT;
		header_info->info.v4.nbo_count = MAX_FO_COUNT;
		header_info->info.v4.sid_count = MAX_FO_COUNT;
	}
}

void c_init_tmp_variables(struct generic_tmp_vars *const tmp_vars)
{
	tmp_vars->changed_fields = MOD_ERROR;
	tmp_vars->changed_fields2 = MOD_ERROR;
	tmp_vars->send_static = -1;
	tmp_vars->send_dynamic = -1;

	/* do not send any bits of SN, outer/inner IP-IDs, outer/inner IPv6
	 * extension header list by default */
	tmp_vars->nr_sn_bits_less_equal_than_4 = 0;
	tmp_vars->nr_sn_bits_more_than_4 = 0;
	tmp_vars->nr_ip_id_bits = 0;
	tmp_vars->nr_ip_id_bits2 = 0;

	tmp_vars->packet_type = ROHC_PACKET_UNKNOWN;
}

uint16_t ip_fast_csum(const uint8_t *const iph, const size_t ihl)
{
	const uint8_t *buff = iph;
	size_t len = ihl * 4;
	bool odd;
	size_t count;
	uint32_t result = 0;

	if(len == 0)
	{
		return ~result;
	}
	odd = 1 & (uintptr_t) buff;
	if(odd)
	{
#ifdef __LITTLE_ENDIAN
		result = *buff;
#else
		result += (*buff << 8);
#endif
		len--;
		buff++;
	}
	count = len >> 1; /* nr of 16-bit words.. */
	if(count)
	{
		if(2 & (uintptr_t) buff)
		{
			result += *(uint16_t *) buff;
			count--;
			len -= 2;
			buff += 2;
		}
		count >>= 1; /* nr of 32-bit words.. */
		if(count)
		{
			uint32_t carry = 0;
			do
			{
				uint32_t word = *(uint32_t *) buff;
				count--;
				buff += sizeof(uint32_t);
				result += carry;
				result += word;
				carry = (word > result);
			}
			while(count);
			result += carry;
			result = (result & 0xffff) + (result >> 16);
		}
		if(len & 2)
		{
			result += *(uint16_t *) buff;
			buff += 2;
		}
	}
	if(len & 1)
	{
#ifdef __LITTLE_ENDIAN
		result += *buff;
#else
		result += (*buff << 8);
#endif
	}
	result = from32to16(result);
	if(odd)
	{
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
	}
	return ~result;
}

bool ipv4_is_fragment(const struct ipv4_hdr *const ipv4)
{
	return !!((rohc_bswap16(ipv4->frag_off) & (~IPV4_DF)) != 0);
}

uint16_t from32to16(const uint32_t x)
{
	uint32_t y;
	/* add up 16-bit and 16-bit for 16+c bit */
	y = (x & 0xffff) + (x >> 16);
	/* add up carry.. */
	y = (y & 0xffff) + (y >> 16);
	return y;
}

unsigned int lcg_rand()
{
    // LCG parameters (adjust as needed)
    unsigned int a = 1664525;
    unsigned int c = 1013904223;
    lcg_rand_seed = (a * lcg_rand_seed + c);
    return lcg_rand_seed;
}
