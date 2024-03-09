#include "ctxt_find.h"

unsigned int lcg_rand_seed = 12345; // Initial seed for LCG
struct rohc_comp_profile c_tcp_profile = {.id = ROHC_PROFILE_TCP,};

size_t rohc_comp_find_ctxt(struct rohc_comp *const comp,
		const uint8_t *data, const int profile_id_hint,
		const struct rohc_ts arrival_time)
{
#pragma HLS INTERFACE m_axi port = data depth = 1500
	const struct rohc_comp_profile *profile;
	size_t cid_to_use = CID_NOT_USED;
	size_t num_used_ctxt_seen = 0;
	size_t i;

	if(profile_id_hint < 0)
	{
		profile = c_get_profile_from_packet(comp, data);
	}
	else
	{
		profile = rohc_get_profile_from_id(comp, profile_id_hint);
	}

	if(profile == NULL)
	{
		return CID_NOT_USED;
	}

	/* get the context using help from the profile we just found */
	for(i = 0; i <= comp->medium.max_cid; i++)
	{
#pragma HLS loop_tripcount min=1 max=16
		size_t cr_score = 0;
		cid_to_use = i;

		if(!comp->contexts[i].used)
		{
			continue;
		}
		num_used_ctxt_seen++;

		if(comp->contexts[i].profile.id != profile->id)
		{
			continue;
		}

		if( c_tcp_check_context(&comp->contexts[i].specific, data, &cr_score) )
		{
			break;
		}

		if(num_used_ctxt_seen >= comp->num_contexts_used)
		{
			cid_to_use = CID_NOT_USED;
			break;
		}
	}
	if( cid_to_use==CID_NOT_USED || i > comp->medium.max_cid)
	{
		printf("FLAG4 %lu\n", cid_to_use);
		cid_to_use = c_create_context(comp, profile, data, arrival_time);
		printf("FLAG5 %lu\n", cid_to_use);
		if( cid_to_use==CID_NOT_USED )
		{
			return cid_to_use;
		}
	}
	else
	{
		printf("FLAG6 %lu\n", cid_to_use);
		comp->contexts[cid_to_use].latest_used = arrival_time.sec;
	}

	return cid_to_use;
}

const struct rohc_comp_profile* c_get_profile_from_packet(const struct rohc_comp *const comp,
		const uint8_t *data)
{
	size_t i;

	/* test all compression profiles */
	for(i = 0; i < C_NUM_PROFILES; i++)
	{
		bool check_profile;

		/* skip profile if the profile is not enabled */
		if(!comp->enabled_profiles[i])
		{
			continue;
		}

		/* does the profile accept the packet? */
		check_profile = c_tcp_check_profile(comp, data);
		if(!check_profile)
		{
			continue;
		}

		/* the packet is compatible with the profile, let's go with it! */
		return &c_tcp_profile;
	}

	return NULL;
}

const struct rohc_comp_profile* rohc_get_profile_from_id(const struct rohc_comp *comp,
	                         const int profile_id)
{
	size_t i;

	/* test all compression profiles */
	for(i = 0; i < C_NUM_PROFILES; i++)
	{
		/* if the profile IDs match and the profile is enabled */
		if(c_tcp_profile.id == profile_id && comp->enabled_profiles[i])
		{
			return &c_tcp_profile;
		}
	}

	return NULL;
}

bool c_tcp_check_context(struct sc_tcp_context *tcp_context,
		const uint8_t *data, size_t *const cr_score)
{
	uint8_t next_proto;
	const struct tcphdr *tcp;

	(*cr_score) = 0;

	const ipv4_context_t *const ip_context = &(tcp_context->ip_context);
	const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) data;
	/* check source address */
	printf("FLAG0\n");
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

	/* the packet matches the context enough to use Context Replication */
	(*cr_score)++;

	tcp = (struct tcphdr *) (data + sizeof(struct ipv4_hdr));

	printf("FLAG1 %hu - %hu\n", tcp_context->old_tcphdr.src_port, tcp->src_port);
	/* check TCP source port */
	if(tcp_context->old_tcphdr.src_port != tcp->src_port)
	{
		if(!rsf_index_enc_possible(tcp->rsf_flags))
		{
			(*cr_score) = 0;
		}
		return false;
	}
	(*cr_score)++;

	printf("FLAG2 %hu - %hu\n", tcp_context->old_tcphdr.dst_port, tcp->dst_port);
	/* check TCP destination port */
	if(tcp_context->old_tcphdr.dst_port != tcp->dst_port)
	{
		return false;
	}
	printf("FLAG3\n");
	(*cr_score)++;

	return true;
}

bool c_tcp_check_profile(const struct rohc_comp *const comp,
		const uint8_t *data)
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

	if((comp->features & ROHC_COMP_FEATURE_NO_IP_CHECKSUMS) == 0 &&
		ip_fast_csum(data, ipv4_min_words_nr) != 0)
	{
		return false;
	}

	next_proto = ipv4->protocol;
	if(next_proto != ROHC_IPPROTO_TCP)
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

size_t c_create_context(struct rohc_comp *const comp,
	                 const struct rohc_comp_profile *const profile,
					 const uint8_t *data,
	                 const struct rohc_ts arrival_time)
{
	struct rohc_comp_ctxt *c;
	size_t cid_to_use = 0;
	size_t win_width = comp->wlsb_window_width;
	if(comp->num_contexts_used > comp->medium.max_cid)
	{
		uint64_t oldest;
		size_t i;

		/* find the oldest context */
		oldest = 0xffffffff;
		for(i = 0; i <= comp->medium.max_cid; i++)
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
		for(i = 0; i <= comp->medium.max_cid; i++)
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
	c = &comp->contexts[cid_to_use];

	c->ir_count = 0;
	c->fo_count = 0;
	c->so_count = 0;
	c->go_back_fo_count = 0;
	c->go_back_fo_time = arrival_time;
	c->go_back_ir_count = 0;
	c->go_back_ir_time = arrival_time;

	c->total_uncompressed_size = 0;
	c->total_compressed_size = 0;
	c->header_uncompressed_size = 0;
	c->header_compressed_size = 0;

	c->total_last_uncompressed_size = 0;
	c->total_last_compressed_size = 0;
	c->header_last_uncompressed_size = 0;
	c->header_last_compressed_size = 0;

	c->num_sent_packets = 0;

	c->cid = cid_to_use;
	c->profile.id = profile->id;

	c->mode = ROHC_U_MODE;
	c->state = ROHC_COMP_STATE_IR;

	c_tcp_create_from_pkt(c, data, win_width);

	/* if creation is successful, mark the context as used */
	c->used = 1;
	c->first_used = arrival_time.sec;
	c->latest_used = arrival_time.sec;
	return cid_to_use;
}

void c_tcp_create_from_pkt(struct rohc_comp_ctxt *const context,
		const uint8_t *data, size_t wlsb_window_width)
{
	struct sc_tcp_context *tcp_context = &(context->specific);
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
	wlsb_init(&tcp_context->msn_wlsb, 16, wlsb_window_width, ROHC_LSB_SHIFT_TCP_SN);
	/* IP-ID offset */
	wlsb_init(&tcp_context->ip_id_wlsb, 16, wlsb_window_width, ROHC_LSB_SHIFT_VAR);
	/* innermost IPv4 TTL or IPv6 Hop Limit */
	wlsb_init(&tcp_context->ttl_hopl_wlsb, 8, wlsb_window_width, ROHC_LSB_SHIFT_TCP_TTL);
	/* TCP window */
	wlsb_init(&tcp_context->window_wlsb, 16, wlsb_window_width, ROHC_LSB_SHIFT_TCP_WINDOW);
	/* TCP sequence number */
	tcp_context->seq_num = rohc_bswap32(tcp->seq_num);
	wlsb_init(&tcp_context->seq_wlsb, 32, wlsb_window_width, ROHC_LSB_SHIFT_VAR);
	wlsb_init(&tcp_context->seq_scaled_wlsb, 32, wlsb_window_width, 7);
	/* TCP acknowledgment (ACK) number */
	tcp_context->ack_num = rohc_bswap32(tcp->ack_num);
	wlsb_init(&tcp_context->ack_wlsb, 32, wlsb_window_width, ROHC_LSB_SHIFT_VAR);
	wlsb_init(&tcp_context->ack_scaled_wlsb, 32, wlsb_window_width, 3);

	/* init the Master Sequence Number to a random value */
	tcp_context->msn = lcg_rand() & 0xffff;
	tcp_context->ack_stride = 0;
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
	/* the rsf_index_enc encoding is possible only if at most one of the RST,
	 * SYN or FIN flag is set */
	uint8_t count = 0;
	uint8_t x = rsf_flags;
	while( x )
	{
#pragma HLS loop_tripcount min=1 max=3
		count += x & 1;
		x >>= 1;
	}
//	return (__builtin_popcount(rsf_flags) <= 1);
	return (count <= 1);
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

uint16_t rohc_bswap16(const uint16_t value)
{
	return (((value >> 8) & 0xff) | ((value & 0xff) << 8));
}

uint32_t rohc_bswap32(const uint32_t value)
{
	return (((value & 0xff000000) >> 24) |
	        ((value & 0x00ff0000) >>  8) |
	        ((value & 0x0000ff00) <<  8) |
	        ((value & 0x000000ff) << 24));
}

unsigned int lcg_rand()
{
    // LCG parameters (adjust as needed)
    unsigned int a = 1664525;
    unsigned int c = 1013904223;
    lcg_rand_seed = (a * lcg_rand_seed + c);
    return lcg_rand_seed;
}
