#include "code_ir.h"

int code_IR_packet(struct rohc_comp_ctxt *contecst,
				  const uint8_t *ip_pkt,
				  uint8_t *const rohc_pkt,
				  const size_t rohc_pkt_max_len,
				  const int packet_type)
{
#pragma HLS INTERFACE m_axi port = ip_pkt depth = 1500
#pragma HLS INTERFACE m_axi port = rohc_pkt depth = 1500
	struct sc_tcp_context *const tcp_context = &contecst->specific;
	uint8_t *rohc_remain_data = rohc_pkt;
	size_t rohc_remain_len = rohc_pkt_max_len;
	size_t first_position;
	size_t crc_position;
	size_t rohc_hdr_len = 0;
	int ret;

	ret = code_cid_values(contecst->cid, rohc_remain_data, rohc_remain_len,
	                      &first_position);
	if(ret < 1)
	{
		return -1;
	}
	rohc_remain_data += ret;
	rohc_remain_len -= ret;
	rohc_hdr_len += ret;

	/* type of packet */
	if(packet_type == ROHC_PACKET_IR)
	{
		rohc_pkt[first_position] = ROHC_PACKET_TYPE_IR;
	}
	else /* ROHC_PACKET_IR_DYN */
	{
		rohc_pkt[first_position] = ROHC_PACKET_TYPE_IR_DYN;
	}

	/* enough room for profile ID and CRC? */
	if(rohc_remain_len < 2)
	{
		return -1;
	}

	/* profile ID */
	rohc_remain_data[0] = contecst->pid;
	rohc_remain_data++;
	rohc_remain_len--;
	rohc_hdr_len++;

	/* the CRC is computed later since it must be computed over the whole packet
	 * with an empty CRC field */
	crc_position = rohc_hdr_len;
	rohc_remain_data[0] = 0;
	rohc_remain_data++;
	rohc_remain_len--;
	rohc_hdr_len++;

	if(packet_type == ROHC_PACKET_IR || packet_type == ROHC_PACKET_IR_DYN)
	{
		/* add static chain for IR packet only */
		if(packet_type == ROHC_PACKET_IR)
		{
			ret = tcp_code_static_part(ip_pkt, rohc_remain_data, rohc_remain_len);
			if(ret < 0)
			{
				return -1;
			}
			rohc_remain_data += ret;
			rohc_remain_len -= ret;
			rohc_hdr_len += ret;
		}

		/* add dynamic chain for IR and IR-DYN packets only */
		ret = tcp_code_dyn_part(tcp_context, ip_pkt, rohc_remain_data,
		                        rohc_remain_len);
		if(ret < 0)
		{
			return -1;
		}
		rohc_hdr_len += ret;
	}
	/* IR(-CR|-DYN) header was successfully built, compute the CRC */
	rohc_pkt[crc_position] = crc_calc_8(rohc_pkt, rohc_hdr_len);
	return rohc_hdr_len;
}

int tcp_code_static_part(const uint8_t *ip_pkt,
                         uint8_t *rohc_pkt,
                         const size_t rohc_pkt_max_len)
{
	size_t rohc_remain_len = rohc_pkt_max_len;
	size_t ip_hdr_pos;
	int ret;

	/* add IP parts of static chain */
	const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) ip_pkt;
	ret = tcp_code_static_ipv4_part(ipv4, rohc_pkt,
									rohc_remain_len);
	if(ret < 0)
	{
		return -1;
	}
	rohc_pkt += ret;
	rohc_remain_len -= ret;

	/* add TCP static part */
	const struct tcphdr *const tcp = (struct tcphdr *) (ip_pkt + sizeof(struct ipv4_hdr));
	ret = tcp_code_static_tcp_part(tcp, rohc_pkt, rohc_remain_len);
	if(ret < 0)
	{
		return -1;
	}
	rohc_remain_len -= ret;

	return (rohc_pkt_max_len - rohc_remain_len);
}

int tcp_code_static_ipv4_part(const struct ipv4_hdr *const ipv4,
                                     uint8_t *const rohc_data,
                                     const size_t rohc_max_len)
{
	ipv4_static_t *const ipv4_static = (ipv4_static_t *) rohc_data;
	const size_t ipv4_static_len = sizeof(ipv4_static_t);

	if(rohc_max_len < ipv4_static_len)
	{
		return -1;
	}

	ipv4_static->version_flag = 0;
	ipv4_static->reserved = 0;
	ipv4_static->protocol = ipv4->protocol;
	ipv4_static->src_addr = ipv4->saddr;
	ipv4_static->dst_addr = ipv4->daddr;

	return ipv4_static_len;
}

int tcp_code_static_tcp_part(const struct tcphdr *const tcp,
                                    uint8_t *const rohc_data,
                                    const size_t rohc_max_len)
{
	tcp_static_t *const tcp_static = (tcp_static_t *) rohc_data;
	const size_t tcp_static_len = sizeof(tcp_static_t);

	if(rohc_max_len < tcp_static_len)
	{
		return -1;
	}

	tcp_static->src_port = tcp->src_port;
	tcp_static->dst_port = tcp->dst_port;

	return tcp_static_len;
}

int tcp_code_dyn_part(struct sc_tcp_context *const tcp_context,
					  const uint8_t *ip_pkt,
                      uint8_t *rohc_pkt,
                      const size_t rohc_pkt_max_len)
{
	int ret;
	size_t rohc_remain_len = rohc_pkt_max_len;

	ipv4_context_t *const ip_context = &(tcp_context->ip_context);
	const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) ip_pkt;

	ret = tcp_code_dynamic_ipv4_part(ip_context, ipv4, rohc_pkt, rohc_remain_len);
	if(ret < 0)
	{
		return -1;
	}
	rohc_pkt += ret;
	rohc_remain_len -= ret;

	/* handle TCP header */
	const struct tcphdr *const tcp = (struct tcphdr *) (ip_pkt + sizeof(struct ipv4_hdr));
	ret = tcp_code_dynamic_tcp_part(tcp_context, tcp, rohc_pkt, rohc_remain_len);
	if(ret < 0)
	{
		return -1;
	}
	rohc_remain_len -= ret;

	/* update context with new values (done at the very end to avoid wrongly
	 * updating the context in case of compression failure) */
	ip_context->last_ip_id_behavior = ip_context->ip_id_behavior;
	ip_context->last_ip_id = rohc_bswap16(ipv4->id);
	ip_context->df = ipv4->df;
	ip_context->dscp = ipv4->dscp;
	ip_context->ttl_hopl = tcp_context->tmp.ttl_hopl;

	return (rohc_pkt_max_len - rohc_remain_len);
}

int tcp_code_dynamic_ipv4_part(ipv4_context_t *const ip_context,
							  const struct ipv4_hdr *const ipv4,
							  uint8_t *const rohc_data,
							  const size_t rohc_max_len)
{
	ipv4_dynamic1_t *const ipv4_dynamic1 = (ipv4_dynamic1_t *) rohc_data;
	size_t ipv4_dynamic_len = sizeof(ipv4_dynamic1_t);
	uint16_t ip_id;

	if(rohc_max_len < ipv4_dynamic_len)
	{
		return -1;
	}

	/* IP-ID */
	ip_id = rohc_bswap16(ipv4->id);

	ipv4_dynamic1->reserved = 0;
	ipv4_dynamic1->df = ipv4->df;

	/* IP-ID behavior
	 * cf. RFC4996 page 60/61 ip_id_behavior_choice() and ip_id_enc_dyn() */
	ipv4_dynamic1->ip_id_behavior = ip_context->ip_id_behavior;
	/* TODO: should not update context there */
	ip_context->last_ip_id_behavior = ip_context->ip_id_behavior;

	ipv4_dynamic1->dscp = ipv4->dscp;
	ipv4_dynamic1->ip_ecn_flags = ipv4->ecn;
	ipv4_dynamic1->ttl_hopl = ipv4->ttl;

	/* IP-ID itself
	 * cf. RFC4996 page 60/61 ip_id_enc_dyn() */
	if(ipv4_dynamic1->ip_id_behavior != IP_ID_BEHAVIOR_ZERO)
	{
		ipv4_dynamic2_t *const ipv4_dynamic2 = (ipv4_dynamic2_t *) rohc_data;

		ipv4_dynamic_len = sizeof(ipv4_dynamic2_t);
		if(rohc_max_len < ipv4_dynamic_len)
		{
			return -1;
		}

		ipv4_dynamic2->ip_id = ipv4->id;
	}

	/* TODO: should not update context there */
	ip_context->dscp = ipv4->dscp;
	ip_context->ttl_hopl = ipv4->ttl;
	ip_context->df = ipv4->df;
	ip_context->last_ip_id = rohc_bswap16(ipv4->id);

	return ipv4_dynamic_len;
}

int tcp_code_dynamic_tcp_part(struct sc_tcp_context *const tcp_context,
							 const struct tcphdr *const tcp,
							 uint8_t *const rohc_data,
							 const size_t rohc_max_len)
{
	uint8_t *rohc_remain_data = rohc_data;
	size_t rohc_remain_len = rohc_max_len;

	tcp_dynamic_t *const tcp_dynamic = (tcp_dynamic_t *) rohc_remain_data;
	size_t tcp_dynamic_len = sizeof(tcp_dynamic_t);

	int indicator;
	int ret;

	if(rohc_remain_len < tcp_dynamic_len)
	{
		return -1;
	}

	tcp_dynamic->ecn_used = tcp_context->ecn_used;
	tcp_dynamic->tcp_res_flags = tcp->res_flags;
	tcp_dynamic->tcp_ecn_flags = tcp->ecn_flags;
	tcp_dynamic->urg_flag = tcp->urg_flag;
	tcp_dynamic->ack_flag = tcp->ack_flag;
	tcp_dynamic->psh_flag = tcp->psh_flag;
	tcp_dynamic->rsf_flags = tcp->rsf_flags;
	tcp_dynamic->msn = rohc_bswap16(tcp_context->msn);
	tcp_dynamic->seq_num = tcp->seq_num;

	rohc_remain_data += sizeof(tcp_dynamic_t);
	rohc_remain_len -= sizeof(tcp_dynamic_t);

	/* TODO: should not update context here */
	tcp_context->tcp_seq_num_change_count++;

	/* ack_zero flag and ACK number: always check for the ACK number value even
	 * if the ACK flag is not set in the uncompressed TCP header, this is
	 * important to transmit all packets without any change, even if those bits
	 * will be ignored at reception */
	ret = c_zero_or_irreg32(tcp->ack_num, rohc_remain_data, rohc_remain_len,
	                        &indicator);
	if(ret < 0)
	{
		return -1;
	}
	tcp_dynamic->ack_zero = indicator;
	rohc_remain_data += ret;
	rohc_remain_len -= ret;

	/* enough room for encoded window and checksum? */
	if(rohc_remain_len < (sizeof(uint16_t) + sizeof(uint16_t)))
	{
		return -1;
	}

	/* window */
	memcpy(rohc_remain_data, &tcp->window, sizeof(uint16_t));
	rohc_remain_data += sizeof(uint16_t);
	rohc_remain_len -= sizeof(uint16_t);

	/* checksum */
	memcpy(rohc_remain_data, &tcp->checksum, sizeof(uint16_t));
	rohc_remain_data += sizeof(uint16_t);
	rohc_remain_len -= sizeof(uint16_t);

	/* urp_zero flag and URG pointer: always check for the URG pointer value
	 * even if the URG flag is not set in the uncompressed TCP header, this is
	 * important to transmit all packets without any change, even if those
	 * bits will be ignored at reception */
	ret = c_zero_or_irreg16(tcp->urg_ptr, rohc_remain_data, rohc_remain_len,
	                        &indicator);
	if(ret < 0)
	{
		return -1;
	}
	tcp_dynamic->urp_zero = indicator;
	rohc_remain_data += ret;
	rohc_remain_len -= ret;

	/* ack_stride */
	const bool is_ack_stride_static =
		tcp_is_ack_stride_static(tcp_context->ack_stride,
								 tcp_context->ack_num_scaling_nr);
	ret = c_static_or_irreg16(rohc_bswap16(tcp_context->ack_stride),
							  is_ack_stride_static,
							  rohc_remain_data, rohc_remain_len, &indicator);
	if(ret < 0)
	{
		return -1;
	}
	tcp_dynamic->ack_stride_flag = indicator;
	rohc_remain_data += ret;
	rohc_remain_len -= ret;

	/* see RFC4996, §6.3.3 : no XI items, PS = 0, m = 0 */
	if(rohc_remain_len < 1)
	{
		return -1;
	}
	rohc_remain_data[0] = 0x00;
	rohc_remain_data++;
	rohc_remain_len--;

	return (rohc_max_len - rohc_remain_len);
}

int c_zero_or_irreg16(const uint16_t packet_value,
                      uint8_t *const rohc_data,
                      const size_t rohc_max_len,
                      int *const indicator)
{
	size_t field_len;

	if(packet_value != 0)
	{
		field_len = sizeof(uint16_t);

		if(rohc_max_len < field_len)
		{
			return -1;
		}

		memcpy(rohc_data, &packet_value, sizeof(uint16_t));
		*indicator = 0;
	}
	else
	{
		field_len = 0;
		*indicator = 1;
	}

	return field_len;
}

int c_zero_or_irreg32(const uint32_t packet_value,
                      uint8_t *const rohc_data,
                      const size_t rohc_max_len,
                      int *const indicator)
{
	size_t field_len;

	if(packet_value != 0)
	{
		field_len = sizeof(uint32_t);

		if(rohc_max_len < field_len)
		{
			return -1;
		}

		memcpy(rohc_data, &packet_value, field_len);
		*indicator = 0;
	}
	else
	{
		field_len = 0;
		*indicator = 1;
	}

	return field_len;
}
