#include "udp_code.h"

int udp_code_packet(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt, uint8_t *const rohc_pkt,
                const size_t rohc_pkt_max_len)
{
	switch(context->rfc3095_specific.rfc_tmp.packet_type)
	{
		case ROHC_PACKET_IR:
			return udp_code_IR_packet(context, ip_pkt, rohc_pkt, rohc_pkt_max_len);
		case ROHC_PACKET_IR_DYN:
			return udp_code_IR_DYN_packet(context, ip_pkt, rohc_pkt, rohc_pkt_max_len);
		case ROHC_PACKET_UO_0:
			return udp_code_UO0_packet(context, ip_pkt, rohc_pkt, rohc_pkt_max_len);
		case ROHC_PACKET_UO_1:
			return rohc_comp_rfc3095_build_uo1_pkt(context, ip_pkt, rohc_pkt, rohc_pkt_max_len);
		case ROHC_PACKET_UOR_2:
			return udp_code_UO2_packet(context, ip_pkt, rohc_pkt, rohc_pkt_max_len);
		default:
			return -1;
	}
}

int udp_code_IR_packet(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt, uint8_t *const rohc_pkt,
			const size_t rohc_pkt_max_len)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt = &context->rfc3095_specific;
	uint8_t type;
	size_t counter;
	size_t first_position;
	int crc_position;
	int ret;

	ret = code_cid_values(context->cid, rohc_pkt, rohc_pkt_max_len, &first_position);
	if(ret < 1)
	{
		return -1;
	}
	counter = ret;

	type = 0xfc;
	type &= 0xfe;
	rohc_pkt[first_position] = type;

	if((rohc_pkt_max_len - counter) < 2)
	{
		return -1;
	}

	rohc_pkt[counter] = context->pid;
	counter++;

	crc_position = counter;
	rohc_pkt[counter] = 0;
	counter++;

	ret = rohc_code_static_part(&context->rfc3095_specific.outer_ip_flags, ip_pkt, rohc_pkt, counter);
	if(ret < 0)
	{
		return -1;
	}
	counter = ret;

	ret = rohc_code_dynamic_part(context, ip_pkt, rohc_pkt, counter);
	if(ret < 0)
	{
		return -1;
	}
	counter = ret;

	ret = c_ip_code_ir_remainder(context->rfc3095_specific.sn, rohc_pkt, rohc_pkt_max_len, counter);
	if(ret < 0)
	{
		return -1;
	}
	counter = ret;

	rohc_pkt[crc_position] = crc_calc_8(rohc_pkt, counter, CRC_INIT_8);
	/* invalid CRC-STATIC cache since some STATIC fields may have changed */
	rfc3095_ctxt->is_crc_static_3_cached_valid = false;
	rfc3095_ctxt->is_crc_static_7_cached_valid = false;

	return counter;
}

int udp_code_IR_DYN_packet(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt,  uint8_t *const rohc_pkt,
                              const size_t rohc_pkt_max_len)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	size_t counter;
	size_t first_position;
	int crc_position;
	int ret;

	rfc3095_ctxt = &context->rfc3095_specific;
	ret = code_cid_values(context->cid, rohc_pkt, rohc_pkt_max_len, &first_position);
	if(ret < 1)
	{
		return -1;
	}
	counter = ret;

	rohc_pkt[first_position] = 0xf8;

	if((rohc_pkt_max_len - counter) < 2)
	{
		return -1;
	}

	rohc_pkt[counter] = context->pid;
	counter++;

	crc_position = counter;
	rohc_pkt[counter] = 0;
	counter++;

	ret = rohc_code_dynamic_part(context, ip_pkt, rohc_pkt, counter);
	if(ret < 0)
	{
		return -1;
	}
	counter = ret;

	ret = c_ip_code_ir_remainder(rfc3095_ctxt->sn, rohc_pkt, rohc_pkt_max_len, counter);
	if(ret < 0)
	{
		return -1;
	}
	counter = ret;

	rohc_pkt[crc_position] = crc_calc_8(rohc_pkt, counter, CRC_INIT_8);

	/* invalid CRC-STATIC cache since some STATIC fields may have changed */
	rfc3095_ctxt->is_crc_static_3_cached_valid = false;
	rfc3095_ctxt->is_crc_static_7_cached_valid = false;

	return counter;
}

int udp_code_UO0_packet(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt, uint8_t *const rohc_pkt,
                           const size_t rohc_pkt_max_len)
{
	size_t counter;
	size_t first_position;
	uint8_t f_byte;
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	uint8_t crc;
	int ret;

	rfc3095_ctxt = &context->rfc3095_specific;
	ret = code_cid_values(context->cid, rohc_pkt, rohc_pkt_max_len, &first_position);
	if(ret < 1)
	{
		return -1;
	}
	counter = ret;

	f_byte = (rfc3095_ctxt->sn & 0x0f) << 3;
	crc = compute_uo_crc(&context->rfc3095_specific, ip_pkt, ROHC_CRC_TYPE_3, CRC_INIT_3);
	f_byte |= crc;
	rohc_pkt[first_position] = f_byte;

	/* build the UO tail */
	counter = code_uo_remainder(&context->rfc3095_specific, ip_pkt, rohc_pkt, counter);

	return counter;
}

int rohc_comp_rfc3095_build_uo1_pkt(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt,
		uint8_t *const rohc_pkt, const size_t rohc_pkt_max_len)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt = &context->rfc3095_specific;
	size_t counter;
	size_t first_position;
	uint8_t crc;
	int ret;

	ip_header_pos_t innermost_ip_hdr;
	size_t nr_innermost_ip_id_bits;
	uint16_t innermost_ip_id_delta;

	if(rfc3095_ctxt->outer_ip_flags.version == 4 &&
	   rfc3095_ctxt->outer_ip_flags.info.v4.rnd == 0)
	{
		/* outer IP header is IPv4 with a non-random IP-ID */
		innermost_ip_hdr = ROHC_IP_HDR_FIRST;
		nr_innermost_ip_id_bits = rfc3095_ctxt->rfc_tmp.nr_ip_id_bits;
		innermost_ip_id_delta = rfc3095_ctxt->outer_ip_flags.info.v4.id_delta;
	}
	else
	{
		/* there is no IPv4 header with a non-random IP-ID */
		innermost_ip_hdr = ROHC_IP_HDR_NONE;
		nr_innermost_ip_id_bits = 0;
		innermost_ip_id_delta = 0;
	}

	ret = code_cid_values(context->cid, rohc_pkt, rohc_pkt_max_len, &first_position);
	if(ret < 1)
	{
		return -1;
	}
	counter = ret;

	rohc_pkt[first_position] = 0x80 | (innermost_ip_id_delta & 0x3f);
	if((rohc_pkt_max_len - counter) < 1)
	{
		return -1;
	}

	crc = compute_uo_crc(&context->rfc3095_specific, ip_pkt, ROHC_CRC_TYPE_3, CRC_INIT_3);
	rohc_pkt[counter] = ((rfc3095_ctxt->sn & 0x1f) << 3) | (crc & 0x07);
	counter++;

	counter = code_uo_remainder(&context->rfc3095_specific, ip_pkt, rohc_pkt, counter);
	return counter;
}

int udp_code_UO2_packet(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt,
                           uint8_t *const rohc_pkt, const size_t rohc_pkt_max_len)
{
	uint8_t f_byte;     /* part 2 */
	uint8_t t_byte = 0; /* part 5 */
	size_t counter;
	size_t first_position;
	size_t t_byte_position;
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	rohc_packet_t packet_type;
	int ret;

	rfc3095_ctxt = &context->rfc3095_specific;
	packet_type = rfc3095_ctxt->rfc_tmp.packet_type;

	ret = code_cid_values(context->cid, rohc_pkt, rohc_pkt_max_len, &first_position);
	if(ret < 1)
	{
		return -1;
	}
	counter = ret;
	f_byte = 0xc0; /* 1 1 0 x x x x x */

	t_byte = compute_uo_crc(&context->rfc3095_specific, ip_pkt, ROHC_CRC_TYPE_7, CRC_INIT_7);
	t_byte_position = counter;
	counter++;

	if( packet_type == ROHC_PACKET_UOR_2 )
	{
		f_byte |= rfc3095_ctxt->sn & 0x1f;
		t_byte &= ~0x80;
	}

	rohc_pkt[first_position] = f_byte;
	if(t_byte_position >= rohc_pkt_max_len)
	{
		return -1;
	}
	rohc_pkt[t_byte_position] = t_byte;

	ret = counter;
	if(ret < 0)
	{
		return -1;
	}
	counter = ret;

	counter = code_uo_remainder(&context->rfc3095_specific, ip_pkt, rohc_pkt, counter);
	return counter;
}

int rohc_code_static_part(struct ip_header_info *const header_info, uint8_t *ip_pkt,
		uint8_t *const rohc_pkt, int counter)
{
	/* static part of the outer IP header */
	int ret = rohc_code_static_ip_part(header_info, ip_pkt, rohc_pkt, counter);
	if(ret < 0)
	{
		return -1;
	}
	counter = ret;

	ret = udp_code_static_udp_part(ip_pkt, rohc_pkt, counter);
	if(ret < 0)
	{
		return -1;
	}
	counter = ret;
	return counter;
}

int rohc_code_static_ip_part(struct ip_header_info *const header_info, uint8_t *ip_pkt,
		uint8_t *const dest, int counter)
{
	const struct ipv4_hdr *const ipv4_hdr = (struct ipv4_hdr *) ip_pkt;
	if(ipv4_hdr->version == 4)
	{
		uint32_t daddr;

		/* part 1 */
		dest[counter] = 0x40;
		counter++;

		/* part 2 */
		dest[counter] = ipv4_hdr->protocol;
		counter++;
		header_info->protocol_count++;

		uint8_t *saddr_bytes = &ipv4_hdr->saddr;
		dest[counter] = saddr_bytes[0];
		dest[counter+1] = saddr_bytes[1];
		dest[counter+2] = saddr_bytes[2];
		dest[counter+3] = saddr_bytes[3];
		counter += 4;

		uint8_t *daddr_bytes = &ipv4_hdr->daddr;
		dest[counter] = daddr_bytes[0];
		dest[counter+1] = daddr_bytes[1];
		dest[counter+2] = daddr_bytes[2];
		dest[counter+3] = daddr_bytes[3];
		counter += 4;
	}

	return counter;
}

size_t udp_code_static_udp_part(const uint8_t *const ip_pkt, uint8_t *const dest, size_t counter)
{
	const struct udphdr *const udp = (struct udphdr *) (ip_pkt + sizeof(struct ipv4_hdr));

	/* part 1 */
	uint8_t *src_port_bytes = &udp->source;
	dest[counter] = src_port_bytes[0];
	dest[counter+1] = src_port_bytes[1];
	counter += 2;

	/* part 2 */
	uint8_t *dst_port_bytes = &udp->dest;
	dest[counter] = dst_port_bytes[0];
	dest[counter+1] = dst_port_bytes[1];
	counter += 2;

	return counter;
}

int rohc_code_dynamic_part(const struct rohc_comp_ctxt *const context, const uint8_t *const ip_pkt,
		uint8_t *const rohc_pkt, int counter)
{
	/* dynamic part of the outer IP header */
	int ret = udp_code_ipv4_dynamic_part(&context->rfc3095_specific.outer_ip_flags, ip_pkt, rohc_pkt, counter);
	if(ret < 0)
	{
		return -1;
	}
	counter = ret;

	ret = udp_code_dynamic_udp_part(&context->rfc3095_specific.specific, ip_pkt, rohc_pkt, counter);
	if(ret < 0)
	{
		return -1;
	}
	counter = ret;

	return counter;
}

int udp_code_ipv4_dynamic_part(struct ip_header_info *const header_info, const uint8_t *const ip_pkt,
						  uint8_t *const dest, int counter)
{
	const struct ipv4_hdr *const ipv4_hdr = (struct ipv4_hdr *) ip_pkt;
	uint8_t df_rnd_nbo_sid;

	dest[counter] = ipv4_hdr->tos;
	counter++;
	header_info->tos_count++;

	dest[counter] = ipv4_hdr->ttl;
	counter++;
	header_info->ttl_count++;

	uint8_t *id_bytes = &ipv4_hdr->id;
	dest[counter] = id_bytes[0];
	dest[counter+1] = id_bytes[1];
	counter += 2;

	df_rnd_nbo_sid = ipv4_hdr->df << 7;
	if(header_info->info.v4.rnd)
	{
		df_rnd_nbo_sid |= 0x40;
	}
	if(header_info->info.v4.nbo)
	{
		df_rnd_nbo_sid |= 0x20;
	}
	if(header_info->info.v4.sid)
	{
		df_rnd_nbo_sid |= 0x10;
	}
	dest[counter] = df_rnd_nbo_sid;
	counter++;

	header_info->info.v4.df_count++;
	header_info->info.v4.rnd_count++;
	header_info->info.v4.nbo_count++;
	header_info->info.v4.sid_count++;
	dest[counter] = 0x00;
	counter++;

	return counter;
}

size_t udp_code_dynamic_udp_part(struct sc_udp_context *udp_context, const uint8_t *const ip_pkt,
								uint8_t *const dest, const size_t counter)
{
	const struct udphdr *udp = (struct udphdr *) (ip_pkt + sizeof(struct ipv4_hdr));
	uint8_t *check_bytes = &udp->check;
	dest[counter] = check_bytes[0];
	dest[counter+1] = check_bytes[1];
	udp_context->udp_checksum_change_count++;

	return counter + 2;
}

int c_ip_code_ir_remainder(uint32_t sn, uint8_t *const dest, const size_t dest_max_len, const size_t counter)
{
	if((counter + 2) > dest_max_len)
	{
		return -1;
	}
	sn = sn & 0xffff;
	sn = rohc_bswap16(sn);
	uint8_t *sn_bytes = &sn;
	dest[counter] = sn_bytes[0];
	dest[counter+1] = sn_bytes[1];

	return counter + 2;
}

uint8_t compute_uo_crc(struct rohc_comp_rfc3095_ctxt *const rfc3095_ctxt, uint8_t *ip_pkt,
					  const rohc_crc_type_t crc_type, const uint8_t crc_init)
{
	uint8_t crc = crc_init;

	/* compute CRC on CRC-STATIC fields */
	if(rfc3095_ctxt->is_crc_static_3_cached_valid && crc_type == ROHC_CRC_TYPE_3)
	{
		crc = rfc3095_ctxt->crc_static_3_cached;
	}
	else if(rfc3095_ctxt->is_crc_static_7_cached_valid && crc_type == ROHC_CRC_TYPE_7)
	{
		crc = rfc3095_ctxt->crc_static_7_cached;
	}
	else
	{
		crc = udp_compute_crc_static(ip_pkt, crc_type, crc);

		switch(crc_type)
		{
			case ROHC_CRC_TYPE_3:
				rfc3095_ctxt->crc_static_3_cached = crc;
				rfc3095_ctxt->is_crc_static_3_cached_valid = true;
				break;
			case ROHC_CRC_TYPE_7:
				rfc3095_ctxt->crc_static_7_cached = crc;
				rfc3095_ctxt->is_crc_static_7_cached_valid = true;
				break;
			default:
				break;
		}
	}

	/* compute CRC on CRC-DYNAMIC fields */
	crc = udp_compute_crc_dynamic(ip_pkt, crc_type, crc);

	return crc;
}

uint8_t udp_compute_crc_static(const uint8_t *const ip_pkt, const rohc_crc_type_t crc_type,
		const uint8_t init_val)
{
	const struct ip_hdr *const ip_hdr = (struct ip_hdr *) ip_pkt;
	uint8_t crc = init_val;
	if(ip_hdr->version == 4)
	{
		const struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *) ip_pkt;

		crc = crc_calculate(crc_type, (uint8_t *)(ipv4_hdr), 2, crc);
		crc = crc_calculate(crc_type, (uint8_t *)(&ipv4_hdr->frag_off), 4, crc);
		crc = crc_calculate(crc_type, (uint8_t *)(&ipv4_hdr->saddr), 8, crc);
	}

	const struct udphdr *udp = (struct udphdr *) (ip_pkt + sizeof(struct ipv4_hdr));
	crc = crc_calculate(crc_type, (uint8_t *)(&udp->source), 4, crc);

	return crc;
}

uint8_t udp_compute_crc_dynamic(const uint8_t *const ip_pkt, const rohc_crc_type_t crc_type,
                                const uint8_t init_val)
{
	uint8_t crc = init_val;
	const struct ip_hdr *const ip_hdr = (struct ip_hdr *) ip_pkt;
	if(ip_hdr->version == 4)
	{
		const struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *) ip_pkt;
		crc = crc_calculate(crc_type, (uint8_t *)(&ipv4_hdr->tot_len), 4, crc);
		crc = crc_calculate(crc_type, (uint8_t *)(&ipv4_hdr->check), 2, crc);
	}

	const struct udphdr *udp = (struct udphdr *) (ip_pkt + sizeof(struct ipv4_hdr));
	crc = crc_calculate(crc_type, (uint8_t *)(&udp->len), 4, crc);

	return crc;
}

int code_uo_remainder(struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt, uint8_t *const ip_pkt,
					 uint8_t *const dest, int counter)
{
	uint16_t id;
	const struct ipv4_hdr *ip_hdr = (struct ipv4_hdr *) ip_pkt;

	/* parts 6: only IPv4 */
	if(ip_hdr->version == 4 && rfc3095_ctxt->outer_ip_flags.info.v4.rnd == 1)
	{
		/* do not care of Network Byte Order because IP-ID is random */
		uint8_t *id_bytes = &ip_hdr->id;
		dest[counter] = id_bytes[0];
		dest[counter+1] = id_bytes[1];
		counter += 2;
	}

	const struct udphdr *const udp = (struct udphdr *) (ip_pkt + sizeof(struct ipv4_hdr));
	if(udp->check != 0)
	{
		uint8_t *check_bytes = &udp->check;
		dest[counter] = check_bytes[0];
		dest[counter+1] = check_bytes[1];
		counter += 2;
	}
	return counter;
}
