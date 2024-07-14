#include "code_co.h"

extern struct rohc_comp compressor;

int code_CO_packet(struct rohc_comp_ctxt *const context,
				uint8_t *ip_pkt, uint8_t *const rohc_pkt,
				const size_t rohc_pkt_max_len,
				const int packet_type)
{
#pragma HLS INTERFACE m_axi port = ip_pkt depth = 1500
#pragma HLS INTERFACE m_axi port = rohc_pkt depth = 1500

	uint8_t *rohc_remain_data = rohc_pkt;
	size_t rohc_remain_len = rohc_pkt_max_len;
	struct sc_tcp_context *const tcp_context = &context->specific;
	const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) ip_pkt;
	const struct tcphdr *tcp;

	size_t pos_1st_byte;
	size_t pos_2nd_byte;
	size_t payload_size = 0;
	size_t ipv4_hdr_len;
	uint8_t crc_computed;
	int ret;

	ipv4_hdr_len = ipv4->ihl * sizeof(uint32_t);
	payload_size = rohc_bswap16(ipv4->tot_len) - ipv4_hdr_len;

	/* parse the TCP header */
	tcp = (struct tcphdr *)(ip_pkt + ipv4_hdr_len);
	const size_t tcp_data_offset = tcp->data_offset << 2;
	payload_size -= tcp_data_offset;
	size_t payload_offset = ipv4_hdr_len + tcp_data_offset;

	/* we have just identified the IP and TCP headers (options included), so
	 * let's compute the CRC on uncompressed headers */
	if(packet_type == ROHC_PACKET_TCP_SEQ_8 ||
	   packet_type == ROHC_PACKET_TCP_RND_8 ||
	   packet_type == ROHC_PACKET_TCP_CO_COMMON)
	{
		crc_computed = crc_calculate(ROHC_CRC_TYPE_7, ip_pkt, payload_offset,
		                             CRC_INIT_7, compressor.crc_table_7);
	}
	else
	{
		crc_computed = crc_calculate(ROHC_CRC_TYPE_3, ip_pkt, payload_offset,
		                             CRC_INIT_3, compressor.crc_table_3);
	}


	/* write Add-CID or large CID bytes: 'pos_1st_byte' indicates the location
	 * where first header byte shall be written, 'pos_2nd_byte' indicates the
	 * location where the next header bytes shall be written */
	ret = code_cid_values(context->cid, rohc_remain_data, rohc_remain_len, &pos_1st_byte);
	if(ret < 1)
	{
		printf("sag 1\n");
		return -1;
	}
	pos_2nd_byte = ret;
	rohc_remain_data += ret - 1; // 1 for CID octets bw first and other CO octets
	rohc_remain_len -= (ret-1);

	ret = co_baseheader(tcp_context, ipv4, rohc_remain_data, rohc_remain_len,
			packet_type, tcp, crc_computed);
	if(ret < 0)
	{
		printf("sag 2\n");
		return -1;
	}
	rohc_remain_data += ret;
	rohc_remain_len -= ret;

	/* add irregular chain */
	ret = tcp_code_irreg_chain(tcp_context, ip_pkt, ipv4->ecn, tcp,
	                           rohc_remain_data, rohc_remain_len);
	if(ret < 0)
	{
		printf("sag 3\n");
		return -1;
	}
	rohc_remain_len -= ret;

	return (rohc_pkt_max_len - rohc_remain_len);
}

int tcp_code_irreg_chain(struct sc_tcp_context *const tcp_context,
							uint8_t *ip_pkt, const uint8_t ip_inner_ecn,
							const struct tcphdr *const tcp,
							uint8_t *const rohc_pkt,
							const size_t rohc_pkt_max_len)
{
	ipv4_context_t *const ip_context = &(tcp_context->ip_context);
	const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) ip_pkt;

	uint8_t *rohc_remain_data = rohc_pkt;
	size_t rohc_remain_len = rohc_pkt_max_len;
	int ret;

	ret = tcp_code_irregular_ipv4_part(ip_context, ipv4, rohc_remain_data, rohc_remain_len);
	if(ret < 0)
	{
		return -1;
	}
	rohc_remain_data += ret;
	rohc_remain_len -= ret;

	/* TCP part (base header + options) of the irregular chain */
	ret = tcp_code_irregular_tcp_part(tcp_context, tcp, ip_inner_ecn,
	                                  rohc_remain_data, rohc_remain_len);
	if(ret < 0)
	{
		return -1;
	}
	rohc_remain_len -= ret;

	return (rohc_pkt_max_len - rohc_remain_len);
}

int tcp_code_irregular_ipv4_part(const ipv4_context_t *const ip_context,
                                        const struct ipv4_hdr *const ipv4,
                                        uint8_t *const rohc_data,
                                        const size_t rohc_max_len)
{
	uint8_t *rohc_remain_data = rohc_data;
	size_t rohc_remain_len = rohc_max_len;

	/* ip_id =:= ip_id_enc_irreg( ip_id_behavior.UVALUE ) */
	if(ip_context->ip_id_behavior == IP_ID_BEHAVIOR_RAND)
	{
		if(rohc_remain_len < sizeof(uint16_t))
		{
			return -1;
		}
		memcpy(rohc_remain_data, &ipv4->id, sizeof(uint16_t));
		rohc_remain_data += sizeof(uint16_t);
		rohc_remain_len -= sizeof(uint16_t);
	}
	return (rohc_max_len - rohc_remain_len);
}

int tcp_code_irregular_tcp_part(const struct sc_tcp_context *const tcp_context,
                                       const struct tcphdr *const tcp,
                                       const uint8_t ip_inner_ecn,
                                       uint8_t *const rohc_data,
                                       const size_t rohc_max_len)
{
	uint8_t *rohc_remain_data = rohc_data;
	size_t rohc_remain_len = rohc_max_len;

	/* ip_ecn_flags = := tcp_irreg_ip_ecn(ip_inner_ecn)
	 * tcp_res_flags =:= static_or_irreg(ecn_used.CVALUE,4)
	 * tcp_ecn_flags =:= static_or_irreg(ecn_used.CVALUE,2) */
	if(tcp_context->ecn_used)
	{
		if(rohc_remain_len < 1)
		{
			return -1;
		}
		rohc_remain_data[0] =
			(ip_inner_ecn << 6) | (tcp->res_flags << 2) | tcp->ecn_flags;
		rohc_remain_data++;
		rohc_remain_len--;
	}

	/* checksum =:= irregular(16) */
	if(rohc_remain_len < sizeof(uint16_t))
	{
		return -1;
	}
	memcpy(rohc_remain_data, &tcp->checksum, sizeof(uint16_t));
	rohc_remain_data += sizeof(uint16_t);
	rohc_remain_len -= sizeof(uint16_t);

	return (rohc_max_len - rohc_remain_len);
}

int co_baseheader(const struct sc_tcp_context *const tcp_context,
				 const struct ipv4_hdr *const inner_ip_hdr,
				 uint8_t *const rohc_pkt,
				 const size_t rohc_pkt_max_len,
				 const int packet_type,
				 const struct tcphdr *const tcp,
				 const uint8_t crc)
{
	ipv4_context_t *ip_context = &(tcp_context->ip_context);
	size_t rohc_hdr_len = 0;
	int ret=0;


	switch(packet_type)
	{
		case ROHC_PACKET_TCP_RND_1:
			ret = c_tcp_build_rnd_1(tcp_context, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_RND_2:
			ret = c_tcp_build_rnd_2(tcp_context, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_RND_3:
			ret = c_tcp_build_rnd_3(tcp_context, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_RND_4:
			ret = c_tcp_build_rnd_4(tcp_context, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_RND_5:
			ret = c_tcp_build_rnd_5(tcp_context, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_RND_6:
			ret = c_tcp_build_rnd_6(tcp_context, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_RND_7:
			ret = c_tcp_build_rnd_7(tcp_context, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_RND_8:
			ret = c_tcp_build_rnd_8(tcp_context, inner_ip_hdr, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_SEQ_1:
			ret = c_tcp_build_seq_1(tcp_context, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_SEQ_2:
			ret = c_tcp_build_seq_2(tcp_context, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_SEQ_3:
			ret = c_tcp_build_seq_3(tcp_context, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_SEQ_4:
			ret = c_tcp_build_seq_4(tcp_context, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_SEQ_5:
			ret = c_tcp_build_seq_5(tcp_context, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_SEQ_6:
			ret = c_tcp_build_seq_6(tcp_context, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_SEQ_7:
			ret = c_tcp_build_seq_7(tcp_context, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_SEQ_8:
			ret = c_tcp_build_seq_8(tcp_context, inner_ip_hdr, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_CO_COMMON:
			c_tcp_build_co_common(ip_context, tcp_context, inner_ip_hdr, tcp, crc,
			                            rohc_pkt, rohc_pkt_max_len, &ret);
			break;
		default:
			ret = -1;
			break;
	}
	if(ret < 0)
	{
		return -1;
	}
	rohc_hdr_len += ret;


	/* update context with new values (done at the very end to avoid wrongly
	 * updating the context in case of compression failure) */
	const struct ipv4_hdr *const inner_ipv4 = (struct ipv4_hdr *) inner_ip_hdr;
	ip_context->last_ip_id_behavior = ip_context->ip_id_behavior;
	ip_context->last_ip_id = rohc_bswap16(inner_ipv4->id);
	ip_context->df = inner_ipv4->df;
	ip_context->dscp = inner_ipv4->dscp;
	ip_context->ttl_hopl = tcp_context->tmp.ttl_hopl;

	return rohc_hdr_len;
}

int c_tcp_build_rnd_1(const struct sc_tcp_context *const tcp_context,
					 const struct tcphdr *const tcp,
					 const uint8_t crc, uint8_t *const rohc_data,
					 const size_t rohc_max_len)
{
	rnd_1_t *const rnd1 = (rnd_1_t *) rohc_data;
	uint32_t seq_num;

	if(rohc_max_len < sizeof(rnd_1_t))
	{
		return -1;
	}

	rnd1->discriminator = 0x2e; /* '101110' */
	seq_num = rohc_bswap32(tcp->seq_num) & 0x3ffff;
	rnd1->seq_num1 = (seq_num >> 16) & 0x3;
	rnd1->seq_num2 = rohc_bswap16(seq_num & 0xffff);
	rnd1->msn = tcp_context->msn & 0xf;
	rnd1->psh_flag = tcp->psh_flag;
	rnd1->header_crc = crc;

	return sizeof(rnd_1_t);
}

int c_tcp_build_rnd_2(const struct sc_tcp_context *const tcp_context,
					 const struct tcphdr *const tcp,
					 const uint8_t crc,
					 uint8_t *const rohc_data,
					 const size_t rohc_max_len)
{
	rnd_2_t *const rnd2 = (rnd_2_t *) rohc_data;

	if(rohc_max_len < sizeof(rnd_2_t))
	{
		return -1;
	}

	rnd2->discriminator = 0x0c; /* '1100' */
	rnd2->seq_num_scaled = tcp_context->seq_num_scaled & 0xf;
	rnd2->msn = tcp_context->msn & 0xf;
	rnd2->psh_flag = tcp->psh_flag;
	rnd2->header_crc = crc;

	return sizeof(rnd_2_t);
}

int c_tcp_build_rnd_3(const struct sc_tcp_context *const tcp_context,
					 const struct tcphdr *const tcp,
					 const uint8_t crc,
					 uint8_t *const rohc_data,
					 const size_t rohc_max_len)
{
	rnd_3_t *const rnd3 = (rnd_3_t *) rohc_data;
	uint16_t ack_num;

	if(rohc_max_len < sizeof(rnd_3_t))
	{
		return -1;
	}

	rnd3->discriminator = 0x0; /* '0' */
	ack_num = rohc_bswap32(tcp->ack_num) & 0x7fff;
	rnd3->ack_num1 = (ack_num >> 8) & 0x7f;
	rnd3->ack_num2 = ack_num & 0xff;
	rnd3->msn = tcp_context->msn & 0xf;
	rnd3->psh_flag = tcp->psh_flag;
	rnd3->header_crc = crc;

	return sizeof(rnd_3_t);
}

int c_tcp_build_rnd_4(const struct sc_tcp_context *const tcp_context,
					 const struct tcphdr *const tcp,
					 const uint8_t crc,
					 uint8_t *const rohc_data,
					 const size_t rohc_max_len)
{
	rnd_4_t *const rnd4 = (rnd_4_t *) rohc_data;


	if(rohc_max_len < sizeof(rnd_4_t))
	{
		return -1;
	}

	rnd4->discriminator = 0x0d; /* '1101' */
	rnd4->ack_num_scaled = tcp_context->ack_num_scaled & 0xf;
	rnd4->msn = tcp_context->msn & 0xf;
	rnd4->psh_flag = tcp->psh_flag;
	rnd4->header_crc = crc;

	return sizeof(rnd_4_t);
}

int c_tcp_build_rnd_5(const struct sc_tcp_context *const tcp_context,
					 const struct tcphdr *const tcp,
					 const uint8_t crc,
					 uint8_t *const rohc_data,
					 const size_t rohc_max_len)
{
	rnd_5_t *const rnd5 = (rnd_5_t *) rohc_data;
	uint16_t seq_num;
	uint16_t ack_num;

	if(rohc_max_len < sizeof(rnd_5_t))
	{
		return -1;
	}

	rnd5->discriminator = 0x04; /* '100' */
	rnd5->psh_flag = tcp->psh_flag;
	rnd5->msn = tcp_context->msn & 0xf;
	rnd5->header_crc = crc;

	/* sequence number */
	seq_num = rohc_bswap32(tcp->seq_num) & 0x3fff;
	rnd5->seq_num1 = (seq_num >> 9) & 0x1f;
	rnd5->seq_num2 = (seq_num >> 1) & 0xff;
	rnd5->seq_num3 = seq_num & 0x01;

	/* ACK number */
	ack_num = rohc_bswap32(tcp->ack_num) & 0x7fff;
	rnd5->ack_num1 = (ack_num >> 8) & 0x7f;
	rnd5->ack_num2 = ack_num & 0xff;

	return sizeof(rnd_5_t);
}

int c_tcp_build_rnd_6(const struct sc_tcp_context *const tcp_context,
					 const struct tcphdr *const tcp,
					 const uint8_t crc,
					 uint8_t *const rohc_data,
					 const size_t rohc_max_len)
{
	rnd_6_t *const rnd6 = (rnd_6_t *) rohc_data;

	if(rohc_max_len < sizeof(rnd_6_t))
	{
		return -1;
	}

	rnd6->discriminator = 0x0a; /* '1010' */
	rnd6->header_crc = crc;
	rnd6->psh_flag = tcp->psh_flag;
	rnd6->ack_num = rohc_bswap16(rohc_bswap32(tcp->ack_num) & 0xffff);
	rnd6->msn = tcp_context->msn & 0xf;
	rnd6->seq_num_scaled = tcp_context->seq_num_scaled & 0xf;

	return sizeof(rnd_6_t);
}

int c_tcp_build_rnd_7(const struct sc_tcp_context *const tcp_context,
					 const struct tcphdr *const tcp,
					 const uint8_t crc,
					 uint8_t *const rohc_data,
					 const size_t rohc_max_len)
{
	rnd_7_t *const rnd7 = (rnd_7_t *) rohc_data;
	uint32_t ack_num;

	if(rohc_max_len < sizeof(rnd_7_t))
	{
		return -1;
	}

	rnd7->discriminator = 0x2f; /* '101111' */
	ack_num = rohc_bswap32(tcp->ack_num) & 0x3ffff;
	rnd7->ack_num1 = (ack_num >> 16) & 0x03;
	rnd7->ack_num2 = rohc_bswap16(ack_num & 0xffff);
	rnd7->window = tcp->window;
	rnd7->msn = tcp_context->msn & 0xf;
	rnd7->psh_flag = tcp->psh_flag;
	rnd7->header_crc = crc;

	return sizeof(rnd_7_t);
}

int c_tcp_build_rnd_8(const struct sc_tcp_context *const tcp_context,
					 const struct ipv4_hdr *const inner_ip_hdr,
					 const struct tcphdr *const tcp,
					 const uint8_t crc,
					 uint8_t *const rohc_data,
					 const size_t rohc_max_len)
{
	rnd_8_t *const rnd8 = (rnd_8_t *) rohc_data;
	uint32_t seq_num;
	uint8_t ttl_hl;
	uint8_t msn;

	if(rohc_max_len < sizeof(rnd_8_t))
	{
		return -1;
	}

	rnd8->discriminator = 0x16; /* '10110' */
	rnd8->rsf_flags = rsf_index_enc(tcp->rsf_flags);
	rnd8->list_present = 0; /* options are set later */
	rnd8->header_crc = crc;

	/* MSN */
	msn = tcp_context->msn & 0xf;
	rnd8->msn1 = (msn >> 3) & 0x01;
	rnd8->msn2 = msn & 0x07;

	rnd8->psh_flag = tcp->psh_flag;

	/* TTL/HL */
	ttl_hl = inner_ip_hdr->ttl;
	rnd8->ttl_hopl = ttl_hl & 0x7;
	rnd8->ecn_used = GET_REAL(tcp_context->ecn_used);

	/* sequence number */
	seq_num = rohc_bswap32(tcp->seq_num) & 0xffff;
	rnd8->seq_num = rohc_bswap16(seq_num);

	/* ACK number */
	rnd8->ack_num = rohc_bswap16(rohc_bswap32(tcp->ack_num) & 0xffff);

	return sizeof(rnd_8_t);
}

int c_tcp_build_seq_1(const struct sc_tcp_context *const tcp_context,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	seq_1_t *const seq1 = (seq_1_t *) rohc_data;
	uint32_t seq_num;


	if(rohc_max_len < sizeof(seq_1_t))
	{
		return -1;
	}

	seq1->discriminator = 0x0a; /* '1010' */
	seq1->ip_id = tcp_context->tmp.ip_id_delta & 0x0f;
	seq_num = rohc_bswap32(tcp->seq_num) & 0xffff;
	seq1->seq_num = rohc_bswap16(seq_num);
	seq1->msn = tcp_context->msn & 0xf;
	seq1->psh_flag = tcp->psh_flag;
	seq1->header_crc = crc;

	return sizeof(seq_1_t);

}

int c_tcp_build_seq_2(const struct sc_tcp_context *const tcp_context,
					 const struct tcphdr *const tcp,
					 const uint8_t crc,
					 uint8_t *const rohc_data,
					 const size_t rohc_max_len)
{
	seq_2_t *const seq2 = (seq_2_t *) rohc_data;


	if(rohc_max_len < sizeof(seq_2_t))
	{
		return -1;;
	}

	seq2->discriminator = 0x1a; /* '11010' */
	seq2->ip_id1 = (tcp_context->tmp.ip_id_delta >> 4) & 0x7;
	seq2->ip_id2 = tcp_context->tmp.ip_id_delta & 0xf;
	seq2->seq_num_scaled = tcp_context->seq_num_scaled & 0xf;
	seq2->msn = tcp_context->msn & 0xf;
	seq2->psh_flag = tcp->psh_flag;
	seq2->header_crc = crc;

	return sizeof(seq_2_t);
}

int c_tcp_build_seq_3(const struct sc_tcp_context *const tcp_context,
					 const struct tcphdr *const tcp,
					 const uint8_t crc,
					 uint8_t *const rohc_data,
					 const size_t rohc_max_len)
{
	seq_3_t *const seq3 = (seq_3_t *) rohc_data;


	if(rohc_max_len < sizeof(seq_3_t))
	{
		return -1;
	}

	seq3->discriminator = 0x09; /* '1001' */
	seq3->ip_id = tcp_context->tmp.ip_id_delta & 0xf;
	seq3->ack_num = rohc_bswap16(rohc_bswap32(tcp->ack_num) & 0xffff);
	seq3->msn = tcp_context->msn & 0xf;
	seq3->psh_flag = tcp->psh_flag;
	seq3->header_crc = crc;

	return sizeof(seq_3_t);
}

int c_tcp_build_seq_4(const struct sc_tcp_context *const tcp_context,
					 const struct tcphdr *const tcp,
					 const uint8_t crc,
					 uint8_t *const rohc_data,
					 const size_t rohc_max_len)
{
	seq_4_t *const seq4 = (seq_4_t *) rohc_data;


	if(rohc_max_len < sizeof(seq_4_t))
	{
		return -1;
	}

	seq4->discriminator = 0x00; /* '0' */
	seq4->ack_num_scaled = tcp_context->ack_num_scaled & 0xf;
	seq4->ip_id = tcp_context->tmp.ip_id_delta & 0x7;
	seq4->msn = tcp_context->msn & 0xf;
	seq4->psh_flag = tcp->psh_flag;
	seq4->header_crc = crc;

	return sizeof(seq_4_t);
}

int c_tcp_build_seq_5(const struct sc_tcp_context *const tcp_context,
					 const struct tcphdr *const tcp,
					 const uint8_t crc,
					 uint8_t *const rohc_data,
					 const size_t rohc_max_len)
{
	seq_5_t *const seq5 = (seq_5_t *) rohc_data;
	uint32_t seq_num;


	if(rohc_max_len < sizeof(seq_5_t))
	{
		return -1;
	}

	seq5->discriminator = 0x08; /* '1000' */
	seq5->ip_id = tcp_context->tmp.ip_id_delta & 0xf;
	seq5->ack_num = rohc_bswap16(rohc_bswap32(tcp->ack_num) & 0xffff);
	seq_num = rohc_bswap32(tcp->seq_num) & 0xffff;
	seq5->seq_num = rohc_bswap16(seq_num);
	seq5->msn = tcp_context->msn & 0xf;
	seq5->psh_flag = tcp->psh_flag;
	seq5->header_crc = crc;

	return sizeof(seq_5_t);
}

int c_tcp_build_seq_6(const struct sc_tcp_context *const tcp_context,
					 const struct tcphdr *const tcp,
					 const uint8_t crc,
					 uint8_t *const rohc_data,
					 const size_t rohc_max_len)
{
	seq_6_t *const seq6 = (seq_6_t *) rohc_data;
	uint8_t seq_num_scaled;


	if(rohc_max_len < sizeof(seq_6_t))
	{
		return -1;
	}

	seq6->discriminator = 0x1b; /* '11011' */

	/* scaled sequence number */
	seq_num_scaled = tcp_context->seq_num_scaled & 0xf;
	seq6->seq_num_scaled1 = (seq_num_scaled >> 1) & 0x07;
	seq6->seq_num_scaled2 = seq_num_scaled & 0x01;

	/* IP-ID */
	seq6->ip_id = tcp_context->tmp.ip_id_delta & 0x7f;
	seq6->ack_num = rohc_bswap16(rohc_bswap32(tcp->ack_num) & 0xffff);
	seq6->msn = tcp_context->msn & 0xf;
	seq6->psh_flag = tcp->psh_flag;
	seq6->header_crc = crc;

	return sizeof(seq_6_t);
}

int c_tcp_build_seq_7(const struct sc_tcp_context *const tcp_context,
					 const struct tcphdr *const tcp,
					 const uint8_t crc,
					 uint8_t *const rohc_data,
					 const size_t rohc_max_len)
{
	seq_7_t *const seq7 = (seq_7_t *) rohc_data;
	uint16_t window;


	if(rohc_max_len < sizeof(seq_7_t))
	{
		return -1;
	}

	seq7->discriminator = 0x0c; /* '1100' */

	/* window */
	window = rohc_bswap16(tcp->window) & 0x7fff;
	seq7->window1 = (window >> 11) & 0x0f;
	seq7->window2 = (window >> 3) & 0xff;
	seq7->window3 = window & 0x07;

	/* IP-ID */
	seq7->ip_id = tcp_context->tmp.ip_id_delta & 0x1f;
	seq7->ack_num = rohc_bswap16(rohc_bswap32(tcp->ack_num) & 0xffff);
	seq7->msn = tcp_context->msn & 0xf;
	seq7->psh_flag = tcp->psh_flag;
	seq7->header_crc = crc;

	return sizeof(seq_7_t);
}

int c_tcp_build_seq_8(const struct sc_tcp_context *const tcp_context,
					 const struct ipv4_hdr *const inner_ip_hdr,
					 const struct tcphdr *const tcp,
					 const uint8_t crc,
					 uint8_t *const rohc_data,
					 const size_t rohc_max_len)
{
	seq_8_t *const seq8 = (seq_8_t *) rohc_data;
	uint16_t ack_num;
	uint16_t seq_num;


	if(rohc_max_len < sizeof(seq_8_t))
	{
		return -1;
	}

	seq8->discriminator = 0x0b; /* '1011' */

	/* IP-ID */
	seq8->ip_id = tcp_context->tmp.ip_id_delta & 0xf;

	seq8->list_present = 0; /* options are set later */
	seq8->header_crc = crc;
	seq8->msn = tcp_context->msn & 0xf;
	seq8->psh_flag = tcp->psh_flag;

	/* TTL/HL */
	seq8->ttl_hopl = inner_ip_hdr->ttl & 0x7;

	/* ecn_used */
	seq8->ecn_used = GET_REAL(tcp_context->ecn_used);

	/* ACK number */
	ack_num = rohc_bswap32(tcp->ack_num) & 0x7fff;
	seq8->ack_num1 = (ack_num >> 8) & 0x7f;
	seq8->ack_num2 = ack_num & 0xff;

	seq8->rsf_flags = rsf_index_enc(tcp->rsf_flags);

	/* sequence number */
	seq_num = rohc_bswap32(tcp->seq_num) & 0x3fff;
	seq8->seq_num1 = (seq_num >> 8) & 0x3f;
	seq8->seq_num2 = seq_num & 0xff;

	return sizeof(seq_8_t);
}

void c_tcp_build_co_common(const ipv4_context_t *const inner_ip_ctxt,
						 const struct sc_tcp_context *const tcp_context,
						 const struct ipv4_hdr *const inner_ip_hdr,
						 const struct tcphdr *const tcp,
						 const uint8_t crc, uint8_t *const rohc_data,
						 const size_t rohc_max_len, int *retval)
{
//#pragma HLS dataflow
	co_common_t *const co_common = (co_common_t *) rohc_data;
	uint8_t *co_common_opt = (uint8_t *) (co_common + 1); /* optional part */
	size_t co_common_opt_len = 0;
	size_t rohc_remain_len = rohc_max_len - sizeof(co_common_t);
	const uint32_t seq_num_hbo = rohc_bswap32(tcp->seq_num);
	const uint32_t ack_num_hbo = rohc_bswap32(tcp->ack_num);
	size_t nr_seq_bits_16383; /* min bits required to encode TCP seqnum with p = 16383 */
	size_t nr_seq_bits_63; /* min bits required to encode TCP seqnum with p = 63 */
	size_t nr_ack_bits_63; /* min bits required to encode TCP ACK number with p = 63 */
	size_t encoded_seq_len;
	size_t encoded_ack_len;
	int indicator;
	int ret;

	if(rohc_max_len < sizeof(co_common_t))
	{
		*retval = -1;
		return;
	}


	co_common->discriminator = 0x7D; // '1111101'
	co_common->ttl_hopl_outer_flag = tcp_context->tmp.ttl_irreg_chain_flag;

	// =:= irregular(1) [ 1 ];
	co_common->ack_flag = tcp->ack_flag;
	// =:= irregular(1) [ 1 ];
	co_common->psh_flag = tcp->psh_flag;
	// =:= rsf_index_enc [ 2 ];
	co_common->rsf_flags = rsf_index_enc(tcp->rsf_flags);
	// =:= lsb(4, 4) [ 4 ];
	co_common->msn = tcp_context->msn & 0xf;

	/* seq_number */
	nr_seq_bits_16383 = wlsb_get_minkp_32bits(&tcp_context->seq_wlsb, seq_num_hbo, 16383);
	nr_seq_bits_63 = wlsb_get_minkp_32bits(&tcp_context->seq_wlsb, seq_num_hbo, 63);
	ret = variable_length_32_enc(rohc_bswap32(tcp_context->old_tcphdr.seq_num),
	                             rohc_bswap32(tcp->seq_num),
	                             nr_seq_bits_63, nr_seq_bits_16383,
	                             co_common_opt, rohc_remain_len, &indicator);
	if(ret < 0)
	{
		*retval = -1;
		return;
	}
	co_common->seq_indicator = indicator;
	encoded_seq_len = ret;
	co_common_opt += encoded_seq_len;
	co_common_opt_len += encoded_seq_len;
	rohc_remain_len -= encoded_seq_len;

	/* ack_number */
	nr_ack_bits_63 = wlsb_get_minkp_32bits(&tcp_context->ack_wlsb, ack_num_hbo, 63);
	ret = variable_length_32_enc(rohc_bswap32(tcp_context->old_tcphdr.ack_num),
	                             rohc_bswap32(tcp->ack_num),
	                             nr_ack_bits_63, tcp_context->tmp.nr_ack_bits_16383,
	                             co_common_opt, rohc_remain_len, &indicator);
	if(ret < 0)
	{
		*retval = -1;
		return;
	}
	co_common->ack_indicator = indicator;
	encoded_ack_len = ret;
	co_common_opt += encoded_ack_len;
	co_common_opt_len += encoded_ack_len;
	rohc_remain_len -= encoded_ack_len;

	/* ack_stride */
	const bool is_ack_stride_static =
		tcp_is_ack_stride_static(tcp_context->ack_stride,
								 tcp_context->ack_num_scaling_nr);
	ret = c_static_or_irreg16(rohc_bswap16(tcp_context->ack_stride),
							  is_ack_stride_static,
							  co_common_opt, rohc_remain_len, &indicator);
	if(ret < 0)
	{
		*retval = -1;
		return;
	}
	co_common->ack_stride_indicator = indicator;
	co_common_opt += ret;
	co_common_opt_len += ret;
	rohc_remain_len -= ret;

	/* window */
	ret = c_static_or_irreg16(tcp->window, !tcp_context->tmp.tcp_window_changed,
	                          co_common_opt, rohc_remain_len, &indicator);
	if(ret < 0)
	{
		*retval = -1;
		return;
	}
	co_common->window_indicator = indicator;
	co_common_opt += ret;
	co_common_opt_len += ret;
	rohc_remain_len -= ret;

	/* innermost IP-ID */
	ret = c_optional_ip_id_lsb(inner_ip_ctxt->ip_id_behavior,
			inner_ip_hdr->id, tcp_context->tmp.ip_id_delta,
			tcp_context->tmp.nr_ip_id_bits_3,
			co_common_opt, rohc_remain_len, &indicator);
	if(ret < 0)
	{
		*retval = -1;
		return;
	}
	co_common->ip_id_indicator = indicator;
	co_common_opt += ret;
	co_common_opt_len += ret;
	rohc_remain_len -= ret;
	// =:= ip_id_behavior_choice(true) [ 2 ];
	co_common->ip_id_behavior = inner_ip_ctxt->ip_id_behavior;

	// cf RFC3168 and RFC4996 page 20 :
	// =:= one_bit_choice [ 1 ];
	co_common->ecn_used = GET_REAL(tcp_context->ecn_used);

	/* urg_flag */
	co_common->urg_flag = tcp->urg_flag;
	/* urg_ptr */
	ret = c_static_or_irreg16(tcp->urg_ptr,
	                          !!(tcp_context->old_tcphdr.urg_ptr == tcp->urg_ptr),
	                          co_common_opt, rohc_remain_len, &indicator);
	if(ret < 0)
	{
		*retval = -1;
		return;
	}
	co_common->urg_ptr_present = indicator;
	co_common_opt += ret;
	co_common_opt_len += ret;
	rohc_remain_len -= ret;

	/* dscp_present =:= irregular(1) [ 1 ] */
	ret = dscp_encode(inner_ip_ctxt->dscp, inner_ip_hdr->dscp,
					  co_common_opt, rohc_remain_len, &indicator);
	if(ret < 0)
	{
		*retval = -1;
		return;
	}
	co_common->dscp_present = indicator;
	co_common_opt += ret;
	co_common_opt_len += ret;
	rohc_remain_len -= ret;

	/* ttl_hopl */
	const bool is_ttl_hopl_static =
		(inner_ip_ctxt->ttl_hopl == tcp_context->tmp.ttl_hopl);
	ret = c_static_or_irreg8(tcp_context->tmp.ttl_hopl, is_ttl_hopl_static,
							 co_common_opt, rohc_remain_len, &indicator);
	if(ret < 0)
	{
		*retval = -1;
		return;
	}
	co_common->ttl_hopl_present = indicator;
	co_common_opt += ret;
	co_common_opt_len += ret;
	rohc_remain_len -= ret;

	// =:= dont_fragment(version.UVALUE) [ 1 ];
	co_common->df = inner_ip_hdr->df;

	// =:= compressed_value(1, 0) [ 1 ];
	co_common->reserved = 0;

	/* the structure of the list of TCP options didn't change */
	co_common->list_present = 0;

	// =:= crc7(THIS.UVALUE,THIS.ULENGTH) [ 7 ];
	co_common->header_crc = crc;

	*retval = (sizeof(co_common_t) + co_common_opt_len);
}

int c_optional_ip_id_lsb(const int behavior,
                         const uint16_t ip_id_nbo,
                         const uint16_t ip_id_offset,
                         const size_t nr_bits_wlsb,
                         uint8_t *const rohc_data,
                         const size_t rohc_max_len,
                         int *const indicator)
{
	size_t length = 0;

	switch(behavior)
	{
		case IP_ID_BEHAVIOR_SEQ_SWAP:
		case IP_ID_BEHAVIOR_SEQ:
			if(nr_bits_wlsb <= 8)
			{
				if(rohc_max_len < 1)
				{
					return -1;
				}
				rohc_data[0] = ip_id_offset & 0xff;
				*indicator = 0;
				length++;
			}
			else
			{
				if(rohc_max_len < sizeof(uint16_t))
				{
					return -1;
				}
				memcpy(rohc_data, &ip_id_nbo, sizeof(uint16_t));
				length += sizeof(uint16_t);
				*indicator = 1;
			}
			break;
		case IP_ID_BEHAVIOR_RAND:
		case IP_ID_BEHAVIOR_ZERO:
			*indicator = 0;
			break;
		default: /* should never happen */
			*indicator = 0;
			break;
	}

	return length;
}

int dscp_encode(const uint8_t context_value,
                const uint8_t packet_value,
                uint8_t *const rohc_data,
                const size_t rohc_max_len,
                int *const indicator)
{
	size_t len;

	if(packet_value == context_value)
	{
		*indicator = 0;
		len = 0;
	}
	else
	{
		/* 6 bits + 2 bits padding */
		if(rohc_max_len < 1)
		{
			return -1;
		}
		rohc_data[0] = ((packet_value & 0x3F) << 2);
		*indicator = 1;
		len = 1;
	}

	return len;
}

int variable_length_32_enc(const uint32_t old_value,
                           const uint32_t new_value,
                           const size_t nr_bits_63,
                           const size_t nr_bits_16383,
                           uint8_t *const rohc_data,
                           const size_t rohc_max_len,
                           int *const indicator)
{
	size_t encoded_len;


	if(new_value == old_value)
	{
		/* 0-byte value */
		encoded_len = 0;
		*indicator = 0;
	}
	else if(nr_bits_63 <= 8)
	{
		/* 1-byte value */
		encoded_len = 1;
		if(rohc_max_len < encoded_len)
		{
			return -1;
		}
		*indicator = 1;
		rohc_data[0] = new_value & 0xff;
	}
	else if(nr_bits_16383 <= 16)
	{
		/* 2-byte value */
		encoded_len = 2;
		if(rohc_max_len < encoded_len)
		{
			return -1;
		}
		*indicator = 2;
		rohc_data[0] = (new_value >> 8) & 0xff;
		rohc_data[1] = new_value & 0xff;
	}
	else
	{
		/* 4-byte value */
		encoded_len = 4;
		if(rohc_max_len < encoded_len)
		{
			return -1;
		}
		*indicator = 3;
		rohc_data[0] = (new_value >> 24) & 0xff;
		rohc_data[1] = (new_value >> 16) & 0xff;
		rohc_data[2] = (new_value >> 8) & 0xff;
		rohc_data[3] = new_value & 0xff;
	}


	return encoded_len;
}

uint8_t crc_calculate(const int crc_type,
                      const uint8_t *const data,
                      const size_t length,
                      const uint8_t init_val,
                      const uint8_t *const crc_table)
{
	uint8_t crc;

	/* call the function that corresponds to the CRC type */
	switch(crc_type)
	{
		case ROHC_CRC_TYPE_7:
			crc = crc_calc_7(data, length, init_val, crc_table);
			break;
		case ROHC_CRC_TYPE_3:
			crc = crc_calc_3(data, length, init_val, crc_table);
			break;
		default:
			/* undefined CRC type, should not happen */
			crc = 0;
			break;
	}

	return crc;
}

uint8_t crc_calc_7(const uint8_t *const buf, const size_t size,
				 const uint8_t init_val, const uint8_t *const crc_table)
{
	uint8_t crc = init_val;
	size_t i;

	for(i = 0; i < size; i++)
	{
#pragma HLS loop_tripcount min=1 max=40
		crc = crc_table[buf[i] ^ (crc & 127)];
	}

	return crc;
}

uint8_t crc_calc_3(const uint8_t *const buf, const size_t size,
				 const uint8_t init_val, const uint8_t *const crc_table)
{
	uint8_t crc = init_val;
	size_t i;

	for(i = 0; i < size; i++)
	{
#pragma HLS loop_tripcount min=1 max=40
		crc = crc_table[buf[i] ^ (crc & 7)];
	}

	return crc;
}
