#include "uncomp_encode.h"

int c_uncompressed_encode(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt, int ip_pkt_len,
		uint8_t *const rohc_pkt, const size_t rohc_pkt_max_len)
{
#pragma HLS INTERFACE m_axi port = ip_pkt depth = 1500
#pragma HLS INTERFACE m_axi port = rohc_pkt depth = 1500
	int size;
	const struct ip_hdr *const ip_hdr = (struct ip_hdr *) ip_pkt;

	uncompressed_decide_state(context, ip_hdr->version);

	size = uncompressed_code_packet(context, ip_pkt, ip_pkt_len, rohc_pkt, rohc_pkt_max_len);
	return size;
}

void uncompressed_decide_state(struct rohc_comp_ctxt *const context, int ip_vers)
{
	/* non-IPv4/6 packets cannot be compressed with Normal packets because the
	 * first byte could be mis-interpreted as ROHC packet types (see note at
	 * the end of §5.10.2 in RFC 3095) */
	if(ip_vers != 4)
	{
		rohc_comp_change_state(context, ROHC_COMP_STATE_IR);
	}
	else if(context->state == ROHC_COMP_STATE_IR &&
	        context->ir_count >= MAX_IR_COUNT)
	{
		/* the compressor got the confidence that the decompressor fully received
		 * the context: enough IR packets transmitted or positive ACK received */
		rohc_comp_change_state(context, ROHC_COMP_STATE_FO);
	}

	if(context->mode == ROHC_U_MODE)
	{
		rohc_comp_periodic_down_transition(context);
	}
}

int uncompressed_code_packet(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt, int ip_pkt_len,
                                    uint8_t *const rohc_pkt, const size_t rohc_pkt_max_len)
{
	int size;

	if(context->state == ROHC_COMP_STATE_IR)
	{
		context->packet_type = ROHC_PACKET_IR;
	}
	else if(context->state == ROHC_COMP_STATE_FO)
	{
		context->packet_type = ROHC_PACKET_NORMAL;
	}
	else
	{
		context->packet_type = ROHC_PACKET_UNKNOWN;
		return -1;
	}

	if(context->packet_type == ROHC_PACKET_IR)
	{
		context->ir_count++;
		size = uncompressed_code_IR_packet(context, ip_pkt, ip_pkt_len, rohc_pkt, rohc_pkt_max_len);
	}
	else /* ROHC_PACKET_NORMAL */
	{
		context->fo_count++; /* FO is used instead of Normal */
		size = uncompressed_code_normal_packet(context, ip_pkt, ip_pkt_len, rohc_pkt, rohc_pkt_max_len);
	}

	return size;
}

int uncompressed_code_IR_packet(const struct rohc_comp_ctxt *context, uint8_t *ip_pkt, int ip_pkt_len,
							   uint8_t *const rohc_pkt, const size_t rohc_pkt_max_len)
{
	size_t counter;
	size_t first_position;
	int ret;

	/* parts 1 and 3:
	 *  - part 2 will be placed at 'first_position'
	 *  - part 4 will start at 'counter'
	 */
	ret = code_cid_values(context->cid, rohc_pkt, rohc_pkt_max_len, &first_position);
	if(ret < 1)
	{
		return -1;
	}
	counter = ret;

	/* part 2 */
	rohc_pkt[first_position] = 0xfc;

	/* is ROHC buffer large enough for parts 4 and 5 ? */
	if((rohc_pkt_max_len - counter) < 2)
	{
		return -1;
	}

	/* part 4 */
	rohc_pkt[counter] = ROHC_PROFILE_UNCOMPRESSED;
	counter++;

	/* part 5 */
	rohc_pkt[counter] = 0;
	rohc_pkt[counter] = crc_calc_8(rohc_pkt, counter, CRC_INIT_8);
	counter++;

	return counter;
}

int uncompressed_code_normal_packet(const struct rohc_comp_ctxt *context, uint8_t *ip_pkt, int ip_pkt_len,
								   uint8_t *const rohc_pkt, const size_t rohc_pkt_max_len)
{
	size_t counter;
	size_t first_position;
	int ret;

	/* parts 1 and 3:
	 *  - part 2 will be placed at 'first_position'
	 *  - part 4 will start at 'counter'
	 */
	ret = code_cid_values(context->cid, rohc_pkt, rohc_pkt_max_len, &first_position);
	if(ret < 1)
	{
		return -1;
	}
	counter = ret;

	/* part 2 */
	rohc_pkt[first_position] = ip_pkt[0];
	return counter;
}
