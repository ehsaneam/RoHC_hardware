#include "rohc_compress.h"

rohc_status_t rohc_compress4(struct rohc_comp *const comp,
                             const struct rohc_buf uncomp_packet,
                             struct rohc_buf *const rohc_packet)
{
	struct net_pkt ip_pkt;
	struct rohc_comp_ctxt *c;
	rohc_packet_t packet_type;
	int rohc_hdr_size;
	size_t payload_size;
	size_t payload_offset;

	rohc_status_t status = ROHC_STATUS_ERROR; /* error status by default */

	/* check inputs validity */
	if(comp == NULL)
	{
		return ROHC_STATUS_ERROR;
	}
	if(rohc_buf_is_malformed(uncomp_packet))
	{
		return ROHC_STATUS_ERROR;
	}
	if(rohc_buf_is_empty(uncomp_packet))
	{
		return ROHC_STATUS_ERROR;
	}
	if(rohc_packet == NULL)
	{
		return ROHC_STATUS_ERROR;
	}
	if(rohc_buf_is_malformed(*rohc_packet))
	{
		return ROHC_STATUS_ERROR;
	}
	if(!rohc_buf_is_empty(*rohc_packet))
	{
		return ROHC_STATUS_ERROR;
	}

	/* parse the uncompressed packet */
	net_pkt_parse(&ip_pkt, uncomp_packet, comp->trace_callback,
	              comp->trace_callback_priv, ROHC_TRACE_COMP);

	/* find the best context for the packet */
	size_t cid = rohc_comp_find_ctxt(comp, &ip_pkt, -1, uncomp_packet.time);

	if(cid == CID_NOT_USED)
	{
		return ROHC_STATUS_ERROR;
	}

	/* create the ROHC packet: */
	rohc_packet->len = 0;

	/* use profile to compress packet */
	rohc_hdr_size =
		c->profile->encode(c, &ip_pkt, rohc_buf_data(*rohc_packet),
		                   rohc_buf_avail_len(*rohc_packet),
		                   &packet_type, &payload_offset);

	if(rohc_hdr_size < 0)
	{
		/* error while compressing, use the Uncompressed profile
		 * (except if we were already using the Uncompressed profile) */
		if(c->profile->id == ROHC_PROFILE_UNCOMPRESSED)
		{
			if(c->num_sent_packets <= 1)
			{
				c->profile->destroy(c);
				c->used = 0;
				assert(comp->num_contexts_used > 0);
				comp->num_contexts_used--;
			}
			return ROHC_STATUS_ERROR;
		}
		if(c->num_sent_packets <= 1)
		{
			c->profile->destroy(c);
			c->used = 0;
			assert(comp->num_contexts_used > 0);
			comp->num_contexts_used--;
		}

		/* find the best context for the Uncompressed profile */
		c = rohc_comp_find_ctxt(comp, &ip_pkt, ROHC_PROFILE_UNCOMPRESSED,
		                        uncomp_packet.time);
		if(c == NULL)
		{
			return ROHC_STATUS_ERROR;
		}

		/* use the Uncompressed profile to compress the packet */
		rohc_hdr_size =
			c->profile->encode(c, &ip_pkt, rohc_buf_data(*rohc_packet),
			                   rohc_buf_avail_len(*rohc_packet),
			                   &packet_type, &payload_offset);
		if(rohc_hdr_size < 0)
		{
			if(c->num_sent_packets <= 1)
			{
				c->profile->destroy(c);
				c->used = 0;
				assert(comp->num_contexts_used > 0);
				comp->num_contexts_used--;
			}
			return ROHC_STATUS_ERROR;
		}
	}
	rohc_packet->len += rohc_hdr_size;

	/* the payload starts after the header, skip it */
	rohc_buf_pull(rohc_packet, rohc_hdr_size);
	payload_size = ip_pkt.len - payload_offset;
	rohc_buf_append(rohc_packet,
					rohc_buf_data_at(uncomp_packet, payload_offset),
					payload_size);

	rohc_buf_push(rohc_packet, rohc_hdr_size);

	status = ROHC_STATUS_OK;

	comp->num_packets++;
	comp->total_uncompressed_size += uncomp_packet.len;
	comp->total_compressed_size += rohc_packet->len;
	comp->last_context = c;

	c->packet_type = packet_type;

	c->total_uncompressed_size += uncomp_packet.len;
	c->total_compressed_size += rohc_packet->len;
	c->header_uncompressed_size += payload_offset;
	c->header_compressed_size += rohc_hdr_size;
	c->num_sent_packets++;

	c->total_last_uncompressed_size = uncomp_packet.len;
	c->total_last_compressed_size = rohc_packet->len;
	c->header_last_uncompressed_size = payload_offset;
	c->header_last_compressed_size = rohc_hdr_size;

	return status;
}
