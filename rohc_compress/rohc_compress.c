#include "rohc_compress.h"

struct rohc_comp comp;

int rohc_compress4(const struct rohc_buf uncomp_packet,
		uint8_t *const rohc_packet, bool reset)
{
#pragma HLS INTERFACE m_axi port = rohc_packet depth = 1500

	if( !reset )
	{
		comp.num_contexts_used = 0;
		for( int i=0 ; i<MAX_CONTEXTS ; i++ )
		{
			comp.contexts[i].used = 0;
		}
	}

	int rohc_hdr_size;
	size_t payload_size;
	size_t payload_offset;

	/* find the best context for the packet */
	size_t cid = rohc_comp_find_ctxt(&comp, uncomp_packet.data, -1, uncomp_packet.time);
	if(cid == CID_NOT_USED)
	{
		return -1;
	}

	/* use profile to compress packet */
	rohc_hdr_size = c_tcp_encode(&comp.contexts[cid], uncomp_packet.data, uncomp_packet.len, rohc_packet, 2048);
	printf("-->%d\n", rohc_hdr_size);
	if(rohc_hdr_size < 0)
	{
		/* error while compressing, use the Uncompressed profile
		 * (except if we were already using the Uncompressed profile) */
		if(comp.contexts[cid].pid == ROHC_PROFILE_UNCOMPRESSED)
		{
			if(comp.contexts[cid].num_sent_packets <= 1)
			{
				comp.contexts[cid].used = 0;
				comp.num_contexts_used--;
			}
			return -1;
		}
		if(comp.contexts[cid].num_sent_packets <= 1)
		{
			comp.contexts[cid].used = 0;
			comp.num_contexts_used--;
		}

		/* find the best context for the Uncompressed profile */
		cid = rohc_comp_find_ctxt(&comp, uncomp_packet.data, ROHC_PROFILE_UNCOMPRESSED,
		                        uncomp_packet.time);
		if(cid == CID_NOT_USED)
		{
			return -1;
		}

		/* use the Uncompressed profile to compress the packet */
		rohc_hdr_size = c_tcp_encode(&comp.contexts[cid], uncomp_packet.data, uncomp_packet.len, rohc_packet, 2048);
		if(rohc_hdr_size < 0)
		{
			if(comp.contexts[cid].num_sent_packets <= 1)
			{
				comp.contexts[cid].used = 0;
				comp.num_contexts_used--;
			}
			return -1;
		}
	}

	/* the payload starts after the header, skip it */
	payload_offset = sizeof(struct ipv4_hdr) + sizeof(struct tcphdr);
	payload_size   = uncomp_packet.len - payload_offset;

//	memcpy(rohc_packet + rohc_hdr_size, uncomp_packet.data + payload_offset, payload_size);
	for( int j=0 ; j<payload_size ; j++ )
	{
#pragma HLS loop_tripcount min=1 max=1500
		rohc_packet[rohc_hdr_size + j] = uncomp_packet.data[payload_offset + j];
	}

	comp.contexts[cid].num_sent_packets++;

	return rohc_hdr_size;
}

