#include "rohc_compress.h"

struct rohc_comp comp;

int rohc_compress4(uint8_t *const uncomp_data, uint16_t uncomp_time, size_t uncomp_len, uint8_t *const rohc_packet)
{
#pragma HLS INTERFACE m_axi port = uncomp_data depth = 1500
#pragma HLS INTERFACE m_axi port = rohc_packet depth = 1500

	int rohc_hdr_size;
	size_t payload_size;
	size_t payload_offset;

	rohc_update_time(&comp, uncomp_time);

	/* find the best context for the packet */
	size_t cid = rohc_comp_find_ctxt(&comp, uncomp_data, -1, uncomp_time);
	if(cid == CID_NOT_USED)
	{
		return -1;
	}

	/* use profile to compress packet */
	if( comp.contexts[cid].pid==ROHC_PROFILE_TCP )
	{
		rohc_hdr_size = c_tcp_encode(&comp.contexts[cid], uncomp_data, uncomp_len, rohc_packet, 2048);
	}
	else if( comp.contexts[cid].pid==ROHC_PROFILE_UDP )
	{
		rohc_hdr_size = c_udp_encode(&comp.contexts[cid], uncomp_data, rohc_packet, 2048);
	}
	else
	{
		rohc_hdr_size = c_uncompressed_encode(&comp.contexts[cid], uncomp_data, uncomp_len, rohc_packet, 2048);
	}

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
		cid = rohc_comp_find_ctxt(&comp, uncomp_data, ROHC_PROFILE_UNCOMPRESSED,
		                        uncomp_time);
		if(cid == CID_NOT_USED)
		{
			return -1;
		}

		/* use the Uncompressed profile to compress the packet */
		if( comp.contexts[cid].pid==ROHC_PROFILE_TCP )
		{
			rohc_hdr_size = c_tcp_encode(&comp.contexts[cid], uncomp_data, uncomp_len, rohc_packet, 2048);
		}
		else if( comp.contexts[cid].pid==ROHC_PROFILE_UDP )
		{
			rohc_hdr_size = c_udp_encode(&comp.contexts[cid], uncomp_data, rohc_packet, 2048);
		}
		else
		{
			rohc_hdr_size = c_uncompressed_encode(&comp.contexts[cid], uncomp_data, uncomp_len,
					rohc_packet, 2048);
		}
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
	payload_offset = rohc_get_payload_offset(cid);
	payload_size   = uncomp_len - payload_offset;

//	memcpy(rohc_packet + rohc_hdr_size, uncomp_data + payload_offset, payload_size);
	for( int j=0 ; j<payload_size ; j++ )
	{
#pragma HLS loop_tripcount min=1 max=1500
		rohc_packet[rohc_hdr_size + j] = uncomp_data[payload_offset + j];
	}

	comp.contexts[cid].num_sent_packets++;

	return payload_size + rohc_hdr_size;
}

void rohc_update_time(struct rohc_comp *const comp, uint16_t uncomp_time)
{
	if( comp->last_arrival_time > uncomp_time ) // overflowed counter
	{
		int num_used = 0, i, j;
		int context_list[ROHC_SMALL_CID_MAX+1];

		// extract used contexts
		for( i=0 ; i<ROHC_SMALL_CID_MAX+1 ; i++ )
		{
			if( comp->contexts[i].used )
			{
				context_list[num_used] = i;
				num_used++;
			}
		}

		// sort used contexts
		for( i=0 ; i<num_used ; i++ )
		{
#pragma HLS loop_tripcount min=0 max=16
			for( j=i+1 ; j<num_used ; j++ )
			{
#pragma HLS loop_tripcount min=0 max=15
				if( comp->contexts[context_list[i]].latest_used > comp->contexts[context_list[j]].latest_used )
				{
					int temp = context_list[j];
					context_list[j] = context_list[i];
					context_list[i] = temp;
				}
			}
		}

		// update time with re-zerod! values
		for( i=0 ; i<num_used ; i++ )
		{
#pragma HLS loop_tripcount min=0 max=16
			comp->contexts[context_list[i]].latest_used = i;
		}
	}
}

int rohc_get_payload_offset(size_t cid)
{
	size_t payload_offset;

	if( comp.contexts[cid].pid==ROHC_PROFILE_TCP )
	{
		payload_offset = sizeof(struct ipv4_hdr) + sizeof(struct tcphdr);
	}
	else if( comp.contexts[cid].pid==ROHC_PROFILE_UDP )
	{
		payload_offset = sizeof(struct ipv4_hdr) + sizeof(struct udphdr);
	}
	else
	{
		if( comp.contexts[cid].packet_type==ROHC_PACKET_IR )
		{
			payload_offset = 0;
		}
		else
		{
			payload_offset = 1;
		}
	}
	return payload_offset;
}
