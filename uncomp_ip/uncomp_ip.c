#include "uncomp_ip.h"

bool tcp_encode_uncomp_ip_fields(struct rohc_comp_ctxt *const context, const struct ipv4_hdr *const ip)
{
	struct sc_tcp_context *tcp_context = &context->specific;

	ipv4_context_t *inner_ip_ctxt = &(tcp_context->ip_context);

	/* parse IP headers */
	tcp_context->tmp.ttl_irreg_chain_flag = 0;

	if( ip->version==4 )
	{
		/* irregular chain? */
		uint8_t ttl_hopl = ip->ttl;
		if( ttl_hopl!=inner_ip_ctxt->ttl_hopl )
		{
			tcp_context->tmp.ttl_irreg_chain_flag |= 1;
		}
	}
	else
	{
		return false;
	}

	tcp_context->tmp.outer_ip_ttl_changed =
		(tcp_context->tmp.ttl_irreg_chain_flag != 0);

	const uint16_t ip_id = rohc_bswap16(ip->id);

	/* does IP-ID behavior changed? */
	tcp_context->tmp.ip_id_behavior_changed =
		(inner_ip_ctxt->last_ip_id_behavior != inner_ip_ctxt->ip_id_behavior);

	/* compute the new IP-ID / SN delta */
	if(inner_ip_ctxt->ip_id_behavior == IP_ID_BEHAVIOR_SEQ_SWAP)
	{
		/* specific case of IP-ID delta for sequential swapped behavior */
		tcp_context->tmp.ip_id_delta = swab16(ip_id) - tcp_context->msn;
	}
	else
	{
		/* compute delta the same way for sequential, zero or random: it is
		 * important to always compute the IP-ID delta and record it in W-LSB,
		 * so that the IP-ID deltas of next packets may be correctly encoded */
		tcp_context->tmp.ip_id_delta = ip_id - tcp_context->msn;
	}

	/* how many bits are required to encode the new IP-ID / SN delta ? */
	if(inner_ip_ctxt->ip_id_behavior != IP_ID_BEHAVIOR_SEQ &&
	   inner_ip_ctxt->ip_id_behavior != IP_ID_BEHAVIOR_SEQ_SWAP)
	{
		/* send all bits if IP-ID behavior is not sequential */
		tcp_context->tmp.nr_ip_id_bits_3 = 16;
		tcp_context->tmp.nr_ip_id_bits_1 = 16;
	}
	else
	{
		/* send only required bits in FO or SO states */
		tcp_context->tmp.nr_ip_id_bits_3 = wlsb_get_minkp_16bits(&tcp_context->ip_id_wlsb,
							   tcp_context->tmp.ip_id_delta, 3);
		tcp_context->tmp.nr_ip_id_bits_1 = wlsb_get_minkp_16bits(&tcp_context->ip_id_wlsb,
							   tcp_context->tmp.ip_id_delta, 1);
	}
	/* add the new IP-ID / SN delta to the W-LSB encoding object */
	/* TODO: move this after successful packet compression */
	c_add_wlsb(&tcp_context->ip_id_wlsb, tcp_context->msn,
			   tcp_context->tmp.ip_id_delta);

	// ip->df
	uint16_t ipdf = ip->frag_off & 0x0040;

	if( ipdf != inner_ip_ctxt->df )
	{
		tcp_context->tmp.ip_df_changed = true;
	}
	else
	{
		tcp_context->tmp.ip_df_changed = false;
	}

	if( ip->dscp != inner_ip_ctxt->dscp )
	{
		tcp_context->tmp.dscp_changed = true;
	}
	else
	{
		tcp_context->tmp.dscp_changed = false;
	}

	tcp_context->tmp.ttl_hopl = ip->ttl;

	/* encode innermost IPv4 TTL or IPv6 Hop Limit */
	if(tcp_context->tmp.ttl_hopl != inner_ip_ctxt->ttl_hopl)
	{
		tcp_context->tmp.ttl_hopl_changed = true;
		tcp_context->ttl_hopl_change_count = 0;
	}
	else if(tcp_context->ttl_hopl_change_count < MAX_FO_COUNT)
	{
		tcp_context->tmp.ttl_hopl_changed = true;
		tcp_context->ttl_hopl_change_count++;
	}
	else
	{
		tcp_context->tmp.ttl_hopl_changed = false;
	}
	tcp_context->tmp.nr_ttl_hopl_bits = wlsb_get_kp_8bits(&tcp_context->ttl_hopl_wlsb,
			tcp_context->tmp.ttl_hopl, tcp_context->ttl_hopl_wlsb.p);
	/* add the new TTL/Hop Limit to the W-LSB encoding object */
	/* TODO: move this after successful packet compression */
	c_add_wlsb(&tcp_context->ttl_hopl_wlsb, tcp_context->msn,
	           tcp_context->tmp.ttl_hopl);

	return true;
}

uint8_t wlsb_get_kp_8bits(const struct c_wlsb *const wlsb,
                         const uint8_t value,
                         const int p)
{
	uint8_t bits_nr;

	if(wlsb->count == 0)
	{
		bits_nr = 8;
	}
	else
	{
		uint8_t k;

		for( k=0 ; k<8 ; k++ )
		{
			const uint8_t interval_width = (1U << k) - 1; /* interval width = 2^k - 1 */
			uint8_t i;
			int8_t computed_p = p;

			for( i=0 ; i<4 ; i++ )
			{
				if( wlsb->window_used[i] )
				{
					const uint8_t v_ref = wlsb->window_value[i];
					const uint8_t min = v_ref - computed_p;
					const uint8_t max = min + interval_width;

					if( (min<=max && (value<min || value>max)) ||
						(min>max && (value<min && value>max)) )
					{
						break;
					}
				}
			}

			if( wlsb->window_used[i]==0 )
			{
				break;
			}
		}
		bits_nr = k;
	}
	return bits_nr;
}

uint8_t wlsb_get_minkp_16bits(const struct c_wlsb *const wlsb,
                             const uint16_t value,
                             const int p)
{
	uint8_t bits_nr;

	if( wlsb->count==0 )
	{
		bits_nr = 16;
	}
	else
	{
		uint8_t k;

		for( k=0 ; k<16 ; k++ )
		{
			const uint16_t interval_width = (1U << k) - 1; /* interval width = 2^k - 1 */
			int16_t computed_p = p;
			uint8_t i;

			for( i=0 ; i<4 ; i++ )
			{
				if( wlsb->window_used[i] )
				{
					const uint16_t v_ref = wlsb->window_value[i];
					const uint16_t min = v_ref - computed_p;
					const uint16_t max = min + interval_width;

					if( (min<=max && (value<min || value>max)) ||
						(min>max && (value<min && value>max)) )
					{
						break;
					}
				}
			}

			if( wlsb->window_used[i]==0 )
			{
				break;
			}
		}
		bits_nr = k;
	}

	return bits_nr;
}

void c_add_wlsb(struct c_wlsb *const wlsb,
                const uint32_t sn,
                const uint32_t value)
{
	/* if window is full, an entry is overwritten */
	if(wlsb->count == wlsb->window_width)
	{
		wlsb->oldest = (wlsb->oldest + 1) % wlsb->window_width;
	}
	else
	{
		wlsb->count++;
	}

	wlsb->window_used[wlsb->next] = true;
	wlsb->window_sn[wlsb->next] = sn;
	wlsb->window_value[wlsb->next] = value;
	wlsb->next = (wlsb->next + 1) % wlsb->window_width;
}

uint16_t swab16(const uint16_t value)
{
	return ((value & 0x00ff) << 8) | ((value & 0xff00) >> 8);
}

uint16_t rohc_bswap16(const uint16_t value)
{
	return (((value >> 8) & 0xff) | ((value & 0xff) << 8));
}
