#include "uncomp_fields.h"

bool tcp_encode_uncomp_fields(struct rohc_comp_ctxt *const context,
                                     const struct net_pkt *const uncomp_pkt,
                                     const struct tcphdr *const tcp)
{
	struct sc_tcp_context *const tcp_context = context->specific;

	tcp_context->tmp.nr_msn_bits =
		wlsb_get_k_16bits(&tcp_context->msn_wlsb, tcp_context->msn);

	c_add_wlsb(&tcp_context->msn_wlsb, tcp_context->msn, tcp_context->msn);

	if( !tcp_encode_uncomp_ip_fields(context, uncomp_pkt) )
	{
		return false;
	}

	if( !tcp_encode_uncomp_tcp_fields(context, tcp) )
	{
		return false;
	}

	return true;
}
