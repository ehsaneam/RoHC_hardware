#include "base.h"

int tcp_decide_packet(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt);
rohc_packet_t tcp_decide_FO_SO_packet(const struct rohc_comp_ctxt *const context,
									  const struct tcphdr *const tcp, const bool crc7_at_least);
rohc_packet_t tcp_decide_FO_SO_packet_seq(const struct rohc_comp_ctxt *const context,
										  const struct tcphdr *const tcp, const bool crc7_at_least);
rohc_packet_t tcp_decide_FO_SO_packet_rnd(const struct rohc_comp_ctxt *const context,
										  const struct tcphdr *const tcp, const bool crc7_at_least);
