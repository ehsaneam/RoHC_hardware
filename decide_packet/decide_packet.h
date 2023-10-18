

rohc_packet_t tcp_decide_packet(struct rohc_comp_ctxt *const context, const ip_context_t *const ip_inner_context,
								const struct tcphdr *const tcp);
rohc_packet_t tcp_decide_FO_SO_packet(const struct rohc_comp_ctxt *const context, const ip_context_t *const ip_inner_context,
									  const struct tcphdr *const tcp, const bool crc7_at_least);
rohc_packet_t tcp_decide_FO_SO_packet_seq(const struct rohc_comp_ctxt *const context,
										  const struct tcphdr *const tcp, const bool crc7_at_least);
rohc_packet_t tcp_decide_FO_SO_packet_rnd(const struct rohc_comp_ctxt *const context,
										  const struct tcphdr *const tcp, const bool crc7_at_least);
bool rsf_index_enc_possible(const uint8_t rsf_flags);
bool tcp_is_ack_stride_static(const uint16_t ack_stride, const size_t nr_trans);
bool tcp_is_ack_scaled_possible(const uint16_t ack_stride, const size_t nr_trans);
uint32_t rohc_bswap32(const uint32_t value);
