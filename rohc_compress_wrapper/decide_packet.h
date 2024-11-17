#include "base.h"

///////////////////////////
//			TCP			 //
///////////////////////////
int tcp_decide_packet(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt);
rohc_packet_t tcp_decide_FO_SO_packet(const struct rohc_comp_ctxt *const context,
									  const struct tcphdr *const tcp, const bool crc7_at_least);
rohc_packet_t tcp_decide_FO_SO_packet_seq(const struct rohc_comp_ctxt *const context,
										  const struct tcphdr *const tcp, const bool crc7_at_least);
rohc_packet_t tcp_decide_FO_SO_packet_rnd(const struct rohc_comp_ctxt *const context,
										  const struct tcphdr *const tcp, const bool crc7_at_least);
rohc_packet_t tcp_decide_FO_SO_packet_rnd123(uint8_t rsf_flags, bool tcp_window_changed,
			 size_t nr_seq_bits_65535, size_t nr_ack_bits_16383, size_t nr_ack_bits_65535,
			 const bool crc7_at_least, bool tcp_seq_num_changed);
rohc_packet_t tcp_decide_FO_SO_packet_rnd456(bool tcp_window_changed, const bool crc7_at_least,
		size_t seq_num_scaling_nr, size_t nr_seq_scaled_bits, bool tcp_ack_num_changed, size_t payload_len,
		uint8_t ack_flag, size_t nr_ack_scaled_bits, bool tcp_seq_num_changed, bool ack_scale_possible);
rohc_packet_t tcp_decide_FO_SO_packet_rnd789(uint8_t ack_flag, size_t nr_ack_bits_8191, const bool crc7_at_least,
		bool tcp_seq_num_changed, size_t nr_seq_bits_65535, bool tcp_ack_num_changed, size_t nr_ack_bits_16383,
		size_t seq_num_scaling_nr, size_t nr_seq_scaled_bits);
rohc_packet_t tcp_decide_FO_SO_packet_rndab(const bool crc7_at_least, size_t nr_seq_bits_8191,
		uint8_t ack_flag, size_t nr_ack_bits_8191, size_t nr_ack_bits_16383, size_t nr_seq_bits_65535);

///////////////////////////
//			UDP			 //
///////////////////////////
uint8_t udp_decide_packet(struct rohc_comp_ctxt *const context);
uint8_t c_ip_decide_FO_packet(const struct rohc_comp_ctxt *context);
uint8_t c_ip_decide_SO_packet(const struct rohc_comp_ctxt *context);
bool rohc_comp_rfc3095_is_sn_possible(const struct rohc_comp_rfc3095_ctxt *const rfc3095_ctxt,
                                      const size_t bits_nr, const size_t add_bits_nr);
bool rfc3095_is_outer_ip_id_bits_possible(const struct rohc_comp_rfc3095_ctxt *const ctxt,
                                                const size_t max_ip_id_bits_nr);
bool no_outer_ip_id_bits_required(const struct rohc_comp_rfc3095_ctxt *const ctxt);
