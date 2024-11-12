#include "base.h"

///////////////////////////
//			TCP			 //
///////////////////////////
bool tcp_encode_uncomp_fields(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt);
bool tcp_encode_uncomp_ip_fields(struct rohc_comp_ctxt *const context,
		const struct ipv4_hdr *const ip);
bool tcp_encode_uncomp_tcp_fields(struct rohc_comp_ctxt *const context,
		const struct tcphdr *const tcp);
void calc_wlsbs(struct c_wlsb *seq_scaled_wlsb, struct c_wlsb *ack_wlsb, struct c_wlsb *ack_scaled_wlsb,
		bool *tcp_seq_num_changed, uint32_t seq_num, uint32_t old_seq_num, uint32_t tcp_seq_num_factor,
		uint32_t seq_num_scaling_nr, uint32_t *nr_seq_scaled_bits, uint32_t tcp_seq_num_scaled,
		bool *tcp_ack_num_changed, uint32_t ack_num, uint32_t old_ack_num, uint32_t ack_num_hbo,
		uint32_t *nr_ack_bits_16383, uint16_t tcp_ack_stride, uint32_t ack_num_scaling_nr,
		uint32_t *nr_ack_scaled_bits, uint32_t tcp_ack_num_scaled);
void c_field_scaling(uint32_t *const scaled_value, uint32_t *const residue_field,
                     const uint32_t scaling_factor, const uint32_t unscaled_value);

///////////////////////////
//			UDP			 //
///////////////////////////
bool udp_encode_uncomp_fields(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt);

///////////////////////////
//		  COMMON		 //
///////////////////////////
bool rohc_packet_carry_crc_7_or_8(const rohc_packet_t packet_type);
