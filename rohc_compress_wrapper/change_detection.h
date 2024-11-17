#include "base.h"

///////////////////////////
//			TCP			 //
///////////////////////////
void tcp_detect_changes(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt, int ip_pkt_len);
void tcp_detect_ecn_used_behavior(struct rohc_comp_ctxt *const context,
								 const uint8_t pkt_ecn_vals, const uint8_t pkt_res_val);
uint16_t c_tcp_get_next_msn(const struct rohc_comp_ctxt *const context);
tcp_ip_id_behavior_t tcp_detect_ip_id_behavior(const uint16_t last_ip_id, const uint16_t new_ip_id);

///////////////////////////
//			UDP			 //
///////////////////////////
int udp_changed_udp_dynamic(struct sc_udp_context *udp_context, const struct udphdr *udp);
bool rohc_comp_rfc3095_detect_changes(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt);
void udp_detect_ip_id_behaviours(struct ip_header_info *const header_info, uint8_t *data);
unsigned short udp_detect_changed_fields(struct ip_header_info *const header_info, uint8_t *data);
int udp_changed_static_both_hdr(struct rohc_comp_ctxt *const context);
int udp_changed_dynamic_both_hdr(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt);

///////////////////////////
//		  COMMON		 //
///////////////////////////
bool is_field_changed(const unsigned short changed_fields, const unsigned short check_field);
bool is_ip_id_increasing(const uint16_t old_id, const uint16_t new_id);
