#include "base.h"

void tcp_detect_changes(struct rohc_comp_ctxt *const context,
		uint8_t *ip_pkt, int ip_pkt_len);
void tcp_detect_ecn_used_behavior(struct rohc_comp_ctxt *const context,
								 const uint8_t pkt_ecn_vals,
								 const uint8_t pkt_res_val);
uint16_t c_tcp_get_next_msn(const struct rohc_comp_ctxt *const context);
tcp_ip_id_behavior_t tcp_detect_ip_id_behavior(const uint16_t last_ip_id,
											  const uint16_t new_ip_id);
bool is_ip_id_increasing(const uint16_t old_id, const uint16_t new_id);
