#include "change_detection.h"
#include "decide_packet.h"
#include "uncomp_fields.h"
#include "tcp_code_ir.h"
#include "tcp_code_co.h"
#include "base.h"

int c_tcp_encode(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt, int ip_pkt_len,
		uint8_t *const rohc_pkt, const size_t rohc_pkt_max_len);
void tcp_decide_state(struct rohc_comp_ctxt *const context);
