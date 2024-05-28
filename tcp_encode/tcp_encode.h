#include "change_detection.h"
#include "decide_state.h"
#include "decide_packet.h"
#include "uncomp_fields.h"
#include "code_ir.h"
#include "code_co.h"
#include "base.h"

int c_tcp_encode(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt, int ip_pkt_len,
		struct rohc_ts ip_time, uint8_t *const rohc_pkt, const size_t rohc_pkt_max_len);
void copyTcp(struct tcphdr *old_tcp, struct tcphdr *tcp);
