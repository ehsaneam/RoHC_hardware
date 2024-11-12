#include "base.h"
#include "udp_code.h"
#include "change_detection.h"
#include "decide_packet.h"
#include "uncomp_fields.h"

int c_udp_encode(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt, uint8_t *const rohc_pkt,
		const size_t rohc_pkt_max_len);
int rohc_comp_rfc3095_encode(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt, uint8_t *const rohc_pkt,
                             const size_t rohc_pkt_max_len);
void udp_decide_state(struct rohc_comp_ctxt *const context);
void rohc_comp_rfc3095_decide_state(struct rohc_comp_ctxt *const context);
void update_context(struct rohc_comp_rfc3095_ctxt *const rfc3095_ctxt, uint8_t *ip_pkt);
