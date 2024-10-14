#include "base.h"

int c_uncompressed_encode(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt, int ip_pkt_len,
		uint8_t *const rohc_pkt, const size_t rohc_pkt_max_len);
void uncompressed_decide_state(struct rohc_comp_ctxt *const context, int ip_vers);
int uncompressed_code_packet(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt, int ip_pkt_len,
                                    uint8_t *const rohc_pkt, const size_t rohc_pkt_max_len);
int uncompressed_code_IR_packet(const struct rohc_comp_ctxt *context, uint8_t *ip_pkt, int ip_pkt_len,
							   uint8_t *const rohc_pkt, const size_t rohc_pkt_max_len);
int uncompressed_code_normal_packet(const struct rohc_comp_ctxt *context, uint8_t *ip_pkt, int ip_pkt_len,
								   uint8_t *const rohc_pkt, const size_t rohc_pkt_max_len);
