#include "base.h"

int udp_code_packet(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt, uint8_t *const rohc_pkt,
                const size_t rohc_pkt_max_len);
int udp_code_IR_packet(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt, uint8_t *const rohc_pkt,
			const size_t rohc_pkt_max_len);
int udp_code_IR_DYN_packet(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt,  uint8_t *const rohc_pkt,
                              const size_t rohc_pkt_max_len);
int udp_code_UO0_packet(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt, uint8_t *const rohc_pkt,
                           const size_t rohc_pkt_max_len);
int rohc_comp_rfc3095_build_uo1_pkt(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt,
		uint8_t *const rohc_pkt, const size_t rohc_pkt_max_len);
int udp_code_UO2_packet(struct rohc_comp_ctxt *const context, uint8_t *ip_pkt,
                           uint8_t *const rohc_pkt, const size_t rohc_pkt_max_len);
int rohc_code_static_part(struct ip_header_info *const header_info, uint8_t *ip_pkt,
		uint8_t *const rohc_pkt, int counter);
int rohc_code_static_ip_part(struct ip_header_info *const header_info, uint8_t *ip_pkt,
		uint8_t *const dest, int counter);
size_t udp_code_static_udp_part(const uint8_t *const ip_pkt, uint8_t *const dest, size_t counter);
int rohc_code_dynamic_part(const struct rohc_comp_ctxt *const context, const uint8_t *const ip_pkt,
		uint8_t *const rohc_pkt, int counter);
int udp_code_ipv4_dynamic_part(struct ip_header_info *const header_info, const uint8_t *const ip_pkt,
						  uint8_t *const dest, int counter);
size_t udp_code_dynamic_udp_part(struct sc_udp_context *udp_context, const uint8_t *const ip_pkt,
								uint8_t *const dest, const size_t counter);
int c_ip_code_ir_remainder(uint32_t sn, uint8_t *const dest, const size_t dest_max_len, const size_t counter);
uint8_t compute_uo_crc(struct rohc_comp_rfc3095_ctxt *const rfc3095_ctxt, uint8_t *ip_pkt,
					  const rohc_crc_type_t crc_type, const uint8_t crc_init);
uint8_t udp_compute_crc_static(const uint8_t *const ip_pkt, const rohc_crc_type_t crc_type,
		const uint8_t init_val);
uint8_t udp_compute_crc_dynamic(const uint8_t *const ip_pkt, const rohc_crc_type_t crc_type,
                                const uint8_t init_val);
int code_uo_remainder(struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt, uint8_t *const ip_pkt,
					 uint8_t *const dest, int counter);
