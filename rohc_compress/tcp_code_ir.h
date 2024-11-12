#include "base.h"

typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t version_flag:1;
	uint8_t reserved:7;
#else
	uint8_t reserved:7;
	uint8_t version_flag:1;
#endif
	uint8_t protocol;
	uint32_t src_addr;
	uint32_t dst_addr;
} __attribute__((packed)) ipv4_static_t;

typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t reserved:5;
	uint8_t df:1;
	uint8_t ip_id_behavior:2;
	uint8_t dscp:6;
	uint8_t ip_ecn_flags:2;
#else
	uint8_t ip_id_behavior:2;
	uint8_t df:1;
	uint8_t reserved:5;
	uint8_t ip_ecn_flags:2;
	uint8_t dscp:6;
#endif
	uint8_t ttl_hopl;
} __attribute__((packed)) ipv4_dynamic1_t;

typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t reserved:5;
	uint8_t df:1;
	uint8_t ip_id_behavior:2;
	uint8_t dscp:6;
	uint8_t ip_ecn_flags:2;
#else
	uint8_t ip_id_behavior:2;
	uint8_t df:1;
	uint8_t reserved:5;
	uint8_t ip_ecn_flags:2;
	uint8_t dscp:6;
#endif
	uint8_t ttl_hopl;
	uint16_t ip_id;
} __attribute__((packed)) ipv4_dynamic2_t;

typedef struct
{
	uint16_t src_port;          /**< irregular(16)                          [ 16 ] */
	uint16_t dst_port;          /**< irregular(16)                          [ 16 ] */
} __attribute__((packed)) tcp_static_t;

typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t ecn_used:1;         /**< one_bit_choice                         [ 1 ] */
	uint8_t ack_stride_flag:1;  /**< irregular(1)                           [ 1 ] */
	uint8_t ack_zero:1;         /**< irregular(1)                           [ 1 ] */
	uint8_t urp_zero:1;         /**< irregular(1)                           [ 1 ] */
	uint8_t tcp_res_flags:4;    /**< irregular(4)                           [ 4 ] */

	uint8_t tcp_ecn_flags:2;    /**< irregular(2)                           [ 2 ] */
	uint8_t urg_flag:1;         /**< irregular(1)                           [ 1 ] */
	uint8_t ack_flag:1;         /**< irregular(1)                           [ 1 ] */
	uint8_t psh_flag:1;         /**< irregular(1)                           [ 1 ] */
	uint8_t rsf_flags:3;        /**< irregular(3)                           [ 3 ] */
#else
	uint8_t tcp_res_flags:4;
	uint8_t urp_zero:1;
	uint8_t ack_zero:1;
	uint8_t ack_stride_flag:1;
	uint8_t ecn_used:1;

	uint8_t rsf_flags:3;
	uint8_t psh_flag:1;
	uint8_t ack_flag:1;
	uint8_t urg_flag:1;
	uint8_t tcp_ecn_flags:2;
#endif
	uint16_t msn;               /**< irregular(16)                          [ 16 ] */
	uint32_t seq_num;           /**< irregular(32)                          [ 32 ] */

	/* variable fields:
	 *   zero_or_irreg(ack_zero.CVALUE, 32)                                 [ 0, 32 ]
	 *   irregular(16)                                                      [ 16 ]
	 *   irregular(16)                                                      [ 16 ]
	 *   zero_or_irreg(urp_zero.CVALUE, 16)                                 [ 0, 16 ]
	 *   static_or_irreg(ack_stride_flag.CVALUE, 16)                        [ 0, 16 ]
	 *   list_tcp_options                                                   [ VARIABLE ]
	 */

} __attribute__((packed)) tcp_dynamic_t;

int tcp_code_IR_packet(struct rohc_comp_ctxt *contecst,
				  const uint8_t *ip_pkt,
				  uint8_t *const rohc_pkt,
				  const size_t rohc_pkt_max_len,
				  const int packet_type);
int tcp_code_static_part(const uint8_t *ip_pkt,
                         uint8_t *const rohc_pkt,
                         const size_t rohc_pkt_max_len);
int tcp_code_static_ipv4_part(const struct ipv4_hdr *const ipv4,
							 uint8_t *const rohc_data,
							 const size_t rohc_max_len);
int tcp_code_static_tcp_part(const struct tcphdr *const tcp,
							uint8_t *const rohc_data,
							const size_t rohc_max_len);
int tcp_code_dyn_part(struct sc_tcp_context *const tcp_context,
					  const uint8_t *ip_pkt,
                      uint8_t *const rohc_pkt,
                      const size_t rohc_pkt_max_len);
int tcp_code_dynamic_ipv4_part(ipv4_context_t *const ip_context,
							  const struct ipv4_hdr *const ipv4,
							  uint8_t *const rohc_data,
							  const size_t rohc_max_len);
int tcp_code_dynamic_tcp_part(struct sc_tcp_context *const tcp_context,
							 const struct tcphdr *const tcp,
							 uint8_t *const rohc_data,
							 const size_t rohc_max_len);
int c_zero_or_irreg16(const uint16_t packet_value,
                      uint8_t *const rohc_data,
                      const size_t rohc_max_len,
                      int *const indicator);
int c_zero_or_irreg32(const uint32_t packet_value,
                      uint8_t *const rohc_data,
                      const size_t rohc_max_len,
                      int *const indicator);
