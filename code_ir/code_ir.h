#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define ROHC_INIT_TS_STRIDE_MIN  3U

#define ROHC_PACKET_TYPE_IR      0xFD
#define ROHC_PACKET_TYPE_IR_DYN  0xF8

#define CRC_INIT_8 0xff

typedef enum
{
	IP_ID_BEHAVIOR_SEQ       = 0, /**< IP-ID increases */
	IP_ID_BEHAVIOR_SEQ_SWAP  = 1, /**< IP-ID increases in little endian */
	IP_ID_BEHAVIOR_RAND      = 2, /**< IP-ID is random */
	IP_ID_BEHAVIOR_ZERO      = 3, /**< IP-ID is constant zero */
} tcp_ip_id_behavior_t;

typedef enum
{
	/** The ROHC Uncompressed profile (RFC 3095, section 5.10) */
	ROHC_PROFILE_UNCOMPRESSED = 0x0000,
	/** The ROHC UDP profile (RFC 3095, section 5.11) */
	ROHC_PROFILE_UDP          = 0x0002,
	/** The ROHC IP-only profile (RFC 3843, section 5) */
	ROHC_PROFILE_IP           = 0x0004,
	/** The ROHC TCP profile (RFC 4996) */
	ROHC_PROFILE_TCP          = 0x0006,

	ROHC_PROFILE_MAX          = 0x0009,

} rohc_profile_t;

typedef enum
{
	/* IR and IR-DYN packets */
	ROHC_PACKET_IR        =  0, /**< ROHC IR packet */
	ROHC_PACKET_IR_DYN    =  1, /**< ROHC IR-DYN packet */

	/* UO-0 packets */
	ROHC_PACKET_UO_0      =  2, /**< ROHC UO-0 packet */

	/* UO-1 packets */
	ROHC_PACKET_UO_1      =  3, /**< ROHC UO-1 packet (for all non-RTP profiles) */

	/* UOR-2 packets */
	ROHC_PACKET_UOR_2     =  7, /**< ROHC UOR-2 packet (for all non-RTP profiles) */

	/* values 11 and 12 were used by CCE packets of the UDP-Lite profile */

	/* Normal packet (Uncompressed profile only) */
	ROHC_PACKET_NORMAL    = 13, /**< ROHC Normal packet (Uncompressed profile only) */

	ROHC_PACKET_UNKNOWN   = 14, /**< Unknown packet type */

	/* packets for TCP profile */
	ROHC_PACKET_TCP_CO_COMMON = 15, /**< TCP co_common packet */
	ROHC_PACKET_TCP_RND_1     = 16, /**< TCP rnd_1 packet */
	ROHC_PACKET_TCP_RND_2     = 17, /**< TCP rnd_2 packet */
	ROHC_PACKET_TCP_RND_3     = 18, /**< TCP rnd_3 packet */
	ROHC_PACKET_TCP_RND_4     = 19, /**< TCP rnd_4 packet */
	ROHC_PACKET_TCP_RND_5     = 20, /**< TCP rnd_5 packet */
	ROHC_PACKET_TCP_RND_6     = 21, /**< TCP rnd_6 packet */
	ROHC_PACKET_TCP_RND_7     = 22, /**< TCP rnd_7 packet */
	ROHC_PACKET_TCP_RND_8     = 23, /**< TCP rnd_8 packet */
	ROHC_PACKET_TCP_SEQ_1     = 24, /**< TCP seq_1 packet */
	ROHC_PACKET_TCP_SEQ_2     = 25, /**< TCP seq_2 packet */
	ROHC_PACKET_TCP_SEQ_3     = 26, /**< TCP seq_3 packet */
	ROHC_PACKET_TCP_SEQ_4     = 27, /**< TCP seq_4 packet */
	ROHC_PACKET_TCP_SEQ_5     = 28, /**< TCP seq_5 packet */
	ROHC_PACKET_TCP_SEQ_6     = 29, /**< TCP seq_6 packet */
	ROHC_PACKET_TCP_SEQ_7     = 30, /**< TCP seq_7 packet */
	ROHC_PACKET_TCP_SEQ_8     = 31, /**< TCP seq_8 packet */

	ROHC_PACKET_MAX                 /**< The number of packet types */
} rohc_packet_t;

struct ipv4_hdr
{
#if WORDS_BIGENDIAN == 1
	uint8_t version:4;          /**< The IP version */
	uint8_t ihl:4;              /**< The IP Header Length (IHL) in 32-bit words */
#else
	uint8_t ihl:4;
	uint8_t version:4;
#endif

	/* service may be read as TOS or DSCP + ECN */
	union
	{
		uint8_t tos;             /**< The Type Of Service (TOS) */
		uint8_t dscp_ecn;        /**< The combined DSCP and ECN fields */
		struct
		{
#if WORDS_BIGENDIAN == 1
			uint8_t dscp:6;       /**< The Differentiated Services Code Point (DSCP) */
			uint8_t ecn:2;        /**< The Explicit Congestion Notification (ECN) */
#else
			uint8_t ecn:2;
			uint8_t dscp:6;
#endif
		} __attribute__((packed));
	} __attribute__((packed));

	uint16_t tot_len;           /**< The Total Length (header + payload) */
	uint16_t id;                /**< The IDentification of the packet */

	/* IP flags and Fragment Offset may be read in 2 ways */
	union
	{
		uint16_t frag_off;       /**< The IP flags + Fragment Offset in 64-bit words */
#define IPV4_RF      0x8000    /**< Mask for reserved flag */
#define IPV4_DF      0x4000    /**< Mask for Don't Fragment (DF) flag */
#define IPV4_MF      0x2000    /**< Mask for More Fragments (MF) flag */
#define IPV4_OFFMASK 0x1fff    /**< mask for Fragment Offset field */
		struct
		{
#if WORDS_BIGENDIAN == 1
			uint8_t reserved:1;   /**< A reserved flag */
			uint8_t df:1;         /**< The Don't Fragment (DF) flag */
			uint8_t mf:1;         /**< The More Fragments (MF) flag */
			uint8_t frag_off1:5;  /**< The Fragment Offset in 64-bit words (part 1) */
#else
			uint8_t frag_off1:5;
			uint8_t mf:1;
			uint8_t df:1;
			uint8_t reserved:1;
#endif
			uint8_t frag_off2;    /**< The Fragment Offset in 64-bit words (part 2) */
		} __attribute__((packed));
	} __attribute__((packed));

	uint8_t ttl;                /**< The Time To Live (TTL) */
	uint8_t protocol;           /**< The Protocol of the next header */
	uint16_t check;             /**< The checksum over the IP header */
	uint32_t saddr;             /**< The source IP address */
	uint32_t daddr;             /**< The destination IP address */

	uint8_t options[0];         /**< The IP options start here */

} __attribute__((packed));

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

struct tcphdr
{
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq_num;
	uint32_t ack_num;
#if WORDS_BIGENDIAN == 1
	uint8_t data_offset:4;
	uint8_t res_flags:4;
	uint8_t ecn_flags:2;
	uint8_t urg_flag:1;
	uint8_t ack_flag:1;
	uint8_t psh_flag:1;
	uint8_t rsf_flags:3;
#else
	uint8_t res_flags:4;
	uint8_t data_offset:4;
	uint8_t rsf_flags:3;
	uint8_t psh_flag:1;
	uint8_t ack_flag:1;
	uint8_t urg_flag:1;
	uint8_t ecn_flags:2;
#endif
	uint16_t window;
	uint16_t checksum;
	uint16_t urg_ptr;
	uint8_t options[0];          /**< The beginning of the TCP options */
} __attribute__((packed));

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

typedef struct __attribute__((packed)) ipv4_context
{
	uint8_t version:4;
	uint8_t df:1;
	uint8_t unused:3;

	uint8_t dscp:6;
	uint8_t ip_ecn_flags:2;

	uint8_t protocol;

	uint8_t ttl_hopl;

	uint8_t ip_id_behavior;
	uint8_t last_ip_id_behavior;
	uint16_t last_ip_id;

	uint32_t src_addr;
	uint32_t dst_addr;

} ipv4_context_t;

struct tcp_tmp_variables
{
	uint8_t ttl_hopl;
};

struct sc_tcp_context
{
	struct tcp_tmp_variables tmp;
	ipv4_context_t ip_context;
	bool ecn_used;
	uint16_t msn;
	int tcp_seq_num_change_count;
	uint16_t ack_stride;
	size_t ack_num_scaling_nr;
};

struct rohc_comp
{
	uint8_t crc_table_8[256];
};

struct rohc_comp_ctxt
{
	size_t cid;
	int pid;
	struct rohc_comp compressor;
	struct sc_tcp_context specific;
};

int code_IR_packet(struct rohc_comp_ctxt *contecst,
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
uint8_t crc_calc_8(const uint8_t *const buf,
				 const size_t size,
				 const uint8_t init_val,
				 const uint8_t *const crc_table);
int c_static_or_irreg16(const uint16_t packet_value,
                        const bool is_static,
                        uint8_t *const rohc_data,
                        const size_t rohc_max_len,
                        int *const indicator);
int c_zero_or_irreg16(const uint16_t packet_value,
                      uint8_t *const rohc_data,
                      const size_t rohc_max_len,
                      int *const indicator);
int c_zero_or_irreg32(const uint32_t packet_value,
                      uint8_t *const rohc_data,
                      const size_t rohc_max_len,
                      int *const indicator);
int code_cid_values(const size_t cid,
                    uint8_t *const dest,
                    const size_t dest_size,
                    size_t *const first_position);
uint8_t c_add_cid(const size_t cid);
bool tcp_is_ack_stride_static(const uint16_t ack_stride,
                              const size_t nr_trans);
uint16_t rohc_bswap16(const uint16_t value);
