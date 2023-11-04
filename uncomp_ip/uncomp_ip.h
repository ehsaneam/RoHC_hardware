#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define MAX_FO_COUNT  3U
#define ROHC_WLSB_WIDTH_MAX  16U

typedef enum
{
	IP_ID_BEHAVIOR_SEQ       = 0, /**< IP-ID increases */
	IP_ID_BEHAVIOR_SEQ_SWAP  = 1, /**< IP-ID increases in little endian */
	IP_ID_BEHAVIOR_RAND      = 2, /**< IP-ID is random */
	IP_ID_BEHAVIOR_ZERO      = 3, /**< IP-ID is constant zero */
} tcp_ip_id_behavior_t;

typedef enum
{
	ROHC_LSB_SHIFT_SN         = -1,      /**< real value for non-RTP SN */
#define ROHC_LSB_SHIFT_TCP_TS_1B  ROHC_LSB_SHIFT_SN /**< real value for TCP TS */
#define ROHC_LSB_SHIFT_TCP_TS_2B  ROHC_LSB_SHIFT_SN /**< real value for TCP TS */
	ROHC_LSB_SHIFT_IP_ID      =  0,      /**< real value for IP-ID */
	ROHC_LSB_SHIFT_TCP_TTL    =  3,      /**< real value for TCP TTL/HL */
#define ROHC_LSB_SHIFT_TCP_ACK_SCALED  ROHC_LSB_SHIFT_TCP_TTL
	ROHC_LSB_SHIFT_TCP_SN     =  4,      /**< real value for TCP MSN */
	ROHC_LSB_SHIFT_TCP_SEQ_SCALED =  7,      /**< real value for TCP seq/ack scaled */
	ROHC_LSB_SHIFT_VAR        =  103,    /**< real value is variable */
	ROHC_LSB_SHIFT_TCP_WINDOW = 16383,   /**< real value for TCP window */
	ROHC_LSB_SHIFT_TCP_TS_3B  = 0x00040000, /**< real value for TCP TS */
	ROHC_LSB_SHIFT_TCP_TS_4B  = 0x04000000, /**< real value for TCP TS */
} rohc_lsb_shift_t;

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


struct c_wlsb
{
	int p;
	size_t window_width;
	size_t oldest;
	size_t next;
	size_t count;
	int window_used[ROHC_WLSB_WIDTH_MAX];
	uint32_t window_sn[ROHC_WLSB_WIDTH_MAX];
	uint32_t window_value[ROHC_WLSB_WIDTH_MAX];
};

struct tcp_tmp_variables
{
	/** The IP-ID / SN delta (with bits swapped if necessary) */
	uint16_t ip_id_delta;
	/** Whether the behavior of the IP-ID field changed with current packet */
	bool ip_id_behavior_changed;
	/** The minimal number of bits required to encode the innermost IP-ID value
	 *  with p = 3 */
	size_t nr_ip_id_bits_3;
	/** The minimal number of bits required to encode the innermost IP-ID value
	 *  with p = 1 */
	size_t nr_ip_id_bits_1;

	/* innermost IPv4 TTL or IPv6 Hop Limit */
	uint8_t ttl_hopl;
	size_t nr_ttl_hopl_bits;
	bool ttl_hopl_changed;
	/* outer IPv4 TTLs or IPv6 Hop Limits */
	int ttl_irreg_chain_flag;
	bool outer_ip_ttl_changed;

	bool ip_df_changed;
	bool dscp_changed;
};

struct sc_tcp_context
{
	uint16_t msn;               /**< The Master Sequence Number (MSN) */
	struct c_wlsb ttl_hopl_wlsb;
	size_t ttl_hopl_change_count;
	struct c_wlsb ip_id_wlsb;
	struct tcphdr old_tcphdr;
	struct tcp_tmp_variables tmp;
	ipv4_context_t ip_context;
};

struct rohc_comp_ctxt
{
	/** Profile-specific data, defined by the profiles */
	struct sc_tcp_context specific;
};

bool tcp_encode_uncomp_ip_fields(struct rohc_comp_ctxt *const context,
		const struct ipv4_hdr *const ip);
uint8_t wlsb_get_kp_8bits(const struct c_wlsb *const wlsb,
		 const uint8_t value, const int p);
uint8_t wlsb_get_minkp_16bits(const struct c_wlsb *const wlsb,
		 const uint16_t value, const int p);
void c_add_wlsb(struct c_wlsb *const wlsb,
		 const uint32_t sn, const uint32_t value);
uint16_t swab16(const uint16_t value);
uint16_t rohc_bswap16(const uint16_t value);
uint8_t wlsb_get_kp_8bits(const struct c_wlsb *const wlsb,
		 const uint8_t value, const int p);
