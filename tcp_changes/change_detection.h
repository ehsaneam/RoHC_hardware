#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define MAX_FO_COUNT  3U

typedef enum
{
	IP_ID_BEHAVIOR_SEQ       = 0, /**< IP-ID increases */
	IP_ID_BEHAVIOR_SEQ_SWAP  = 1, /**< IP-ID increases in little endian */
	IP_ID_BEHAVIOR_RAND      = 2, /**< IP-ID is random */
	IP_ID_BEHAVIOR_ZERO      = 3, /**< IP-ID is constant zero */
} tcp_ip_id_behavior_t;

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

struct tcp_tmp_variables
{
	/* the length of the TCP payload (headers and options excluded) */
	size_t payload_len;

	/** Whether the ecn_used flag changed or not */
	bool ecn_used_changed;
};

struct sc_tcp_context
{
	/** Explicit Congestion Notification used */
	bool ecn_used;
	/** The number of times the ECN fields were added to the compressed header */
	size_t ecn_used_change_count;
	/** The number of times the ECN fields were not needed */
	size_t ecn_used_zero_count;

	uint16_t msn;               /**< The Master Sequence Number (MSN) */

	/// The previous TCP header
	struct tcphdr old_tcphdr;

	/// @brief TCP-specific temporary variables that are used during one single
	///        compression of packet
	struct tcp_tmp_variables tmp;

	ipv4_context_t ip_context;
};

struct rohc_comp_ctxt
{
	/** Profile-specific data, defined by the profiles */
	struct sc_tcp_context specific;

	/** The number of sent packets */
	int num_sent_packets;
};

void tcp_detect_changes(struct rohc_comp_ctxt *const context,
	   int uncomp_pkt_len, struct ipv4_hdr *ipv4_hdr, struct tcphdr *tcp);
void tcp_detect_ecn_used_behavior(struct rohc_comp_ctxt *const context,
								 const uint8_t pkt_ecn_vals,
								 const uint8_t pkt_res_val);
uint16_t c_tcp_get_next_msn(const struct rohc_comp_ctxt *const context);
tcp_ip_id_behavior_t tcp_detect_ip_id_behavior(const uint16_t last_ip_id,
											  const uint16_t new_ip_id);
bool is_ip_id_increasing(const uint16_t old_id, const uint16_t new_id);
uint16_t rohc_bswap16(const uint16_t value);
uint16_t swab16(const uint16_t value);
