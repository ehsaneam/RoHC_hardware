#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define IPV4_DF      		0x4000
#define C_NUM_PROFILES 		4U
#define MAX_FO_COUNT  		3U
#define ROHC_WLSB_WIDTH_MAX 16U
#define MAX_CONTEXTS		16U
#define	CID_NOT_USED		1E6

typedef enum
{
	/** Unknown operational mode */
	ROHC_UNKNOWN_MODE = 0,
	/** The Unidirectional mode (U-mode) */
	ROHC_U_MODE 	  = 1,
} rohc_mode_t;

enum
{
	/** The IP protocol number for Hop-by-Hop option */
	ROHC_IPPROTO_HOPOPTS   = 0,
	/** The IP protocol number for Transmission Control Protocol (TCP) */
	ROHC_IPPROTO_TCP       = 6,
	/** The IP protocol number for the User Datagram Protocol (UDP) */
	ROHC_IPPROTO_UDP       = 17,
	/** The IP protocol number for Authentication Header */
	ROHC_IPPROTO_AH        = 51,
	/** The IP protocol number for Minimal Encapsulation within IP (RFC 2004) */
	ROHC_IPPROTO_MINE      = 55,
	/** The IP protocol number for Mobility Header */
	ROHC_IPPROTO_MOBILITY  = 135,
	/** The IP protocol number for the Host Identity Protocol (HIP) */
	ROHC_IPPROTO_HIP       = 139,
	/** The IP protocol number for the Shim6 Protocol */
	ROHC_IPPROTO_SHIM      = 140,
	/** The IP protocol number reserved for experimentation and testing */
	ROHC_IPPROTO_RESERVED1 = 253,
	/** The IP protocol number reserved for experimentation and testing */
	ROHC_IPPROTO_RESERVED2 = 254,
	/** The maximum IP protocol number */
	ROHC_IPPROTO_MAX       = 255
};

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
	/** No feature at all */
	ROHC_COMP_FEATURE_NONE            = 0,
	/** Be compatible with 1.6.x versions */
	ROHC_COMP_FEATURE_COMPAT_1_6_x    = (1 << 0),
	/** Do not check IP checksums at compressor */
	ROHC_COMP_FEATURE_NO_IP_CHECKSUMS = (1 << 2),
	/** Dump content of packets in traces (beware: performance impact) */
	ROHC_COMP_FEATURE_DUMP_PACKETS    = (1 << 3),
	/** Allow periodic refreshes based on inter-packet time */
	ROHC_COMP_FEATURE_TIME_BASED_REFRESHES = (1 << 4),

} rohc_comp_features_t;

typedef enum
{
	/** Unknown compressor state */
	ROHC_COMP_STATE_UNKNOWN = 0,
	/** The Initialization and Refresh (IR) compressor state */
	ROHC_COMP_STATE_IR = 1,
	/** The First Order (FO) compressor state */
	ROHC_COMP_STATE_FO = 2,
	/** The Second Order (SO) compressor state */
	ROHC_COMP_STATE_SO = 3,

} rohc_comp_state_t;

struct rohc_medium
{
	/** The CID type: large or small */
	int cid_type;

	/// The maximum CID value
	size_t max_cid;
};

struct rohc_ts
{
	uint64_t sec;   /**< The seconds part of the timestamp */
	uint64_t nsec;  /**< The nanoseconds part of the timestamp */
};

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

struct c_wlsb
{
	/** The width of the window */
	size_t window_width; /* TODO: R-mode needs a non-fixed window width */

	/** A pointer on the oldest entry in the window (change on acknowledgement) */
	size_t oldest;
	/** A pointer on the current entry in the window  (change on add and ack) */
	size_t next;

	/** The count of entries in the window */
	size_t count;

	/** The maximal number of bits for representing the value */
	size_t bits;
	/** The shift parameter (see 4.5.2 in the RFC 3095) */
	size_t p;

	/** The window in which previous values of the encoded value are stored */
	bool window_used[ROHC_WLSB_WIDTH_MAX];
	uint32_t window_sn[ROHC_WLSB_WIDTH_MAX];
	uint32_t vwindow_alue[ROHC_WLSB_WIDTH_MAX];
};

struct rohc_comp_profile
{
	int id;
};

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

struct sc_tcp_context
{
	ipv4_context_t ip_context;
	struct tcphdr old_tcphdr;
	struct c_wlsb msn_wlsb;    /**< The W-LSB decoding context for MSN */
	struct c_wlsb window_wlsb; /**< The W-LSB decoding context for TCP window */
	struct c_wlsb ip_id_wlsb;
	struct c_wlsb ttl_hopl_wlsb;
	struct c_wlsb seq_wlsb;
	struct c_wlsb seq_scaled_wlsb;
	struct c_wlsb ack_wlsb;
	struct c_wlsb ack_scaled_wlsb;

	int tcp_seq_num_change_count;
	size_t ttl_hopl_change_count;
	size_t tcp_window_change_count;
	size_t ecn_used_change_count;
	size_t ecn_used_zero_count;
	size_t ip_contexts_nr;
	bool ecn_used;
	uint16_t msn;               /**< The Master Sequence Number (MSN) */
	uint16_t ack_stride;
	uint32_t seq_num;
	uint32_t ack_num;
};

struct rohc_comp_ctxt
{
	struct rohc_comp_profile profile;
	struct sc_tcp_context specific;
	struct rohc_ts go_back_fo_time;
	struct rohc_ts go_back_ir_time;

	uint64_t latest_used;
	uint64_t first_used;
	size_t cid;
	size_t ir_count;
	size_t fo_count;
	size_t so_count;
	size_t go_back_fo_count;
	size_t go_back_ir_count;
	int mode;
	int state;
	int used;
	int total_uncompressed_size;
	int total_compressed_size;
	int header_uncompressed_size;
	int header_compressed_size;
	int total_last_uncompressed_size;
	int total_last_compressed_size;
	int header_last_uncompressed_size;
	int header_last_compressed_size;
	int num_sent_packets;
};

struct rohc_comp
{
	struct rohc_medium medium;
	struct rohc_comp_ctxt contexts[MAX_CONTEXTS];

	int features;
	size_t wlsb_window_width;
	size_t num_contexts_used;
	bool enabled_profiles[C_NUM_PROFILES];
};

size_t rohc_comp_find_ctxt(struct rohc_comp *const comp,
		const uint8_t *data, const int profile_id_hint,
		const struct rohc_ts arrival_time);
const struct rohc_comp_profile* c_get_profile_from_packet(
		const struct rohc_comp *const comp, const uint8_t *data);
const struct rohc_comp_profile* rohc_get_profile_from_id(
		const struct rohc_comp *comp, const int profile_id);
bool c_tcp_check_context(struct sc_tcp_context *tcp_context,
		const uint8_t *data, size_t *const cr_score);
bool c_tcp_check_profile(const struct rohc_comp *const comp,
		const uint8_t *data);
size_t c_create_context(struct rohc_comp *const comp,
		const struct rohc_comp_profile *const profile, const uint8_t *data,
		const struct rohc_ts arrival_time);
void c_tcp_create_from_pkt(struct rohc_comp_ctxt *const context,
		const uint8_t *data, size_t wlsb_window_width);
void wlsb_init(struct c_wlsb *const wlsb, const size_t bits, const size_t window_width,
		const size_t p);
bool rsf_index_enc_possible(const uint8_t rsf_flags);
uint16_t ip_fast_csum(const uint8_t *const iph, const size_t ihl);
bool ipv4_is_fragment(const struct ipv4_hdr *const ipv4);
uint16_t from32to16(const uint32_t x);
uint16_t rohc_bswap16(const uint16_t value);
uint32_t rohc_bswap32(const uint32_t value);
unsigned int lcg_rand();
