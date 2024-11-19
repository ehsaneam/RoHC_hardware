#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define GET_REAL(x)  ((x) ? 1 : 0)

#define ROHC_INIT_TS_STRIDE_MIN 3U
#define ROHC_WLSB_WIDTH_MAX 	4U
#define ACK_DELTAS_WIDTH 		16U
#define MAX_IR_COUNT  			3U
#define MAX_FO_COUNT  			3U
#define ROHC_PACKET_TYPE_IR     0xFD
#define ROHC_PACKET_TYPE_IR_DYN 0xF8
#define IPV4_DF      			0x4000

#define CHANGE_TO_IR_COUNT  1700
#define CHANGE_TO_FO_COUNT  700

#define CRC_TABLE_SIZE		256
#define CRC_INIT_3 			0x7
#define CRC_INIT_7 			0x7f
#define CRC_INIT_8 			0xff

#define ROHC_SMALL_CID_MAX  15U
#define	CID_NOT_USED		1E6
#define C_NUM_PROFILES 		4U
#define MAX_CONTEXTS		16U

#define RSF_RST_ONLY  0x04
#define RSF_SYN_ONLY  0x02
#define RSF_FIN_ONLY  0x01
#define RSF_NONE      0x00

#define MOD_TOS       0x0001
#define MOD_PROTOCOL  0x0020
#define MOD_TTL       0x0010
#define MOD_ERROR 	  0x0008

typedef enum
{
	ROHC_CRC_TYPE_NONE = 0,  /**< No CRC selected */
	ROHC_CRC_TYPE_3 = 3,     /**< The CRC-3 type */
	ROHC_CRC_TYPE_7 = 7,     /**< The CRC-7 type */
	ROHC_CRC_TYPE_8 = 8,	 /**< The CRC-8 type */
} rohc_crc_type_t;

typedef enum
{
	ROHC_IP_HDR_NONE   = 0,  /**< No IP header selected */
	ROHC_IP_HDR_FIRST  = 1,  /**< The first IP header is selected */
	ROHC_IP_HDR_SECOND = 2,  /**< The second IP header is selected */
	/* max 2 IP headers hanlded at the moment */
} ip_header_pos_t;

typedef enum
{
	IP_ID_BEHAVIOR_SEQ       = 0, /**< IP-ID increases */
	IP_ID_BEHAVIOR_SEQ_SWAP  = 1, /**< IP-ID increases in little endian */
	IP_ID_BEHAVIOR_RAND      = 2, /**< IP-ID is random */
	IP_ID_BEHAVIOR_ZERO      = 3, /**< IP-ID is constant zero */
} tcp_ip_id_behavior_t;

typedef enum
{
	ROHC_UNKNOWN_MODE = 0,
	ROHC_U_MODE = 1,
} rohc_mode_t;

typedef enum
{
	ROHC_COMP_STATE_UNKNOWN = 0,
	ROHC_COMP_STATE_IR = 1,
	ROHC_COMP_STATE_FO = 2,
	ROHC_COMP_STATE_SO = 3,

} rohc_comp_state_t;

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

struct c_wlsb
{
	int p;
	uint8_t window_width;
	uint8_t oldest;
	uint8_t next;
	uint8_t count;
	uint8_t bits;
	uint8_t window_used[ROHC_WLSB_WIDTH_MAX];
	uint32_t window_sn[ROHC_WLSB_WIDTH_MAX];
	uint32_t window_value[ROHC_WLSB_WIDTH_MAX];
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

struct ip_hdr
{
	uint8_t reserved:4;
	uint8_t version:4;
} __attribute__((packed));

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

struct ipv4_header_info
{
	struct c_wlsb ip_id_window;
	struct ipv4_hdr old_ip;
	size_t df_count;
	size_t rnd_count;
	size_t nbo_count;
	size_t sid_count;
	int rnd;
	int nbo;
	int sid;
	int old_rnd;
	int old_nbo;
	int old_sid;
	uint16_t id_delta;
};

struct ip_header_info
{
	int version;            ///< The version of the IP header
	size_t tos_count;
	size_t ttl_count;
	size_t protocol_count;
	bool is_first_header;
	union
	{
		struct ipv4_header_info v4; ///< The IPv4-specific header info
	} info;                        ///< The version specific header info
};

struct udphdr
{
	uint16_t source; /**< The source port of the UDP header */
	uint16_t dest;   /**< The destination port of the UDP header */
	uint16_t len;    /**< The length (in bytes) of the UDP packet (header + payload) */
	uint16_t check;  /**< The checksum over of the UDP header + pseudo IP header */
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
	uint16_t ip_id_delta;
	uint8_t ttl_hopl;

	size_t payload_len;
	size_t nr_ip_id_bits_3;
	size_t nr_ip_id_bits_1;
	size_t nr_ttl_hopl_bits;
	size_t nr_window_bits_16383;
	size_t nr_ack_bits_16383;
	size_t nr_seq_scaled_bits;
	size_t nr_ack_scaled_bits;
	size_t nr_msn_bits;

	bool tcp_window_changed;
	bool ecn_used_changed;
	bool ip_id_behavior_changed;
	bool ttl_hopl_changed;
	bool outer_ip_ttl_changed;
	bool ip_df_changed;
	bool dscp_changed;
	bool tcp_ack_num_changed;
	bool tcp_ack_flag_changed;
	bool tcp_urg_flag_present;
	bool tcp_urg_flag_changed;
	bool tcp_seq_num_changed;

	int ttl_irreg_chain_flag;
};

struct generic_tmp_vars
{
	unsigned short changed_fields;
	unsigned short changed_fields2;
	int send_static;
	int send_dynamic;
	size_t nr_sn_bits_less_equal_than_4;
	size_t nr_sn_bits_more_than_4;
	size_t nr_ip_id_bits;
	size_t nr_ip_id_bits2;
	uint8_t packet_type;
};

struct sc_tcp_context
{
	struct tcphdr old_tcphdr;
	struct tcp_tmp_variables tmp;
	struct c_wlsb ttl_hopl_wlsb;
	struct c_wlsb ip_id_wlsb;
	struct c_wlsb window_wlsb;
	struct c_wlsb seq_wlsb;
	struct c_wlsb seq_scaled_wlsb;
	struct c_wlsb ack_wlsb;
	struct c_wlsb ack_scaled_wlsb;
	struct c_wlsb msn_wlsb;

	ipv4_context_t ip_context;

	bool ecn_used;
	int tcp_seq_num_change_count;

	size_t ecn_used_change_count;
	size_t ecn_used_zero_count;
	size_t ttl_hopl_change_count;
	size_t seq_num_factor;
	size_t seq_num_scaling_nr;
	size_t ack_deltas_next;
	size_t tcp_window_change_count;
	size_t ack_num_scaling_nr;
	size_t ip_contexts_nr;

	uint16_t msn;
	uint16_t ack_deltas_width[ACK_DELTAS_WIDTH];
	uint16_t ack_stride;
	uint16_t ack_num_residue;
	uint16_t msn_of_last_ctxt_updating_pkt;

	uint32_t seq_num;
	uint32_t ack_num;
	uint32_t ack_num_scaled;
	uint32_t seq_num_scaled;
	uint32_t seq_num_residue;
};

struct sc_udp_context
{
	size_t udp_checksum_change_count;
	struct udphdr old_udp;
	int send_udp_dynamic;
};

struct rohc_comp_rfc3095_ctxt
{
	struct sc_udp_context specific;

	struct generic_tmp_vars rfc_tmp;
	struct c_wlsb sn_window;
	struct c_wlsb msn_non_acked;
	struct ip_header_info outer_ip_flags;

	uint32_t sn;
	uint32_t msn_of_last_ctxt_updating_pkt;
	uint8_t crc_static_3_cached;
	uint8_t crc_static_7_cached;

	size_t ip_hdr_nr;
	bool is_crc_static_3_cached_valid;
	bool is_crc_static_7_cached_valid;
	unsigned int next_header_proto;
	unsigned int next_header_len;
};

struct rohc_comp_ctxt
{
	struct sc_tcp_context tcp_specific;
	struct rohc_comp_rfc3095_ctxt rfc3095_specific;

	int packet_type;
	int num_sent_packets;
	int mode;
	int state;
	int pid;
	int used;

	size_t cid;
	size_t ir_count;
	size_t fo_count;
	size_t so_count;
	uint64_t latest_used;
	size_t go_back_fo_count;
	size_t go_back_ir_count;
};

struct rohc_comp
{
	struct rohc_comp_ctxt contexts[MAX_CONTEXTS];
	size_t num_contexts_used;
	uint16_t last_arrival_time;
};

void rohc_comp_periodic_down_transition(struct rohc_comp_ctxt *const context);
void rohc_comp_change_state(struct rohc_comp_ctxt *const context,
                            const int new_state);

uint8_t wlsb_get_minkp_32bits(const struct c_wlsb *const wlsb,
		const uint32_t value, const int p);
uint8_t wlsb_get_kp_8bits(const struct c_wlsb *const wlsb,
		 const uint8_t value, const int p);
uint8_t wlsb_get_minkp_16bits(const struct c_wlsb *const wlsb,
		 const uint16_t value, const int p);
void c_add_wlsb(struct c_wlsb *const wlsb,
		 const uint32_t sn, const uint32_t value);
void wlsb_init(struct c_wlsb *const wlsb, const size_t bits, const size_t window_width,
		const size_t p);

uint8_t c_add_cid(const size_t cid);
int code_cid_values(const size_t cid, uint8_t *const dest, const size_t dest_size,
		size_t *const first_position);
int c_static_or_irreg8(const uint8_t packet_value,
                       const bool is_static,
                       uint8_t *const rohc_data,
                       const size_t rohc_max_len,
                       int *const indicator);
int c_static_or_irreg16(const uint16_t packet_value, const bool is_static,
		uint8_t *const rohc_data, const size_t rohc_max_len, int *const indicator);
bool rsf_index_enc_possible(const uint8_t rsf_flags);
unsigned int rsf_index_enc(const uint8_t rsf_flags);
bool tcp_is_ack_stride_static(const uint16_t ack_stride, const size_t nr_trans);
bool tcp_is_ack_scaled_possible(const uint16_t ack_stride,
                                const size_t nr_trans);

uint32_t rohc_bswap32(const uint32_t value);
uint16_t rohc_bswap16(const uint16_t value);
uint16_t swab16(const uint16_t value);
uint8_t crc_calculate(const rohc_crc_type_t crc_type, const uint8_t *const data,
                      const size_t length, const uint8_t init_val);
uint8_t crc_calc_8(const uint8_t *const buf, const size_t size, const uint8_t init_val);
uint8_t crc_calc_7(const uint8_t *const buf, const size_t size, const uint8_t init_val);
uint8_t crc_calc_3(const uint8_t *const buf, const size_t size, const uint8_t init_val);
