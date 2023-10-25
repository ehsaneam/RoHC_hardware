#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#define ROHC_WLSB_WIDTH_MAX  16U
#define ROHC_INIT_TS_STRIDE_MIN  3U

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

typedef enum
{
	IP_ID_BEHAVIOR_SEQ       = 0, /**< IP-ID increases */
	IP_ID_BEHAVIOR_SEQ_SWAP  = 1, /**< IP-ID increases in little endian */
	IP_ID_BEHAVIOR_RAND      = 2, /**< IP-ID is random */
	IP_ID_BEHAVIOR_ZERO      = 3, /**< IP-ID is constant zero */
} tcp_ip_id_behavior_t;

struct c_wlsb
{
	uint8_t count;
	uint32_t window_value[ROHC_WLSB_WIDTH_MAX];
	uint32_t window_used[ROHC_WLSB_WIDTH_MAX];
};

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
	/* the length of the TCP payload (headers and options excluded) */
	size_t payload_len;

	/** The minimal number of bits required to encode the MSN value */
	size_t nr_msn_bits;

	/** Whether the TCP window changed or not */
	size_t tcp_window_changed;
	/** The minimal number of bits required to encode the TCP window */
	size_t nr_window_bits_16383;

	/** Whether the TCP sequence number changed or not */
	bool tcp_seq_num_changed;
	/** The minimal number of bits required to encode the TCP scaled sequence
	 *  number */
	size_t nr_seq_scaled_bits;

	/** Whether the ACK number changed or not */
	bool tcp_ack_num_changed;
	/** The minimal number of bits required to encode the TCP ACK number
	 *  with p = 16383 */
	size_t nr_ack_bits_16383;
	/** The minimal number of bits required to encode the TCP scaled ACK
	 * number */
	size_t nr_ack_scaled_bits;

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
	bool outer_ip_ttl_changed;

	bool ip_df_changed;
	bool dscp_changed;

	bool tcp_ack_flag_changed;
	bool tcp_urg_flag_present;
	bool tcp_urg_flag_changed;

	/** Whether the ecn_used flag changed or not */
	bool ecn_used_changed;
};

struct sc_tcp_context
{
	struct c_wlsb seq_wlsb;
	size_t seq_num_scaling_nr;

	struct c_wlsb ack_wlsb;
	uint16_t ack_stride;
	size_t ack_num_scaling_nr;

	/// The previous TCP header
	struct tcphdr old_tcphdr;

	/// @brief TCP-specific temporary variables that are used during one single
	///        compression of packet
	struct tcp_tmp_variables tmp;
};

struct rohc_comp_ctxt
{
	/** Profile-specific data, defined by the profiles */
	struct sc_tcp_context specific;

	/** The operation state in which the context operates: IR, FO, SO */
	int state;

	/** The number of packets sent while in Initialization & Refresh (IR) state */
	size_t ir_count;
	/** The number of packets sent while in First Order (FO) state */
	size_t fo_count;
	/** The number of packets sent while in Second Order (SO) state */
	size_t so_count;

	/** The number of sent packets */
	int num_sent_packets;
};

int tcp_decide_packet(struct rohc_comp_ctxt *const context, const ipv4_context_t *const ip_inner_context,
								const struct tcphdr *const tcp);
rohc_packet_t tcp_decide_FO_SO_packet(const struct rohc_comp_ctxt *const context, const ipv4_context_t *const ip_inner_context,
									  const struct tcphdr *const tcp, const bool crc7_at_least);
rohc_packet_t tcp_decide_FO_SO_packet_seq(const struct rohc_comp_ctxt *const context,
										  const struct tcphdr *const tcp, const bool crc7_at_least);
rohc_packet_t tcp_decide_FO_SO_packet_rnd(const struct rohc_comp_ctxt *const context,
										  const struct tcphdr *const tcp, const bool crc7_at_least);
bool rsf_index_enc_possible(const uint8_t rsf_flags);
bool tcp_is_ack_stride_static(const uint16_t ack_stride, const size_t nr_trans);
bool tcp_is_ack_scaled_possible(const uint16_t ack_stride, const size_t nr_trans);
uint8_t wlsb_get_minkp_32bits(const struct c_wlsb *const wlsb,
							  const uint32_t value, const int p);
uint32_t rohc_bswap32(const uint32_t value);
