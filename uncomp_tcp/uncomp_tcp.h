#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define ROHC_INIT_TS_STRIDE_MIN  3U
#define ROHC_WLSB_WIDTH_MAX  16U
#define MAX_FO_COUNT  3U
#define ACK_DELTAS_WIDTH 16

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
	size_t nr_ttl_hopl_bits;
	size_t nr_window_bits_16383;
	size_t nr_ack_bits_16383;
	size_t payload_len;
	size_t tcp_window_changed;
	size_t nr_seq_scaled_bits;
	size_t nr_ack_scaled_bits;
	bool tcp_ack_num_changed;
	bool tcp_ack_flag_changed;
	bool tcp_urg_flag_present;
	bool tcp_urg_flag_changed;
	bool tcp_seq_num_changed;
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
	uint8_t options[0];
} __attribute__((packed));

struct sc_tcp_context
{
	struct c_wlsb window_wlsb;
	struct c_wlsb seq_scaled_wlsb;
	struct c_wlsb ack_wlsb;
	struct c_wlsb ack_scaled_wlsb;
	struct tcphdr old_tcphdr;
	struct tcp_tmp_variables tmp;
	size_t seq_num_factor;
	size_t seq_num_scaling_nr;
	size_t ack_deltas_next;
	size_t tcp_window_change_count;
	size_t ack_num_scaling_nr;
	uint16_t ack_deltas_width[ACK_DELTAS_WIDTH];
	uint16_t ack_stride;
	uint16_t msn;
	uint16_t ack_num_residue;
	uint32_t ack_num_scaled;
	uint32_t seq_num_scaled;
	uint32_t seq_num_residue;
};

struct rohc_comp_ctxt
{
	struct sc_tcp_context specific;
	int num_sent_packets;
};

bool tcp_encode_uncomp_tcp_fields(struct rohc_comp_ctxt *const context,
                                         const struct tcphdr *const tcp);
void calc_wlsbs(struct c_wlsb *seq_scaled_wlsb, struct c_wlsb *ack_wlsb, struct c_wlsb *ack_scaled_wlsb,
		bool *tcp_seq_num_changed, uint32_t seq_num, uint32_t old_seq_num, uint32_t tcp_seq_num_factor,
		uint32_t seq_num_scaling_nr, uint32_t *nr_seq_scaled_bits, uint32_t tcp_seq_num_scaled,
		bool *tcp_ack_num_changed, uint32_t ack_num, uint32_t old_ack_num, uint32_t ack_num_hbo,
		uint32_t *nr_ack_bits_16383, uint16_t tcp_ack_stride, uint32_t ack_num_scaling_nr,
		uint32_t *nr_ack_scaled_bits, uint32_t tcp_ack_num_scaled);
uint8_t wlsb_get_minkp_32bits(const struct c_wlsb *const wlsb, const uint32_t value, const int p);
uint8_t wlsb_get_minkp_16bits(const struct c_wlsb *const wlsb,
                             const uint16_t value, const int p);
void c_add_wlsb(struct c_wlsb *const wlsb, const uint32_t sn,
                const uint32_t value);
void c_field_scaling(uint32_t *const scaled_value, uint32_t *const residue_field,
                     const uint32_t scaling_factor, const uint32_t unscaled_value);
bool tcp_is_ack_scaled_possible(const uint16_t ack_stride,
                                const size_t nr_trans);
uint32_t rohc_bswap32(const uint32_t value);
uint16_t rohc_bswap16(const uint16_t value);
