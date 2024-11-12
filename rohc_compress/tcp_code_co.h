#include "base.h"

typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t discriminator:6;    /**< '101110'                               [  6 ] */
	uint8_t seq_num1:2;         /**< lsb(18, 65535)                         [ 18 ] */
	uint16_t seq_num2;          /**< sequel of \e seq_num1                  [  - ] */
	uint8_t msn:4;              /**< lsb(4, 4)                              [  4 ] */
	uint8_t psh_flag:1;         /**< irregular(1)                           [  1 ] */
	uint8_t header_crc:3;       /**< crc3(THIS.UVALUE, THIS.ULENGTH)        [  3 ] */
#else
	uint8_t seq_num1:2;
	uint8_t discriminator:6;
	uint16_t seq_num2;
	uint8_t header_crc:3;
	uint8_t psh_flag:1;
	uint8_t msn:4;
#endif
	/* irregular chain                                                      [ VARIABLE ] */
} __attribute__((packed)) rnd_1_t;


/**
 * @brief The rnd_2 compressed packet format
 *
 * Send scaled sequence number LSBs
 * See RFC4996 page 81
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t discriminator:4;    /**< '1100'                                 [ 4 ] */
	uint8_t seq_num_scaled:4;   /**< lsb(4, 7)                              [ 4 ] */
	uint8_t msn:4;              /**< lsb(4, 4)                              [ 4 ] */
	uint8_t psh_flag:1;         /**< irregular(1)                           [ 1 ] */
	uint8_t header_crc:3;       /**< crc3(THIS.UVALUE, THIS.ULENGTH)        [ 3 ] */
#else
	uint8_t seq_num_scaled:4;
	uint8_t discriminator:4;
	uint8_t header_crc:3;
	uint8_t psh_flag:1;
	uint8_t msn:4;
#endif
	/* irregular chain                                                      [ VARIABLE ] */
} __attribute__((packed)) rnd_2_t;


/**
 * @brief The rnd_3 compressed packet format
 *
 * Send acknowledgment number LSBs
 * See RFC4996 page 81
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t discriminator:1;    /**< '0'                                    [  1 ] */
	uint8_t ack_num1:7;         /**< lsb(15, 8191)                          [ 15 ] */
	uint8_t ack_num2;           /**< sequel of \e ack_num1                  [  - ] */
	uint8_t msn:4;              /**< lsb(4, 4)                              [  4 ] */
	uint8_t psh_flag:1;         /**< irregular(1)                           [  1 ] */
	uint8_t header_crc:3;       /**< crc3(THIS.UVALUE, THIS.ULENGTH)        [  3 ] */
#else
	uint8_t ack_num1:7;
	uint8_t discriminator:1;
	uint8_t ack_num2:8;
	uint8_t header_crc:3;
	uint8_t psh_flag:1;
	uint8_t msn:4;
#endif
	/* irregular chain                                                      [ VARIABLE ] */
} __attribute__((packed)) rnd_3_t;


/**
 * @brief The rnd_4 compressed packet format
 *
 * Send acknowlegment number scaled
 * See RFC4996 page 81
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t discriminator:4;    /**< '1101'                                 [ 4 ] */
	uint8_t ack_num_scaled:4;   /**< lsb(4, 3)                              [ 4 ] */
	uint8_t msn:4;              /**< lsb(4, 4)                              [ 4 ] */
	uint8_t psh_flag:1;         /**< irregular(1)                           [ 1 ] */
	uint8_t header_crc:3;       /**< crc3(THIS.UVALUE, THIS.ULENGTH)        [ 3 ] */
#else
	uint8_t ack_num_scaled:4;
	uint8_t discriminator:4;
	uint8_t header_crc:3;
	uint8_t psh_flag:1;
	uint8_t msn:4;
#endif
	/* irregular chain                                                      [ VARIABLE ] */
} __attribute__((packed)) rnd_4_t;


/**
 * @brief The rnd_5 compressed packet format
 *
 * Send ACK and sequence number
 * See RFC4996 page 82
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t discriminator:3;    /**< '100'                                  [  3 ] */
	uint8_t psh_flag:1;         /**< irregular(1)                           [  1 ] */
	uint8_t msn:4;              /**< lsb(4, 4)                              [  4 ] */
	uint32_t header_crc:3;      /**< crc3(THIS.UVALUE, THIS.ULENGTH)        [  3 ] */
	uint32_t seq_num1:5;        /**< lsb(14, 8191)                          [ 14 ] */
	uint32_t seq_num2:8;        /**< sequel of \e seq_num1                  [  - ] */
	uint32_t seq_num3:1;        /**< sequel of \e seq_num1 and \e seq_num2  [  - ] */
	uint32_t ack_num1:7;        /**< lsb(15, 8191)                          [ 15 ] */
	uint32_t ack_num2:8;        /**< sequel of \e ack_num1                  [  - ] */
#else
	uint8_t msn:4;
	uint8_t psh_flag:1;
	uint8_t discriminator:3;
	uint8_t seq_num1:5;
	uint8_t header_crc:3;
	uint8_t seq_num2;
	uint8_t ack_num1:7;
	uint8_t seq_num3:1;
	uint8_t ack_num2;
#endif
	/* irregular chain                                                      [ VARIABLE ] */
} __attribute__((packed)) rnd_5_t;


/**
 * @brief The rnd_6 compressed packet format
 *
 * Send both ACK and scaled sequence number LSBs
 * See RFC4996 page 82
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t discriminator:4;    /**< '1010'                                 [ 4 ] */
	uint8_t header_crc:3;       /**< crc3(THIS.UVALUE, THIS.ULENGTH)        [ 3 ] */
	uint8_t psh_flag:1;         /**< irregular(1)                           [ 1 ] */
#else
	uint8_t psh_flag:1;
	uint8_t header_crc:3;
	uint8_t discriminator:4;
#endif
	uint16_t ack_num;           /**< lsb(16, 16383)                         [ 16 ] */
#if WORDS_BIGENDIAN == 1
	uint8_t msn:4;              /**< lsb(4, 4)                              [ 4 ] */
	uint8_t seq_num_scaled:4;   /**< lsb(4, 7)                              [ 4 ] */
#else
	uint8_t seq_num_scaled:4;
	uint8_t msn:4;
#endif
	/* irregular chain                                                      [ VARIABLE ] */
} __attribute__((packed)) rnd_6_t;


/**
 * @brief The rnd_7 compressed packet format
 *
 * Send ACK and window
 * See RFC4996 page 82
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t discriminator:6;    /**< '101111'                               [ 6 ] */
	uint8_t ack_num1:2;         /**< lsb(18, 65535)                         [ 18 ] */
	uint16_t ack_num2;          /**< sequel of \e ack_num1                  [ - ]*/
#else
	uint8_t ack_num1:2;
	uint8_t discriminator:6;
	uint16_t ack_num2;
#endif
	uint16_t window;            /**< irregular(16)                          [ 16 ] */
#if WORDS_BIGENDIAN == 1
	uint8_t msn:4;              /**< lsb(4, 4)                              [ 4 ] */
	uint8_t psh_flag:1;         /**< irregular(1)                           [ 1 ] */
	uint8_t header_crc:3;       /**< crc3(THIS.UVALUE, THIS.ULENGTH)        [ 3 ] */
#else
	uint8_t header_crc:3;
	uint8_t psh_flag:1;
	uint8_t msn:4;
#endif
	/* irregular chain                                                      [ VARIABLE ] */
} __attribute__((packed)) rnd_7_t;


/**
 * @brief The rnd_8 compressed packet format
 *
 * Can send LSBs of TTL, RSF flags, change ECN behavior and options list
 * See RFC4996 page 82
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t discriminator:5;    /**< '10110'                                [ 5 ] */
	uint8_t rsf_flags:2;        /**< rsf_index_enc                          [ 2 ] */
	uint8_t list_present:1;     /**< irregular(1)                           [ 1 ] */
	uint16_t header_crc:7;      /**< crc7(THIS.UVALUE, THIS.ULENGTH)        [ 7 ] */
	uint16_t msn1:1;            /**< lsb(4, 4)                              [ 4 ] */
	uint16_t msn2:3;            /**< sequel of \e msn1                      [ - ] */
	uint16_t psh_flag:1;        /**< irregular(1)                           [ 1 ] */
	uint16_t ttl_hopl:3;        /**< lsb(3, 3)                              [ 3 ] */
	uint16_t ecn_used:1;        /**< one_bit_choice                         [ 1 ] */
#else
	uint8_t list_present:1;
	uint8_t rsf_flags:2;
	uint8_t discriminator:5;
	uint8_t msn1:1;
	uint8_t header_crc:7;
	uint8_t ecn_used:1;
	uint8_t ttl_hopl:3;
	uint8_t psh_flag:1;
	uint8_t msn2:3;
#endif
	uint16_t seq_num;           /**< lsb(16, 65535)                         [ 16 ] */
	uint16_t ack_num;           /**< lsb(16, 16383)                         [ 16 ] */
	uint8_t options[0];         /**< tcp_list_presence_enc(list_present.CVALUE)
	                                                                        [ VARIABLE ] */
	/* irregular chain                                                      [ VARIABLE ] */
} __attribute__((packed)) rnd_8_t;


/**
 * @brief The seq_1 compressed packet format
 *
 * Send LSBs of sequence number
 * See RFC4996 page 83
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t discriminator:4;    /**< '1010'                                 [ 4 ] */
	uint8_t ip_id:4;            /**< ip_id_lsb(ip_id_behavior.UVALUE, 4, 3) [ 4 ] */
#else
	uint8_t ip_id:4;
	uint8_t discriminator:4;
#endif
	uint16_t seq_num;           /**< lsb(16, 32767)                         [ 16 ] */
#if WORDS_BIGENDIAN == 1
	uint8_t msn:4;              /**< lsb(4, 4)                              [ 4 ] */
	uint8_t psh_flag:1;         /**< irregular(1)                           [ 1 ] */
	uint8_t header_crc:3;       /**< crc3(THIS.UVALUE, THIS.ULENGTH)        [ 3 ] */
#else
	uint8_t header_crc:3;
	uint8_t psh_flag:1;
	uint8_t msn:4;
#endif
	/* irregular chain                                                      [ VARIABLE ] */
} __attribute__((packed)) seq_1_t;


/**
 * @brief The seq_2 compressed packet format
 *
 * Send scaled sequence number LSBs
 * See RFC4996 page 83
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint16_t discriminator:5;   /**< '11010'                                [ 5 ] */
	uint16_t ip_id1:3;          /**< ip_id_lsb(ip_id_behavior.UVALUE, 7, 3) [ 7 ] */
	uint16_t ip_id2:4;          /**< sequel of ip_id1                       [ - ] */
	uint16_t seq_num_scaled:4;  /**< lsb(4, 7)                              [ 4 ] */
	uint8_t msn:4;              /**< lsb(4, 4)                              [ 4 ] */
	uint8_t psh_flag:1;         /**< irregular(1)                           [ 1 ] */
	uint8_t header_crc:3;       /**< crc3(THIS.UVALUE, THIS.ULENGTH)        [ 3 ] */
#else
	uint8_t ip_id1:3;
	uint8_t discriminator:5;
	uint8_t seq_num_scaled:4;
	uint8_t ip_id2:4;
	uint8_t header_crc:3;
	uint8_t psh_flag:1;
	uint8_t msn:4;
#endif
	/* irregular chain                                                      [ VARIABLE ] */
} __attribute__((packed)) seq_2_t;


/**
 * @brief The seq_3 compressed packet format
 *
 * Send acknowledgment number LSBs
 * See RFC4996 page 83
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t discriminator:4;    /**< '1001'                                 [  4 ] */
	uint8_t ip_id:4;            /**< ip_id_lsb(ip_id_behavior.UVALUE, 4, 3) [  4 ] */
#else
	uint8_t ip_id:4;
	uint8_t discriminator:4;
#endif
	uint16_t ack_num;           /**< lsb(16, 16383)                         [ 16 ] */
#if WORDS_BIGENDIAN == 1
	uint8_t msn:4;              /**< lsb(4, 4)                              [  4 ] */
	uint8_t psh_flag:1;         /**< irregular(1)                           [  1 ] */
	uint8_t header_crc:3;       /**< crc3(THIS.UVALUE, THIS.ULENGTH)        [  3 ] */
#else
	uint8_t header_crc:3;
	uint8_t psh_flag:1;
	uint8_t msn:4;
#endif
	/* irregular chain                                                      [ VARIABLE ] */
} __attribute__((packed)) seq_3_t;


/**
 * @brief The seq_4 compressed packet format
 *
 * Send scaled acknowledgment number scaled
 * See RFC4996 page 84
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t discriminator:1;    /**< '0'                                    [ 1 ] */
	uint8_t ack_num_scaled:4;   /**< lsb(4, 3)                              [ 4 ] */
	uint8_t ip_id:3;            /**< ip_id_lsb(ip_id_behavior.UVALUE, 3, 1) [ 3 ] */
	uint8_t msn:4;              /**< lsb(4, 4)                              [ 4 ] */
	uint8_t psh_flag:1;         /**< irregular(1)                           [ 1 ] */
	uint8_t header_crc:3;       /**< crc3(THIS.UVALUE, THIS.ULENGTH)        [ 3 ] */
#else
	uint8_t ip_id:3;
	uint8_t ack_num_scaled:4;
	uint8_t discriminator:1;
	uint8_t header_crc:3;
	uint8_t psh_flag:1;
	uint8_t msn:4;
#endif
	/* irregular chain                                                      [ VARIABLE ] */
} __attribute__((packed)) seq_4_t;


/**
 * @brief The seq_5 compressed packet format
 *
 * Send ACK and sequence number
 * See RFC4996 page 84
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t discriminator:4;    /**< '1000'                                 [  4 ] */
	uint8_t ip_id:4;            /**< ip_id_lsb(ip_id_behavior.UVALUE, 4, 3) [  4 ] */
#else
	uint8_t ip_id:4;
	uint8_t discriminator:4;
#endif
	uint16_t ack_num;           /**< lsb(16, 16383)                         [ 16 ] */
	uint16_t seq_num;           /**< lsb(16, 32767)                         [ 16 ] */
#if WORDS_BIGENDIAN == 1
	uint8_t msn:4;              /**< lsb(4, 4)                              [  4 ] */
	uint8_t psh_flag:1;         /**< irregular(1)                           [  1 ] */
	uint8_t header_crc:3;       /**< crc3(THIS.UVALUE, THIS.ULENGTH)        [  3 ] */
#else
	uint8_t header_crc:3;
	uint8_t psh_flag:1;
	uint8_t msn:4;
#endif
	/* irregular chain                                                      [ VARIABLE ] */
} __attribute__((packed)) seq_5_t;


/**
 * @brief The seq_6 compressed packet format
 *
 * Send both ACK and scaled sequence number LSBs
 * See RFC4996 page 84
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint16_t discriminator:5;   /**< '11011'                                [  5 ] */
	uint16_t seq_num_scaled1:3; /**< lsb(4, 7)                              [  4 ] */
	uint16_t seq_num_scaled2:1; /**< sequel of \e seq_num_scaled1           [  4 ] */
	uint16_t ip_id:7;           /**< ip_id_lsb(ip_id_behavior.UVALUE, 7, 3) [  7 ] */
#else
	uint8_t seq_num_scaled1:3;
	uint8_t discriminator:5;
	uint8_t ip_id:7;
	uint8_t seq_num_scaled2:1;
#endif
	uint16_t ack_num;           /**< lsb(16, 16383)                         [ 16 ] */
#if WORDS_BIGENDIAN == 1
	uint8_t msn:4;              /**< lsb(4, 4)                              [ 4 ] */
	uint8_t psh_flag:1;         /**< irregular(1)                           [ 1 ] */
	uint8_t header_crc:3;       /**< crc3(THIS.UVALUE, THIS.ULENGTH)        [ 3 ] */
#else
	uint8_t header_crc:3;
	uint8_t psh_flag:1;
	uint8_t msn:4;
#endif
	/* irregular chain                                                      [ VARIABLE ] */
} __attribute__((packed)) seq_6_t;


/**
 * @brief The seq_7 compressed packet format
 *
 * Send ACK and window
 * See RFC4996 page 85
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t discriminator:4;    /**< '1100'                                 [  4 ] */
	uint8_t window1:4;          /**< lsb(15, 16383)                         [ 15 ] */
	uint8_t window2;            /**< sequel of \e window1                   [  - ] */
	uint8_t window3:3;          /**< sequel of \e window1 and \e window2    [  - ] */
	uint8_t ip_id:5;            /**< ip_id_lsb(ip_id_behavior.UVALUE, 5, 3) [  5 ] */
	uint16_t ack_num;           /**< lsb(16, 32767)                         [ 16 ] */
	uint8_t msn:4;              /**< lsb(4, 4)                              [  4 ] */
	uint8_t psh_flag:1;         /**< irregular(1)                           [  1 ] */
	uint8_t header_crc:3;       /**< crc3(THIS.UVALUE, THIS.ULENGTH)        [  3 ] */
#else
	uint8_t window1:4;
	uint8_t discriminator:4;
	uint8_t window2;
	uint8_t ip_id:5;
	uint8_t window3:3;
	uint16_t ack_num;
	uint8_t header_crc:3;
	uint8_t psh_flag:1;
	uint8_t msn:4;
#endif
	/* irregular chain                                                      [ VARIABLE ] */
} __attribute__((packed)) seq_7_t;


/**
 * @brief The seq_8 compressed packet format
 *
 * Can send LSBs of TTL, RSF flags, change ECN behavior, and options list
 * See RFC4996 page 85
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t discriminator:4;    /**< '1011'                                 [  4 ] */
	uint8_t ip_id:4;            /**< ip_id_lsb(ip_id_behavior.UVALUE, 4, 3) [  4 ] */
	uint8_t list_present:1;     /**< irregular(1)                           [  1 ] */
	uint8_t header_crc:7;       /**< crc7(THIS.UVALUE, THIS.ULENGTH)        [  7 ] */
	uint8_t msn:4;              /**< lsb(4, 4)                              [  4 ] */
	uint8_t psh_flag:1;         /**< irregular(1)                           [  1 ] */
	uint8_t ttl_hopl:3;         /**< lsb(3, 3)                              [  3 ] */
	uint8_t ecn_used:1;         /**< one_bit_choice                         [  1 ] */
	uint8_t ack_num1:7;         /**< lsb(15, 8191)                          [ 15 ] */
	uint8_t ack_num2;           /**< sequel of \e ack_num1                  [  - ] */
	uint8_t rsf_flags:2;        /**< rsf_index_enc                          [  2 ] */
	uint8_t seq_num1:6;         /**< lsb(14, 8191)                          [ 14 ] */
	uint8_t seq_num2;           /**< sequel of \e seq_num1                  [  - ] */
#else
	uint8_t ip_id:4;
	uint8_t discriminator:4;
	uint8_t header_crc:7;
	uint8_t list_present:1;
	uint8_t ttl_hopl:3;
	uint8_t psh_flag:1;
	uint8_t msn:4;
	uint8_t ack_num1:7;
	uint8_t ecn_used:1;
	uint8_t ack_num2;
	uint8_t seq_num1:6;
	uint8_t rsf_flags:2;
	uint8_t seq_num2:8;
#endif
	uint8_t options[0];       /**< tcp_list_presence_enc(list_present.CVALUE)
	                                                                      [ VARIABLE ] */
	/* irregular chain                                                    [ VARIABLE ] */
} __attribute__((packed)) seq_8_t;

typedef struct
{
#if WORDS_BIGENDIAN == 1

	uint8_t discriminator:7;         /**< '1111101'                         [ 7 ] */
	uint8_t ttl_hopl_outer_flag:1;   /**< compressed_value(1,
												           ttl_irregular_chain_flag)   [ 1 ] */

	uint8_t ack_flag:1;              /**< irregular(1)                      [ 1 ] */
	uint8_t psh_flag:1;              /**< irregular(1)                      [ 1 ] */
	uint8_t rsf_flags:2;             /**< rsf_index_enc                     [ 2 ] */
	uint8_t msn:4;                   /**< lsb(4, 4)                         [ 4 ] */

	uint8_t seq_indicator:2;         /**< irregular(2)                      [ 2 ] */
	uint8_t ack_indicator:2;         /**< irregular(2)                      [ 2 ] */
	uint8_t ack_stride_indicator:1;  /**< irregular(1)                      [ 1 ] */
	uint8_t window_indicator:1;      /**< irregular(1)                      [ 1 ] */
	uint8_t ip_id_indicator:1;       /**< irregular(1)                      [ 1 ] */
	uint8_t urg_ptr_present:1;       /**< irregular(1)                      [ 1 ] */

	uint8_t reserved:1;              /**< compressed_value(1, 0)            [ 1 ] */
	uint8_t ecn_used:1;              /**< one_bit_choice                    [ 1 ] */
	uint8_t dscp_present:1;          /**< irregular(1)                      [ 1 ] */
	uint8_t ttl_hopl_present:1;      /**< irregular(1)                      [ 1 ] */
	uint8_t list_present:1;          /**< irregular(1)                      [ 1 ] */
	uint8_t ip_id_behavior:2;        /**< ip_id_behavior_choice(true)       [ 2 ] */
	uint8_t urg_flag:1;              /**< irregular(1)                      [ 1 ] */

	uint8_t df:1;                    /**< dont_fragment(version.UVALUE)     [ 1 ] */
	uint8_t header_crc:7;            /**< crc7(THIS.UVALUE,THIS.ULENGTH)    [ 7 ] */

#else

	uint8_t ttl_hopl_outer_flag:1;
	uint8_t discriminator:7;

	uint8_t msn:4;
	uint8_t rsf_flags:2;
	uint8_t psh_flag:1;
	uint8_t ack_flag:1;

	uint8_t urg_ptr_present:1;
	uint8_t ip_id_indicator:1;
	uint8_t window_indicator:1;
	uint8_t ack_stride_indicator:1;
	uint8_t ack_indicator:2;
	uint8_t seq_indicator:2;

	uint8_t urg_flag:1;
	uint8_t ip_id_behavior:2;
	uint8_t list_present:1;
	uint8_t ttl_hopl_present:1;
	uint8_t dscp_present:1;
	uint8_t ecn_used:1;
	uint8_t reserved:1;

	uint8_t header_crc:7;
	uint8_t df:1;

#endif

	/* variable fields:
	 *   variable_length_32_enc(seq_indicator.CVALUE)                       [ 0, 8, 16, 32 ]
	 *   variable_length_32_enc(ack_indicator.CVALUE)                       [ 0, 8, 16, 32 ]
	 *   static_or_irreg(ack_stride_indicator.CVALUE, 16)                   [ 0, 16 ]
	 *   static_or_irreg(window_indicator.CVALUE, 16)                       [ 0, 16 ]
	 *   optional_ip_id_lsb(ip_id_behavior.UVALUE,ip_id_indicator.CVALUE)   [ 0, 8, 16 ]
	 *   static_or_irreg(urg_ptr_present.CVALUE, 16)                        [ 0, 16 ]
	 *   dscp_enc-dscp_present.CVALUE)                                      [ 0, 8 ]
	 *   static_or_irreg(ttl_hopl_present.CVALUE, 8)                        [ 0, 8 ]
	 *   tcp_list_presence_enc(list_present.CVALUE)                         [ VARIABLE ]
	 *   irregular chain                                                    [ VARIABLE ]
	 */

} __attribute__((packed)) co_common_t;

int tcp_code_CO_packet(struct rohc_comp_ctxt *const context,
				uint8_t *ip_pkt, uint8_t *const rohc_pkt,
				const size_t rohc_pkt_max_len,
				const int packet_type);
int tcp_code_irreg_chain(struct sc_tcp_context *const tcp_context,
				uint8_t *ip_pkt, const uint8_t ip_inner_ecn,
				const struct tcphdr *const tcp,
				uint8_t *const rohc_pkt,
				const size_t rohc_pkt_max_len);
int tcp_code_irregular_ipv4_part(const ipv4_context_t *const ip_context,
				const struct ipv4_hdr *const ipv4,
				uint8_t *const rohc_data,
				const size_t rohc_max_len);
int tcp_code_irregular_tcp_part(const struct sc_tcp_context *const tcp_context,
				const struct tcphdr *const tcp,
				const uint8_t ip_inner_ecn,
				uint8_t *const rohc_data,
				const size_t rohc_max_len);
int co_baseheader(const struct sc_tcp_context *const tcp_context,
				const struct ipv4_hdr *const inner_ip_hdr,
				uint8_t *const rohc_pkt,
				const size_t rohc_pkt_max_len,
				const int packet_type,
				const struct tcphdr *const tcp,
				const uint8_t crc);
int c_tcp_build_rnd_1(const struct sc_tcp_context *const tcp_context,
					 const struct tcphdr *const tcp,
					 const uint8_t crc, uint8_t *const rohc_data,
					 const size_t rohc_max_len);
int c_tcp_build_rnd_2(const struct sc_tcp_context *const tcp_context,
					 const struct tcphdr *const tcp,
					 const uint8_t crc,
					 uint8_t *const rohc_data,
					 const size_t rohc_max_len);
int c_tcp_build_rnd_3(const struct sc_tcp_context *const tcp_context,
					 const struct tcphdr *const tcp,
					 const uint8_t crc,
					 uint8_t *const rohc_data,
					 const size_t rohc_max_len);
int c_tcp_build_rnd_4(const struct sc_tcp_context *const tcp_context,
					 const struct tcphdr *const tcp,
					 const uint8_t crc,
					 uint8_t *const rohc_data,
					 const size_t rohc_max_len);
int c_tcp_build_rnd_5(const struct sc_tcp_context *const tcp_context,
					 const struct tcphdr *const tcp,
					 const uint8_t crc,
					 uint8_t *const rohc_data,
					 const size_t rohc_max_len);
int c_tcp_build_rnd_6(const struct sc_tcp_context *const tcp_context,
					 const struct tcphdr *const tcp,
					 const uint8_t crc,
					 uint8_t *const rohc_data,
					 const size_t rohc_max_len);
int c_tcp_build_rnd_7(const struct sc_tcp_context *const tcp_context,
					 const struct tcphdr *const tcp,
					 const uint8_t crc,
					 uint8_t *const rohc_data,
					 const size_t rohc_max_len);
int c_tcp_build_rnd_8(const struct sc_tcp_context *const tcp_context,
					 const struct ipv4_hdr *const inner_ip_hdr,
					 const struct tcphdr *const tcp,
					 const uint8_t crc,
					 uint8_t *const rohc_data,
					 const size_t rohc_max_len);
int c_tcp_build_seq_1(const struct sc_tcp_context *const tcp_context,
					 const struct tcphdr *const tcp,
					 const uint8_t crc,
					 uint8_t *const rohc_data,
					 const size_t rohc_max_len);
int c_tcp_build_seq_2(const struct sc_tcp_context *const tcp_context,
					 const struct tcphdr *const tcp,
					 const uint8_t crc,
					 uint8_t *const rohc_data,
					 const size_t rohc_max_len);
int c_tcp_build_seq_3(const struct sc_tcp_context *const tcp_context,
					 const struct tcphdr *const tcp,
					 const uint8_t crc,
					 uint8_t *const rohc_data,
					 const size_t rohc_max_len);
int c_tcp_build_seq_4(const struct sc_tcp_context *const tcp_context,
					 const struct tcphdr *const tcp,
					 const uint8_t crc,
					 uint8_t *const rohc_data,
					 const size_t rohc_max_len);
int c_tcp_build_seq_5(const struct sc_tcp_context *const tcp_context,
					 const struct tcphdr *const tcp,
					 const uint8_t crc,
					 uint8_t *const rohc_data,
					 const size_t rohc_max_len);
int c_tcp_build_seq_6(const struct sc_tcp_context *const tcp_context,
					 const struct tcphdr *const tcp,
					 const uint8_t crc,
					 uint8_t *const rohc_data,
					 const size_t rohc_max_len);
int c_tcp_build_seq_7(const struct sc_tcp_context *const tcp_context,
					 const struct tcphdr *const tcp,
					 const uint8_t crc,
					 uint8_t *const rohc_data,
					 const size_t rohc_max_len);
int c_tcp_build_seq_8(const struct sc_tcp_context *const tcp_context,
					 const struct ipv4_hdr *const inner_ip_hdr,
					 const struct tcphdr *const tcp,
					 const uint8_t crc,
					 uint8_t *const rohc_data,
					 const size_t rohc_max_len);
void c_tcp_build_co_common(const ipv4_context_t *const inner_ip_ctxt,
						 const struct sc_tcp_context *const tcp_context,
						 const struct ipv4_hdr *const inner_ip_hdr,
						 const struct tcphdr *const tcp,
						 const uint8_t crc,
						 uint8_t *const rohc_data,
						 const size_t rohc_max_len, int *ret);
int c_optional_ip_id_lsb(const int behavior,
                         const uint16_t ip_id_nbo,
                         const uint16_t ip_id_offset,
                         const size_t nr_bits_wlsb,
                         uint8_t *const rohc_data,
                         const size_t rohc_max_len,
                         int *const indicator);
int dscp_encode(const uint8_t context_value,
                const uint8_t packet_value,
                uint8_t *const rohc_data,
                const size_t rohc_max_len,
                int *const indicator);
int variable_length_32_enc(const uint32_t old_value,
                           const uint32_t new_value,
                           const size_t nr_bits_63,
                           const size_t nr_bits_16383,
                           uint8_t *const rohc_data,
                           const size_t rohc_max_len,
                           int *const indicator);
