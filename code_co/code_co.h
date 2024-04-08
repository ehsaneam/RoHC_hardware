#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define CRC_INIT_3 0x7
#define CRC_INIT_7 0x7f

#define ROHC_WLSB_WIDTH_MAX  16U
#define ROHC_INIT_TS_STRIDE_MIN  3U

#define RSF_RST_ONLY  0x04
#define RSF_SYN_ONLY  0x02
#define RSF_FIN_ONLY  0x01
#define RSF_NONE      0x00

#define GET_REAL(x)  ((x) ? 1 : 0)

typedef enum
{
	ROHC_CRC_TYPE_3 = 3,     /**< The CRC-3 type */
	ROHC_CRC_TYPE_7 = 7,     /**< The CRC-7 type */
} rohc_crc_type_t;

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

typedef enum
{
	/// IP version 4
	IPV4 = 4,
	/// not IP
	IP_UNKNOWN = 0,
	/// IP version 4 (malformed)
	IPV4_MALFORMED = 1,
} ip_version;

typedef enum
{
	ROHC_SMALL_CID,
} rohc_cid_type_t;

struct net_hdr
{
	uint8_t proto;  /**< The header protocol */
	uint8_t *data;  /**< The header data */
	size_t len;     /**< The header length (in bytes) */
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

struct ip_packet
{
	ip_version version;
	union
	{
		struct ipv4_hdr v4;
	} header;
	const uint8_t *data;
	size_t size;
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

struct c_wlsb
{
	uint8_t count;
	uint32_t window_value[ROHC_WLSB_WIDTH_MAX];
	uint32_t window_used[ROHC_WLSB_WIDTH_MAX];
};

struct tcp_tmp_variables
{
	bool tcp_window_changed;
	uint8_t ttl_hopl;
	uint16_t ip_id_delta;
	uint32_t nr_ack_bits_16383;
	uint32_t nr_ip_id_bits_3;
	int ttl_irreg_chain_flag;
};

struct sc_tcp_context
{
	bool ecn_used;
	size_t ack_num_scaling_nr;
	uint32_t seq_num_scaled;
	uint32_t ack_num_scaled;
	uint16_t ack_stride;
	uint16_t msn;
	struct c_wlsb seq_wlsb;
	struct c_wlsb ack_wlsb;
	struct tcphdr old_tcphdr;
	struct tcp_tmp_variables tmp;
	ipv4_context_t ip_context;
};

struct rohc_comp
{
	uint8_t crc_table_3[256];
	uint8_t crc_table_7[256];
};

struct rohc_comp_ctxt
{
	size_t cid;
	struct sc_tcp_context specific;
	struct rohc_comp compressor;
};

int code_CO_packet(struct rohc_comp_ctxt *const context,
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
int c_tcp_build_rnd_8(struct sc_tcp_context *const tcp_context,
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
int c_tcp_build_seq_8(struct sc_tcp_context *const tcp_context,
					 const struct ipv4_hdr *const inner_ip_hdr,
					 const struct tcphdr *const tcp,
					 const uint8_t crc,
					 uint8_t *const rohc_data,
					 const size_t rohc_max_len);
void c_tcp_build_co_common(const ipv4_context_t *const inner_ip_ctxt,
						 struct sc_tcp_context *const tcp_context,
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
uint8_t wlsb_get_minkp_32bits(const struct c_wlsb *const wlsb,
								const uint32_t value,
								const int p);
int c_static_or_irreg8(const uint8_t packet_value,
                       const bool is_static,
                       uint8_t *const rohc_data,
                       const size_t rohc_max_len,
                       int *const indicator);
int c_static_or_irreg16(const uint16_t packet_value,
                        const bool is_static,
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
bool tcp_is_ack_stride_static(const uint16_t ack_stride,
                              const size_t nr_trans);
int code_cid_values(const size_t cid,
                    uint8_t *const dest,
                    const size_t dest_size,
                    size_t *const first_position);
uint8_t c_add_cid(const size_t cid);
uint8_t crc_calculate(const int crc_type,
                      const uint8_t *const data,
                      const size_t length,
                      const uint8_t init_val,
                      const uint8_t *const crc_table);
unsigned int rsf_index_enc(const uint8_t rsf_flags);
uint8_t crc_calc_7(const uint8_t *const buf,
				 const size_t size,
				 const uint8_t init_val,
				 const uint8_t *const crc_table);
uint8_t crc_calc_3(const uint8_t *const buf,
				 const size_t size,
				 const uint8_t init_val,
				 const uint8_t *const crc_table);
uint16_t rohc_bswap16(const uint16_t value);
uint32_t rohc_bswap32(const uint32_t value);
