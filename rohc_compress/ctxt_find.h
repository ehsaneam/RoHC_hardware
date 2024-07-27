#include "base.h"

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

uint16_t ip_fast_csum(const uint8_t *const iph, const size_t ihl);
bool ipv4_is_fragment(const struct ipv4_hdr *const ipv4);
uint16_t from32to16(const uint32_t x);
unsigned int lcg_rand();
