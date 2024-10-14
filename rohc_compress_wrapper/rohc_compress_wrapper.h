#include <hls_stream.h>

#define ETH_HDR_LEN 14
#define TOTAL_HDR_LEN (sizeof(struct ipv4_hdr) + sizeof(struct tcphdr) + ETH_HDR_LEN)

void read_hdr(hls::stream<uint8_t> *input_stream, uint8_t *hdr_buf);
