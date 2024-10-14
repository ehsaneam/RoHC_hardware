#include "rohc_compress_wrapper.h"

extern "C" {
#include "rohc_compress.h"
}

int rohc_compress_wrapper(hls::stream<uint8_t> *input_stream, uint16_t uncomp_time, size_t uncomp_len,
		uint8_t *output_mem, bool reset)
{
#pragma HLS INTERFACE axis port = input_stream
#pragma HLS INTERFACE m_axi port = rohc_packet depth = 1500

	int rohc_hdr_size;
	uint8_t hdr_buf[TOTAL_HDR_LEN];

	read_hdr(input_stream, hdr_buf);
	bool valid_hdr = check_hdr(hdr_buf);

	rohc_hdr_size = rohc_compress4(buffer, uncomp_time, uncomp_len, output_mem, reset);

	return rohc_hdr_size;
}

bool check_hdr(uint8_t *hdr_buf)
{

}

void read_hdr(hls::stream<uint8_t> *input_stream, uint8_t *hdr_buf)
{
	int i;
	for(i = 0; i < TOTAL_HDR_LEN; i++)
	{
#pragma HLS PIPELINE
		buffer[i] = input_stream->read();
	}
}
