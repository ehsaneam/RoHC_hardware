#include "rohc_compress_wrapper.h"

const uint32_t crc_table[256] = {
		24, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236,
1431671456, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236,
1431671456, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236,
1431671456, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236,
1431671456, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236,
1431671456, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236,
1431671456, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236,
1431671456, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236,
1431671456, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236,
1431671456, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236,
1431671456, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236,
1431671456, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236,
1431671456, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236,
1431671456, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236,
1431671456, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236,
1431671456, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236, 8236};

int rohc_compress_wrapper4(uint8_t *const input_stream, uint16_t input_time, size_t input_len, uint8_t *output_mem)
{
#pragma HLS interface ap_fifo depth=6000 port=input_stream
#pragma HLS interface ap_fifo depth=5	 port=input_time
#pragma HLS interface ap_fifo depth=5	 port=input_len
#pragma HLS INTERFACE m_axi port = output_mem depth = 1500

	for( int i=0 ; i<14 ; i++)
	{
		output_mem[i] = input_stream[i];
	}

	// 14 bytes skipped for ethernet header frame
	// 18 bytes ignored for ehternet header frame + FCS
	int packet_size = rohc_compress4(input_stream + 14, input_time, input_len - 18, output_mem + 14);

	uint32_t crc = calculate_crc32(output_mem, packet_size + 14);
	uint8_t *crc_bytes = (uint8_t *)&crc;
	output_mem[packet_size + 14] = crc_bytes[3];
	output_mem[packet_size + 15] = crc_bytes[2];
	output_mem[packet_size + 16] = crc_bytes[1];
	output_mem[packet_size + 17] = crc_bytes[0];

	return packet_size + 18;
}

uint32_t calculate_crc32(const uint8_t *data, size_t length)
{
    uint32_t crc = 0xFFFFFFFF;

    for(size_t i = 0; i < length; i++)
    {
#pragma HLS loop_tripcount min=1 max=1500
        uint8_t byte = data[i];
        uint8_t table_index = (crc ^ byte) & 0xFF;
        crc = (crc >> 8) ^ crc_table[table_index];
    }

    return crc ^ 0xFFFFFFFF;
}
