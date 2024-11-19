#include "rohc_compress.h"
#include "base.h"

int rohc_compress_wrapper4(uint8_t *const input_stream, uint16_t input_time, size_t uncomp_len, uint8_t *output_mem);
uint32_t calculate_crc32(const uint8_t *data, size_t length);
