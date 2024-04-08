#include "code_co.h"


#define IN_LEN 28

int main()
{
	int i=0, j, failed = 0;

	struct rohc_comp_ctxt contexts[IN_LEN];
	uint8_t ip_pkts[IN_LEN][2048];
	uint8_t rohc_pkts[IN_LEN][2048];
	int packets_type[IN_LEN];
	size_t payload_offsets[IN_LEN];
	size_t rohc_pkts_max_len[IN_LEN];

	uint8_t exp_rohc_pkts[IN_LEN][2048];
	size_t exp_hdrs_len[IN_LEN];
	size_t exp_payloads_offset[IN_LEN];
	uint8_t exp_last_ipids_bhv[IN_LEN];
	uint16_t exp_last_ipids[IN_LEN], exp_dfs[IN_LEN], exp_dscps[IN_LEN], exp_ttl_hopls[IN_LEN];

	FILE *fp = fopen("./../../../resources/inputs","r");
	if( fp==NULL )
	{
		printf("***********************--->file nis\n");
		return -1;
	}

	for( i=0 ; i<IN_LEN ; i++ )
	{
		uint8_t temp, temp1;

		fscanf(fp, "|rohc_max:%lu, pkt_type:%d, cid:%lu, ipid_bhv:%hhu, ecn_used:%d, "
				   "ttl_hopl:%hhu, msn:%hu, seq_num_sca:%u, ipid_delta:%hu, "
				   "ack_num_sca:%u, irg_flg:%d, old_seq_num:%u, old_ack_num:%u, "
				   "ack_bits:%u, ack_str:%hu, ack_num_sca_nr:%lu, win_chng:%u, "
				   "ipid_bits3:%u, old_urg_ptr:%hu, dscp:%hhu, seq_wlsb_cnt:%hhu, "
				   "ack_wlsb_cnt:%hhu, wlsb:",
					&rohc_pkts_max_len[i], &packets_type[i], &contexts[i].cid,
					&contexts[i].specific.ip_context.ip_id_behavior,
					&contexts[i].specific.ecn_used,
					&contexts[i].specific.tmp.ttl_hopl, &contexts[i].specific.msn,
					&contexts[i].specific.seq_num_scaled,
					&contexts[i].specific.tmp.ip_id_delta,
					&contexts[i].specific.ack_num_scaled,
					&contexts[i].specific.tmp.ttl_irreg_chain_flag,
					&contexts[i].specific.old_tcphdr.seq_num,
					&contexts[i].specific.old_tcphdr.ack_num,
					&contexts[i].specific.tmp.nr_ack_bits_16383,
					&contexts[i].specific.ack_stride,
					&contexts[i].specific.ack_num_scaling_nr,
					&contexts[i].specific.tmp.tcp_window_changed,
					&contexts[i].specific.tmp.nr_ip_id_bits_3,
					&contexts[i].specific.old_tcphdr.urg_ptr,
					&temp, &contexts[i].specific.seq_wlsb.count,
					&contexts[i].specific.ack_wlsb.count);
		contexts[i].specific.ip_context.dscp = temp;

		for( j=0 ; j<4 ; j++ )
		{
			fscanf(fp, "%u %u %u %u ", &contexts[i].specific.seq_wlsb.window_value[j],
					&contexts[i].specific.seq_wlsb.window_used[j],
					&contexts[i].specific.ack_wlsb.window_value[j],
					&contexts[i].specific.ack_wlsb.window_used[j]);
		}
		fscanf(fp, ", crc:");

		for( j=0 ; j<256 ; j++ )
		{
			fscanf(fp, "%hhu %hhu ", &contexts[i].compressor.crc_table_3[j],
					&contexts[i].compressor.crc_table_7[j]);
		}
		fscanf(fp, ", data:");
		for( j=0 ; j<sizeof(struct ipv4_hdr) + sizeof(struct tcphdr) ; j++ )
		{
			fscanf(fp, "%hhu ", &ip_pkts[i][j]);
		}

		fscanf(fp, ", rohc_hdrlen:%lu, payload_offset:%lu, last_ipid_bhv:%hhu, "
				   "last_ipid:%hu, df:%hhu, dscp:%hhu, ttl_hopl:%hhu, data:",
				&exp_hdrs_len[i], &exp_payloads_offset[i],
				&exp_last_ipids_bhv[i], &exp_last_ipids[i],
				&exp_dfs[i],
				&exp_dscps[i],
				&exp_ttl_hopls[i]);
		for( size_t j=0 ; j<exp_hdrs_len[i] ; j++ )
		{
			fscanf(fp, "%hhu ", &exp_rohc_pkts[i][j]);
		}
		fscanf(fp, "|\n");
	}

	fclose(fp);

	for( i=0 ; i<IN_LEN ; i++ )
	{
		int ret = code_CO_packet(&contexts[i], ip_pkts[i], rohc_pkts[i],
						rohc_pkts_max_len[i], packets_type[i]);
		printf("%i) %d\n", i, ret);

		if( ret!=exp_hdrs_len[i] )
		{
			printf("*********************** %d)%lu %lu\n", i, ret, exp_hdrs_len[i]);
			failed = 1;
			break;
		}

		for( j=0 ; j<ret ; j++ )
		{
			if( exp_rohc_pkts[i][j]!=rohc_pkts[i][j] )
			{
				printf("*********************** %d-%d\n", i, j);
				failed = 1;
			}
		}
	}

	if( failed )
	{
		printf("***********************sag tush fail shod\n");
	}
	else
	{
		printf("***********************yes, ye karo doros anjam dadim\n");
	}
	return failed;
}
