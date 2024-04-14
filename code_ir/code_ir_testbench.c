#include "code_ir.h"

#define IN_LEN 12

int main()
{
	int i=0, j, failed = 0;

	struct rohc_comp_ctxt contexts[IN_LEN];
	uint8_t ip_pkts[IN_LEN][2048];
	uint8_t rohc_pkts[IN_LEN][2048];
	int packets_type[IN_LEN];
	size_t rohc_pkts_max_len[IN_LEN];

	uint8_t exp_rohc_pkts[IN_LEN][2048];
	size_t exp_hdrs_len[IN_LEN];

	FILE *fp = fopen("./../../../resources/inputs","r");
	if( fp==NULL )
	{
		printf("***********************--->file nis\n");
		return -1;
	}

	for( i=0 ; i<IN_LEN ; i++ )
	{
		fscanf(fp, "|max_len:%lu, cid:%lu, pid:%d, ptype:%d, bhv:%hhu, ttl:%hhu, ecn:%u, msn:%hu, "
				   "seq_cnt:%d, ack_str:%hu, ack_sca:%lu, crc:",
				&rohc_pkts_max_len[i], &contexts[i].cid, &contexts[i].pid, &packets_type[i],
				&contexts[i].specific.ip_context.ip_id_behavior,
				&contexts[i].specific.ip_context.ttl_hopl, &contexts[i].specific.ecn_used,
				&contexts[i].specific.msn, &contexts[i].specific.tcp_seq_num_change_count,
				&contexts[i].specific.ack_stride, &contexts[i].specific.ack_num_scaling_nr);
		for( j=0 ; j<256 ; j++)
		{
			fscanf(fp, "%hhu ", &contexts[i].compressor.crc_table_8[j]);
		}
		fscanf(fp, ", data:");
		for( j=0 ; j<sizeof(struct ipv4_hdr) + sizeof(struct tcphdr) ; j++)
		{
			fscanf(fp, "%hhu ", &ip_pkts[i][j]);
		}
		fscanf(fp, ", hdr_len:%lu, rohc:", &exp_hdrs_len[i]);
		for( j=0 ; j<exp_hdrs_len[i] ; j++)
		{
			fscanf(fp, "%hhu ", &exp_rohc_pkts[i][j]);
		}
		fscanf(fp, "|\n");
	}
	fclose(fp);

	for( i=0 ; i<IN_LEN ; i++ )
	{
		size_t ret = code_IR_packet(&contexts[i], ip_pkts[i],
					  rohc_pkts[i], rohc_pkts_max_len[i], packets_type[i]);
		if( exp_hdrs_len[i]!=ret )
		{
			printf("*********************** %d)%lu %lu\n", i, exp_hdrs_len[i], ret);
			failed = 1;
			break;
		}
		for( j=0 ; j<ret ; j++ )
		{
			if( exp_rohc_pkts[i][j]!=rohc_pkts[i][j] )
			{
				printf("*********************** %d-%d) %hhu-%hhu\n", i, j, exp_rohc_pkts[i][j], rohc_pkts[i][j]);
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
